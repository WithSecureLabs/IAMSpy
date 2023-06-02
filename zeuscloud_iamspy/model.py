from typing import Dict, List, Optional, Set
import logging
import json
import os
import z3
import hashlib
from zeuscloud_iamspy.iam import AuthorizationDetails, ResourcePolicy
from zeuscloud_iamspy import parse
from zeuscloud_iamspy.datatypes import parse_string
from zeuscloud_iamspy.utils import get_conditions, get_vars


logger = logging.getLogger("iamspy.model")


class Model:
    def __init__(self):
        self.solver = z3.Solver()
        self._model_vars = None

    def __enter__(self):
        new_solver = z3.Solver()
        new_solver.add(*list(self.solver.assertions()))
        return new_solver

    def __exit__(self, exc_type, exc_value, exc_traceback):
        pass

    def save(self, filename: str):
        """
        Save a generated Z3 model to a file
        """
        output = self.solver.to_smt2()
        with open(filename, "w") as fs:
            fs.write(output)

    def load_model(self, filename: str):
        """
        Load an existing Z3 model from a file.
        """
        self.solver.from_file(filename)
        self._model_vars = None

    def load_gaad(self, filename: str) -> AuthorizationDetails:
        """
        Load the output of `aws iam get-account-authorization-details`

        Returns a python object representation of the JSON doc, after adding
        the model to the Z3 solver.
        """
        return self.load_gaad_json(json.load(open(filename)))

    def load_gaad_json(self, gaad_json: Dict) -> AuthorizationDetails:
        auth_details = AuthorizationDetails(**gaad_json)
        conditions = parse.generate_model(auth_details)
        self.solver.add(*conditions)
        self._model_vars = None
        return auth_details

    def load_resource_policies(self, filename: str) -> None:
        """
        Load resource policies in from a JSON file
        """
        return self.load_resource_policies_json(json.load(open(filename)))

    def load_resource_policies_json(self, resource_policies_json: List) -> AuthorizationDetails:
        policies = [ResourcePolicy(**item) for item in resource_policies_json]
        for policy in policies:
            self.solver.add(*parse.parse_resource_policy(policy.Resource, policy.Policy, policy.Account))
        self._model_vars = None

    @property
    def model_vars(self):
        # Try loading from file
        if self._model_vars is None:
            try:
                with open("model.vars") as fs:
                    data = fs.read()
                    h, v = data.split("\n", 1)
                    if h == self.hash:
                        logger.info("Loading model vars from model.vars")
                        self._model_vars = set(v.split("\n"))
            except FileNotFoundError:
                pass

        # Re-generate the model vars
        if self._model_vars is None:
            self._model_vars = get_vars(list(self.solver.assertions()))
            with open("model.vars", "w") as fs:
                logger.info("Saving model vars to model.vars")
                fs.write(self.hash + "\n")
                fs.write("\n".join(list(self._model_vars)))

        return self._model_vars

    @property
    def hash(self):
        return hashlib.md5(self.solver.to_smt2().encode()).hexdigest()

    def generate_evaluation_logic_checks(self, source: Optional[str], resource: str):
        """
        Generate the assertions for the model
        """
        return parse.generate_evaluation_logic_checks(self.model_vars, source, resource)

    def _generate_query_conditions(
        self,
        source: Optional[str],
        action: str,
        resource: str,
        conditions: Optional[List[str]] = None,
        condition_file: Optional[str] = None,
        strict_conditions: bool = False,
        model_conditions: Set[str] = set(),
    ):
        if conditions is None:
            conditions = []

        output = self.generate_evaluation_logic_checks(source, resource)

        s, a, r = z3.Strings("s a r")

        if source is not None:
            logger.debug(f"Adding constraint source is {source}")
            output.append(parse_string(s, source, wildcard=False))
        logger.debug(f"Adding constraint action is {action}")
        logger.debug(f"Adding constraint resource is {resource}")
        output.append(parse_string(a, action, wildcard=False))
        output.append(parse_string(r, resource, wildcard=False))

        provided_conditions = set()

        for condition in conditions:
            key, value = condition.split("=")
            logger.debug(f"Adding constraint to set {key} condition as {value}")
            provided_conditions.add(key)
            output.append(z3.String(f"condition_{key}") == z3.StringVal(value))

        if condition_file:
            logger.debug(f"Parsing {condition_file}")
            condition_file_data = json.load(open(condition_file))
            output.append(parse._parse_condition(condition_file_data))
            for test, variables in condition_file_data.items():
                for key, value in variables.items():
                    provided_conditions.add(key)

        if strict_conditions:
            logger.debug(f"Non existent conditions from request are: {model_conditions - provided_conditions}")

            for condition in model_conditions - provided_conditions:
                output.append(z3.Bool(f"condition_{condition}_exists") == False)

            for condition in provided_conditions:
                output.append(z3.Bool(f"condition_{condition}_exists"))

        return output

    def can_i(
        self,
        source: str,
        action: str,
        resource: str,
        conditions: List[str] = [],
        condition_file: Optional[str] = None,
        strict_conditions: bool = False,
        debug: bool = False,
    ) -> bool:
        """
        Used by the CLI to provide the can-i call.
        """
        with self as solver:
            logger.debug("Identifying model conditions")
            model_conditions = get_conditions(self.model_vars)
            logger.debug(f"Model conditions identified as: {model_conditions}")

            query_conditions = self._generate_query_conditions(
                source=source,
                action=action,
                resource=resource,
                conditions=conditions,
                condition_file=condition_file,
                strict_conditions=strict_conditions,
                model_conditions=model_conditions,
            )

            solver.add(*query_conditions)

            if debug:
                return solver
            else:
                return solver.check() == z3.sat

    def who_can(
        self,
        action: str,
        resource: str,
        conditions: List[str] = [],
        condition_file: Optional[str] = None,
        strict_conditions: bool = False,
    ) -> List[str]:
        """
        Used by the CLI to provide the who-can call.
        """
        with self as solver:
            logger.debug("Identifying model conditions")
            model_conditions = get_conditions(self.model_vars)
            logger.debug(f"Model conditions identified as: {model_conditions}")

            query_conditions = self._generate_query_conditions(
                source=None,
                action=action,
                resource=resource,
                conditions=conditions,
                condition_file=condition_file,
                strict_conditions=strict_conditions,
                model_conditions=model_conditions,
            )

            solver.add(*query_conditions)
            sat = solver.check() == z3.sat
            sources = []
            while sat:
                s = z3.String("s")
                m = solver.model()
                source = m[s]
                sources.append(str(source)[1:-1])
                solver.add(s != source)
                sat = solver.check() == z3.sat
            return sources
