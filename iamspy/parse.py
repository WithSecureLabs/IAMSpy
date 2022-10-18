"""
Parses IAM JSON documents into z3
"""
from collections import defaultdict
import z3
import logging
from pprint import pformat
import re
import string
from typing import List, Any, Union, Dict, Optional
from iamspy.iam import (
    Document,
    GroupDetail,
    RoleDetail,
    Statements,
    Effects,
    AuthorizationDetails,
    UserDetail,
)
from iamspy.conditions import condition_functions
from iamspy.datatypes import parse_string
from pydantic.json import pydantic_encoder

# A union set of all printable strings
CHARSET = string.ascii_letters + string.digits + string.punctuation
ANY = z3.Union(*[z3.Re(x) for x in CHARSET])

logger = logging.getLogger("iamspy.parse")

used_conditions = set()


def json_encoder(obj: Any, nested=True) -> Any:
    """
    For printing results
    """
    if nested:
        obj = pydantic_encoder(obj)

    if isinstance(obj, dict):
        for key in list(obj.keys()):
            if obj[key] is None:
                obj.pop(key)
            else:
                json_encoder(obj[key], False)
    elif isinstance(obj, list):
        while None in obj:
            obj.pop(obj.index(None))

        for x in obj:
            json_encoder(x, False)

    return obj


def _parse_condition(conditions: Dict[str, Dict[str, Union[str, List[str]]]]):
    """
    Map IAM condition keys to the condition functions in conditions.py.
    Ands together all the conditions present.
    """
    logger.debug(f"Parsing condition {pformat(conditions)}")

    items = []
    for test, variables in conditions.items():
        logger.debug(f"Condition test: {test}, variables: {variables}")
        if ":" in test:
            logger.warning(
                f"Multi key/value operator detected: {test}, this is currently not supported, skipping condition"
            )
            continue
        if if_exists := test.endswith("IfExists"):
            test = test.removesuffix("IfExists")
        for key, value in variables.items():
            logger.debug(f"Variable key: {key}, value: {value}")
            used_conditions.add(key)
            if not isinstance(value, list):
                value = [value]
            items.append(condition_functions[test](f"condition_{key}", value, if_exists=if_exists))

    return z3.simplify(z3.And(*items))


def _parse_statement(statement: Statements):
    """
    Parse an IAM statement block
    TODO: InvalidStatementError error handling
    """
    logger.debug(f"Parsing statement {statement.Sid}")
    if isinstance(statement.Action, str):
        statement.Action = [statement.Action]

    if isinstance(statement.NotAction, str):
        statement.NotAction = [statement.NotAction]

    a = z3.String("a")
    if statement.Action:
        actions = z3.Or([parse_string(a, action) for action in statement.Action])
    elif statement.NotAction:
        actions = z3.Not(z3.Or([parse_string(a, action) for action in statement.NotAction]))
    else:
        raise NotImplementedError()

    if isinstance(statement.Resource, str):
        statement.Resource = [statement.Resource]

    r = z3.String("r")
    if statement.Resource:
        resources = z3.Or([parse_string(r, resource) for resource in statement.Resource])
    elif statement.NotResource:
        resources = z3.Or([z3.Not(parse_string(r, resource)) for resource in statement.NotResource])
    else:
        resources = True

    s = z3.String("s")
    s_account = z3.String("s_account")
    if statement.Principal:
        # AWS Principals can not use wildcards
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
        # TODO: Makes these into an z3.Or
        if "AWS" in statement.Principal:
            items = []
            for principal in statement.Principal["AWS"]:
                if re.match(r"[0-9]{12}", principal):
                    principal = f"arn:aws:iam::{principal}:root"
                try:
                    account_id = principal.split(":")[4]
                except IndexError:
                    account_id = "*"
                if principal.endswith(":root"):
                    items.append(z3.And(z3.Bool("identity"), parse_string(s_account, account_id, wildcard=False)))
                else:
                    items.append(
                        z3.And(parse_string(s, principal, wildcard=False), s_account == z3.StringVal(account_id))
                    )
            principals = z3.Or(*items)
        elif "Service" in statement.Principal:
            principals = z3.Or(
                [parse_string(s, principal, wildcard=False) for principal in statement.Principal["Service"]]
            )
        elif "Federated" in statement.Principal:
            logger.warning(f"Federated principals {statement.Principal} currently not supported, skipping statement")
            principals = False
        else:
            raise NotImplementedError()
    else:
        principals = True

    if statement.Condition:
        conditions = _parse_condition(statement.Condition)
    else:
        conditions = True

    return z3.simplify(z3.And(actions, resources, principals, conditions))


def _parse_document(document: Document, identifier: str):
    """
    Parse an IAM document of multiple statement
    """
    allow = []
    deny = []
    logger.info(f"Parsing policy document: {identifier}")
    doc = z3.Bool(identifier)
    # doc_allow and doc_deny are to allow querying later on for
    # what documents allow or deny what and where
    doc_allow = z3.Bool(f"{identifier}_allow")
    doc_deny = z3.Bool(f"{identifier}_deny")

    for stmt in document.Statement:
        parsed = _parse_statement(stmt)
        if stmt.Effect == Effects.ALLOW:
            allow.append(parsed)
        else:
            deny.append(parsed)

    return (
        doc == z3.And(doc_allow, doc_deny),
        doc_allow == z3.simplify(z3.Or(*allow)),
        doc_deny == z3.simplify(z3.Not(z3.Or(*deny))),
    )


def _parse_group(data: AuthorizationDetails, group: GroupDetail):
    logger.info(
        f"Parsing {group.Arn} with {len(group.GroupPolicyList)} inline and {len(group.AttachedManagedPolicies)} managed policies"
    )
    model = []
    identifiers = []

    for inline_policy in group.GroupPolicyList:
        logger.info(f"Parsing inline {group.Arn}_{inline_policy.PolicyName}")
        identifier = f"identity_{group.Arn}_{inline_policy.PolicyName}"
        model.extend(_parse_document(inline_policy.PolicyDocument, identifier))
        identifiers.append(identifier)
        testing.add(identifier)

    for managed_policy in group.AttachedManagedPolicies:
        logger.info(f"Parsing managed {group.Arn}_{managed_policy.PolicyName}")
        assert f"identity_{managed_policy.PolicyArn}" in testing
        identifiers.append(f"identity_{managed_policy.PolicyArn}")

    testing.add(f"identity_{group.Arn}")
    g = z3.Bool(f"identity_{group.Arn}")
    group_allow = z3.Bool(f"identity_{group.Arn}_allow")
    group_deny = z3.Bool(f"identity_{group.Arn}_deny")

    identifiers_allow = [z3.Bool(f"{x}_allow") for x in identifiers]
    identifiers_deny = [z3.Bool(f"{x}_deny") for x in identifiers]

    model.extend(
        (
            g == z3.And(group_allow, group_deny),
            group_allow == z3.Or(*identifiers_allow),
            group_deny == z3.And(*identifiers_deny),
        )
    )
    return model


def _parse_role(data: AuthorizationDetails, role: RoleDetail):
    logger.info(
        f"Parsing {role.Arn} with {len(role.RolePolicyList)} inline and {len(role.AttachedManagedPolicies)} managed policies"
    )
    model = []

    identifiers = []

    for inline_policy in role.RolePolicyList:
        logger.info(f"Parsing inline {role.Arn}_{inline_policy.PolicyName}")
        identifier = f"identity_{role.Arn}_{inline_policy.PolicyName}"
        model.extend(_parse_document(inline_policy.PolicyDocument, identifier))
        identifiers.append(identifier)
        testing.add(identifier)

    for managed_policy in role.AttachedManagedPolicies:
        logger.info(f"Parsing managed {role.Arn}_{managed_policy.PolicyName}")
        assert f"identity_{managed_policy.PolicyArn}" in testing
        identifiers.append(f"identity_{managed_policy.PolicyArn}")

    testing.add(f"identity_{role.Arn}")
    r = z3.Bool(f"identity_{role.Arn}")
    role_allow = z3.Bool(f"identity_{role.Arn}_allow")
    role_deny = z3.Bool(f"identity_{role.Arn}_deny")

    identifiers_allow = [z3.Bool(f"{x}_allow") for x in identifiers]
    identifiers_deny = [z3.Bool(f"{x}_deny") for x in identifiers]

    model.extend(parse_resource_policy(role.Arn, role.AssumeRolePolicyDocument))

    model.extend(
        (
            r == z3.And(role_allow, role_deny),
            role_allow == z3.Or(*identifiers_allow),
            role_deny == z3.And(*identifiers_deny),
        )
    )
    return model


def _parse_user(data: AuthorizationDetails, user: UserDetail):
    logger.info(
        f"Parsing {user.Arn} with {len(user.UserPolicyList)} inline and {len(user.AttachedManagedPolicies)} managed policies, {len(user.GroupList)} groups"
    )
    model = []
    identifiers = []

    for inline_policy in user.UserPolicyList:
        identifier = f"identity_{user.Arn}_{inline_policy.PolicyName}"
        model.extend(_parse_document(inline_policy.PolicyDocument, identifier))
        identifiers.append(identifier)
        testing.add(identifier)

    for managed_policy in user.AttachedManagedPolicies:
        assert f"identity_{managed_policy.PolicyArn}" in testing
        identifiers.append(f"identity_{managed_policy.PolicyArn}")

    for group_name in user.GroupList:
        group = next(x for x in data.GroupDetailList if x.GroupName == group_name)
        assert f"identity_{group.Arn}" in testing
        identifiers.append(f"identity_{group.Arn}")

    testing.add(f"identity_{user.Arn}")
    u = z3.Bool(f"identity_{user.Arn}")
    user_allow = z3.Bool(f"identity_{user.Arn}_allow")
    user_deny = z3.Bool(f"identity_{user.Arn}_deny")

    identifiers_allow = [z3.Bool(f"{x}_allow") for x in identifiers]
    identifiers_deny = [z3.Bool(f"{x}_deny") for x in identifiers]

    model.extend(
        (
            u == z3.And(user_allow, user_deny),
            user_allow == z3.Or(*identifiers_allow),
            user_deny == z3.And(*identifiers_deny),
        )
    )
    return model


def parse_resource_policy(arn: str, doc: Document, account_id: Optional[str] = None):
    logger.info(f"Parsing resource policy for {arn}")
    if account_id is None:
        account_id = arn.split(":")[4]
    if not account_id:
        raise Exception(f"Missing account id for {arn}")
    return [
        parse_string(z3.String(f"resource_{arn}_account"), account_id),
        *_parse_document(doc, f"resource_{arn}"),
    ]


testing = set()


def generate_model(data: AuthorizationDetails):
    """
    Parses a GAAD, pulls out policies, users, groups etc
    """
    logger.info(
        f"Generating model from GAAD output with {len(data.UserDetailList)} users, {len(data.GroupDetailList)} groups, {len(data.RoleDetailList)} roles, {len(data.Policies)} policies"
    )
    model = []

    for policy in data.Policies:
        document = next(x for x in policy.PolicyVersionList if x.IsDefaultVersion).Document

        model.extend(_parse_document(document, f"identity_{policy.Arn}"))
        testing.add(f"identity_{policy.Arn}")

    for group in data.GroupDetailList:
        model.extend(_parse_group(data, group))

    for role in data.RoleDetailList:
        model.extend(_parse_role(data, role))

    for user in data.UserDetailList:
        model.extend(_parse_user(data, user))

    logger.info(f"Used condition keys: {used_conditions}")
    return model


def generate_evaluation_logic_checks(model_vars, source: str, resource: str):
    logger.info(f"Generating evaluation logic checks for {source} against {resource}")
    constraints = []

    s_account = z3.String("s_account")
    s = z3.String("s")
    constraints.append(s_account == z3.SubString(s, 13, 12))
    resource_account = resource.split(":")[4]
    if resource_account:
        constraints.append(z3.String("r_account") == z3.StringVal(resource_account))
    else:
        constraints.append(z3.String("r_account") == z3.String(f"resource_{resource}_account"))

    # Explicit Deny

    # SCPs

    # Resource Policy
    resource_identifier = f"resource_{resource}"
    resource_check = z3.Bool(resource_identifier)
    constraints.append(z3.Bool("resource") == resource_check)
    constraints.append(z3.Bool(f"resource_{resource}_deny") == True)  # noqa: E712
    if resource.startswith("arn:aws:s3:::") and "/" in resource:
        bucket_resource = resource.split("/")[0]
        logger.info(f"Associating {bucket_resource} policy with bucket object {resource}")
        constraints.append(z3.Bool(f"resource_{resource}") == z3.Bool(f"resource_{bucket_resource}"))
        constraints.append(z3.Bool(f"resource_{resource}_allow") == z3.Bool(f"resource_{bucket_resource}_allow"))
        constraints.append(z3.Bool(f"resource_{resource}_deny") == z3.Bool(f"resource_{bucket_resource}_deny"))
        constraints.append(
            z3.String(f"resource_{resource}_account") == z3.String(f"resource_{bucket_resource}_account")
        )
        resource_identifier = f"resource_{bucket_resource}"
    if resource_identifier not in model_vars:
        logger.debug(f"Missing resource policy for {resource_identifier}, defaulting to False")
        constraints.append(resource_check == False)  # noqa: E712

    # Identity Policy
    identity_identifier = f"identity_{source}"
    identity_check = z3.And(z3.Bool(identity_identifier), z3.Bool(f"identity_{source}_deny"))
    if source:
        if identity_identifier not in model_vars:
            constraints.append(identity_check == False)  # noqa: E712
        source_account = source.split(":")[4]
        constraints.append(z3.String("s_account") == z3.StringVal(source_account))
    else:
        identities = [x for x in model_vars if x.startswith('identity') and not x.endswith('_allow') and not x.endswith('_deny')]
        identities = [x for x in identities if len(x.split(':')) > 4 and (x.split(":")[5].startswith('user') or x.split(":")[5].startswith('role'))] 
        identity_identifiers = [z3.And(z3.Bool(x), z3.Bool(f"{x}_deny"), s == x.lstrip("identity_"), z3.String("s_account") == z3.StringVal(x.split(":")[4])) for x in identities]
        identity_check = z3.Or(*identity_identifiers)

    constraints.append(z3.Bool("identity") == identity_check)
    # Boundary Policy

    # Session Policy

    constraints.append(z3.Or(resource_check, identity_check))
    constraints.append(
        # TODO: Add further cases where resource policy is always required
        z3.Or(
            z3.And(parse_string(z3.String("a"), "sts:assumerole"), resource_check),
            z3.Not(parse_string(z3.String("a"), "sts:assumerole")),
        )
    )
    constraints.append(
        z3.Or(
            z3.And(z3.String("s_account") != z3.String("r_account"), resource_check),
            z3.String("s_account") == z3.String("r_account"),
        )
    )

    logger.debug(f"Evaluation logic constraints: {constraints}")
    return constraints
