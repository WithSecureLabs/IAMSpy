from z3 import AstRef, Z3_OP_UNINTERPRETED, is_const
import re


# https://stackoverflow.com/questions/14080398/z3py-how-to-get-the-list-of-variables-from-a-formula
class AstRefKey:
    def __init__(self, n):
        self.n = n

    def __hash__(self):
        return self.n.hash()

    def __eq__(self, other):
        return self.n.eq(other.n)

    def __repr__(self):
        return str(self.n)


def askey(n):
    assert isinstance(n, AstRef)
    return AstRefKey(n)


def get_vars(f):
    r = set()

    def collect(f):
        if is_const(f):
            if f.decl().kind() == Z3_OP_UNINTERPRETED:
                r.add(askey(f))
        else:
            for c in f.children():
                collect(c)

    if isinstance(f, list):
        [collect(x) for x in f]
    else:
        collect(f)

    return {str(x) for x in r}


def get_conditions(all_vars):
    condition_keys = set()

    for var in all_vars:
        if regex := re.match(r"condition_(.*)_exists", var):
            condition_keys.add(regex.groups()[0])

    return condition_keys
