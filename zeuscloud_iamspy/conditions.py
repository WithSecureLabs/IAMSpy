import logging
import z3

from zeuscloud_iamspy.datatypes import convert

logger = logging.getLogger("iamspy.conditions")

"""
IAM Condition handling functions are defined here

IAM condition operators:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
Conditions with multiple keys or values:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_multi-value-conditions.html

TODO: Multi key/value sets
TODO: Policy Variables: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
"""


def if_exists(func):
    def wrapper(key, value, if_exists=False):
        condition = func(key, value)

        if not if_exists:
            condition = z3.And(z3.Bool(f"{key}_exists"), condition)

        return condition

    return wrapper


@if_exists
def string_equals(key, values):
    """
    StringEquals condition key

    Exact matching, case sensitive
    """
    logger.debug(f"string_equals condition: {key}, {values}")
    return z3.Or(*[z3.String(key) == convert("String", x) for x in values])


@if_exists
def string_not_equals(key, values):
    """
    StringNotEquals condition key

    Negated matching
    """
    logger.debug(f"string_not_equals condition: {key}, {values}")
    return z3.Not(string_equals(key, values))


@if_exists
def string_equals_ignore_case(key, values):
    """
    StringEqualsIgnoreCase condition key

    Exact matching, ignoring case
    """
    logger.debug(f"string_equals_ignore_case condition: {key}, {values}")
    return string_equals(key.lower(), [x.lower() for x in values])


@if_exists
def string_not_equals_ignore_case(key, values):
    """
    StringNotEqualsIgnoreCase condition key

    Negated matching, ignoring case
    """
    logger.debug(f"string_not_equals_ignore_case condition: {key}, {values}")
    return z3.Not(string_equals_ignore_case(key, values))


@if_exists
def string_like(key, values):
    """
    StringLike condition key

    Case-sensitive matching. The values can include multi-character match
    wildcards (*) and single-character match wildcards (?) anywhere in the
    string.

    Note
    If a key contains multiple values, StringLike can be qualified with set
    operators—ForAllValues:StringLike and ForAnyValue:StringLike.
    """
    logger.debug(f"string_like condition: {key}, {values}")
    return z3.Or(*[z3.InRe(z3.String(key), convert("RegexString", x, case_sensitive=True)) for x in values])


@if_exists
def string_not_like(key, values):
    """
    StringNotLike condition key

    Negated case-sensitive matching. The values can include multi-character match
    wildcards (*) or single-character match wildcards (?) anywhere in the string.
    """
    logger.debug(f"string_not_like condition: {key}, {values}")
    return z3.Not(string_like(key, values))


@if_exists
def numeric_equals(key, values):
    """
    NumericEquals condition key

    True if input number matches value specified in policy
    """
    logger.debug(f"numeric_equals condition: {key}, {values}")
    return z3.Or(*[z3.Int(key) == convert("Numeric", x) for x in values])


@if_exists
def numeric_not_equals(key, values):
    """
    NumericNotEquals condition key

    True if input number does not match value specified in policy
    """
    logger.debug(f"numeric_not_equals condition: {key}, {values}")
    return z3.Not(numeric_equals(key, values))


@if_exists
def numeric_less_than(key, values):
    """
    NumericLessThan condition key

    True if input less than value
    """
    logger.debug(f"numeric_less_than condition: {key}, {values}")
    return z3.Or(*[z3.Int(key) < convert("Numeric", x) for x in values])


@if_exists
def numeric_less_than_equals(key, values):
    """
    NumericLessThanEquals condition key

    True if input less than or equal to value
    """
    logger.debug(f"numeric_less_than_equals condition: {key}, {values}")
    return z3.Or(*[z3.Int(key) <= convert("Numeric", x) for x in values])


@if_exists
def numeric_greater_than(key, values):
    """
    NumericGreaterThan condition key

    True if input greater than value
    """
    logger.debug(f"numeric_greater_than condition: {key}, {values}")
    return z3.Or(*[z3.Int(key) > convert("Numeric", x) for x in values])


@if_exists
def numeric_greater_than_equals(key, values):
    """
    NumericGreaterThanEquals condition key

    True if input greater than or equal to value
    """
    logger.debug(f"numeric_greater_than_equals condition: {key}, {values}")
    return z3.Or(*[z3.Int(key) >= convert("Numeric", x) for x in values])


@if_exists
def date_equals(key, values):
    """
    DateEquals

    Matching a specific date
    """
    logger.debug(f"date_equals condition: {key}, {values}")
    return numeric_equals(key, [convert("Date", x) for x in values])


@if_exists
def date_not_equals(key, values):
    """
    DateNotEquals

    Negated matching
    """
    logger.debug(f"date_not_equals condition: {key}, {values}")

    return z3.Not(date_equals(key, values))


@if_exists
def date_less_than(key, values):
    """
    DateLessThan

    Matching before a specific date and time
    """
    logger.debug(f"date_less_than condition: {key}, {values}")
    return numeric_less_than(key, [convert("Date", x) for x in values])


@if_exists
def date_less_than_equals(key, values):
    """
    DateLessThanEquals

    Matching at or before a specific date and time
    """
    logger.debug(f"date_less_than_equals condition: {key}, {values}")
    return numeric_less_than_equals(key, [convert("Date", x) for x in values])


@if_exists
def date_greater_than(key, values):
    """
    DateGreaterThan

    Matching after a specific a date and time
    """
    logger.debug(f"date_greater_than condition: {key}, {values}")
    return numeric_greater_than(key, [convert("Date", x) for x in values])


@if_exists
def date_greater_than_equals(key, values):
    """
    DateGreaterThanEquals

    Matching at or after a specific date and time
    """
    logger.debug(f"date_greater_than_equals condition: {key}, {values}")
    return numeric_greater_than_equals(key, [convert("Date", x) for x in values])


@if_exists
def bool_match(key, values):
    """
    Bool

    Boolean matching
    """
    logger.debug(f"bool condition: {key}, {values}")
    return z3.Or(*[z3.Bool(key) == convert("Bool", x) for x in values])


@if_exists
def binary_equals(key, values):
    """
    BinaryEquals

    The BinaryEquals condition operator let you construct Condition elements that
    test key values that are in binary format. It compares the value of the specified
    key byte for byte against a base-64 encoded representation of the binary
    value in the policy.
    """
    logger.debug(f"binary_equals condition: {key}, {values}")
    # As these are base64 encoded strings, for now we are just passing these as string
    # comparisons on the encoded data. if_exists is set to True to bypass the additional
    # if_exists=False logic from the string function that would be done by the binary equals
    # if_exists decorator
    return string_equals(key, values, if_exists=True)


@if_exists
def ip_address(key, values):
    """
    IpAddress

    The specified IP address or range
    """
    logger.debug(f"ip_address condition: {key}, {values}")
    parts = []
    for x in values:
        base_ip, netmask = convert("IpNetwork", x)
        parts.append((z3.BitVec(key, netmask.size()) & netmask) == base_ip)
    return z3.Or(*parts)


@if_exists
def not_ip_address(key, values):
    """
    NotIpAddress

    All IP addresses except the specified IP address or range
    """
    logger.debug(f"not_ip_address condition: {key}, {values}")
    return z3.Not(ip_address(key, values))


@if_exists
def arn_equals(key, values):
    """
    ArnEquals

    Case-sensitive matching of the ARN. Each of the six colon-delimited components of the ARN is checked separately and
    each can include multi-character match wildcards (*) or single-character match wildcards (?). The ArnEquals
    and ArnLike condition operators behave identically.
    """
    logger.debug(f"arn_equals condition: {key}, {values}")
    suffixes = ["arn", "partition", "service", "region", "account", "resource"]
    parts = []

    for x in values:
        parts.append(
            z3.And(
                *[z3.InRe(z3.String(f"{key}_{suffix}"), regex) for suffix, regex in zip(suffixes, convert("Arn", x))]
            )
        )

    return z3.Or(*parts)


@if_exists
def arn_like(key, values):
    """
    ArnLike

    Case-sensitive matching of the ARN. Each of the six colon-delimited components of the ARN is checked separately
    and each can include multi-character match wildcards (*) or single-character match wildcards (?). The ArnEquals
    and ArnLike condition operators behave identically.
    """
    logger.debug(f"arn_like condition: {key}, {values}")
    return arn_equals(key, values)


@if_exists
def arn_not_equals(key, values):
    """
    ArnNotEquals

    Negated matching for ARN. The ArnNotEquals and ArnNotLike condition operators behave identically.
    """
    logger.debug(f"arn_not_equals condition: {key}, {values}")
    return z3.Not(arn_equals(key, values))


@if_exists
def arn_not_like(key, values):
    """
    ArnNotLike

    Negated matching for ARN. The ArnNotEquals and ArnNotLike condition operators behave identically.
    """
    logger.debug(f"arn_not_like condition: {key}, {values}")
    return arn_not_equals(key, values)


@if_exists
def null(key, values):
    """
    Null

    Checks existence of condition keys
    """
    logger.debug(f"null condition: {key}, {values}")
    values = [False if x == "true" else True for x in values]
    return z3.Or(*[z3.Bool(f"{key}_exists") == x for x in values])


condition_functions = {
    # String condition operators
    "StringEquals": string_equals,
    "StringNotEquals": string_not_equals,
    "StringEqualsIgnoreCase": string_equals_ignore_case,
    "StringNotEqualsIgnoreCase": string_not_equals_ignore_case,
    "StringLike": string_like,
    "StringNotLike": string_not_like,
    # Numeric condition operators
    "NumericEquals": numeric_equals,
    "NumericNotEquals": numeric_not_equals,
    "NumericLessThan": numeric_less_than,
    "NumericLessThanEquals": numeric_less_than_equals,
    "NumericGreaterThan": numeric_greater_than,
    "NumericGreaterThanEquals": numeric_greater_than_equals,
    # Date condition operators
    "DateEquals": date_equals,
    "DateNotEquals": date_not_equals,
    "DateLessThan": date_less_than,
    "DateLessThanEquals": date_less_than_equals,
    "DateGreaterThan": date_greater_than,
    "DateGreaterThanEquals": date_greater_than_equals,
    # Bool condition operators
    "Bool": bool_match,
    # Binary condition operators
    "BinaryEquals": binary_equals,
    # IP address condition operators
    "IpAddress": ip_address,
    "NotIpAddress": not_ip_address,
    # ARN condition operators
    "ArnEquals": arn_equals,
    "ArnLike": arn_like,
    "ArnNotEquals": arn_not_equals,
    "ArnNotLike": arn_not_like,
    # Null condition operator
    "Null": null,
}
