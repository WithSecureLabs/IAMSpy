import boto3
import json


def handle_next_token(api_call, response_key, **kwargs):
    resp = api_call(**kwargs)

    results = resp[response_key]

    token = resp.get("NextToken", None)
    while token:
        resp = api_call(NextToken=token, **kwargs)
        results.extend(resp[response_key])
        token = resp.get("NextToken", None)

    return results


client = boto3.client(service_name="organizations")


def get_roots():
    return handle_next_token(client.list_roots, "Roots")


def get_policies(target_id):
    policies = handle_next_token(
        client.list_policies_for_target,
        "Policies",
        TargetId=target_id,
        Filter="SERVICE_CONTROL_POLICY",
    )

    for policy in policies:
        policy["Content"] = json.loads(
            client.describe_policy(PolicyId=policy["Id"])["Policy"]["Content"],
        )

    return policies


def get_children(parent):
    parent_id = parent["Id"]
    ous = handle_next_token(
        client.list_children,
        "Children",
        ParentId=parent_id,
        ChildType="ORGANIZATIONAL_UNIT",
    )
    accounts = handle_next_token(
        client.list_children,
        "Children",
        ParentId=parent_id,
        ChildType="ACCOUNT",
    )

    resp = parent

    resp["Policies"] = get_policies(resp["Id"])

    if ous:
        ous = [
            get_children(
                client.describe_organizational_unit(OrganizationalUnitId=x["Id"])["OrganizationalUnit"],
            )
            for x in ous
        ]
        ous = [{**x, "Type": "OU"} for x in ous]

    if accounts:
        accounts = [client.describe_account(AccountId=x["Id"])["Account"] for x in accounts]
        accounts = [{**x, "Policies": get_policies(x["Id"]), "Type": "Account"} for x in accounts]

    resp["Children"] = ous + accounts

    return resp


print(json.dumps(get_children(get_roots()[0]), indent=4, default=str))
