import boto3
import sys
import traceback
from botocore.exceptions import ClientError
import json
from datetime import date, datetime


def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()

    raise TypeError(f"Type {type(obj)} is not serializable: {obj}")


def handle_pagination(call, key, args=None):
    if args is None:
        args = {}
    output = []
    try:
        resp = call(**args)
        output.extend(resp[key])

        while resp["IsTruncated"]:
            args["Marker"] = resp["Marker"]
            resp = call(**args)
            output.extend(resp[key])
    except ClientError:
        print(traceback.format_exc(), file=sys.stderr)
        return []

    return output


iam = boto3.client("iam")

roles = handle_pagination(iam.list_roles, "Roles")

for role in roles:
    name = role["RoleName"]
    role_query = iam.get_role(RoleName=name)["Role"]
    role["InstanceProfileList"] = handle_pagination(
        iam.list_instance_profiles_for_role, "InstanceProfiles", {"RoleName": name}
    )

    role["AttachedManagedPolicies"] = handle_pagination(
        iam.list_attached_role_policies, "AttachedPolicies", {"RoleName": name}
    )

    role["RoleLastUsed"] = role_query["RoleLastUsed"]

    role["RolePolicyList"] = [
        iam.get_role_policy(RoleName=name, PolicyName=policy)
        for policy in handle_pagination(
            iam.list_role_policies, "PolicyNames", {"RoleName": name}
        )
    ]

    if "PermissionsBoundary" in role_query:
        role["PermissionsBoundary"] = role_query["PermissionsBoundary"]

    for policy in role["RolePolicyList"]:
        for key in ["RoleName", "ResponseMetadata"]:
            if key in policy:
                del policy[key]

    for key in ["MaxSessionDuration", "Description"]:
        if key in role:
            del role[key]


groups = handle_pagination(iam.list_groups, "Groups")

for group in groups:
    name = group["GroupName"]
    group["AttachedManagedPolicies"] = handle_pagination(
        iam.list_attached_group_policies, "AttachedPolicies", {"GroupName": name}
    )

    group["GroupPolicyList"] = [
        iam.get_group_policy(GroupName=name, PolicyName=policy)
        for policy in handle_pagination(
            iam.list_group_policies, "PolicyNames", {"GroupName": name}
        )
    ]


users = handle_pagination(iam.list_users, "Users")

for user in users:
    name = user["UserName"]
    user_query = iam.get_user(UserName=name)["User"]

    user["GroupList"] = [
        x["GroupName"]
        for x in handle_pagination(
            iam.list_groups_for_user, "Groups", {"UserName": name}
        )
    ]

    user["UserPolicyList"] = [
        iam.get_user_policy(UserName=name, PolicyName=policy)
        for policy in handle_pagination(
            iam.list_user_policies, "PolicyNames", {"UserName": name}
        )
    ]

    for x in user["UserPolicyList"]:
        del x["UserName"]
        del x["ResponseMetadata"]

    user["AttachedManagedPolicies"] = handle_pagination(
        iam.list_attached_user_policies, "AttachedPolicies", {"UserName": name}
    )

    if "PermissionsBoundary" in user_query:
        user["PermissionsBoundary"] = user_query["PermissionsBoundary"]


policies = [
    x
    for x in handle_pagination(iam.list_policies, "Policies")
    if x["AttachmentCount"] > 0 or x.get("PermissionsBoundaryUsageCount", 0) > 0
]
for policy in policies:
    arn = policy["Arn"]

    policy["PolicyVersionList"] = [
        iam.get_policy_version(PolicyArn=arn, VersionId=version["VersionId"])[
            "PolicyVersion"
        ]
        for version in handle_pagination(
            iam.list_policy_versions, "Versions", {"PolicyArn": arn}
        )
    ]


output = {
    "RoleDetailList": roles,
    "GroupDetailList": groups,
    "UserDetailList": users,
    "Policies": policies,
}

print(json.dumps(output, indent=4, default=json_serial))
