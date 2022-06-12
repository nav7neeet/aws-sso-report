import logging
import boto3
from botocore.exceptions import ClientError
import pandas

MANAGEMENT_SSO_ROLE = "sso-read-only-role"
MANAGEMENT_ACCOUNT_ID = "000000000000"
ROLE_SESSION_NAME = "sso-report"

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def get_client(role, service_name):
    sts_client = boto3.client("sts")
    response = sts_client.assume_role(RoleArn=role, RoleSessionName=ROLE_SESSION_NAME)
    temp_creds = response["Credentials"]

    client = boto3.client(
        service_name,
        aws_access_key_id=temp_creds["AccessKeyId"],
        aws_secret_access_key=temp_creds["SecretAccessKey"],
        aws_session_token=temp_creds["SessionToken"],
    )
    return client


def get_account_list(organizations):
    account_list = []
    paginator = organizations.get_paginator("list_accounts")
    pages = paginator.paginate()

    for page in pages:
        for account in page["Accounts"]:
            account_list.append({"name": account["Name"], "id": account["Id"]})

    return account_list

def get_account_assignment(sso_admin, account_id, instance_arn):
    response = sso_admin.list_permission_sets_provisioned_to_account(
        InstanceArn=instance_arn, AccountId=account_id
    )
    account_assignments = []

    for permission_set in response["PermissionSets"]:
        response = sso_admin.list_account_assignments(
            InstanceArn=instance_arn,
            AccountId=account_id,
            PermissionSetArn=permission_set,
        )
        for item in response["AccountAssignments"]:
            account_assignments.append(item)
    return account_assignments


def get_principal_name(identity_store, identity_store_id, principal_id, principal_type):

    if principal_type == "GROUP":
        response = identity_store.describe_group(
            IdentityStoreId=identity_store_id, GroupId=principal_id
        )
        return response["DisplayName"]
    else:
        response = identity_store.describe_user(
            IdentityStoreId=identity_store_id, UserId=principal_id
        )
        return response["UserName"]


def get_permission_set_name(sso_admin, instance_arn, permission_set_arn):
    response = sso_admin.describe_permission_set(
        InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
    )
    return response["PermissionSet"]["Name"]


def get_data_frame():
    table = []
    columns = ["Account ID", "Account Name", "Permission Set", "Assignment", "Type"]
    data_frame = pandas.DataFrame(table, columns=columns)
    return data_frame


def create_table(data_frame, data):
    data_frame = pandas.concat(
        [
            data_frame,
            pandas.DataFrame.from_records(
                [
                    {
                        "Account ID": data[0],
                        "Account Name": data[1],
                        "Permission Set": data[2],
                        "Assignment": data[3],
                        "Type": data[4],
                    }
                ]
            ),
        ]
    )
    return data_frame


def write_to_excel(table):
    file_name = "sso-report.xlsx"
    table.to_excel(file_name)


def main():
    try:
        role = f"arn:aws:iam::{MANAGEMENT_ACCOUNT_ID}:role/{MANAGEMENT_SSO_ROLE}"
        client = get_client(role, "organizations")
        account_list = get_account_list(client)
        sso_admin = get_client(role, "sso-admin")
        identity_store = get_client(role, "identitystore")
        response = sso_admin.list_instances()

        data_frame = get_data_frame()
        for sso_instance in response["Instances"]:
            identity_store_id = sso_instance["IdentityStoreId"]
            instance_arn = sso_instance["InstanceArn"]

            for account in account_list:
                logger.info(f'sso group names for {account["id"]}')
                account_assignments = get_account_assignment(
                    sso_admin, account["id"], instance_arn
                )

                for item in account_assignments:
                    data = []
                    principal_name = get_principal_name(
                        identity_store,
                        identity_store_id,
                        item["PrincipalId"],
                        item["PrincipalType"],
                    )
                    permission_set_name = get_permission_set_name(
                        sso_admin, instance_arn, item["PermissionSetArn"]
                    )
                    data.append(account["id"])
                    data.append(account["name"])
                    data.append(permission_set_name)
                    data.append(principal_name)
                    data.append(item["PrincipalType"])
                    data_frame = create_table(data_frame, data)
            write_to_excel(data_frame)

    except Exception as exception:
        logger.error("##### An error occured #####: " + str(exception))
        quit()


if __name__ == "__main__":
    main()
