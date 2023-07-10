import logging
import time
import boto3
from botocore.exceptions import ClientError
import pandas

MNGMT_ACCNT_ID = "975300453774"
MNGMT_ACCNT_ROLE = "sso-read-only-role"
ROLE_SESSION_NAME = "sso-report"
role = f"arn:aws:iam::{MNGMT_ACCNT_ID}:role/{MNGMT_ACCNT_ROLE}"

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def get_client(service_name, temp_creds):
    client = boto3.client(
        service_name,
        aws_access_key_id=temp_creds["AccessKeyId"],
        aws_secret_access_key=temp_creds["SecretAccessKey"],
        aws_session_token=temp_creds["SessionToken"],
    )
    return client


def get_accnt_list(organizations):
    accnt_list = []
    paginator = organizations.get_paginator("list_accounts")
    response_iterator = paginator.paginate()

    for response in response_iterator:
        for accnt in response["Accounts"]:
            # if accnt["Id"] != "541383790912":
            accnt_list.append({"name": accnt["Name"], "id": accnt["Id"]})

    return accnt_list


def get_accnt_assignment(sso_admin, account_id, instance_arn):
    response = sso_admin.list_permission_sets_provisioned_to_account(
        InstanceArn=instance_arn, AccountId=account_id
    )
    print(f"{account_id} - {response}")
    accnt_assignment = []

    if "PermissionSets" in response:
        for permission_set in response["PermissionSets"]:
            response = sso_admin.list_account_assignments(
                InstanceArn=instance_arn,
                AccountId=account_id,
                PermissionSetArn=permission_set,
            )
            for item in response["AccountAssignments"]:
                accnt_assignment.append(item)
        return accnt_assignment


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
    file_name = "report.xlsx"
    table.to_excel(file_name)


def main():
    try:
        sts = boto3.client("sts")
        response = sts.assume_role(RoleArn=role, RoleSessionName=ROLE_SESSION_NAME)
        organizations = get_client("organizations", response["Credentials"])
        sso_admin = get_client("sso-admin", response["Credentials"])
        identity_store = get_client("identitystore", response["Credentials"])
        accnt_list = get_accnt_list(organizations)
        response = sso_admin.list_instances()

        data_frame = get_data_frame()
        for sso_instance in response["Instances"]:
            identity_store_id = sso_instance["IdentityStoreId"]
            instance_arn = sso_instance["InstanceArn"]

            for accnt in accnt_list:
                logger.info(f'sso group names for {accnt["id"]}')
                accnt_assignment = get_accnt_assignment(
                    sso_admin, accnt["id"], instance_arn
                )

                if accnt_assignment:
                    for item in accnt_assignment:
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
                        data.append(accnt["id"])
                        data.append(accnt["name"])
                        data.append(permission_set_name)
                        data.append(principal_name)
                        data.append(item["PrincipalType"])
                        data_frame = create_table(data_frame, data)
            write_to_excel(data_frame)

    except Exception as exception:
        logger.error("##### An error occured #####: " + str(exception))
        quit()


if __name__ == "__main__":
    threaded_start = time.time()
    main()
    print("Time:", time.time() - threaded_start)
