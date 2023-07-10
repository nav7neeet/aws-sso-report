import logging
import time
import boto3
from botocore.exceptions import ClientError
import pandas
import concurrent.futures

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
            if accnt["Id"] != "541383790912":
                accnt_list.append(accnt["Id"])

    return accnt_list


def get_accnt_assignment(sso_admin, account_id, instance_arn):
    response = sso_admin.list_permission_sets_provisioned_to_account(
        InstanceArn=instance_arn, AccountId=account_id
    )
    accnt_assignment = []

    for permission_set in response["PermissionSets"]:
        response = sso_admin.list_account_assignments(
            InstanceArn=instance_arn,
            AccountId=account_id,
            PermissionSetArn=permission_set,
        )
        for item in response["AccountAssignments"]:
            accnt_assignment.append(item)
    return accnt_assignment


def get_principal_name(tag, accnt_id, identity_store, store_id, principal_id, type):
    output = None
    if type == "GROUP":
        response = identity_store.describe_group(
            IdentityStoreId=store_id, GroupId=principal_id
        )
        output = response["DisplayName"]
    elif type == "USER":
        response = identity_store.describe_user(
            IdentityStoreId=store_id, UserId=principal_id
        )
        output = response["UserName"]

    return {tag: [accnt_id, output]}


def get_permission_set_name(tag, accnt_id, sso_admin, instance_arn, permission_set_arn):
    response = sso_admin.describe_permission_set(
        InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
    )
    return {tag: [accnt_id, response["PermissionSet"]["Name"]]}


def get_accnt_name(tag, accnt_id, organizations):
    response = organizations.describe_account(AccountId=accnt_id)
    return {tag: [accnt_id, response["Account"]["Name"]]}


def write_to_excel(*args):
    x = []
    keys = []
    for item in args:
        x.append(item)
        keys = keys + list(item.keys())
    data_frame = pandas.DataFrame()
    for key in set(keys):
        sum = []
        loop = 0
        for item in x:
            loop = loop + 1
            if key in item:
                if loop == 1:
                    sum = sum + item[key]
                else:
                    sum = sum + [item[key][1]]
        record = pandas.DataFrame.from_records([sum])
        data_frame = pandas.concat([data_frame, record])
    data_frame.columns = ["ID", "Name", "PS", "Assi", "Type"]
    print(data_frame)
    data_frame.set_index("ID", inplace=True)
    data_frame.to_excel("report.xlsx")


def main():
    try:
        sts = boto3.client("sts")
        response = sts.assume_role(RoleArn=role, RoleSessionName=ROLE_SESSION_NAME)
        organizations = get_client("organizations", response["Credentials"])
        sso_admin = get_client("sso-admin", response["Credentials"])
        identity_store = get_client("identitystore", response["Credentials"])

        response = sso_admin.list_instances()
        store_id = response["Instances"][0]["IdentityStoreId"]
        instance_arn = response["Instances"][0]["InstanceArn"]

        executor = concurrent.futures.ThreadPoolExecutor()
        task1 = []
        task2 = []
        task3 = []
        task4 = []
        task2_dict = {}
        task3_dict = {}
        task4_dict = {}
        task5_dict = {}
        row_num = 0

        accnt_list = get_accnt_list(organizations)
        for accnt in accnt_list:
            thread = executor.submit(
                get_accnt_assignment, sso_admin, accnt, instance_arn
            )
            task1.append(thread)

        for task in concurrent.futures.as_completed(task1):
            accnt_assignment = task.result()
            for item in accnt_assignment:
                row_num = row_num + 1
                task5_dict[row_num] = [item["AccountId"], item["PrincipalType"]]

                thread = executor.submit(
                    get_principal_name,
                    row_num,
                    item["AccountId"],
                    identity_store,
                    store_id,
                    item["PrincipalId"],
                    item["PrincipalType"],
                )
                task2.append(thread)

                thread = executor.submit(
                    get_permission_set_name,
                    row_num,
                    item["AccountId"],
                    sso_admin,
                    instance_arn,
                    item["PermissionSetArn"],
                )
                task3.append(thread)

                thread = executor.submit(
                    get_accnt_name,
                    row_num,
                    item["AccountId"],
                    organizations,
                )
                task4.append(thread)

        for task in concurrent.futures.as_completed(task2):
            task2_dict = task2_dict | task.result()

        for task in concurrent.futures.as_completed(task3):
            task3_dict = task3_dict | task.result()

        for task in concurrent.futures.as_completed(task4):
            task4_dict = task4_dict | task.result()

        write_to_excel(task4_dict, task3_dict, task2_dict, task5_dict)

    except Exception as exception:
        logger.error("##### An error occured #####: " + str(exception))
        quit()


if __name__ == "__main__":
    threaded_start = time.time()
    main()
    print("Time:", time.time() - threaded_start)
