# AWS SSO Report

sso-report.py script helps to get SSO assignments for all the accounts under AWS organization. The script first assumes a role in the management account to get the list of AWS accounts. It then iterates through each account to get the assignment details. The final output is an excel file containig the SSO assignment details for various AWS accounts in the organization.

**Sample Output** <br>

| Account ID        | Account Name | Permission Set     | Assignment                 | Type  |
| ----------------- | ------------ | ------------------ | -------------------------- | ----- |
| \***\*\*\*\***468 | QA           | AWSPowerUserAccess | AWSSecurityAuditPowerUsers | GROUP |
| \***\*\*\*\***468 | QA           | AWSReadOnlyAccess  | ReadOnlyAccess             | GROUP |
| \***\*\*\*\***728 | Dev          | AWSPowerUserAccess | AWSSecurityAuditPowerUsers | GROUP |
| \***\*\*\*\***728 | Dev          | AWSPowerUserAccess | user@email.com             | USER  |
| \***\*\*\*\***763 | Test         | AWSPowerUserAccess | AWSSecurityAuditPowerUsers | GROUP |

<br>

**Prerequisites**<br>
MNGMT_ACCNT_ROLE<br>
Create a role with appropriate policy in all the member accounts. This role should have trust relationship with the Security Tooling account or some other account which is used to run the python script. The script assumes this role to get the list of member accounts present in the organization.<br>

**Installation**<br>
Clone the repo and install the following dependencies<br>
- boto3
- pandas
- openpyxl <br><br>

**Required Configuration** <br>
Update the following variables in the python file before running the script.
1. MNGMT_ACCNT_ID = "000000000000" --Account number of the management account. <br>
2. MNGMT_ACCNT_ROLE = role that you have created in the Prerequisites section<br>