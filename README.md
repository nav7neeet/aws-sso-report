# aws-sso-report

sso-report.py script helps automate the process to get SSO assignments for all the accounts under AWS organization. The script first assumes a role in the management account (Parent account) to get the list of AWS accounts. It then iterates through each account to get the assignment details. The final output is an excel file containig the SSO assignment details for various AWS accounts in the organization.
