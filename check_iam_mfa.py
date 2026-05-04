import boto3

iam = boto3.client('iam')
users = iam.list_users()['Users']

print("=== IAM MFA Audit ===\n")

risky = []
for user in users:
    username = user['UserName']
    mfa = iam.list_mfa_devices(UserName=username)['MFADevices']
    if not mfa:
        risky.append(username)
        print(f"  [NO MFA] {username}")
    else:
        print(f"  [MFA OK] {username}")

print(f"\nSummary: {len(risky)} user(s) without MFA")
if risky:
    print("Recommendation: Enable MFA immediately for above users")