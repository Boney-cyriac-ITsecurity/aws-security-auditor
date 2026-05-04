import boto3
from datetime import datetime

findings = []

def check_s3():
    print("Checking S3 buckets...")
    s3 = boto3.client('s3')
    for bucket in s3.list_buckets()['Buckets']:
        try:
            cfg = s3.get_public_access_block(
                Bucket=bucket['Name'])['PublicAccessBlockConfiguration']
            if not all(cfg.values()):
                findings.append({
                    'severity': 'CRITICAL',
                    'service': 'S3',
                    'resource': bucket['Name'],
                    'issue': 'Bucket public access not fully blocked'
                })
        except:
            pass

def check_iam():
    print("Checking IAM users...")
    iam = boto3.client('iam')
    for user in iam.list_users()['Users']:
        mfa = iam.list_mfa_devices(
            UserName=user['UserName'])['MFADevices']
        if not mfa:
            findings.append({
                'severity': 'HIGH',
                'service': 'IAM',
                'resource': user['UserName'],
                'issue': 'No MFA device registered'
            })

def check_sg():
    print("Checking security groups...")
    ec2 = boto3.client('ec2')
    danger_ports = [22, 3389, 3306, 5432]
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        for rule in sg.get('IpPermissions', []):
            port = rule.get('FromPort', 0)
            for ip in rule.get('IpRanges', []):
                if ip.get('CidrIp') == '0.0.0.0/0':
                    if port in danger_ports:
                        findings.append({
                            'severity': 'HIGH',
                            'service': 'EC2',
                            'resource': sg['GroupId'],
                            'issue': f'Port {port} open to entire internet'
                        })

# Run all checks
print(f"\n=== AWS Security Audit — {datetime.now().strftime('%Y-%m-%d %H:%M')} ===\n")
check_s3()
check_iam()
check_sg()

# Print results
print(f"\n=== Findings ===\n")
if not findings:
    print("  No issues found. All checks passed.")
else:
    for f in findings:
        print(f"  [{f['severity']}] {f['service']} / {f['resource']}")
        print(f"           {f['issue']}\n")

print(f"Total findings: {len(findings)}")
print("\nAudit complete.")