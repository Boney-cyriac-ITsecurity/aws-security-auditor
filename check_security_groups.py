import boto3

ec2 = boto3.client('ec2')
sgs = ec2.describe_security_groups()['SecurityGroups']

print("=== Security Group Audit ===\n")

found = False
danger_ports = [22, 3389, 3306, 5432]

for sg in sgs:
    for rule in sg.get('IpPermissions', []):
        port = rule.get('FromPort', 0)
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                if port in danger_ports:
                    found = True
                    print(f"  [EXPOSED] {sg['GroupName']}")
                    print(f"           Port {port} open to entire internet")
                    print(f"           SG ID: {sg['GroupId']}\n")

if not found:
    print("  [SAFE] No dangerous open ports found")

print("Audit complete.")