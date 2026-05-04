import boto3

s3 = boto3.client('s3')
buckets = s3.list_buckets()['Buckets']

print("=== S3 Public Access Audit ===\n")

for bucket in buckets:
    name = bucket['Name']
    try:
        block = s3.get_public_access_block(Bucket=name)
        cfg = block['PublicAccessBlockConfiguration']
        all_blocked = all([
            cfg.get('BlockPublicAcls', False),
            cfg.get('IgnorePublicAcls', False),
            cfg.get('BlockPublicPolicy', False),
            cfg.get('RestrictPublicBuckets', False)
        ])
        status = "SAFE" if all_blocked else "!!! EXPOSED !!!"
        print(f"  [{status}] {name}")
    except Exception as e:
        print(f"  [UNKNOWN] {name} — {e}")

print("\nAudit complete.")