# AWS Security Auditor

Automated AWS security auditor that scans cloud infrastructure 
for misconfigurations and generates a findings report.

## What it checks
- S3 buckets with public access enabled
- IAM users with no MFA registered  
- EC2 security groups with dangerous ports open to the internet

## How to run

### Install dependencies
pip install boto3 awscli

### Configure AWS credentials
aws configure

### Run the auditor
python aws_auditor.py

## Sample output
=== AWS Security Audit ===
[CRITICAL] S3 / my-bucket — Public access not blocked
[HIGH] IAM / john — No MFA registered
[HIGH] EC2 / sg-123 — Port 22 open to internet
Total findings: 3

## Standards
Checks mapped to CIS AWS Benchmark v1.4