# aws-s3-permission-check
Non-compliance in S3 buckets across AWS accounts/profiles.

The python script checks for:
1. World readable/aws readable permissions in bucket ACLs
2. World readable/aws readable permissions for objects in the buckets.
3. Default encryption of the S3 bucket and its objects.
4. Last modified of the S3 bucket
5. Accountability by checking whether logging is enabled in the S3 bucket

Pre-requisite:
1. AWS account with console access (Access ID & Key) and appropriate permissions.
2. AWS-CLI installed & configured to use the Access ID & Key.
3. Python 2.7
4. Boto3 library (pip install boto3)

Environment: Linux, OSX

Usage: python s3_permission_check.py
