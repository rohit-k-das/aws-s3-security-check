import boto3
import os
import datetime

#Check for buckets public ACL
def s3_bucket_acl_check(s3_client, bucket_name):
	Permissions = {} 
	bucket_acl = s3_client.get_bucket_acl(Bucket=bucket_name)

	if 'DisplayName' in bucket_acl['Owner']:
		id_or_name = 'DisplayName'
	else:
		id_or_name = 'ID'

	bucket_owner = bucket_acl['Owner'][id_or_name]

	for grant in bucket_acl['Grants']:
		if grant['Grantee']['Type'] == "Group":
			if "global/AuthenticatedUsers" in grant['Grantee']['URI']:
				user = "Any AWS user"
				if user not in Permissions:
					Permissions[user] = []
				Permissions[user].append(grant['Permission'])

			if "global/AllUsers" in grant['Grantee']['URI']:
				user = "Everyone(even Non-AWS user)"
				if user not in Permissions:
					Permissions[user] = []
				Permissions[user].append(grant['Permission'])
	if Permissions:
		print "Bucket Name:" + bucket_name
		print "Owner:" + bucket_owner
		for user in Permissions:
			print user + " has permissions" + str(Permissions[user])
			print

#Checks s3_bucket_policy_permissions
def s3_bucket_policy_permissions(s3_client, bucket_name):
	try:
		bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)
	except Exception, e:
		if "The bucket policy does not exist" in e.message:
			bucket_policy = "N/A"
			print 'No bucket policy found  attached to ' + bucket_name + '. Hope there is an IAM policy to control access.'

#Checks bucket not touched since 90 days
def s3_untouched(s3_client, bucket_name):
	timelimit = datetime.datetime.now() - datetime.timedelta(days=90)
	last_activity = 'N/A'
	object_list = s3_client.list_objects_v2(Bucket=bucket_name,FetchOwner=True)
	if 'Contents' in object_list:
		for object in object_list['Contents']:
			if last_activity == 'N/A' or last_activity > object['LastModified']:
				last_activity = object['LastModified']
		if last_activity.date() < datetime.datetime.now().date():
			days = datetime.datetime.now().date() - last_activity.date()
			if days > 90:
				print 'Bucket Name: ' + bucket_name

#Checks default server side encryption of bucket
def s3_encryption_check(s3_client, bucket_name):
	try:
		bucket_encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
	except Exception, e:
		if 'ServerSideEncryptionConfigurationNotFoundError' in e.message:
			print "Bucket Name:" + bucket_name + ' is unencrypted. Checking objects in bucket ....'
			object_list = s3_client.list_objects_v2(Bucket=bucket_name)
			if 'Contents' in object_list:
				for object in object_list['Contents']:
					key = object['Key']
					object_metadata = s3_client.head_object(Bucket=bucket_name, Key=key)
					if 'ServerSideEncryption' not in object_metadata:
						print "Object " + key + " is unencrypted."
						print
		else:
			print e.message

#Checks logging Server Access Logging
def s3_logging_enabled_check(s3_client, bucket_name):
	bucket_logging = s3_client.get_bucket_logging(Bucket=bucket_name)
	if 'LoggingEnabled' not in bucket_logging:
		print 'Access to bucket ' + bucket_name + ' is not logged.'

#Object ACL check
def object_acl_check(s3_client, bucket_name):
	object_list = s3_client.list_objects_v2(Bucket=bucket_name,FetchOwner=True)
	if 'Contents' in object_list:
		for object in object_list['Contents']:
			object_Owner = object['Owner']['DisplayName']
			key = object['Key']
			object_acl = s3_client.get_object_acl(Bucket=bucket_name, Key=key)
			for grant in object_acl['Grants']:
				if grant['Grantee']['Type'] == 'Group':
					if 'global/AuthenticatedUsers' in grant['Grantee']['URI'] or 'global/AllUsers' in grant['Grantee']['URI']:
						print 'Object: ' + object['Key']
						print 'Owner : ' + object_Owner
						print 'Object is open to the world'
						print
				
	else:
		print 'Found empty bucket ' + bucket_name + '.'


#Get all AWS account profiles from aws credentials file
def get_profiles(cred_file):
	profiles = []
	try:
		with open(cred_file) as f:
			for line in f.readlines():
				if '[' in line:
					line = line.replace('[','').replace(']','').strip('\n')
					profiles.append(line)
	except Exception, e:
		print "Error:" + str(e)
	return profiles

#Get default home dir of user executing the script
def get_home_dir():
	current_user_id = os.getuid()
	with  open('/etc/passwd') as passwd_file:
		for line in passwd_file.readlines():
			field = line.split(':')
			if current_user_id == int(field[2]):
				home_dir = field[5]
	return home_dir

def main():
	home_dir = get_home_dir()
	cred_file_path = home_dir + '/.aws/credentials'

	#Checks if aws credential file exists and get all AWS account profiles
	if os.path.exists(cred_file_path):
		profile_names = get_profiles(cred_file_path)
	else:
		cred_file_path = raw_input("Please enter credential files absolute path: ")
		profile_names = get_profiles(cred_file_path)

	print "\t\t\tAWS S3 Permission Problems"
	print "\t\t\t--------------------------\n\n"
	for profile in profile_names:
		print "Account " + profile.upper()
		print "-----------------"
		print
		session = boto3.session.Session(profile_name = profile)
		s3_client = session.client('s3')
		try:
			bucket_list = s3_client.list_buckets()
			print "\t\t\tBUCKET ACL CHECK"
			print "\t\t\t----------------"
			for bucket in bucket_list['Buckets']:
				s3_bucket_acl_check(s3_client, bucket['Name'])
				object_acl_check(s3_client, bucket['Name'])			
			print
			print "\t\t\tBUCKET ENCRYPTION CHECK"
			print "\t\t\t-----------------------"
			for bucket in bucket_list['Buckets']:
				s3_encryption_check(s3_client, bucket['Name'])
			print
			print "\t\t\tBUCKET LOGGING ENABLED CHECK"
			print "\t\t\t----------------------------"
			for bucket in bucket_list['Buckets']:
				s3_logging_enabled_check(s3_client, bucket['Name'])
			print
			print "\t\t\tBUCKET POLICY ATTACHED CHECK"
			print "\t\t\t----------------------------"
			for bucket in bucket_list['Buckets']:
				s3_bucket_policy_permissions(s3_client, bucket['Name'])
			print
			print "\t\t\tBUCKET NOT USED IN 90 DAYS"
			print "\t\t\t--------------------------"
			for bucket in bucket_list['Buckets']:
				s3_untouched(s3_client, bucket['Name'])
			print
		
		except Exception, e:
			if 'AccessDenied' in e.message:
				print 'ERROR: Insufficient permissions to access S3 buckets for account ' + profile + '.'
			else:
				print e.message	

	   			  	
if __name__ == '__main__':
	main()

