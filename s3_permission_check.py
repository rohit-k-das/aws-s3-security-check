import boto3
import os
import datetime

def s3_bucket_acl_permissions(profile,s3_client):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list['Buckets']:
        name = bucket['Name']
        bucket_acl = s3_client.get_bucket_acl(Bucket=name)
        try:
            bucket_policy = s3_client.get_bucket_policy(Bucket=name)
        except Exception as e:
            if "The bucket policy does not exist" in e.message:
                bucket_policy = "N/A"
                        
        if 'DisplayName' in bucket_acl['Owner']:
            id_or_name = 'DisplayName'
        else:
            id_or_name = 'ID'
        
        bucket_owner = bucket_acl['Owner'][id_or_name]
        Permissions = {}
        for grant in bucket_acl['Grants']:
                if grant['Grantee']['Type'] == "CanonicalUser":
                    if bucket_owner != grant['Grantee'][id_or_name]:
                        user = grant['Grantee'][id_or_name]
                        if user not in Permissions:
                            Permissions[user] = []
                        Permissions[user].append(grant['Permission'])
                        
                if grant['Grantee']['Type'] == "Group":
                    if "global/AuthenticatedUsers" not in grant['Grantee']['URI'] and "global/AllUsers" not in grant['Grantee']['URI'] and "s3/LogDelivery" not in grant['Grantee']['URI']:
                        user = grant['Grantee']['URI']
                        if user not in Permissions:
                            Permissions[user] = []
                        Permissions[user].append(grant['Permission'])
                    
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
            print "Bucket Name:" + name 
            print "Owner:" + bucket_owner
            for user in Permissions:
                print user + " has permissions" + str(Permissions[user])
                print

#TODO: Check s3_bucket_policy_permissions
def s3_bucket_policy_permissions(profile,s3_client):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list['Buckets']:
        name = bucket['Name']
        try:
            bucket_policy = s3_client.get_bucket_policy(Bucket=name)
        except Exception as e:
            if "The bucket policy does not exist" in e.message:
                bucket_policy = "N/A" 
        if bucket_policy != "N/A":
            print bucket_policy
            print

#TODO: Check s3_untouched
def s3_untouched(profile,s3_client):
    #Bucket not touched since 90 days
    bucket_list = s3_client.list_buckets()
    timelimit = datetime.datetime.now() - datetime.timedelta(days=90)
    for bucket in bucket_list['Buckets']:
        name = bucket['Name']
        try:
            object_not_touched = s3_client.head_object(Bucket=name)
            print object_not_touched
        except:
            pass

#TODO: Write function to check encryption

#TODO: Write function to check logging

#Get all AWS account profiles from aws credentials file
def get_profiles(cred_file):
    profiles = []
    try:
        with open(cred_file) as f:
            for line in f.readlines():
                if '[' in line:
                    line = line.replace('[','').replace(']','').strip('\n')
                    profiles.append(line)
    except Exception,e:
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
	print "\t\t\t--------------------------\n"
        for profile in profile_names:
	    print "Account " + profile.upper()
	    print "-----------------"
	    print
            session = boto3.session.Session(profile_name = profile)
            s3_client = session.client('s3')
            print "BUCKET ACL"
            print "----------"
            print
            s3_bucket_acl_permissions(profile,s3_client)
            #print "BUCKET POLICY"
            #print "----------"
            #s3_bucket_policy_permissions(profile,s3_client)
            #print "Bucket last accessed"
            #print "--------------------"
            #s3_untouched(profile,s3_client)

if __name__ == '__main__':
    main()
