# Scenario
Your organization utilizes AWS to host critical data and applications. An incident has been reported that involves unauthorized access to data and potential exfiltration. The security team has detected unusual activities and needs to investigate the incident to determine the scope of the attack.

# Introduction
This lab involves investigating a security incident occuring on a cloud network from the Amazon Cloud provider AWS, this will involve analysing the AWS Cloudtrail logs which track API calls and account activity.
These serve as an audit trail to who did what, where, and when. Using these logs we will determine the scope of the attack and TTP's used.

## Question 1 Knowing which user account was compromised is essential for understanding the attacker's initial entry point into the environment. What is the username of the compromised user?
When looking for signs of compromise on a cloud account it is useful to search through the logs related to signin activity, the signin activity is managed by the AWS Console and can be found under the event type
`AwsConsoleSignIn`. This logs all attempts to signin for any of the users on the cloud and can be used to determine suspicious login behaviour.

Within the Responses for the event we can see that if we expand `responseElements` it will either display **Success** or **Failure**, if we filter by failures we are presented with all failed login attempts, if we look at the
fields on the left the `userIdentity.userName` there are alot of entries for the `helpdesk.luke` user.

If we drilldown to this we can see that 10 attempts were made in a very short period for lukes account, suggesting someone may be trying to bruteforce the password
![image](https://github.com/user-attachments/assets/f2b2508a-0583-400a-8ad4-e78b939381aa)

These occur betwen 9:53 and 9:54.

We can now look and see if there were any successful attempts after this time period by viewing the successful logins
![image](https://github.com/user-attachments/assets/8d4ba4a1-ebb8-4432-a065-cfc7f9357a43)

We can see there was a successful signin just after the failed logins.

Answer: helpdesk.luke

## Question 2 We must investigate the events following the initial compromise to understand the attacker's motives. What is the timestamp for the first access to an S3 object by the attacker?
With knowledge of the account that has been compromised we can now look into the actions taken by the attacker, such as their access to S3 objects. S3 buckets are used to store files and other data as objects.
Accessing these objects requires triggers certain events within the aws cloudtrail logs which can be used to determine what exactly the attacker was doing with s3 objects.

S3 Events
1. `Get-object` - used to read the object from the s3 bucket
2. `Put-Object` - used to Write to an object ( Creating or overwriting)
3. `Delete-Object` - used to remove an object from an s3 bucket
4. `List_Bucket` - used to list the objects in an s3 bucket

We now have knowledge of the Username and we know what action is related to accessing an s3 object. We can now prepare the filter and view the results related to retreiving objects. We can then find the first
request made to the S3 bucket and convert the timestamp from Unix Format.

![image](https://github.com/user-attachments/assets/93294525-a0de-4e65-a095-737b0f7aac0d)
![image](https://github.com/user-attachments/assets/a50f747d-f199-4221-9293-1287d37a7bd0)

Answer: 2023-11-02 09:55

## Question 3 Among the S3 buckets accessed by the attacker, one contains a DWG file. What is the name of this bucket?
Finding out which buckets were accessed by the attacker involves knowing what field is available when there is a file being requested for download which the attacker will likely want to perform to obtain the files they have read, this is found in `requestParameters.response-content-disposition` where the `attachment` value is specified to let the bucket know that the file should be downloaded rather than displayed.
Then we can look for the field involved in storing the Amazon Resource Name (ARN) the unique name for the object, this contains the extension of the file which we can use glob expressions to only show files ending in .dwg. The ARN is available `resources.ARN`.

![image](https://github.com/user-attachments/assets/6f9af678-3172-447c-b2a9-25b19ed889bd)

Answer: product-designs-repository31183937

## Question 4 We've identified changes to a bucket's configuration that allowed public access, a significant security concern. What is the name of this particular S3 bucket?
Looking for any changes to the public access configuration of a bucket will involve looking for the event `PutBucketPublicAcessBlock` which is used to enable or disable the public access of an s3 bucket.
We could additionally filter for the username of the compromised machine to narrow down the events solely to ones performed by the attacker.
![image](https://github.com/user-attachments/assets/f4786f9c-acaf-4b5a-993d-d37ff66ddfdb)

Answer:backup-and-restore98825501

## Question 5 Creating a new user account is a common tactic attackers use to establish persistence in a compromised environment. What is the username of the account created by the attacker?
The event `CreateUser` is used to log any user creation activities on the cloud, Knowing this we can search for any of these events being performed by the attacker
![image](https://github.com/user-attachments/assets/6b6a3b59-1b2f-4188-b9f0-59ffa42534f5)

Answer: marketing.mark

## Question 6 Following account creation, the attacker added the account to a specific group. What is the name of the group to which the account was added?
The event `AddUserToGroup` is used to track when any user is assigned to a group in the cloud. This can be used to see what group the attacker added themselves to.
![image](https://github.com/user-attachments/assets/3181ab3c-0773-439d-9ca5-5a48d26eba29)

Answer:Admins

# Conclusion
The AWSRaid Lab offered practical experience in investigating and detecting suspicious activity within an AWS environment using native monitoring tools such as AWS CloudTrail. Through simulated attack scenarios, the lab demonstrated how attackers can exploit misconfigurations, overly permissive IAM policies, and insufficient logging to gain access, escalate privileges, and exfiltrate data.

Key outcomes from the lab include:

1. Gaining familiarity with critical CloudTrail events such as CreateUser, AddUserToGroup, PutBucketPolicy, and GetObject.

2. Learning how to use Splunk to query CloudTrail logs for evidence of unauthorized access or changes to IAM and S3 configurations.

3. Understanding the importance of enabling S3 data event logging to monitor object-level access.

4. Identifying how CloudTrail logs can reveal the who, what, when, and where of activity across AWS services.

Overall, the lab emphasized the importance of continuous visibility, strong access controls, and vigilant log analysis to detect and respond to potential security incidents in AWS. The knowledge and techniques applied here are essential for both proactive cloud security monitoring and effective incident response.
