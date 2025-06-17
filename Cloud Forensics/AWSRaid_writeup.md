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
