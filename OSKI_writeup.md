# Synopsis
The accountant at the company received an email titled "Urgent New Order" from a client late in the afternoon. When he attempted to access the attached invoice, he discovered it contained false order information. Subsequently, the SIEM solution generated an alert regarding downloading a potentially malicious file. Upon initial investigation, it was found that the PPT file might be responsible for this download. Could you please conduct a detailed examination of this file?

## Question 1 When was the file created?
Enter the hash into virustotal and go to the details page where the creation time is documented
![image](https://github.com/user-attachments/assets/2d874cb3-b25c-4827-b705-7b9edd2245ff)

Answer: 2022-09-28 17:40:46 UTC

## Question 2 What is the command and control server being contacted?
To find the c2 servers being contacted we can observe the relations tab which shows contacted urls, domains and ips

![image](https://github.com/user-attachments/assets/6bde88c1-6c0c-4b57-9380-26243b3668b2)

Answer: http://171.22.28.221/5c06c05b7b34e8e6.php

## Question 3 What is the first library the malware requests upon execution

Also found in the relations tab we can see that there was a request made for sqlite3.dll which through researching on google i learned can be used for interacting with databases and can also pass antivirus programs due to being a legitimate dll
This could potentially be used by attackers to itneract with databases and extract usernames, passwords or credit card details
Answer: sqlite3.dll

## Question 4 Upon examining the malware, it appears to utilize the RC4 key for decrypting a base64 string. What specific RC4 key does this malware use?
To view the rc4 key being used i found a report on anyrun on the file where the first process vpn.exe had a cfg option which shows the rc4 encryption secret being used to decrypt the base64 string
![image](https://github.com/user-attachments/assets/658235ad-24e4-42a8-b230-f8ef22dc43ce)

Answer: 5329514621441247975720749009

## Question 5 Identifying an adversary's techniques can aid in understanding their methods and devising countermeasures. Which MITRE ATT&CK technique are they employing to steal a user's password?
Using the ATT&CK link in anyrun we are taken to a matrix showing the tatctics and techniques used by the malware, if we focus on the credential access phase then we can see that T1555 Credentials from Password Stores, in this particular
scenario it seems lkike web browser databases storing usernames and passwords have been enumerated using sql to obtain credentials 

![image](https://github.com/user-attachments/assets/2c85e50c-ccf5-4b9d-b579-8d153e43a5cb)

Answer: T1555


## Question 6 Malware may delete files left behind by the actions of its intrusion activity. Which directory does the malware target for deletion?
Again in the ATT&CK Matrix it can be seen that in the defense evasion phase the attackers have used T1070 Indicator Removal by deleting files in the programdata directory which may leave traces of attacks
![image](https://github.com/user-attachments/assets/40f769ab-ed00-4e07-aa35-9d430c895f59)

Answer: C:/ProgramData

## Question 7 Understanding the malware's behavior post-data exfiltration can give insights into its evasion techniques. After successfully exfiltrating the user's data, how many seconds does it take for the malware to self-delete?

This is in the command executed in the indicator removal screenshot provided in question 6 where the file would wait 5 seconds before deleting

#Conclusion
This was an interesting lab which required many intelligence platforms to be able to determine the malwares behaviour and the TTPS used by the malware. It required a combination of static and dynamic analysis of the malware, to show a full picture of its capabilities.
Using platforms such as virustotal, AnyRun and Hybrid Analysis we were able to determine the c2 server and the goal of the malware which was to steal credentials from computers




