# Synopsis
A large multinational corporation heavily relies on the 3CX software for phone communication, making it a critical component of their business operations. After a recent update to the 3CX Desktop App, antivirus alerts flag sporadic instances of the software being wiped from some workstations while others remain unaffected. Dismissing this as a false positive, the IT team overlooks the alerts, only to notice degraded performance and strange network traffic to unknown servers. Employees report issues with the 3CX app, and the IT security team identifies unusual communication patterns linked to recent software updates.

As the threat intelligence analyst, it's your responsibility to examine this possible supply chain attack. Your objectives are to uncover how the attackers compromised the 3CX app, identify the potential threat actor involved, and assess the overall extent of the incident. 

# Introduction
This lab involves analysing a common exploit that affected the softphone software 3CX where versions of the software were trojanised and compromised many enterprise systems running the affected versions
it is our job to piece together the actions taken by the malware and conduct threat intelligence to determine the TTP's used by the attacker to prevent the attack and remediate affected systems

## Question 1 Understanding the scope of the attack and identifying which versions exhibit malicious behavior is crucial for making informed decisions if these compromised versions are present in the organization. How many versions of 3CX running on Windows have been flagged as malware?
Using google to search for known 3cx vulnerabilities i was able to find  a report on fortinet detailing the extent of the attack and the affected versions
![image](https://github.com/user-attachments/assets/74b520da-ab04-482e-87f3-caad443eed80)

Answer: 2

## Question 2 Determining the age of the malware can help assess the extent of the compromise and track the evolution of malware families and variants. What's the UTC creation time of the .msi malware?
uploading the file to virustotal it returns a report for 3CXDesktopApp-18.12.416.msi, examining the details page we can see the creation time.

![image](https://github.com/user-attachments/assets/0601f149-fac0-4e7b-bc89-2614622c27a6)

Answer:2023-03-13 06:33
## Question 3 Executable files (.exe) are frequently used as primary or secondary malware payloads, while dynamic link libraries (.dll) often load malicious code or enhance malware functionality. Analyzing files deposited by the Microsoft Software Installer (.msi) is crucial for identifying malicious files and investigating their full potential. Which malicious DLLs were dropped by the .msi file?
To find the dlls dropped by the malware we could go through the files dropped on sources such as virustotal and any.run, however due to there being many results of dlls being dropped it is unclear without
further analysis which ones are responsible for malware payloads. Instead i used zscalers report which provided a handy graphic of the infection chain where it details two dlls, one used to load the other and the
other containing shellcode responsible for downloading an icon file from a github repo and decrypting it using the rc4 key to obtain the c2 url.
![image](https://github.com/user-attachments/assets/87879b76-1658-450f-b0ce-1e6610be29ef)

Answer: ffmpeg.dll, d3dcompiler.dll

## Question 4 Recognizing the persistence techniques used in this incident is essential for current mitigation strategies and future defense improvements. What is the MITRE Technique ID employed by the .msi files to load the malicious DLL?
Determining the TTP's of the malware can be acheived using virustotal or any.run, where we can look for persistince techniques used by the malware and determine how to completely remove the infection from the system
We can see that in this case we want to know how the malicious DLL was loaded, the only reference to loading of DLLS is Under Hijack Execution flow
![image](https://github.com/user-attachments/assets/fced7a07-f6a5-40cd-a84e-fa5784b45b09)

Answer: T1574

## Question 5 Recognizing the malware type (threat category) is essential to your investigation, as it can offer valuable insight into the possible malicious actions you'll be examining. What is the threat category of the two malicious DLLs?
Whilst it has already been stated in many of the reports as a trojanised software we can see the category in the detection tab on virsutotal where it is classified as a trojan
![image](https://github.com/user-attachments/assets/370cb7a1-06b6-4c5d-aeb1-a12882e6171a)

Answer: Trojan

## Question 6 As a threat intelligence analyst conducting dynamic analysis, it's vital to understand how malware can evade detection in virtualized environments or analysis systems. This knowledge will help you effectively mitigate or address these evasive tactics. What is the MITRE ID for the virtualization/sandbox evasion techniques used by the two malicious DLLs?
Understanding how the malware avoids being analysed in virtual sandbox involves looking at the defence evasions techniques used by the attackers using their Mitre Matrix available in virustotal, we can see
that under the Virtualization/Sandbox Evasion Tecnique we can see that the malware will sleep in an attempt to timeout a sandbox environment trying to analyse it.

![image](https://github.com/user-attachments/assets/8a3e1dcd-9839-4a48-96b6-cf395a298f42)

Answer:T1497

## Question 7 When conducting malware analysis and reverse engineering, understanding anti-analysis techniques is vital to avoid wasting time. Which hypervisor is targeted by the anti-analysis techniques in the ffmpeg.dll file?
Finding the technique used to target the hypervisor involved looking into the defence evasion techniques listed on hybrid analyis, where we can see that one of the techniques is used to constrain execution
based on enviornment variables, this is the malware checking to see if it is in a virtual enviorment by targeting the vmware hypervisor which is confirmed in this article: https://www.vmray.com/sandbox-evasion-techniques/
![image](https://github.com/user-attachments/assets/f83e3203-1797-4488-89cc-1bce3898690b)

## Question 8 dentifying the cryptographic method used in malware is crucial for understanding the techniques employed to bypass defense mechanisms and execute its functions fully. What encryption algorithm is used by the ffmpeg.dll file?
This was identified earlier in the infection chain and is used to decrypt the malicious DLL and run it with the shellcode

Answer: RC4

## Question 9 As an analyst, you've recognized some TTPs involved in the incident, but identifying the APT group responsible will help you search for their usual TTPs and uncover other potential malicious activities. Which group is responsible for this attack?
Identifying the threat actor involved researching into reports online on the attack where i found an article detailing the threat actors believed to be involved
![image](https://github.com/user-attachments/assets/2c4c2372-2ee7-4c87-8f7e-bc43c4e020a2)

Answer: Lazarus

# Conclusion
The 3CX supply chain compromise highlights the growing sophistication and impact of modern supply chain attacks. By infiltrating a trusted software vendor, threat actors were able to deliver malicious payloads to a wide range of downstream targets with minimal initial detection. This lab provided critical insight into how such compromises unfold—from initial intrusion and trojanized installers to post-compromise command and control activity. Understanding these techniques is essential for developing robust detection, response, and supply chain security strategies. 

