# Synopsis 
You are part of the Threat Intelligence team in the SOC (Security Operations Center). An executable file has been discovered on a colleague's computer, and it's suspected to be linked to a Command and Control (C2) server, indicating a potential malware infection.
Your task is to investigate this executable by analyzing its hash. The goal is to gather and analyze data beneficial to other SOC members, including the Incident Response team, to respond to this suspicious behavior efficiently.

## Question 1 Categorizing malware enables a quicker and clearer understanding of its unique behaviors and attack vectors. What category has Microsoft identified for that malware in VirusTotal?
Knowing the malware type is vital in determining your next steps, using virustotal we can view the detections tab, the default page for a malware entry where it is clearly categorised as a trojan

![image](https://github.com/user-attachments/assets/5ee25950-1797-42ca-bb98-784d9a22111d)

Answer: Trojan

## Question 2 Clearly identifying the name of the malware file improves communication among the SOC team. What is the file name associated with this malware?
While the name can be changed slightly or altogether it is useful to know, the main name and aliases can be found in the names section in the details page 

![image](https://github.com/user-attachments/assets/ccb7a168-4738-4345-92af-5280260a8625)

Answer: wextract

## Question 3 Knowing the exact timestamp of when the malware was first observed can help prioritize response actions. Newly detected malware may require urgent containment and eradication compared to older, well-documented threats. What is the UTC timestamp of the malware's first submission to VirusTotal?
As seen in the screenshot above the submission timestamp is listed 

Answer: 2023-10-06 04:41

## Question 4 Understanding the techniques used by malware helps in strategic security planning. What is the MITRE ATT&CK technique ID for the malware's data collection from the system before exfiltration?
To find the techniques used by the attacker in the collection phase of the mitre matrix we can go to the behaviour tab and begin to drill down into the different tactics used by the attacker and the techniques
they used to acheive this, this gives a clear story of what the malware done at each phase of the attack, TA009 Collection is the tactic we are interested in, within this we can see T1005 Data from Local System.
This technique is used to extract information from the local system using keystrokes, accessing sensitive files or web browser history, all in an attempt tog ather credentials and build a profile on the victim

![image](https://github.com/user-attachments/assets/69fe7a17-eda2-4599-90d9-807461a5f1e8)

Answer: T1005
## Question 5 Following execution, which social media-related domain names did the malware resolve via DNS queries?

Looking at the DNS resolutions section of the behaviours poage where we can see DNS queries for facebook
![image](https://github.com/user-attachments/assets/2c8334ed-1afd-40a8-94f9-bfd7199ab597)

Answer: Facebook

## Question 6 Once the malicious IP addresses are identified, network security devices such as firewalls can be configured to block traffic to and from these addresses. Can you provide the IP address and destination port the malware communicates with?
We can see that the majority of the ip traffic goes to an unresolved ip and port, whilst all others appear to be to legitimate sources
![image](https://github.com/user-attachments/assets/b326ca83-d835-4b33-b69c-ac448b731ef4)

Answer: 77.91.124.55:19071

## Question 7 YARA rules are designed to identify specific malware patterns and behaviors. Using MalwareBazaar, what's the name of the YARA rule created by "Varp0s" that detects the identified malware?
In order for us to configure our environment to detect and possibly respond to this threat in the future we require detection rules capable of identifying the malware

MalwareBazaar is a platform, developed by Abuse.ch, that serves as a repository for malware samples, providing researchers, AV vendors, and threat intelligence providers with a central resource for analyzing and understanding malicious software.
It also provides detection rules for YARA

In the Yara Signature sections we can see the first signature meets the requirements
MalwareBazaar is a platform, developed by Abuse.ch, that serves as a repository for malware samples, providing researchers, AV vendors, and threat intelligence providers with a central resource for analyzing and understanding malicious software.
![image](https://github.com/user-attachments/assets/40fe4ab1-0dee-48a4-b0e9-6cffdf12e65f)

Answer: detect_Redline_Stealer

## Question 8 Understanding which malware families are targeting the organization helps in strategic security planning for the future and prioritizing resources based on the threat. Can you provide the different malware alias associated with the malicious IP address according to ThreatFox?
Knowing the name of the malware Redline stealer which is used to steasl sensitive information such as passwords and usernames we can look for aliases using threatfox, specifying malware:Redline on threatfox we can
find entries about the malware, selecting the first one we can see the alias listed in the contents
![image](https://github.com/user-attachments/assets/9da0ad67-3887-411b-b5a4-ec72f1a305e3)

Answer:RECORDSTEALER

## Question 9 By identifying the malware's imported DLLs, we can configure security tools to monitor for the loading or unusual usage of these specific DLLs. Can you provide the DLL utilized by the malware for privilege escalation?
Determining the loaded dlls can be done on many sources, i chose hybrid analysis due to its combination of static and dynamic analysis in a neat format, the DLL responsible for privilege escalation was determined
to be advapi32.dll and was found in the File Imports section of HybridAnalysis, through research i could find that the ADVAPI32.dll can be used to gain additional permissions by calling the AdjustTokenPrivileges. I found this by searching for the method
on google where i found a useful site detailing all of the methods called by malware and what they can be used for, this will be useful in future challenges as its a quick lookup to determine if a call
is malicious or not 

![image](https://github.com/user-attachments/assets/e62d0169-01d8-49c5-a35e-4217afe6ec06)

![image](https://github.com/user-attachments/assets/8152b397-aaa6-494e-b5bd-90552a65d568)

Helpful Link: https://malapi.io
Answer: ADVAPI32.dll

# Conclusion
This lab was extremly useful in learning how to drilldown further into the behaviour of a particularly infamous malware where we learned how to use the Mitre Matrix to determine the TTP's of the malware. We also identified the family of malware and subsequently determiend detection signatures
and firewall rules to block the attackers attempts, finally we determined dll's critical to the operation of the malware and determined the methods used so we can flag similar behaviour in the future.

