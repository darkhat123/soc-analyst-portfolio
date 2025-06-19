# Scenario
You are a Threat Hunter working for a cybersecurity consulting firm. One of your clients has been recently affected by a ransomware attack that caused the encryption of multiple of their employees' machines. The affected users have reported encountering a ransom note on their desktop and a changed desktop background. You are tasked with using Splunk SIEM containing Sysmon event logs of one of the encrypted machines to extract as much information as possible.

Introduction
We are tasked with analysing a ransomware attack that affected several computers within an enterprise network. We have access to the sysmon logs of the machines affected, it is our task to analyse these log files and 
determine the scope of the attack and the steps needed to prevent this occuring again.

## Question 1 To begin your investigation, can you identify the filename of the note that the ransomware left behind?
When looking for events within sysmon it is crucial to identify what event code we are looking for, in terms of File Creation/Overwriting we will be looking for Event code 11.

Now we have all File creation Events on the system, we can then view the fiels associated with these events, We can look through the fiels and look for anything pertaining to the filename of the files being
accessed. We can see that the event log stores a parameter `winlog.event_data.TargetFilename`. Using this we can search for occurences of the phrase Desktop within the paths of the filenames. 

The final filter is `index=revil "event.code"=11 winlog.event_data.TargetFilename = "*Desktop*"`
![image](https://github.com/user-attachments/assets/3c08a840-e142-4cf3-b344-f7ed629eb621)

Looking through these results we can see that there are 3 occurences of a file being saved to different users Desktops
![image](https://github.com/user-attachments/assets/f11f0747-cd38-47d1-b037-bc6ce2a79955)

Answer:5uizv5660t-readme.txt 

## Question 2 After identifying the ransom note, the next step is to pinpoint the source. What's the process ID of the ransomware that's likely involved
WIth knowledge of the event that was triggered when the attacker created the ransom notes on multiple computers, we can now begin to determine what process invoked the writing to text files and determine the
root cause of the attack. Each process should have a parent process that was used to invoke it. We can see two entries for Process Id's, one is related to the process being invoked, the one which created the text file while the other `event_data.ProcessId` pertains to the process responsible for triggering the event, ie the parent process for the text file creation.

![image](https://github.com/user-attachments/assets/01ab9511-43a2-482d-8ed0-f00cbd0d05dd)
Answer: 5348  


## Question 3 Having determined the ransomware's process ID, the next logical step is to locate its origin. Where can we find the ransomware's executable file?
Now that we know the process id of the parent process we can begin to see what other actions were performed under this process and map out the attackers behaviour.
Knowing what file was responsible for instantiating these processes and performing malicious actions is useful in removing the threat from the PC and Detecting any further attempts of intrusion.

We must simply search splunk for all actions performed with the specific process ID. This returns 21 results, all of which will have been spawned from the same file. Now we must find the filename

This can again be found in the winlog event data section and falls under the field `winlog.event_data.Image` which is used to denote the file responsible for spawning the process in the first place
![image](https://github.com/user-attachments/assets/a8ff5d47-6b12-4d31-9f10-dadb84a8368c)

Answer:C:\Users\Administrator\Downloads\facebook assistant.exe


## Question 4 Now that you've pinpointed the ransomware's executable location, let's dig deeper. It's a common tactic for ransomware to disrupt system recovery methods. Can you identify the command that was used for this purpose?
Now that we know the executable used to spawn the processes associated with the malware we can begin to look into other avenues other than file creation and overwriting. Typically attackers will try to disrupt
recovery by deleting or locking backups. This can be done in many ways but the main method is to use powershell. We can filter for any events triggered by the malicious exe that utilises powershell. This will involve spawning a new process so filtering for Process Creation Sysmon Event Id 1 we can narrow down the results to only those of new processes with powershell in their contents. We can then construct a table
with the time, parent command line and the command line ran. Making it easy to see what command was ran by the malicious file.

![image](https://github.com/user-attachments/assets/c911eed3-0b1b-4216-8bf8-6fe3149fdeb3)

One of the processes is clearly an encoded powershell command being ran by an attacker. If we take this and base64 decode it we will have the command ran by the attacker.

![image](https://github.com/user-attachments/assets/39ff62b8-b4fb-4ac6-8999-b5e0cdb4c200)

Answer:Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
## Question 5 As we trace the ransomware's steps, a deeper verification is needed. Can you provide the sha256 hash of the ransomware's executable to cross-check with known malicious signatures?
When looking for the hash of the file it is useful to again look at process creation events within sysmon, the file will have its hashes calculated when the process is created, these are logges in the Hashes section within the process creation event

![image](https://github.com/user-attachments/assets/4899d52c-f2e6-4215-8baf-17d750884356)
Answer: B8D7FB4488C0556385498271AB9FFFDF0EB38BB2A330265D9852E3A6288092AA

## Question 6 One crucial piece remains: identifying the attacker's communication channel. Can you leverage threat intelligence and known Indicators of Compromise (IoCs) to pinpoint the ransomware author's onion domain?

Whilst the hash of a file can change when one bit in a file is altered it can be a useful way to search for records of the malware that have been analysed. Platforms such as ANY.Run, VirusTotal, Talos Intelligence and much more are dedicated to providing in depth reports of the malware samples they analyse. We can submit our hash to virustotal and take a look at the relations tab which will detail any domains, ip, urls that the malware interacts with. Unlucky, there is no results for DNS requests being made to a .onion site, using the hybrid analysis website ANY.Run we can find a file report for the suspected hash, if we go to the domains tab and filter for .onion sites we see entries for one .onion site.

![image](https://github.com/user-attachments/assets/e8debb49-ae07-45a6-b8c3-00024005d727)
Answer: aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion

# Conclusion
REvil remains one of the most sophisticated and dangerous ransomware-as-a-service (RaaS) operations, known for its double extortion tactics, rapid propagation, and use of obfuscation techniques. It often exploits vulnerable RDP services, unpatched software, and trusted third-party access to infiltrate environments. Defenders must stay vigilant and proactive, as REvil actors adapt quickly to defensive measures and evolve their tactics regularly.

# Mitigations
1. Patch and Update Systems

Regularly apply security patches, especially for remote access services (e.g., RDP) and VPN software.

2. Enforce Least Privilege

Limit administrative privileges and ensure users only have access to the resources necessary for their roles.

3. Network Segmentation

Segment critical systems to restrict lateral movement and isolate backup infrastructure from production networks.

4. Secure RDP and Remote Access

Disable RDP if not needed; otherwise, use MFA, VPN access controls, and restrict access to known IPs.

5. Implement Strong Email Filtering

Block phishing attempts with advanced spam filters and sandboxing of suspicious attachments.

6. Monitor for Suspicious Behavior

Use tools like Sysmon and EDR solutions to detect anomalies such as:

Suspicious process execution

Unauthorized registry changes

Shadow copy deletions

7. Harden Backups

Maintain offline, immutable backups and regularly test recovery procedures.

8. User Awareness Training

Educate employees about phishing, social engineering, and the importance of reporting suspicious activity.



