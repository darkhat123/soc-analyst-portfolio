# Scenario
As a member of the Security Blue team, your assignment is to analyzehttps://github.com/darkhat123/soc-analyst-portfolio/security a memory dump using Redline and Volatility tools. Your goal is to trace the steps taken by the attacker on the compromised machine and determine how they managed to bypass the Network Intrusion Detection System (NIDS). Your investigation will identify the specific malware family employed in the attack and its characteristics. Additionally, your task is to identify and mitigate any traces or footprints left by the attacker.

# Introduction
This lab challenges us to use Redline and volatility 3 to perform memory forensics analysis on a memory dump of a macine which is believe to be compromised by an attacker. This will involve using the snapshot of the pc at the time of
the malwares execution to determine the TTPs used by the attacker to compromise the PC.

## Question 1 What is the name of the suspicious process?
When looking for suspicious processes it is typical to look at any processes that are outwith the normal behaviour of a windows pc. These will typically have process names that are not part of the essential windows processes and may even have typo's of common known processes in an attempt to masquerade as a legitimate process. It is useful to also analyse the parent child relationships of a process to determine scenarios such as processes with no parent process or sub processes which arent utilised by a parent process. These are both scenarios indicative of malware running unwanted actions on the computer.

To determine the malicious process and examine the parent-child relationship we can use `python3 vol.py -f Memdump.mem windows.pstree`

We can quickly see that a strange process (PID 5896) with the name oneetx.exe. With a simple google search we see that this process name has been associated with a trojan 
horse infection malware.

We can see that this malware was executed from the user tammams temp directory and is likely being executed with the users privileges
![image](https://github.com/user-attachments/assets/b0b2572e-14af-490b-8887-1c4068db6a4b)

Answer: oneetx.exe


## Question 2 What is the child process name of the suspicious process?
Knowing the malicious process in question we can see that they have a child process (PID 7732) that was spawned with the process name rundll32.exe which is likely
the malware attempting to masquearade as the legitimate rundll32.exe. rundll32.exe known as the program responsible for running dlls as apps, can be abused by attackers to perform DLL injection or to act as a downloader/dropper for further malware payloads.

Answer: rundll32.exe

## Question 3 What is the memory protection applied to the suspicious process memory region?
Memory protection is used to determine what apps and processes are allowed to manipulate a memory region associated with a single process. Typically malware will utilise Read, Write and Execute permissions on the memory meaning that the region can contain arbitrary code supllied by the attacker (Write) which can then be subsequently executed by the attacker (Execute) allowing attackers to insert shellcode and perform arbitrary code execution.

If we look at the memory regions we can see their Virtual address descriptors (VAD's) such as the starting and ending virtual addresses and the permissions assigned to this memory region.

![image](https://github.com/user-attachments/assets/65df57e6-afea-4394-be39-70df8d814f6f)

We can see one of the memory regions has the Read, Write Execute protection. This is likely the area where the code responsible for futher activities is stored
Answer: PAGE_EXECUTE_READWRITE


## Question 4 What is the name of the process responsible for the VPN connection?
When looking for processes responsible for VPN connections we can use both the process tree and the network connections to determine VPN activity. Beginning with the process tree we see a process with the name tun2socks which as it suggests is likely creating a VPN tunnel for communication. Using google we can determine this is a component of the Outline VPN service a popular VPN service used to create secure VPN connections.
![image](https://github.com/user-attachments/assets/ca2f96b3-615e-43b1-b72b-444df7d08e52)


We can verify that the process is indeed creating VPN connections from the machine by viewing the network connections on the machine at the time of the memory dump
where we can see that the tun2socks.exe has multiple outbound connections 

Answer: Outline.exe

