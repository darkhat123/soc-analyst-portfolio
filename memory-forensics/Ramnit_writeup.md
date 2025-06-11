# Synopsis
Our intrusion detection system has alerted us to suspicious behavior on a workstation, pointing to a likely malware intrusion. A memory dump of this system has been taken for analysis. Your task is to analyze this dump, trace the malware’s actions, and report key findings.

# Introduction
This is another memory forensics challenge in soc analyst tier 1 that challenges us to analyse a memory dump of a windows PC using the built-in modules from volatility 3 a popular memory forensics tool. This will involve identifying the root cause of the attack through
analysing the processes on the machine at the time of collection. From there we will trace the steps of the attacker to determine their actions on the pc and their connections to external servers, this will be used to categorise the malware to determine what the attack was trying
to acheive and the steps necessary to fully eradicate the threat and prevent further intrusions.

## Question 1 What is the name of the process responsible for the suspicious activity?
The first step in memory forensics using volatility 3 is to determine the processes available on the machine at the time of the attack to determine what process initiated the attack chain and the subsequent processes spawned to continue the attack, knowing the strategy used
by the attacker allows us to create effective detection signatures that can prevent the malware from infecting other workstations on the network. In this lab when we list the processes and redirect them to the more command for readability we can see that other than
the expected processes there is a process spawned with the name ChromeSetup.exe which at first appears to be the google installer executable used to install the browser to the computer, this is the only process that seems to be ran from the users download folder and was instantiated 
using explorer.exe to find the file and execute it, whilst this could be a harmless install of chrome onto the computer, it is strange that a user is configuring the browser on a company issued computer as this would likely be done by an IT team.

The command used to list the processes in a hierarchical format displaying parent and child relationships we use the `python3 vol.py -f memory.dmp windows.pstree | more` command
![image](https://github.com/user-attachments/assets/e9e3596a-f4ce-4b99-b63c-3c2656323eeb)

Answer: ChromeSetup.exe

## Question 2 What is the exact path of the executable for the malicious process?
The pstree command also lists the path that the process was executed from, this can be used to see where the malware is stored

Answer: C:\Users\alex\Downloads\ChromeSetup.exe

## Question 3 Identifying network connections is crucial for understanding the malware's communication strategy. What IP address did the malware attempt to connect to?
With the process name and id we are able to filter the results of the netstat command for connections initiated by the suspicious process by filtering for the Process id of ChromeSetup.exe (4628)

Command: `python3 vol.py -f memory.dmp windows.netscan | grep 4628`
![image](https://github.com/user-attachments/assets/91ca9f1d-458f-45ff-9d0b-7d5353c8d463)

Answer: 58.64.204.181

## Question 4 To determine the specific geographical origin of the attack, Which city is associated with the IP address the malware communicated with?
Determining the geographical location for the ip can help in identifying the threat actor attributed to the malware or provide pointers in likely TTP's used in the malware, a simple WHOIS lookup of the IP address can tell us where it originated from.
![image](https://github.com/user-attachments/assets/a5161721-1723-4fca-a9ee-68c6b9b16300)
Answer: Hong Kong

## Question 5 Hashes serve as unique identifiers for files, assisting in the detection of similar threats across different machines. What is the SHA1 hash of the malware executable?
In order to determine the hash of the file we must first have access to the file, in order to do this we need to use volatility3 to dump the necessary files associated with a process, for this we need the process id of the suspicious process (4628).
With the process id we can use this as an argument with `windows.dumpfile` to extract all the files connected to the suspicious process. We can then use the `grep` functionality to match our filename, this will then be available in our directory where we can
easily pass it to the `sha1sum` command.

![image](https://github.com/user-attachments/assets/6e89caa0-944b-4092-be48-1f4454ec9a7a)
![image](https://github.com/user-attachments/assets/a44af644-9592-4bfc-a3b1-7a9d0a308a80)

Answer:280c9d36039f9432433893dee6126d72b9112ad2
## Question 6 Examining the malware's development timeline can provide insights into its deployment. What is the compilation timestamp for the malware?
One of the useful Sections of virustotal is the Portable Executable info section which tells us details about the PE after static analysis, this can be used to determine if the malware is packed, what imports are used to interact with the Operating system and the compilation
timestamp.
![image](https://github.com/user-attachments/assets/8c7e050a-1d1c-4f58-b165-ab336e3db5eb)
Answer: 2019-12-01 08:36

## Question 7 Identifying the domains associated with this malware is crucial for blocking future malicious communications and detecting any ongoing interactions with those domains within our network. Can you provide the domain connected to the malware?
Finally to prevent the domains being accessible from the network we need to know which domains were contacted by the malware and their reputations, this is provided in the Contacted Domains section, there are two malicious domains listed, the first is a subdomain of the main domain
so the second is the right answer.
![image](https://github.com/user-attachments/assets/a95e649a-c7aa-4887-abe3-d2b081335043)
Answer: dnsnb8.net

# Conclusion
This lab was another useful lab in memory forensics using volatility3, extending upon the previous applications such as viewing the commands executed on the machine and extracting patterns from the memory of a specific file, this lab additionally taught us how to extract the
malicious files in a safe manner with the appended extensions utilised in the ouput from dumpfile where we can then extract the file hash and perform further investigation into the malwares TTP's
