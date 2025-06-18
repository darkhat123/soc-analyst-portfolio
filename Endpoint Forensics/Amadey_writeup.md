# Synopsis

An after-hours alert from the Endpoint Detection and Response (EDR) system flags suspicious activity on a Windows workstation. The flagged malware aligns with the Amadey Trojan Stealer. Your job is to analyze the presented memory dump and create a detailed report for actions taken by the malware.

# Question 1 In the memory dump analysis, determining the root of the malicious activity is essential for comprehending the extent of the intrusion. What is the name of the parent process that triggered this malicious behavior?
From the question we can see we will be analysing a memory dump to determine the malwares behaviour. The tool provide in this lab is volatilty 3 which is a command line tool capable of extracting processes, network connections
and Registry Forensics.

To begin we can list the processes that were avaiable at the time of the memory dump and determine any suspicious processes that may be indicators of the malware running on the system. Using the process of elimination and independent research we can identify a supicous 
process

We can utilise *windows.pstree*, *windows.psscan* and *windows.pslist*, the tree format is particularly useful in viewing the parent child relationshipbetween the processes.
After searching all processes one by one i noticed that there were two processes with similar names, upon inspection it appeared one of the names was masquerading as a legitimate service, with no information avaiable about lssass.exe it
was clear this process was suspicious
![image](https://github.com/user-attachments/assets/780f0f83-350a-4d1c-813f-e3f49b0500bb)

Answer: lssass.exe

# Question 2 Once the rogue process is identified, its exact location on the device can reveal more about its nature and source. Where is this process housed on the workstation?
With knowledge of the process id and its name we can now look to the commands run on the computer to determine where the file responsible for executing the process resides, we cna simply print the output in this scenario
however it is useful to grep to remove undesired results. This can be done using the proces name or id. The command used is *windows.cmdline | grep lssass* 

![image](https://github.com/user-attachments/assets/8ca96080-7486-4361-92dc-2761bc71a81c)
We can see the command line argument run to begin the process and where exactly the malware resides

 Answer: C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe

 # Question 3 Persistent external communications suggest the malware's attempts to reach out C2C server. Can you identify the Command and Control (C2C) server IP that the process interacts with?
 
Determining the ip address of the c2 server is essential in eradicating the threat by cutting communications between the affected enpoint and the attacker, the question states that persistent connections are suspicious
we can see that the ip address 41.75.84.12 has made multiple connections tio the same ip with incrementing port numbers. This was found using *windows.netscan* and grepping for lssass
![image](https://github.com/user-attachments/assets/f1bb6bb9-3474-49b0-aef2-34343f6b47d3)

Answer: 41.75.84.12
# Question 4 Following the malware link with the C2C, the malware is likely fetching additional tools or modules. How many distinct files is it trying to bring onto the compromised workstation?
In this scenario there is no built-in plugin capable of extracting get requests from a specific process, in order to be able to access the requests made by this process we need to access its memory, we can use the memmap plugin to determine
the memory regions relevant to the process which can then be searched for request patterns.

In order to create the memory map we can use the plugin *windows.memmap.Memmap* and specify the process id of the suspicious process

The command i used was *python3 vol.py -f /home/ubuntu/Desktop/'Start here'/Artifacts/'Windows 7 x64-Snapshot4.vmem' windows.memmap.Memmap --pid 2748 --dump*

Once the memory dump is created its as simple as runnign the strings program on the memory dump and grepping for get requests, they typically have the prefix "GET /" which is what we will try to match, we then select unique requests and count the lines

The full command used: *strings pid.2748.dmp | grep "GET /" | uniq | wc -l*

![image](https://github.com/user-attachments/assets/bd9c9694-f10e-4561-aaad-41dd70aad0f3)

Answer: 2

# Question 5 Identifying the storage points of these additional components is critical for containment and cleanup. What is the full path of the file downloaded and used by the malware in its malicious activity?
With knowledge that a dll file was downloaded onto the computer by the malware we can search for execution of a dll by grepping for the dll extension

![image](https://github.com/user-attachments/assets/a3545441-06ae-4fa7-a37d-dd762d9f82c8)

Answer: C:\Users\0xsh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll

# Question 6 Once retrieved, the malware aims to activate its additional components. Which child process is initiated by the malware to execute these files?
This can be found in the previous screenshot and shows rundll32 was used to execute the file downloaded by the malware, we can see from the pstree command that this is running below the lssass process as a child

Answer: rundll32.exe

# Question 7 Understanding the full range of Amadey's persistence mechanisms can help in an effective mitigation. Apart from the locations already spotlighted, where else might the malware be ensuring its consistent presence?
When looking for persistence mechanisms we can look for command line arguments for task scheduler or we can check to see if the file used to run the process is available in any other areas of the filesystem
Using the filescan utility and grepping for the root malicious exe shows us that the file is also stored in the tasks folder which will likely activate at a set time.


![image](https://github.com/user-attachments/assets/5c960266-d6c8-4b56-9cac-f35d5c36a291)

Answer: C:\Windows\System32\Tasks\lssass.exe

Conclusion
This was a really engaging lab on using volatility to peice together a malwares TTP's and determine the extent of the malwares infection, this involved identifying suspicious processes, determing their root cause and documenting the 
steps after initial execution.
