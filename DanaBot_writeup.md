# Synopsis
The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. Your task is to use Network Capture (PCAP) files and Threat Intelligence to investigate the incident and determine how the breach occurred.

## Question 1 Which IP address was used by the attacker during the initial access?
When looking for initial access IOC's it is critical to look at the dns requests being made to external ips and evaluating the domain and ip reputation to determine if it is malicious, upon opening the pcap the first and second packet is a DNS Query to a questionable domain
and a DNS response with an external ip, upon investigation using virsutotal to check both the reputation of the domain and the ip we can see that the domain is malicious with the following description:
"This DOMAIN is used by DANABOT. Danabot, a banking trojan emerging in 2018, gained notoriety for its robust delivery and modular structure. It is constantly updated and has become a significant threat globally. Initially targeting Australian companies, it expanded its attacks to Europe and North America. The trojan is versatile, featuring credential theft functions, and is split into loader, main component, and modules. It steals sensitive data, including screenshots, system info, and credentials, sending it to the control server encrypted. Danabot evolved over time, using advanced encryption methods and evasion techniques to mislead researchers and security systems."
![image](https://github.com/user-attachments/assets/8ea554e3-92ea-43c2-8600-7bf57f58268e)

If we dig deeper into the relations tab we can see that the server typically resolves to the ip in the DNS response in our network capture, its clear that an internal pc has made a connection to a server associated with a trojan targeting the financial sector
![image](https://github.com/user-attachments/assets/85586f72-ad3b-47e0-9022-abb5f1bb4a77)

Answer: 62.173.142.148

## Question 2 What is the name of the malicious file used for initial access?
With knowledge of the malicious ip involved we can look for any requests made to the malicious domain, we can see that the user is directed to the login.php where they are served a javascript file which is successfuly tansferred to the victim machine. We can see this by
following the HTTP stream of the request to the login page, where the filename is disclosed

![image](https://github.com/user-attachments/assets/246bc6e8-b093-4f0e-b5ff-cd5d49d90ab1)

Answer: allegato_708.js

## Question 3 What is the SHA-256 hash of the malicious file used for initial access?
Copying the contents of the file from the stream we can paste these into a sha256 generator tool and determine the files hash, which we will use to search on virusotal

![image](https://github.com/user-attachments/assets/f62b53f1-8603-42d3-bad2-6bf81df92f1d)

Answer: 847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268

## Question 4 Which process was used to execute the malicious file?
We can look at the behaviour of the malware and see if we can find any information on processes being used to execute malicious files, in the processes created we can see that the file was run using wscript.exe a commonly used executable for performing malicious actions
in trojans
![image](https://github.com/user-attachments/assets/258dfdcf-59d1-43d5-af02-47b123c57352)

Answer: wscript.exe

## Question 5 What is the file extension of the second malicious file utilized by the attacker?
If we view the Deobfuscated javascript of the file downloaded to the victim pc we can see that a request to http://soundata.top/resources.dll is made to retrieve a second malicious file 
![image](https://github.com/user-attachments/assets/7da164b4-c78c-47d8-ae78-8511205c0413)

Answer: .dll





