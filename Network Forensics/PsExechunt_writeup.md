# Synopsis
An alert from the Intrusion Detection System (IDS) flagged suspicious lateral movement activity involving PsExec. This indicates potential unauthorized access and movement across the network. As a SOC Analyst, your task is to investigate the provided PCAP file to trace the attacker’s activities. Identify their entry point, the machines targeted, the extent of the breach, and any critical indicators that reveal their tactics and objectives within the compromised environment.

# Introduction
In this lab, we are tasked with analysing a pcap file of network traffic believed to be involved in the attack. We will be looking for the execution of commands by an attacker using psexec and gathering the context around the initial breach and the subsequent impact
PsExec lets you run processes remotely and works like a command line version of Remote Desktop, where instead of a GUI the commands are entered in the terminal. For psexec to work the following criteria must be met:

-A modern Windows computer (local)
-File and Printer Sharing open (remote computer, TCP port 445)
-The admin$ administrative share is available (remote computer)
-You know a local account’s credentials (remote computer)

Due to the lateral movement mentioned in the lab we know that the attacker will likely be using an internal IP to connect to other computers on the same network. For PsExec to be avaiable on the target machine the attacker would need to use Server Message Block a file and printer
sharing protocol. SMB is used to transfer the psexesvc executable to the target machine, where commands can then be run and the output redirected to the attackers terminal. The attacker takes these steps:

Connects via SMB to \\target\ADMIN$

Uploads PSEXESVC.exe to the remote system

Starts a Windows service remotely via SCM (Service Control Manager)

Executes the specified command

Streams stdout/stderr back over the network

## Question 1 To effectively trace the attacker's activities within our network, can you identify the IP address of the machine from which the attacker initially gained access?
We can filter the pcaps to focus specifically on SMB packets, in this example the version mutually agreed upon is SMB2 so we can simply filter for smb2 traffic in wireshark
There is alot of results but quickly we can see an attempt to authenticate to another pc using SMB from an internal ip 10.0.0.130. Whilst this is sufficient to search for smb responses to focus solely on smb authentication packets we can filter for NTLMSSP over SMB
![image](https://github.com/user-attachments/assets/2578199b-a6c7-4cd9-b4f4-a650dc2c158e)

Answer: 10.0.0.130

## Question 2 To fully understand the extent of the breach, can you determine the machine's hostname to which the attacker first pivoted?
To determine the hostname of the first target machine we need to look into the authentication mechanism being used by SMB to establish a session and find the first instance of a connection attempt, the authentication used in SMB2 is  NT (New Technology) LAN Manager (NTLM)
an authentication method used in Windows Lan environments.

Looking through the SMB packets we can see that the connection attempt was initiated by the attacker and was subsequently successful in connecting to the user ssales on the target machine

When the server responds to the initial request it sends parameters over to the source machine 

### How NTLM works
Client Initiates Authentication
Sends username and domain name (no password yet)


Server Sends Challenge
Server sends a random 8-byte challenge (nonce)


Client Responds

Hashes the password
Uses it to encrypt the challenge
Sends this encrypted response back

Server Verifies
Server (or domain controller) performs the same hash/encryption and compares results.
If they match: authentication is successful.
No password is ever sent across the network — only a response to the challenge.
