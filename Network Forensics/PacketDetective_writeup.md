# Synopsis
In September 2020, your SOC detected suspicious activity from a user device, flagged by unusual SMB protocol usage. Initial analysis indicates a possible compromise of a privileged account and remote access tool usage by an attacker.

Your task is to examine network traffic in the provided PCAP files to identify key indicators of compromise (IOCs) and gain insights into the attacker’s methods, persistence tactics, and goals. Construct a timeline to better understand the progression of the attack by addressing the following questions.


## Question 1 The attacker’s activity showed extensive SMB protocol usage, indicating a potential pattern of significant data transfer or file access.What is the total number of bytes of the SMB protocol?
Before beginning an investiagtion into any pcap it is wise to display the summary of protocols used during the capture, this can show us the best areas to look for traffic indicative of an attack, we can go to **Statistics > Protocol Hierarchy** and see that the SMB
protocol is listed and accounts for 100% of the traffic in the packet capture, we can also see the total bytes involved in the SMB traffic.
![image](https://github.com/user-attachments/assets/8bf9117e-e662-49e3-a825-73713aecc949)

Answer: 4406

## Question 2 Authentication through SMB was a critical step in gaining access to the targeted system. Identifying the username used for this authentication will help determine if a privileged account was compromised.Which username was utilized for authentication via SMB?

When a user authenticates to an SMB server, the process is as follows:
✅ Step 1: Client Initiates Connection
The client sends a Negotiate Protocol Request to the server, offering supported SMB protocol versions.

🔄 Server Responds:
Sends a Negotiate Protocol Response, choosing the highest SMB version supported by both.

✅ Step 2: Session Setup Request (Start Authentication)
The client begins authentication with a Session Setup Request, including:
Username
Security token (based on NTLM or Kerberos)
Domain info (if applicable)
NTLM Authentication

🛠️ NTLM Authentication Steps
Client → Server:
Sends an NTLM Negotiate Message.

Server → Client:
Sends back an NTLM Challenge Message (includes a nonce).

Client → Server:
Sends an NTLM Authenticate Message:
Encrypted response using the user's password hash and the challenge.
User/domain info.

Server:
Verifies the response using its own copy of the password hash (or domain controller).

From the following process ,we can see that we are looking for the NTLMSPP_AUTH being passed to the server from the client, which passes the username and hash to the SMB server for verification

We can see from the following screenshot that the administrator account was successfully authenticated to 
![image](https://github.com/user-attachments/assets/a8d4281e-3c0d-417a-a022-faf71928ec06)

To Find this in a large packet capture we can use the filter `smb and ntlmssp.auth.username` 
![image](https://github.com/user-attachments/assets/ea42006e-2cd2-483e-9f76-56a1b1833b9f)

Answer: Administrator

## Question 3 During the attack, the adversary accessed certain files. Identifying which files were accessed can reveal the attacker's intent.What is the name of the file that was opened by the attacker?
To find the packets responsible for accessing files on the smb server we must first understand how a file is accessed in the SMB process, from googling we can see that the initial step is to send a create request to the SMB server which will return a create response
telling us that the file is accessible or not. Then we have two options for interacting with the file: we can either read the file, which involves sending a read request, which will be replied to with a read response containing the data in the file. We can also
write to the file using a write request, which will return a write response letting us know if the file has been updated.

The filename of the file being accessed is available in many of these packets; we can see it in the header of the Create Request packet.

![image](https://github.com/user-attachments/assets/9809485f-ab0d-4921-8ff4-7af1d62eec2a)

Answer: eventlog

## Question 4 Clearing event logs is a common tactic to hide malicious actions and evade detection. Pinpointing the timestamp of this action is essential for building a timeline of the attacker’s behavior.What is the timestamp of the attempt to clear the event log?

Interacting with the event log uses the DCERPC protocol to provide remote administration to the Windows event logs on a machine. This can be used to query the events, but can also be vulnerable to the logs being cleared if there are no protections in place. We can see there is indeed DCERPC traffic within the packet capture which appears to be calling a function ClearEventLogW, which was found to be used to clear the event log and optionally back it up (https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-cleareventlogw). 

This function name could possibly be used as a filter to identify the attacker in the context of this scenario but this function name could change, we need something more reliable to ensure that someone was indeed clearing the log in any situation.

Here's what really matters in DCERPC:
When a client calls a function over DCERPC (like clearing an event log), the communication includes:

The interface UUID and version (e.g., for EventLog)

The Opnum (operation number — like 0)

The parameters, encoded in a standard format (NDR)

The function name itself is not transmitted. It's just a label in source code or documentation for human readability and developer reference.

Each RPC interface (like the EventLog interface) assigns a unique operation number (Opnum) to each remote procedure. For example:
Opnum 0 = ElfrClearELFW

This is defined in Microsoft’s MS-EVEN protocol specification

This means: If you see a call to Opnum 0 within the context of the EventLog interface, you know the client is trying to clear a log.

Wireshark Filter: `dcerpc.opnum == 0`

![image](https://github.com/user-attachments/assets/71e8a620-8cf6-499f-862f-23d36f16f1d0)

Answer:2020-09-23 16:50:16

## Question 5 The attacker used "named pipes" for communication, suggesting they may have utilized Remote Procedure Calls (RPC) for lateral movement across the network. RPC allows one program to request services from another remotely, which could grant the attacker unauthorized access or control.What is the name of the service that communicated using this named pipe?

To discover the service using Named pipes we first must understand what named pipes are and their purpose in communication, we must also understand how named pipes can be abused by attackers.

Named pipes are a powerful inter-process communication (IPC) mechanism, primarily used in Windows, that allow two processes to communicate — either on the same machine or across a network.

They are called "named" because, unlike anonymous pipes, they exist as a named object in the file system (e.g., \\.\pipe\mypipe), which makes them accessible to multiple processes.

Many Windows services expose their management interfaces via named pipes

These can be used by attackers to perform reconaissance, lateral movement, privilege escation and more


Finding the Named Pipe in wireshark is possible through searching for the PIPE string within any frame, we can do this by entering the hexadecimal representation
of \PIPE. We can see that we have an entry for a procol ISystemActivator which appears to be receving a response RemoteCreateInstance.

To fully understand what this packet represents we can dig deeper into the way windows performs instrucitons sent from one machine on another machine.
When one object on a computer needs to be accessed remotely by another computer windows uses the DCOM protocol.

DCOM (Distributed Component Object Model)
What it is:
A Microsoft extension of COM (Component Object Model) that supports remote communication between software components over a network using DCERPC.

Primary uses:
Allows applications to call COM objects on remote machines
Used heavily by Windows management services (e.g., WMI—Windows Management Instrumentation)

Ports:
Uses DCERPC for communication
Starts on TCP 135 (RPC endpoint mapper) and then uses dynamic ports (1024-65535, or configurable)

The interplay between SMB, DCERPC and DCOM is evident in our packet as we have the use of named pipes which are used in SMB to allow interprocess communication,
the named pipe is used by DCERPC to send function calls to the pipe which will be used to determine the behaviour of the target process using the pipe.
DCOM is used to provide object methods from one machine to the other, we can see that a DCOM object ISystemActivatior has returned a RemoteCreateInstance repsonse. This means that the COM object and its methods are now available to the attacker, understanding what named pipe was targeted is useful in determining
what the attacker was trying to do on the remote machine. Scrolling through the packet data for the suspicious packet we can see the \PIPE entry in the packet, reading round the string gives us context to what server the attacker was targeting and the named pipe, this is provided in the NetworkAddr section. This can
be hard to filter for as it can be avaiable in other sections of the DCERPC packet, thus the reason for filtering for occurences of \PIPE within frames being
the best way to identify the traffic

![image](https://github.com/user-attachments/assets/3eba2756-68a7-403f-97c1-177e8d9549b2)

The atsvc Named Pipe is related to the task scheduler program, the attacker is likely trying to perform commands to access another computer using the task scheduler to manipulate scheduled tasks to run arbitrary commands typically with SYSTEM privileges. Due to no interactive shell being spwaned this isnt noisy
and can go unnoticed as the attacker performs their attack.

Answer:atsvc

## Question 6 Measuring the duration of suspicious communication can reveal how long the attacker maintained unauthorized access, providing insights into the scope and persistence of the attack.What was the duration of communication between the identified addresses 172.16.66.1 and 172.16.66.36?
Manually determining how long two computers were communicating can be arduous, luckily wireshark provides a built in feature known as conversations which collects
information on the traffic between two computers as a whole, this can be accessed in **Statistics>Conversations**, with both ips filtered for it should only
display info on the addresses present with the filter applied.

Answer: 11.7247

## Question 7 The attacker used a non-standard username to set up requests, indicating an attempt to maintain covert access. Identifying this username is essential for understanding how persistence was established.Which username was used to set up these potentially suspicious requests?
When looking for Samba traffic it should be known that different versions are available, typically the version is determined by choosing the highest available for both parties, when using our filter from Q2 we cant see any entries trying to authenticate to any SMB servers, when we change the version to samba 2 we get a hit
Command `smb2 and ntlmssp.auth.username`
![image](https://github.com/user-attachments/assets/2d2f737e-d80a-40a7-861b-99550465a4fd)

Answer:backdoor

## Question 8 The attacker leveraged a specific executable file to execute processes remotely on the compromised system. Recognizing this file name can assist in pinpointing the tools used in the attack.What is the name of the executable file utilized to execute processes remotely?
When determining what file was used we can do two things, we can observe the SMB objects exported from wireshark where it is clearly listed
![image](https://github.com/user-attachments/assets/c3157ff6-78ba-4201-b107-434cef060dd1)

Furthermore if we know the extension of the file we can use the SMB filename field to indentify any entries containing the extension

`smb2.filename contains ".exe"`

![image](https://github.com/user-attachments/assets/d93ee8c0-6d71-4469-8ea3-e8e1eba315a3)

Answer psexesvc.exe

# Conclusion
This was an interesting network forensics challenge where we gained insight into how to reconstruct an attack over SMB where multiple endpoints were affected, this involved analysing the underlying protocols being used to perform remote administration on computers to determine what the attacker did. We learned about the interplay between SMB, DCERPC and DCOM and their roles in a windows environment, we also constructed filters which can quickly identify traffic.


