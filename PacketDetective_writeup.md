# Synopsis
In September 2020, your SOC detected suspicious activity from a user device, flagged by unusual SMB protocol usage. Initial analysis indicates a possible compromise of a privileged account and remote access tool usage by an attacker.

Your task is to examine network traffic in the provided PCAP files to identify key indicators of compromise (IOCs) and gain insights into the attacker’s methods, persistence tactics, and goals. Construct a timeline to better understand the progression of the attack by addressing the following questions.


## Question 1 The attacker’s activity showed extensive SMB protocol usage, indicating a potential pattern of significant data transfer or file access.What is the total number of bytes of the SMB protocol?
Before beginning an investiagtion into any pcap it is wise to display the summary of protocols used during the capture, this can show us the best areas to look for traffic indicative of an attack, we can go to **Statistics > Protocol Hierarchy** and see that the SMB
protocol is listed and accounts for 100% of the traffic in the packet capture, we can also see the total bytes involved in the SMB traffic.
![image](https://github.com/user-attachments/assets/8bf9117e-e662-49e3-a825-73713aecc949)

Answer: 4406

## Question 2 Authentication through SMB was a critical step in gaining access to the targeted system. Identifying the username used for this authentication will help determine if a privileged account was compromised.Which username was utilized for authentication via SMB?

When a user authenticates to an SMB server the process is as follows:
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
Sends a NTLM Negotiate Message.

Server → Client:
Sends back a NTLM Challenge Message (includes a nonce).

Client → Server:
Sends an NTLM Authenticate Message:
Encrypted response using the user's password hash and the challenge.
User/domain info.

Server:
Verifies the response using its own copy of the password hash (or domain controller).

From this following process we can see that we are looking for the NTLMSPP_AUTH being passed to the server from the client, which passes the username and hash to the SMB server for verification

We can see from the following screenshot that the administrator account was successfully authenticated to 
![image](https://github.com/user-attachments/assets/a8d4281e-3c0d-417a-a022-faf71928ec06)

Answer: Administrator

## Question 3 During the attack, the adversary accessed certain files. Identifying which files were accessed can reveal the attacker's intent.What is the name of the file that was opened by the attacker?
To find the packets responsible for accessing files on the smb server we must first understand how a file is accessed in the SMB process, from googling we can see that the initial step is to send a create request to the SMB server which will return a create response
telling us that the file is accessible or not. Then we have two options for interacting with the file, we can either read the file which involves sending a read request which will be replied to with a read response containing the data in the file. We can also
write to the file using a write request which will return a write response letting us know if the file has been updated.

The filename of the file being accessed is available in many of these packets, we can see it in the header of the Create Request packet.

![image](https://github.com/user-attachments/assets/9809485f-ab0d-4921-8ff4-7af1d62eec2a)

Answer: eventlog

## Question 4 Clearing event logs is a common tactic to hide malicious actions and evade detection. Pinpointing the timestamp of this action is essential for building a timeline of the attacker’s behavior.What is the timestamp of the attempt to clear the event log?

Interacting with the event log uses its own protocol to provide remote administration to the windows event logs on a machine, this can be used to query the events but can also be vulnerable to the logs being cleared if there are no protections in place. We can see that the
attacker 
