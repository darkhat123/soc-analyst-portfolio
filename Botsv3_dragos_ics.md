# Scenario


# Question 1: Which host gets notified when the 1756-L61/B LOGIX5561 card undergoes a PLC status change?
PLCs can have different states and in some cases, it may be considered normal for their state to change during normal operations. Being able to identify and detect state changes can inform of normal or malicious intent

To identify any PLC state changes being propogated through the network we must first identify the category of this event from dragos, through looking for any fields related to status change we see the
**PLC Status Change** category, which logs all events where a change in the PLC's state is idenfified. This brigns up all PLC's in the environment and shows us the traffic related to notifying the concerned hosts.
Armed with this we can identify the field responsible for denoting the PLC logic card. Within the message body there is a section describign which PLC card made the change, we can sue this to drilldown into 
only the PLC we are interested. We are now presented with multiple entries detailing different src ips for the card with the same mac address (**00:00:BC:3C:DB:0D**) notifying multiple IP addresses of the status change.

The early results are likely when the PLC was just being configured as it continues to add more entries to the destination which needs to be identified, after a while we see that all destinations have been configured and the
PLC switches ip address, this is still the same PLC just using a different src_ip, it notifies many destinations of its PLC status change.

| Hostname                 | IP Address      | Notes / Role (from context)               |
|---------------------------|-----------------|-------------------------------------------|
| ews-hq-siemens01.local    | 192.168.1.200   | Siemens engineering workstation (EWS)     |
| desktop-mln7j12.local     | 192.168.96.200  | User desktop (engineering/maintenance)    |
| ews-hq-rslogix01.local    | 192.168.1.100   | Rockwell RSLogix engineering workstation  |
| *(no hostname in logs)*   | 192.168.97.6    | Host notified by PLC (role unclear, likely HMI or historian) |

The main host being notified is 192.168.97.6, but all other dest_ip's are sent the same update.

Query: `index="dragos" category="PLC Status Change" "1756-L61/B LOGIX5561"  | sort descending`
Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/19fd7ef6-d58f-41da-be40-6075b8c43668" />

Answer: 192.168.97.6

# Question 2: Based on the previous question, who is the manufacturer of the card?

Answer: Rockwell Automation

# Question 3: Based on the answer in question 102, answering in MB, how large is the user memory on the previously identified controller?
Knowing technical specifications of hardware can help with system designs and requirements. This can include software and hardware specs.

We can simply look up the specs online

Answer: 2

# Question 4: What is the built-in COM (communication) port?
Along with knowing technical specifications of hardware, knowing built-in ports can help with upgrading systems and determining compatibility.

COM ports whilst slowly becoming obselete are still found in many PLC's to this day, they can be used for PLC programming by connecting to a PC and may even be connected to simple field devices, they are also
used to connect PLC's to HMI's.

Ethernet ports are the new normal providing much faster speeds and encapsulating protocols like Modbus RTU into Modbus TCP, it also allows the PLC to communicate with many devices at once in a network topology

We can research the built in COM port specifications online

Answer: RS-232

# Question 5: What is the destination IP address of the TCP reverse shell that was detected?

Dragos provides many helpful dashboards for analysing the network from a general perspective, we have a section dedicated to **Threat Behaviour** which identifies any traffic that may pose a threat to the security posture. Alerts are categorised by their severity and if we go from highest to lowest we quickly identify a record with the category **SQL Server xp_cmdshell observed**.
Screenshot: <img width="1851" height="911" alt="image" src="https://github.com/user-attachments/assets/0014dabe-6a1b-4d04-9b5e-d06789dde680" />

This tells us an SQL Server(10.0.128) has made a connection to a C2 endpoint (10.0.0.31) using the xp_cmdshell functionality which allows the sql server to execute commands on the underlying operating system, this can be used to download malware or spawn rever shells to C2 endpoints or pivot to another host. 

We can drill down into the records involved with this threat behaviour by filtering by category and we will get results displaying traffic related to xp_cmdshell.

Screenshot: <img width="1894" height="853" alt="dragos-xp_cmsdhell" src="https://github.com/user-attachments/assets/8e5d2559-4e8e-4aa6-9d53-b5d7bf94c174" />

Now that we know the attacker was using 10.0.0.31 as a C2 endpoint to spawn a reverse shell we can see if there is any other traffic or alerts generated with these machines.

Query: `index="dragos" dest_ip="10.0.0.131" src_ip="10.0.0.128" | table category, body`

Screenshot: <img width="1911" height="849" alt="image" src="https://github.com/user-attachments/assets/4b58bcfa-1d08-4540-b593-6ec97428af2c" />

**Further investigation**
Now that we have the alert we would begin to gather context about the attack using network and EDR logs to identify:
- Command ran to initiate reverse shell
- Further commands ran on the system
- user context ( What privileges were available)
- Further connection attempts made by 10.0.0.128 to internal or external resources
- Event IDs 4624 (logon), 4688 (process creation), 5140 (file access)
Answer: 10.0.0.131

# Question 6: What was the hostname that was connected to with a SMB command shell?
Using dragos's category feature to look for any alerts produced involving the SMB protocolwe can quickly create a timeline of the smb activity detected by dragos and determine how it was abused and what systems were affected.

Query:`index="dragos" category="*SMB*" | table _time src_ip, src_name, dest_ip, dest_name, category, body | reverse`

Screenshot: <img width="1903" height="846" alt="image" src="https://github.com/user-attachments/assets/bf52793b-cba1-4ad6-b4f4-f1a56a79e96f" />

We can see that their are multiple entries regarding smb traffic, we can see that command shell comes up quite often, we can drill down to find this

Query: `index="dragos" category="SMB Command Shell Activity"  | table  _time src_ip, src_name, dest_ip, dest_name, dest_host category, body  | reverse`

Screenshot: <img width="1884" height="659" alt="image" src="https://github.com/user-attachments/assets/9fb6aa11-183b-4e8e-8506-b50d4d0a5af6" />

Answer: rslogix5000

## Question 7: If you were going to use the tool 'pylogix', what config file parameter needs to change in order to set the slot number?
PyLogix is a Python library used to communicate with Allen-Bradley (Rockwell Automation) PLCs over the Ethernet/IP protocol. It’s commonly used in Industrial Control System (ICS) environments for monitoring and interacting with PLCs programmatically.

We can find guidance on the pylogix tool on github: https://github.com/dmroeder/pylogix

Answer: comm.ProcessorSlot

## Question 8: Using pylogix, what value is used to read a tag by routing through another device?

## Question 9: Using pylogix, what value is used to enumerate and get all controller and program tags?

Answer: GetTagList()

## Question 10: On which hostname was the Metasploit alert for detected windows/speak_pwned run against?

This is a proof of concept used to demonstrate the ability for a remote system to induce a function on a windows pc saying its been pwned and is used for testing exercises. 

We know that the category is likely to inlcude metasploit, and we know that the windows/speak_pwned module is used, we can filter for any traffic with this category and it quickly tells us that
srv-hq-bkup01(192.168.193.12) was able to use metsasploit to access srv-hq-nas01(192.168.193.14).
Query: `index=* sourcetype=dragos_alert  category ="*windows/speak_pwned*" 
| table _time, src_host, src_ip, dest_host, dest_ip, category`

Screnshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/7a255bd9-93d8-4f3b-b0a8-2e8c565cb046" />

We could then pivot to other dragos logs including metasploit to gather information on the threat behaviour, then we can pivot to network and enpoint logs to determine whether the attacking ip made any further commands or exfiltrated any data.

Query: `index=* sourcetype=dragos_alert  category ="*Metasploit*" 
| table _time, src_host, src_ip, dest_host, dest_ip, category`

Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/ca7f2715-186b-434b-bcef-8f4b9c75c8e7" />

We can also look into the activtities related to the attacking ip to build a picture of their actions

Query: `index=* sourcetype=dragos_alert  "192.168.193.12" 
| table _time, src_host, src_ip, dest_host, dest_ip, category`
Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/4a02bb99-f694-4c76-8fd6-a193cb1d1401" />

We can see that the attacker first attempted to execute commands remotely on the rslogix5000 host, transferred a file to the host then moved on to the host in question and ran metasploit

Answer: srv-hq-nas01

## Question 11: What offensive PowerShell tool was used by the adversary?

We know that this will produce some alert related to powershell, we can search for any categories involving powershell and look from the beginning to the end, we can see that initially one host executed powershell scripts using smb likely done by the attacker, next we see the 10.0.30.129 has attempted to send traffic to 10.0.30.131 using signatures common with empire c2 communications, whether the 10.0.30.129 executed empire using powershell or 10.0.30.131 has launched a malicious PHP listener.

Query: `index=* category="*Powershell*" | table  _time, src_host, src_ip, src_name, dest_host, dest_ip, dest_name, body  | reverse`
Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/70e42dc2-77d6-4350-83b0-4e3d30109060" />

Answer: Empire

## Question 12: MS17-101 was run against a target. What was the target's MAC address?

Query: `index=* category="*EternalBlue*" | table  _time, src_host, src_ip, src_name, dest_host, dest_ip, dest_name, dest_mac, body  | reverse`

Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/60962d26-a882-4751-84cf-1b7c999088a3" />

Answer: F8:DB:88:3E:83:A0

## Question 13: Which host attempted to modify the Usermemory object on the host 192.168.1.6 more than once?
This involves looking for any occurences of the usermemory object in our alerts

Query: `index=* dest_ip="192.168.1.6" "*Usermemory*"| table  _time, src_host, src_ip, src_name, dest_host, dest_ip, dest_name, dest_mac, body  | reverse`

Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/1e555140-36f8-46c6-ae9e-ca3e4005d528" />

This tells us 192.168.1.6 is a PLC, we could now look into any traffic related to that ip to see other actions taken

Query: `index=* dest_ip="192.168.1.6" | table  _time, src_host, src_ip, src_name, dest_host, dest_ip, dest_name, dest_mac, body  | reverse`

Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/fb2c86ed-f222-4023-ad9c-8a9b70e2e28d" />

Answer: 192.168.1.100

## Question 14: 
This suggests that an alert was generated from 192.168.1.6 notifying 192.168.1.200 that the specified command was not authorised and therefore unsuccessful, the body of the alert gives us details as to what was rejected by the PLC.
Query: `index=*  src_ip="192.168.1.6" dest_ip="*192.168.1.200*"  category="CIP Error (Service Not Supported) Indicating Unauthorized Command Message" | table  _time, src_host, src_ip, src_name, dest_host, dest_ip, dest_name, dest_mac, body   | reverse`

Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/af7073ab-f052-4bc5-bb93-0ec3a49e2d7e" />

Answer: Get Attribute List

## Question 15: There was a port scan initiated at 03:06. Providing the port number only, what was the highest port number scanned?

Query: `index=*  category="*scan*" | table  _time, src_host, src_ip, src_name, dest_host, dest_ip, dest_name, dest_mac, body   | reverse`

Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/76221bc5-ebba-4b9d-a3de-f7745e4dc295" />

Answer: 1331

## Question 16: Based on the previous question, what is the hostname of where the scanner originated?

Answer: factory-talk-vi

## Question 17: Host 192.168.193.12 sent a file from 192.168.2.2. What was the access technique used? 

Query: `index=*  category="*file*" src_ip = 192.168.193.12 dest_ip = 192.168.2.2 | table  _time, src_host, src_ip, src_name, dest_host, dest_ip, dest_name, dest_mac, body    | reverse`

Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/efdfdbe1-2af5-41dc-92c1-32ddb90eeab4" />

Answer: None Logon

## Question 18: There was a Metasploit reverse TCP shell detected, started from 10.0.0.128. Provide the IPv4 address of where it was connecting to.

Query: `index=*  category="*reverse*" src_ip = 10.0.0.128 | table  _time, src_host, src_ip, src_name, dest_host, dest_ip, dest_name, dest_mac, body    | reverse`

Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/c1ffeec2-72b5-49be-8f85-dc27feebb492" />

Answer: 10.0.0.131

## Question 19: 

We can first determine the most occurences of pycomm alerts for each src_ip to detemrine which ip was used the most

Query: `index=*  category="*pycomm3*"  | table  _time, src_host, src_ip, src_name, dest_host, dest_ip, dest_name, dest_mac, body
| stats count by src_ip`

Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/81fe6fd1-fb47-41a5-be34-2c8e218c03f1" />

Now we know what src_ips are associated with the traffic we can filter for these specifically

Query: `index=*  category="*pycomm3*" src_ip = "192.168.212.229,192.168.212.226" | table  _time, src_host, src_ip, src_name, dest_host, dest_ip, dest_name, dest_mac, body`

Screenshot: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/067e5ebc-f4f1-4b5f-a8e9-c7dbe1343bca" />

Answer: 192.168.212.229

## Question 20: 
