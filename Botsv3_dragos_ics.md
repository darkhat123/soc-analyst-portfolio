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
Screenshot: 
