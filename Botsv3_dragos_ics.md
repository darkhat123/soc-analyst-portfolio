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
