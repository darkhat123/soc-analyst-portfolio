# Scenario
A high-profile corporation that manages critical data and services across diverse industries has reported a significant security incident. Recently, their network has been impacted by a suspected ransomware attack. Key files have been encrypted, causing disruptions and raising concerns about potential data compromise. Early signs point to the involvement of a sophisticated threat actor. Your task is to analyze the evidence provided to uncover the attacker’s methods, assess the extent of the breach, and aid in containing the threat to restore the network’s integrity.

# Introduction
In this lab we will examine a full attack chain conducted by an APT which results in the downloading and executing of ransomware on an enterprise network, we will peice together a timeline of the attacker's TTP's to determine
how they initially compromised the network and how they managed to execute the ransomware.

## Question 1 Knowing the source IP of the attack allows security teams to respond to potential threats quickly. Can you identify the source IP responsible for potential port scanning activity?

Port scanning can be done in a number of ways, typically attackers utilise tools such as NMAP to automate this process and identify open ports which they can perform futher probing into to determine vulnerabilities.
Port scanning relies on the workings of the TCP handshake to determine if a port is open, when a computer wants to connect to a port it will send a SYN packet to the target computer, when doing the full 3 way handshake the server
can either responded with a SYN-ACK telling the source the destination port is avaiable or RST-ACK if the port isnt available. A Half-Connect scan which is much stealthier requires the client to send a RST packet if a port is determined to beopen

In our Scenario we can tell that the attacker has made a Full TCP connect scan, we can first identify packets where there is a SYN packet, but no ACK, indicative of a client probing a servers port, we can see many attempts to connect to many
different ports.

Query: `tcp.flags.syn== 1 && tcp.flags.ack==0`
Screenshot:<img width="1912" height="968" alt="image" src="https://github.com/user-attachments/assets/53684823-31d0-4150-a039-1684df2cfa9f" />

We can now determine the ports the attacker identified by looking for any SYN-ACK replies from the server. Our query filters only open port replies from the victim server.

Query: `tcp.flags.syn== 1 && tcp.flags.ack==1 && ip.src==87.96.21.81`
Screenshot: <img width="1914" height="836" alt="image" src="https://github.com/user-attachments/assets/e3845814-5751-4cdf-8b73-7ffde138e5ee" />

Reading through the ports we can see that a few were available:
- 1433 - SQL server - Database
- 5357 - Web Services on Devices API (WSDAPI) - Used to discover and access remote resources on a network - Network Discovery required
- 135 -
- 139
- 445
