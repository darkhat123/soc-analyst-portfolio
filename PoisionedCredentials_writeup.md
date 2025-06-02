# Synopsis 
Your organization's security team has detected a surge in suspicious network activity. There are concerns that LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) poisoning attacks may be occurring within your network. These attacks are known for exploiting these protocols to intercept network traffic and potentially compromise user credentials. Your task is to investigate the network logs and examine captured network traffic.


We are provided a pcap which when oipened with wireshark can be filtered to begin our investigation 

## Question 1 In the context of the incident described in the scenario, the attacker initiated their actions by taking advantage of benign network traffic from legitimate machines. Can you identify the specific mistyped query made by the machine with the IP address 192.168.232.162?

LLMNR and NBT-NS poisioning attacks rely on legacy resolution protocols which can be used for local name resolution, in a scenario where an attacker has access to the local network he can intercept the traffic
on the local network and wait for a situation where a user mistypes a query to a fileshare server, resulting in the query attempting to be resolved by LLMNR or NBT-NS, the attacker can then provide his ip and all subsequent requests will be 
sent to the attacker ip

![image](https://github.com/user-attachments/assets/f445cf3a-59ca-4dd1-b533-76dfb545e1cf)

From the image above we can see that the victim attempted to connect to fileshaare which resulted in the query being sent to LLMNR and NBT-NS which were both intercepted by the attacker and the ip address was updated to that of their machine

## Question 2 We are investigating a network security incident. To conduct a thorough investigation, We need to determine the IP address of the rogue machine. What is the IP address of the machine acting as the rogue entity?
From the response to both the queries in the above image we can see that the attacker ip is 192.168.232.215 

## Question 3

Using the attackers ip to narrow down all communciations between the attacker and victim machines we can see that the second machine to be affected is
192.168.232.176

Answer: 192.168.232.176
![image](https://github.com/user-attachments/assets/c9af76bb-36df-4dae-b990-db1a30ae67e3)

## Question 4 We suspect that user accounts may have been compromised. To assess this, we must determine the username associated with the compromised account. What is the username of the account that the attacker compromised?

After a LLMNR or NBT-NS poisonign attack an attacker will likely wait until a user attempts to authenticate to them and once the user authenticates they have access to their NTLM hash which can be used in pass the hash attacks or cracked offline

![image](https://github.com/user-attachments/assets/ff47f835-15a1-4f9e-8917-90fb136be302)

From the above image it can be seen that the victim janesmith attempted to authenticate to the attacker ip 

## Question 5 
We can find details on the hostname within the smb session setup packets which contained the hostname 



