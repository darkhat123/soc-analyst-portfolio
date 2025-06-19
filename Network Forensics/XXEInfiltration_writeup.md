# Scenario
An automated alert has detected unusual XML data being processed by the server, which suggests a potential XXE (XML External Entity) Injection attack. This raises concerns about the integrity of the company's customer data and internal systems, prompting an immediate investigation.

Analyze the provided PCAP file using the network analysis tools available to you. Your goal is to identify how the attacker gained access and what actions they took.

## Question 1 Identifying the open ports discovered by an attacker helps us understand which services are exposed and potentially vulnerable. Can you identify the highest-numbered port that is open on the victim's web server?
When an attacker is looking to determine the open ports on a computer he will likely attempt to connect to as many as possible using port scanning tools such as Nmap.
Nmap has multiple ways to scan a host to determine if it is live, the default is to create a TCP handshake with the IP:PORT of the connecting machine.
Syn scanning is known as half open scanning, where the attacker will send a syn flag, initating the connection with each port on the machine, the machine then responds
with a SYN-ACK reply notifying that the port is available for communication. At this point to complete the handshake the client would send an ACK reply letting the
server know it is willing to initate a connection, completing the three way handshake. What is different with SYN scanning is that the attacker sends a RST flag to reset
the connection, or doesnt reply at all, essentially masking the attackers IP. 

We can filter for SYN-ACK replies to determine what ports on the machine were open.

![image](https://github.com/user-attachments/assets/ab5b722f-c981-45f3-ba43-0841898d4f32)
Now we just need to look through the results and determine the highest port
Answer:3306

## Question 2 By identifying the vulnerable PHP script, security teams can directly address and mitigate the vulnerability. What's the complete URI of the PHP script vulnerable to XXE Injection?
Knowing that the attacker abused a vulnerable PHP script we can filter any requests made to a URL containing the .php extension. This will return all requests made to php
pages by the attacker. To narrow it down to the PHP script thats being abused we can assume the attacker likely submitted malicious input into a form to send to the server
for processing. This requires the POST request to be used to submit the data. 

![image](https://github.com/user-attachments/assets/47682199-9ffa-410d-96bc-392a2f4582dc)

Answer: /review/upload.php

## Question 3 To construct the attack timeline and determine the initial point of compromise. What's the name of the first malicious XML file uploaded by the attacker?
When trying to determine what files were sent to the vulnerable php page we are looking for any POST requests containing the .xml extension in their Content-Disposition section. This contains a field known as filename which is used to specify the name of file being submitted. 

![image](https://github.com/user-attachments/assets/181850d5-155d-43b3-98a9-9d420bf00b14)

We can see that multiple XML files have been submitted to the server , the first timestamp shows us what file the attacker submitted.

Answer: TheGreatGatsby.xml

## Question 4 Understanding which sensitive files were accessed helps evaluate the breach's potential impact. What's the name of the web app configuration file the attacker read?

With knowledge of the requests sent by the attacker this is as simple as navigating through each request and determining what files were accessed by the attacker
THe files requested were either index pages, the passwd file on the system or what appears to be a booking page. The only one related to configuration seems to be config.php
![image](https://github.com/user-attachments/assets/bf6ca45a-2349-4451-8dbb-c79770ca9d28)

Answer:config.php

## Question 5 To assess the scope of the breach, what is the password for the compromised database user?
Following the http stream of the request for the configuration file request we can see that the reply contains the configuration files contents which seems to be connecting to an sql database. The hardcoded credentials in the file are a mistake made by the creators and should not be stored in plaintext within the file.

![image](https://github.com/user-attachments/assets/5c9a5be0-496b-4b43-bed9-c02f5f2c67cb)

Answer: Winter2024

## Question 6 Following the database user compromise. What is the timestamp of the attacker's initial connection to the MySQL server using the compromised credentials after the exposure?


