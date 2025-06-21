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
Now we know the attacker has access to database credentials we must begin looking for evidence of the attacker connecting to the database. From the config files contents we can see the attacker will be using mysql to connect to the database, we can filter for packets specific to mysql. Finally we know that when a user attempts to login to a mysql database it sends a Login Request Packet with the username and password and awaits a reply saying their authentication was successful.

We know that the attacker retrieved the credentials in packet 88338 so we can assume that the packetsa following this will be the ones who utilise the stolen credentials.

We can see that the initial attempt in packet 88348 was made.
![image](https://github.com/user-attachments/assets/8dce0663-74dc-4553-9ad1-bc9cae914e2e)

Answer: 2024-05-31 12:08

## Question 7 To eliminate the threat and prevent further unauthorized access, can you identify the name of the web shell that the attacker uploaded for remote code execution and persistence?

Typically when an application is written in php it is likely that the reverse shell will involve using a php file to connect to the reverse shell and to execute commands remotely. We can see from the PrideandPrejudice.xml upload that the attacker has created two external entities, one used as a variable to assign the URL that will be requested and another to define the function that will be used to make the request. Within the booking.php file being requested will be code to eastablish the reverse shell, maintain persistence and perform remote code execution on the vulnerable system. This will likely bypass firealls since the request is made from an internal server over HTTP/HTTP's which is likely permitted in an enterprise environment. The function used to request the URL is the `php://filter`
wrapper which is an Input/Output stream manipulation wrapper. This allows us to perform operations such as Base64 Encoding/Decoding or encryption to bypass. This is done with `/read=convert.base64-encode`. Finally we specify the resource that we would like to perform I/O manipulation using `/resource=%payload` which in our case will request the remote file containing the web shell for maintaining persitence and executing commands.

![image](https://github.com/user-attachments/assets/ff7d1816-d553-4d16-b68c-c0cf8fb38a31)

Answer: booking.php

# Conclusion
This lab demostrates the need for Web application security measures both in the development of web applications and in the maintenance thereafter. From a simple port scan on a public facing web site an attacker was able to identify vulnerable functionality within the applications file upload process which allowed submission
of files without validation of the files contents. This resulted in the attacker being able to submit arbitrary requests to sensitive files on the webservers filesystem which lead to the disclosure of user credentials to application critical databases where further enumeration could take place. Finally the attacker was able to abuse the file upload to create an XXE Injection which utlised external entities to craft a payload capable of calling home to the attackers malicious php file where a webshell and remote execution code resides. Resulting in persitence for the attacker and likely helped their laterla movement. 

This highlights the need to:

1. Whitelist file types: Only allow specific, known-safe MIME types and file extensions (e.g., .jpg, .png).
2. Content inspection: Validate the actual content (magic bytes) of uploaded files—not just extensions.
3. Sanitize file names: Strip or randomize filenames to prevent path traversal or overwrites.
4. Store uploads outside web root: Avoid direct web access to uploaded files.
5. Use a secure intermediary: Store files in blob storage (e.g., S3) with proper access policies.
6. Scan files: Use antivirus/malware scanners on uploaded content.
7. Disable DTDs and external entities in XML parsers: `parser = defusedxml.ElementTree.parse()  # Python example using a safe library`
8. Use safe libraries (e.g., defusedxml, or equivalent in other languages).
9. Validate input: Sanitize and validate all user-supplied XML data.
10. Use JSON instead of XML where possible.
