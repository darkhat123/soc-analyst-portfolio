# Scenario 
Unusual network activity has been detected within a university environment, indicating potential malicious intent. These anomalies, observed six hours ago, suggest the presence of command and control (C2) communications and other harmful behaviors within the network.

Your team has been tasked with analyzing recent network traffic logs to investigate the scope and impact of these activities. The investigation aims to identify command and control servers and uncover malicious interactions.


## Question 1 During the investigation of network traffic, unusual patterns of activity were observed in Suricata logs, suggesting potential unauthorized access. One external IP address initiated access attempts and was later seen downloading a suspicious executable file. This activity strongly indicates the origin of the attack.
What is the IP address from which the initial unauthorized access originated?

We know that the attacker has been making requests for downloads to an external ip address, therefore they will be generating HTTP logs made between server and clients. The suricata logs have picked up this traffic and contains the ifnormation were loooking for. Finally we know that the ip address was downloading executable files however we are not aware
of the extension of the executable, the safest query to identify the records is `sourcetype=suricata event_type="http"
| stats values(http.http_user_agent) as user_agent, values(http.url) as url, values(src_ip) as server by dest_ip`. This will produce all http requests logged by suricata. If we scroll through we can see multiple exe files being downloaded from a single sever.

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/02bf64f1-3ce8-4bc4-8ded-473f946cc513" />
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/69dea814-5916-4b57-8a11-5f558e7fb841" />
Answer: 195.88.191.59
