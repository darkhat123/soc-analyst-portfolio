# Webstrike Writeup

## Synopsis
A suspicious file was identified on a company web server, raising alarms within the intranet. The Development team flagged the anomaly, suspecting potential malicious activity. To address the issue, the network team captured critical network traffic and prepared a PCAP file for review.
Your task is to analyze the provided PCAP file to uncover how the file appeared and determine the extent of any unauthorized activity.

## Identifying how the file was uploaded
As the synopsis states this is a file with unknown origins residing on a public facing web server, this could possibly have been uploaded by a malicoious attacker, it is important to also determine what the file is and remove it to prevent execution.

Using wireshark we can look for indicators of file uploads to the web server through common protocols such as SMB, FTP and HTTP POST

**HTTP Queries**
http.request.method == POST
http contains "filename="
http contains "Content-Disposition"

From the first query we can see that there were three results, two inbound connections from an  ip address *117.11.88.124* sent a post request to *reviews/upload.php* with a file image.jpg.php to be uploaded to the web server and an outbound connection to the external ip

Upon examining the files contents we can see the creation of a reverse shell to an external ip on port 8080, likely a persistence mechanism created by an attacker to gain a foothold into the web server 

When checking the ip we can see that its origin is from *tianjin*, china 

https://whatismyipaddress.com/ip/117.11.88.124
![image](https://github.com/user-attachments/assets/7ee2891e-494b-4375-8685-fc2ebc4f3af2)

To find the user agent we can follow the tcp or http stream
The user Agent used is *Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0*
![image](https://github.com/user-attachments/assets/c4cc1c85-e37e-4b6b-8532-132c7feeb06b)

The filename *image.jpg.php* of the submitted file can be found following the http stream of the first result
![image](https://github.com/user-attachments/assets/48c2432a-5f42-4078-8c8e-7951c2547bc6)


To find where the files are uploaded we can follow the tcp or http stream and see that the directory is /reviews/uploads
![image](https://github.com/user-attachments/assets/20564e1b-b88c-4a78-933d-7d164ae9d493)

The port is detailed in the reverse shell shown earlier

The File the attacker was trying to obtain was the passwd file which contains usernames that they can use for futher investigation into the system
![image](https://github.com/user-attachments/assets/4c53b00d-66a8-42a4-b18b-119c502c5d09)

# Conclusion
This room was a solid introduction into the investigation of file uploads via HTTP to public facing web servers and demonstrated a common tactic of abusing file extension validation to upload  php webshell which was then used to connect
back to the attackers ip where the usernames of the system were extracted and further tactics could be performed 

# Mitigations
From reading the owasp File Upload Cheat Sheet and reviewing the bypass techniques used by the attacker it is clear that the current file upload page is vulnerable to extension validation bypasses through the use of double extensions, it is reccomended to update the code and use input validation alongside a whitelist of acceptable extensions. It is also recommended to validate the type of file by its MIME Type rather than the Content-Type which can be easily spoofed by the user

