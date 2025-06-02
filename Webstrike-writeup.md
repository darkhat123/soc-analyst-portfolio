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

From the first query we can see that the ip address *117.11.88.124* sent a post request to *reviews/upload.php* with a file image.jpg.php to be uploaded to the web server 

Upon examining the files contents we can see the creation of a reverse shell to an external ip on port 8080, likely a persistence mechanism created by an attacker to gain a foothold into the web server 

When checking the ip we can see that its origin is from tianjin, china 

https://whatismyipaddress.com/ip/117.11.88.124
![image](https://github.com/user-attachments/assets/7ee2891e-494b-4375-8685-fc2ebc4f3af2)


The user Agent used is 

The directory is /reviews/uploads

The File the attacker was trying to obtain was the passwd file which contains usernames that they can use for futher investigation into the system 

