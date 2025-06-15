# Scenario 
During a recent security incident, an attacker successfully exploited a vulnerability in our web server, allowing them to upload webshells and gain full control over the system. The attacker utilized the compromised web server as a launch point for further malicious activities, including data manipulation. 

As part of the investigation, You are provided with a packet capture (PCAP) of the network traffic during the attack to piece together the attack timeline and identify the methods used by the attacker. The goal is to determine the initial entry point, the attacker's tools and techniques, and the compromise's extent.

# Introduction
This lab challenges us to peice together the steps taken by an attacker to upload a webshell to a vulnerable server and then execute it to gain a foothold into the web server where futher pivoting took place.
When looking for evidence of webshells we will largely be focusing on the HTTP/HTTPS traffic coming into the server however there may be other protocols utilised which we will then need to analyse further.

## Question 1 Identifying the attacker's IP address helps trace the source and stop further attacks. What is the attacker's IP address?
Identifying the attackers ip can help us narrow down the traffic related solely to that ip, when determining the attackers IP we can filter for common request methods used to upload a file, a critical step in acheiving a webshell.
The most common method for uploading files to a web server is through submitting the file by inputting the details and file in form data which is then sent in a POST request to the web server, which will perform any checks on
the file and then upload it to the specified directory. 

When looking for HTTP POST Requests in Wireshark we can use the `http.request.method == "POST"` to view all post requests sent to the server.
This produces a large amount of results all of which come from the same IP, likely the attacker traversing the website to identify weak points, this is enough to satsify the question but not all of these requests are used to upload files to a web server.

![image](https://github.com/user-attachments/assets/4d754cf3-db25-41f9-9581-8f109ea0bfaf)


To properly filter for only File Uploads we can use a standard entry used for the Content-Type which is specified when a file is being entered into form data, when the `<input type="file">` is used in a web form
the web browser submits the form with the Content-Type **multipart/form-data** this allows the transfer of binary data over to the server as other Content-Types only support key:value pairs used to submit arbitrary
information

We pass the wireshark filter `http.request.method == "POST" and http.content_type contains "multipart/form-data"
![image](https://github.com/user-attachments/assets/517b8870-38c2-4ddf-8f89-063da1c3dcde)

Now we can see that there was a post request made to the /admin/pluginUpload.html uploading a zip folder with the filename NSt8bHTg.zip. This is likely a functionality used to extend the sites functionality through installation
of third party plugins. 

Answer: 23.158.56.196

## Question 2 To identify potential vulnerability exploitation, what version of our web server service is running?
With the packet responsible for uploading the file to the server identified it is now time to determine how the attacker was able to identify a vulnerability in the websites functionality, as the question suggests the attacker
would be looking to detemrine the version of the web server before uploading the malicious file, we can use the packet used to upload the file and **Follow HTTP stream** where we see all the previous and following requests for a
particular connection to the server. This can typically show the actions taken before a file upload such as probing for vulnerabilities

We can see that the first entry in the HTTP stream was a request made to the server which received a response containing server information including the server version. This could be found easier by using the find utility and searching
for occurences of version and understanding the occurences context. 

![image](https://github.com/user-attachments/assets/363c121e-59ff-4466-ab99-5bab4f14f621)
Answer: 2023.11.3
## Question 3 After identifying the version of our web server service, what CVE number corresponds to the vulnerability the attacker exploited?
With information such as the endpoint used to obtain the version we can begin to try and identify what web server is running and what version, from

