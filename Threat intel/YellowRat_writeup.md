# Synopsis
During a regular IT security check at GlobalTech Industries, abnormal network traffic was detected from multiple workstations. Upon initial investigation, it was discovered that certain employees' search queries were being redirected to unfamiliar websites. This discovery raised concerns and prompted a more thorough investigation. Your task is to investigate this incident and gather as much information as possible.

Upon downloading and extracting the contents of the zip folder we have a text file containing a hash to a particular malware, using online threat inteligence platforms and malware sandboxes we can determine the purpose of the file
and the objectives it was trying to acheive, with this we can understand where to look for further malicious traffic

## Question 1 Understanding the adversary helps defend against attacks. What is the name of the malware family that causes abnormal network traffic?
To begin analysing the malware we can enter its hash into sites such as VirusTotal, Hybrid Analysis or Cisco Talos to discover the malware family that the file belongs to, this can give insight into both the operation of the malware
and the TTP's associated with the threat actors known to be utilising the malware in the wild. Finding the malware family took longer than expected however i finally found the malware family from the detection rule in cisco talos

![image](https://github.com/user-attachments/assets/ffaab564-88a3-4a2d-8786-6523922f63e0)

Answer: Yellow Cockatoo RAT

## Question 2 As part of our incident response, knowing common filenames the malware uses can help scan other workstations for potential infection. What is the common filename associated with the malware discovered on our workstations?
Finding the common file name can be tricky sometimes, using virustotal we can go through the list of names and see what one is the common name, presuming the most common is at the top we can begin there. This is the name most commonly used

![image](https://github.com/user-attachments/assets/9981296f-2641-4171-a800-529e5f234c9b)


Answer: 111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll

## Question 3 Determining the compilation timestamp of malware can reveal insights into its development and deployment timeline. What is the compilation timestamp of the malware that infected our network?
Again virustotal can provide the creation time of the malware which can be useful in seeing how long it has been available and can indicate whether it is likely to be resolved easily.

It can be found both in the creation time field or the compilation timestamp in poratable executable info

![image](https://github.com/user-attachments/assets/364c4071-4463-44f2-8923-46c7179f005b)

Answer: 2020-09-24 18:26

## Question 4 Understanding when the broader cybersecurity community first identified the malware could help determine how long the malware might have been in the environment before detection. When was the malware first submitted to VirusTotal?

Again this can be found in the details tab alongside the creation time, this is helpful in understanding when it was first submitted ot virusotal whereas the creation time is the estimated time of creation of the malware

![image](https://github.com/user-attachments/assets/2157cfbc-5658-489d-acd0-63ed08088461)


Answer: 2020-10-15 02:47

# Question 5 To completely eradicate the threat from Industries' systems, we need to identify all components dropped by the malware. What is the name of the .dat file that the malware dropped in the AppData folder?

While it is possible to use HybridAnalysis or AnyRun to determine the behaviour of the malware we can also use reports created on google as a resource to determine the main components of the malware and the steps we need to take to completely
eradicate the threat and prevent further breaches, with a google search of "Yellow Cockatoo RAT" i was able to access a report by cybercanary where research into the interaction with the filesystem was able to produce the answer
![image](https://github.com/user-attachments/assets/a6ee0ad8-64eb-435a-bb4d-fabd1a190c9d)

Answer: solarmarker.dat

# Question 6 It is crucial to identify the C2 servers with which the malware communicates to block its communication and prevent further data exfiltration. What is the C2 server that the malware is communicating with?

When identifying C2 Servers it is useful to determine the ips, domains, urls that the malware is connecting to to determine what servers the attacker is responsible for and to identify traffic and data that may be routed to here

![image](https://github.com/user-attachments/assets/676742c9-3877-4a0c-8cc8-323cde2334cb)

Answer: https://gogohid.com

# Conclusion
This was an easy room where it was possibel to demonstrate our threat intelligence skills by determining key characteristics about a malware using a combination of static and dynamic analysi and internet research


# Mitigations
Whilst the challenge never specified how the malware became present on the system we can still provide recommendations such as enabling industry standard antivirus protection on the network on the hosts to help detect the presence of known malware.
We can also implementing stricter firewall rules and allow only necessary inbound and oubtound connections.
