# Scenario 
A cyber threat group was identified for initiating widespread phishing campaigns to distribute further malicious payloads. The most frequently encountered payloads were IcedID. You have been given a hash of an IcedID sample to analyze and monitor the activities of this advanced persistent threat (APT) group.

## Question 1 What is the name of the file associated with the given hash?
With the hash available to us we can begin gathering IOC's associated with the malware, knowing what to call the malware can be really helpful in identifying its purpose
and what makes it unique. Looking at the **Details** tab we can see in the **Names** section the human-friendly document name.
![image](https://github.com/user-attachments/assets/468c7b95-6b2d-42d5-9ea4-1f4c8eb32a2e)

Answer: document-1982481273.xlsm


## Question 2 Can you identify the filename of the GIF file that was deployed?
When looking for how the GIF file was deployed we can look at how such a file could become available on the machine, it can be assumed that the malware requested a gif from
an attacker controlled domain and downloaded it from there. If we go to the **Relations** tabs and check the **Contacted URL's** we can see that several requests were
made to different domains all requesting the same GIF file.
![image](https://github.com/user-attachments/assets/c07d4f24-336f-4159-9a6c-f47ebf2d5548)

We can also check the **Dropped Files** section which details any files created or placed on a system by the malware
![image](https://github.com/user-attachments/assets/6b0d9939-1352-4bc9-9f4e-27634bfde343)

This confirms the file was successfully downloaded

Answer: 3003.gif

## Question 3 How many domains does the malware look to download the additional payload file in Q2?
From the previous screenshot we can see that five domains were contacted requesting the file. These should all be blocked and considered malicious.
Answer: 5
## Question 4 From the domains mentioned in Q3, a DNS registrar was predominantly used by the threat actor to host their harmful content, enabling the malware's functionality. Can you specify the Registrar INC?
This involves Analysing the Domain registras associated with each domain, these details may sometime be incomplete and require further inspection. We can see one of the malicous domains
has the namecheap registrar which infamously provides anonymity and rapid deployment.
![image](https://github.com/user-attachments/assets/a9ce3e1e-e530-4ef1-9cdd-85e3c67e0f95)

Answer: Namecheap

## Question 5 Could you specify the threat actor linked to the sample provided?
Knowing that the malware sample IcedID is a known malware sample we can perform a google search on the malware to determine its purpose, target and objectives.
It is helpful to know who is likely utilising the malware in their campaigns as this can give us an insight into the TTP's they are likely to use given prvious
compromises. We can see that the IcedID is associated with a few Groups which when we click on the first group we see the associated groups include Gold Cabin and Shathak
![image](https://github.com/user-attachments/assets/1424e481-4904-49a5-b339-9d00c4f31a43)

Answer: Gold Cabin

## Question 6 In the Execution phase, what function does the malware employ to fetch extra payloads onto the system?
When looking to see how extra payloads are obtained on the system we can use the mitre att&ck matrix which is avilable on many threat intellgience reports and is used to
map techniques used by the attacker into an attack chain which can be easily visualised at each stage of the attack. We can go to the Execution phase in virustotal 
where we can see that there is many sections detailing the use of the urlmon.dll, infamoulsy used by attackers to download payloads. We can see they all utilise the same function
to make their requests

![image](https://github.com/user-attachments/assets/5c9d1e72-74ae-4bce-8b08-b27dc4af85f4)

Answer:URLDownloadToFileA

# Conclusion
We analysed a malware sample known to be used as a trojan in banking systems with the sole purpose of harvseting banking credentials. This malware is also modular and is capable of
dropping futher malware payloads to extend its capabilities. The malware once installed via phishing and ran will begin by making requests for a particular gif file
which is used as a second stage payload to continue its malicious behaviour. It does this using urlmon.dll to request the resources using the URLDownloadToFileA function which is commonly abused by attackers due to being trusted
by windows and being signed. These will then be executed by the attacker to perform futher malicious actions.

Monitoring the use of URLDownloadToFileA for suspicous requests is advised as is Logging DLL usage through sysmon

