# Scenario
You are a Threat Hunter working for a cybersecurity consulting firm. One of your clients has been recently affected by a ransomware attack that caused the encryption of multiple of their employees' machines. The affected users have reported encountering a ransom note on their desktop and a changed desktop background. You are tasked with using Splunk SIEM containing Sysmon event logs of one of the encrypted machines to extract as much information as possible.

Introduction
We are tasked with analysing a ransomware attack that affected several computers within an enterprise network. We have access to the sysmon logs of the machines affected, it is our task to analyse these log files and 
determine the scope of the attack and the steps needed to prevent this occuring again.

## Question 1 To begin your investigation, can you identify the filename of the note that the ransomware left behind?
When looking for events within sysmon it is crucial to identify what event code we are looking for, in terms of File Creation/Overwriting we will be looking for Event code 11.

Now we have all File creation Events on the system, we can then view the fiels associated with these events, We can look through the fiels and look for anything pertaining to the filename of the files being
accessed. We can see that the event log stores a parameter `winlog.event_data.TargetFilename`. Using this we can search for occurences of the phrase Desktop within the paths of the filenames. 

The final filter is `index=revil "event.code"=11 winlog.event_data.TargetFilename = "*Desktop*"`
![image](https://github.com/user-attachments/assets/3c08a840-e142-4cf3-b344-f7ed629eb621)

Looking through these results we can see that there are 3 occurences of a file being saved to different users Desktops
![image](https://github.com/user-attachments/assets/f11f0747-cd38-47d1-b037-bc6ce2a79955)

Answer:5uizv5660t-readme.txt 

