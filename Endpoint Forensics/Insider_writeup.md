# Synopsis
After Karen started working for 'TAAUSAI,' she began doing illegal activities inside the company. 'TAAUSAI' hired you as a soc analyst to kick off an investigation on this case.

You acquired a disk image and found that Karen uses Linux OS on her machine. Analyze the disk image of Karen's computer and answer the provided questions.

# Introduction
In this lab were goin4g to be using ftk imager to navigate the file system of the suspected attackers pc to determine what they were doing on the computer and collect artefacts to prove their actions. Usually when analysing a disk image we have to work to a certain deadline
, like in this example we need to quickly know what the attacker was doing. FTK imager is perfect for quickly viewing a logical disk in a hiearachichal file system format meaning we can search common areas of interest to guide us when we complete a deep forensic
investigation using Autopsy. FTK imager does not contain modules capable of finding artefacts so knowledge of the disk image filesystem is crucial.

## Question 1 Which Linux distribution is being used on this machine?
Typically when trying to determine the version of the linux distribution the best places to look if they are available:
/etc/issue
/etc/os-release

For whatever reason, the etc directory is not available for this disk image so we must look for other methods to confirm the version, from googling it is also possible to check the boot directory where kernel filenames may disclose the version or the grub configuration
file may list it.

In our case if we go to the grub.cfg file and look for menuentry's we can see that one contains the distribution
We foudnd this by using the Find tool and entering menunetry, after a few non-relevant results we are successful
![image](https://github.com/user-attachments/assets/4be80688-9970-40ce-b89f-63ab5a4a04af)

We could also have found this through the /var/log/syslog directory which is responsible for storing:

| Type of Event          | Example Entry                                        |
| ---------------------- | ---------------------------------------------------- |
| System boot            | `systemd[1]: Started Network Service.`               |
| Networking             | `NetworkManager[763]: <info>  device state changed`  |
| Cron jobs              | `CRON[1029]: (root) CMD (backup.sh)`                 |
| Kernel messages (some) | `kernel: [ 0.000000] Initializing cgroup subsys cpu` |
| Hardware info          | USB connections, device detection                    |
| Errors & warnings      | From services and applications                       |
| Daemon messages        | Like `cupsd`, `sshd`, etc.                           |

The system boot information typically contains information about the underlying distribution that is being loaded.
![image](https://github.com/user-attachments/assets/e68d5906-8d24-42ce-92f4-83f5e8b2fe23)

Answer: Kali

## Question 2 What is the MD5 hash of the Apache access.log file?
FTK imager can compute the MD5 and sha256 hash of any file present in the filesystem, in order to obtain the MD5 hash of the apache access log we will go to the /apache2/access.log file and right click and select Export File Hash List, this will create a CSV file
which can be read with any text editor, extract the md5 hash value.
![image](https://github.com/user-attachments/assets/0854516a-0f8f-4104-aef9-c7044784361e)
Answer: d41d8cd98f00b204e9800998ecf8427e

## Question 3 It is suspected that a credential dumping tool was downloaded. What is the name of the downloaded file?
Downloads typically reside in the users download folder which is located at /home/user/Downloads on Linux, from the filesystem present we can see the Downloads folder, when we click in we can see a zip file concerning mimikatz, a credential dumping tool used
by adversaries to gain a foothold into a system. 

Answer: mimikatz_trunk.zip

## Question 4 A super-secret file was created. What is the absolute path to this file?
Without any knowledge of the name of the file the best way to find out where it is stored is to look for files containing the history of commands executed on the computer by the user, the .bash_history file logs all commands entered by the user from the running instance
this is a key place to find adversary actions such as file creation

Since bash_history is hidden by default we must select the root directory and trawl the file list till we reach the hidden files, these will not be accessible in the tree view
We can see straight away that the file was created using touch and was saved in the desktop directory
![image](https://github.com/user-attachments/assets/6e85b2b5-e017-4ec7-9aaf-5a3d278bb1f1)

Answer: /root/Desktop/SuperSecretFile.txt

## Question 5 What program used the file didyouthinkwedmakeiteasy.jpg during its execution?
Reading through the list of commands in the bash_history file, right at the bottom we can see that the file was used in the execution of binwalk 
![image](https://github.com/user-attachments/assets/28f15739-2d51-4543-a95b-8342e12f85ea)

Answer: binwalk

## Question 6 What is the third goal from the checklist Karen created?
Given that karen seems to be relatively new to hacking we can assume shes unaware of evading detection and storing her files in the regular places users store their information and documents, this will likely be the desktop folder, when we click on it
we see a file named checklist.txt, upon inspection we see karens evil plan.

![image](https://github.com/user-attachments/assets/d8f9bb4c-8570-47da-a933-d67e62f5cf60)

Answer: Profit

## Question 7 How many times was Apache run?
When apache is run it is logged in the /var/apache2 logs, if these files dont contain any entries then it is likely apache did not run at all
![image](https://github.com/user-attachments/assets/e8300e02-2d9b-4be5-843a-a26472137ca0)

Answer: 0

## Question 8 This machine was used to launch an attack on another. Which file contains the evidence for this?
Initially i thought this would have something to do with the MSF4 folder present in the root directory which when inspected has a history file with proof of attempted attacks using the EternalBlue Exploit, however it was incorrect so i began looking through the directory for suspicious files
i stumbled uypon an imagein the root diretory and when exported and opened i can see an attacker using a command prompt to run executables.

Answer: irZLAohL.jpeg

## Question 9 It is believed that Karen was taunting a fellow computer expert through a bash script within the Documents directory. Who was the expert that Karen was taunting? 
We can see a few bash scripts in the documents directory, reading through each we can see that the attacker used the firstscript_fixed.sh file to taunt the computer expert
![image](https://github.com/user-attachments/assets/9d4f9315-540c-4336-a34a-8fc96b42e0fd)

Answer: Young

## Question 10 A user executed the su command to gain root access multiple times at 11:26. Who was the user?
Since the user has to authenticate to access root privileges we can assume that the su command will be logged in the /var/log/auth.log where all authentication logs are stored, scrolling to the specified time we can see that su was attempted multiple times
by the one user
![image](https://github.com/user-attachments/assets/ffd68387-66a3-4edb-b0fe-3275c625af4a)

Answer:postgres

## Question 11 Based on the bash history, what is the current working directory?
This involves walking through the cd commands and finding which path was changed into last

![image](https://github.com/user-attachments/assets/9269b90c-3367-480d-9cd3-a3bba4382708)

Answer: /root/documents/myfirsthack/

# Conclusion
This lab demonstrates FTK's capabilities allowing us to create initial findings on the steps taken by the attacker without performing a deep forensic analysis using Autopsy and its built in modules, using a partial file system we were able to identify the affected pc,
the techniques used and the attackers goals. All without enetering a single command.





