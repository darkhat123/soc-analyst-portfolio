# Synopsis
A decentralized finance (DeFi) platform recently reported multiple user complaints about unauthorized fund withdrawals. A forensic review uncovered a phishing site impersonating the legitimate PancakeSwap exchange, luring victims into entering their wallet seed phrases. The phishing kit was hosted on a compromised server and exfiltrated credentials via a Telegram bot.

Your task is to conduct threat intelligence analysis on the phishing infrastructure, identify indicators of compromise (IoCs), and track the attacker’s online presence, including aliases and Telegram identifiers, to understand their tactics, techniques, and procedures (TTPs).

# Introduction
This lab challenges us to analyse the directories of a cloned website to determine what the attacker was trying to emulate, what they were trying to obtain and what they planned to do if the attack was successful, creating sites that are identical to other sites is trivial with the tools available to attackers today and is likely to succeed when used upon an everyday pc user unaware of the dangers of cloned sites.

## Question 1 Which wallet is used for asking the seed phrase?
To determine what wallet is being used we must first navigate the files and directories available to us looking for a reference to any wallets dispalyed to the user, opening the index.html available in the top directory we can see that three common bitcoin wallets are displayed. To narrow down exactly what wallet is used to obtain the users details we must investigate further into the directories and files associated with the phishing attempt, we can see here that there is a directory named after one of the wallets mentioned in the
main page of the phishihng site, the metamask directory also holds another index page which is dedicated purely to entering the seed phrase for the intended users wallet.
![image](https://github.com/user-attachments/assets/67d45457-5710-469c-b121-b0835bc8c914)
![image](https://github.com/user-attachments/assets/06263e1e-3c0a-45eb-ad8e-ca253f5e73bc)

Answer: metamask

## Question 2 What is the file name that has the code for the phishing kit?
The question here is referring to the code responsible for extracting the users seed phrase which can then be used to authenticate their accounts and in turn make transfers and give them control over the users bitcoin wallet, we can see that within the metamask directory
there is an index.html page used to prompt the user to enter their seed phrase, which they believe will be processed by the legitimate website, when in reality we can see that the form is submitted to the **metamask.php** file which will house code responsible for
extracting the submitted seed phrases. 
![image](https://github.com/user-attachments/assets/2ba552e9-b930-4198-9f1b-1d28d77f2d99)

Answer: metamask.php

## Question 3 In which language was the kit written?
The previous file give a major clue to the language used to create the phishing kit

Answer: php

## Question 4 What service does the kit use to retrieve the victim's machine information?
To determine how the kit retrieves the users machine information we must look into the php file used to extract the input entered by the user, we can see that within the **metamask.php** file gathers the victims machine information at the beginning of the cript, the users ip address is passed to sypex geo where the details of the ip are returned in json format

![image](https://github.com/user-attachments/assets/56252ba0-ab31-4b7d-a238-ebb8899963f8)

Answer: sypex geo
 
## Question 5 How many seed phrases were already collected?
Finding where the seed phrases are stored is crucial in determining how many accounts may have been compromised during the attack, we can again check the previous file for where it may be storing the seed phrases, we can see that the code attempts to store data into a log.txt file, upon investigation of the logs directory we see the file available, when we open it we can see three lines of seed phrases
![image](https://github.com/user-attachments/assets/6da11a6e-baec-468b-a8ec-b4c7619e9c7c)
![image](https://github.com/user-attachments/assets/b880d1a0-059f-44b5-a1f7-1842695ff6d7)

Answer: 3

## Question 6 Could you please provide the seed phrase associated with the most recent phishing incident?
Due to the code choosing to append a new line for each seed phrase we can assume that the last line in the text file is the most recent seed phrase.

Answer: father also recycle embody balance concert mechanic believe owner pair muffin hockey


## Question 7 Which medium was used for credential dumping?
Determining what tool was used for credential dumping again involves reading through the code and looking for ways the attacker could have exfiltrated the data, we can see that when the **metamask.php** file runs it will take the post data submitted by the user
and send this to a telegram bot, we can also see that the seed phrases are additionally logged locally as discovered in the previous question
![image](https://github.com/user-attachments/assets/e5c66421-0f39-4f7d-8bcd-8409a3f594e5)

Answer: telegram
## Question 8 What is the token for accessing the channel?
The token is appeneded to the request to the telegram bot and is used to authenticate to the telegram bot, with access to this we can query the telegram bot  for any user input submitted to it 
Answer: 5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10

## Question 9 What is the Chat ID for the phisher's channel?
Again the id is appended to the request to the telegram bot and is used to identify the specific channel the attacker wants to communicate with

Answer: 5442785564

## Question 10 What are the allies of the phish kit developer?
This can be found in the comments of the malicious file, we can possibly use this to find accounts associated with the threat actor 

Answer: j1j1b1s@m3r0

## Question 11 What is the full name of the Phish Actor?
Now that we have the details of the telegram bot including the channel id and the api token used by the attacker we can begin to query the bots methods for details on the attacker, certain methods such as getChat will return among many things the first and second name
submitted by the user upon creation.
![image](https://github.com/user-attachments/assets/622978d4-ece6-42aa-b439-9a9f3f152ae1)

Answer: Marcus Aurelius

## Question 12 What is the username of the Phish Actor?
Again this is disclosed when querying the previous method of the telegram api

Answer: pumpkinboii

# Conclusion
This was a unique lab with an attack vector still in use today, the bitcoin wallet relies on a seeded phrase to access the wallet, which is passed in plaintext over the internet, with the phishihng site in place and useres being redirected to it it was possible to eavesdrop for the phrase being submitted to the attacker controlled site, where they exflitrated the data to a telegram bot managed by the attacker, luckily using hardcoded values in the code left the attacker vulnerable to investigation.

