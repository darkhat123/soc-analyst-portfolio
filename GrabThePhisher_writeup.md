# Synopsis
A decentralized finance (DeFi) platform recently reported multiple user complaints about unauthorized fund withdrawals. A forensic review uncovered a phishing site impersonating the legitimate PancakeSwap exchange, luring victims into entering their wallet seed phrases. The phishing kit was hosted on a compromised server and exfiltrated credentials via a Telegram bot.

Your task is to conduct threat intelligence analysis on the phishing infrastructure, identify indicators of compromise (IoCs), and track the attacker’s online presence, including aliases and Telegram identifiers, to understand their tactics, techniques, and procedures (TTPs).

# Introduction
This lab challenges us to analyse the directories of a cloned website to determine what the attacker was trying to emulate, what they were trying to obtain and what they planned to do if the attack was successful, creating sites that are identical to other sites is trivial
with the tools available to attackers today and is likely to succeed when used upon an everyday pc user unaware of the dangers of cloned sites.

## Question 1 Which wallet is used for asking the seed phrase?
In order to determine what wallet is being used we must first navigate the files and directories available to us looking for a reference to any wallets dispalyed to the user, opening the index.html available in the top directory we can see that three common bitcoin wallets
are displayed. To narrow down exactly what wallet is used to obtain the users details we must investigate further 
