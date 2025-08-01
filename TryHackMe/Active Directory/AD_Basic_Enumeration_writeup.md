# Learning Objectives

In this room, we’ll learn how to:

    Enumerate the target domain and network.
    Enumerate valid domain users and identify misconfigurations.
    Perform password spraying attacks to get your first pair of valid AD credentials.
    Discover sensitive credentials stored in configuration files.
# Mapping out the Network
When looking to breach into an active directory environment it is necessary to know key information such as the domain controller. We can utilise both passive and active scanning to determine a machines role in the network.

To begin we can perform a basic ping scan with fping which can output the alive hosts to a specified file which will be useful for port scanning using nmap
Command Used: `fping -agq 10.211.11.0/24 > hosts.txt`

<img width="344" height="133" alt="image" src="https://github.com/user-attachments/assets/5d7f50bb-c713-474f-8eaa-760e3de4edfd" />

We can exclude the .250 address from the list as this has been identified as the VPN server.

We can also utilise the ping scan found in nmap to probe the subnet

Command Used: `sudo namp -sn 10.211.11.0/24`

Now that we have confirmed all hosts available, we can begin our search for the Domain Controller.

Knowing what services come as standard on the domain controller can reduce the amount of ports we need to scan and identify the domain controller much faster.

Port 	Protocol 	What it Means
88 	Kerberos 	Potential for Kerberos-based enumeration
135 	MS-RPC 	Potential for RPC enumeration (null sessions)
139 	SMB/NetBIOS 	Legacy SMB access
389 	LDAP 	LDAP queries to AD
445 	SMB 	Modern SMB access, critical for enumeration
464 	Kerberos (kpasswd) 	Password-related Kerberos service

With this we can craft a scan specific to these ports that will try to determine the verson of the services running and run the scripts in NSE.

Command Used:`nmap -p 88,135,139,389,445 -sV -sC -iL hosts.txt`
<img width="937" height="839" alt="image" src="https://github.com/user-attachments/assets/5f04bb09-81fe-48d2-aed3-bbcb48801575" />

We can now perform an exhaustive portscan to fully enumerate the two hosts that have been identified.

Command Used: `nmap -sS -p- -T3 -iL hosts.txt -oN full_port_scan.txt`
<img width="1772" height="851" alt="image" src="https://github.com/user-attachments/assets/d48ea523-6ba6-4d3b-bfef-47e100939876" />

## Question 1 What is the domain name of our target?
Answer: tryhackme.loc

## Question 2 What version of Windows Server is running on the DC?
Answer: Windows Server 2019 Datacenter

# Network Enumeration with SMB
With knowledge that SMB is running on both the hosts it is wise to attempt to enumerate the SMB shares available on the devices which can give access to sensitive files possibly containing credentials.

Since we dont have any available credentials we can attempt to connect to the share anonymously to list the shares on an available server.

The linux tool smbclient can be used `smbclient -L //10.211.11.10 -N`

This will return a number of shares.
<img width="1045" height="278" alt="image" src="https://github.com/user-attachments/assets/c75f43d8-987b-44b2-b5cb-120a06c70fa0" />

This isnt really useful for showing the permissions we have for each share. A much more useful tool is smbmap which will determine what access we have to each share
Command Used:`smbmap -H 10.211.11.10`
<img width="757" height="446" alt="image" src="https://github.com/user-attachments/assets/29b7b2ab-23d5-4e0d-8a52-e502c8266dbb" />

Now we know the shares we can connect to each share with smbclient

Command Used: `smbclient  //10.211.11.10/UserBackups -N`
<img width="746" height="247" alt="image" src="https://github.com/user-attachments/assets/2be611f4-de46-4889-ba59-05b86b8f7501" />

## Question 1 What is the flag hidden in one of the shares?
Answer: THM{88_SMB_88}

# Domain Enumeration

Enumerating the demain for usernames and groups can be acheived in many ways 

1. Method 1: LDAP search
Lightweight Directory Access Protocol (LDAP) is a widely used protocol for accessing and managing directory services, such as Microsoft Active Directory. LDAP helps locate and organise resources within a network, including users, groups, devices, and organisational information, by providing a central directory that applications and users can query.
Some LDAP servers allow anonymous users to perform read-only queries. This can expose user accounts and other directory information.

We can try and enumerate users from the LDAP server by creating a tailored query

Command Used: ldapsearch -x -H ldap://10.211.11.10 -b "DC=tryhackme,DC=loc" "(objectClass=user)" sAMAccountName,memberof

This will find all users and provide their sAMAccountName and what groups they are members of, this can be used to gather a list of users, a list of possible groups/ous which can be examined to build a picture of the network including departments, admins, domain admins and much more
<img width="1369" height="821" alt="image" src="https://github.com/user-attachments/assets/4fd42643-d571-4efe-8f08-c5e9baeec9cb" />

2. Method 2: Enum4linux
Enum4linux is capable of full SMB enumeration and can find alot more than just the users and groups available on a network  it can also find shares, password policy, RID cycling, OS information and NetBIOS information

3. RPC Enumeration
RPC Enumeration (Null Sessions)

Microsoft Remote Procedure Call (MSRPC) is a protocol that enables a program running on one computer to request services from a program on another computer, without needing to understand the underlying details of the network. RPC services can be accessed over the SMB protocol. When SMB is configured to allow null sessions that do not require authentication, an unauthenticated user can connect to the IPC$ share and enumerate users, groups, shares, and other sensitive information from the system or domain.

We can run the following command to verify null session access with:

Command Used: `rpcclient -U "" 10.211.11.10 -N`

If connection is successful we use `enumdomusers` which will enumerate all domain users for a remote domain controller using SMB
<img width="834" height="557" alt="image" src="https://github.com/user-attachments/assets/02780cbe-eb36-4203-a32c-e3a7d0ae462d" />

4. Username Enumeration with kerbrute
Kerberos is the primary authentication protocol for Microsoft Windows domains. Unlike NTLM, which relies on a challenge-response mechanism, Kerberos uses a ticket-based system managed by a trusted third party, the Key Distribution Centre (KDC). This approach not only enables mutual authentication between client and server but also leverages stronger encryption methods, making it generally more resilient against attacks. Kerbrute is a popular enumeration tool used to brute-force and enumerate valid Active Directory users by abusing the Kerberos pre-authentication.

Tools like enum4linux-ng or rpcclient may return some usernames, but they could be:

    Disabled accounts
    Non-domain accounts
    Fake honeypot users
    Or even false positives

Running those through kerbrute lets us confirm which ones are real, active AD users, which allows us to target them more accurately with password sprays.

First we must create a list of usernames found from the following output

Then we must download kerbrute for Kali linux and make executable

Command Used: `./kerbrute userenum --dc 10.211.11.10 -d tryhackme.loc /home/kali/usernames.txt`

<img width="956" height="639" alt="image" src="https://github.com/user-attachments/assets/09f7f0c2-eb8c-43a5-88f7-087c47596d25" />

We want to see what group the user is a member of so we can filter for the occurence of rduke in our output and capture 25 lines of context before and after the occurence of our query, we will then query the ldap server for the domain we wnat to enumearate and target the Users
object which refers to real accounts.

Command Used: `ldapsearch -x -H ldap://10.211.11.10 -b "DC=tryhackme,DC=loc" "(objectClass=user)" | grep 'rduke' -C25`

We can see the GID assigned to the user is 513, which is a known group and is the Domain Users group
<img width="1071" height="827" alt="image" src="https://github.com/user-attachments/assets/8fefe789-d3e1-42c0-a2fc-d1ffb63498ca" />

## Question 1 What group is the user rduke part of?
Answer: Domain Users

## Question 2 What is this user's full name?
Answer: Raoul duke

## Question 3 Which username is associated with RID 1634?
We can find the RID associated with the usernames from the output found using rpcclient or from the Users section in enum4linux output, the RID is in hexadecimal format so we must conver this, we are looking for 662

<img width="854" height="855" alt="image" src="https://github.com/user-attachments/assets/550c8471-2bca-48fa-bca5-ad44cb671820" />

Answer: katie.thomas

# Password Spraying
Now that we have a list of likely usernames we can begin to attempt to compromise these accounts using a password spray attack, where a few common passwords are entered for each username in hopes of a weak password being configured on one of the many accounts.

First we must obtain the password criteria so we can focus our attacks on passwords that fit this criteria

We can again connect to the client using RPC and use the `getdompwinfo` command to determine password requirements

<img width="445" height="112" alt="image" src="https://github.com/user-attachments/assets/2e76c386-5639-44be-b950-b0286978e257" />

Now that we know the password has a minimum length of 7 characters we can user crackmapexec to perform a targeted password spray at the list of valid usernames.

Command Used: `sudo crackmapexec smb 10.211.11.20 -u usernames.txt -p pass.txt`

We now have credentials for rduke 

## Question 1 What is the Minimum Password Length?
Answer: 7

## Question 2: What is the locked account duration?
Answer: 2 minutes

## Question 3: username/password Pair
Answer: rduke:Password1!

# Conclusion
Completing the AD: Basic Enumeration room on TryHackMe provided me with foundational knowledge and hands-on experience in enumerating Active Directory environments. I learned how to identify key services and components such as LDAP, Kerberos, and SMB, and practiced using essential enumeration tools like ldapsearch, enum4linux, and rpcclient to extract valuable information about domain users, groups, and policies.

Key takeaways include:

Understanding the structure of Active Directory domains and the importance of LDAP as a query protocol.

Identifying users and their attributes using LDAP filters and object classes.

Leveraging tools to enumerate usernames, group memberships, and potential attack paths without initial credentials.

Recognizing the significance of default naming conventions, RID patterns, and privilege escalation vectors.

This room strengthened my ability to gather and analyze AD-related information in a structured and methodical way—an essential skill for both Blue and Red Team roles. It also laid the groundwork for deeper exploration into privilege escalation and post-compromise activities within Active Directory environments.



<img width="1150" height="517" alt="image" src="https://github.com/user-attachments/assets/4fd740d1-5a75-4918-8569-4125f2f11a63" />




