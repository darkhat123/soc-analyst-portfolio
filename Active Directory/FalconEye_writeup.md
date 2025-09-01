# Scenario
As a SOC analyst, you aim to investigate a security breach in an Active Directory network using Splunk SIEM solution to uncover the attacker's steps and techniques while creating a timeline of their activities. The investigation begins with network enumeration to identify potential vulnerabilities. Using a specialized privilege escalation tool, the attacker exploited an unquoted service path vulnerability in a specific process.

Once the attacker had elevated access, the attacker launched a DCsync attack to extract sensitive data from the Active Directory domain controller, compromising user accounts. The attacker employed evasion techniques to avoid detection and utilized a pass-the-hash (pth) attack to gain unauthorized access to user accounts. Pivoting through the network, the attacker explored different systems and established persistence.

Throughout the investigation, tracking the attacker's activities and creating a comprehensive timeline is crucial. This will provide valuable insights into the attack and aid in identifying potential gaps in the network's security.

| Technique                                                           | Tactic                             | Technique ID              | Evidence in Investigation                                                                 |
| ------------------------------------------------------------------- | ---------------------------------- | ------------------------- | ----------------------------------------------------------------------------------------- |
| **Hijack Execution Flow: Path Interception by Unquoted Path**       | Privilege Escalation, Persistence  | **T1574.009**             | Service `Automate-Basic-Monitoring.exe` exploited due to unquoted service path            |
| **OS Credential Dumping: DCSync**                                   | Credential Access                  | **T1003.006**             | `fun.exe` (Mimikatz) executed with `lsadump::dcsync /user:Abdullah-work\Administrator`    |
| **Pass-the-Hash (PtH) for Lateral Movement**                        | Lateral Movement                   | **T1550.002**             | Compromised `Abdullah-work\HelpDesk` via NTLM logons (4624, LogonType 3/9/10)             |
| **Command-Line Interface (PowerShell / bloodhound.exe)**            | Discovery                          | **T1059.001**             | PowerShell execution of `bloodhound.exe` on `Client02`                                    |
| **LSASS Memory Dump (fun.exe / mimikatz)**                          | Credential Access                  | **T1003**                 | `fun.exe` = `mimikatz.exe` dropped via PowerShell, dumped credentials from LSASS          |
| **Over-Pass-the-Hash / Kerberos Ticket Theft**                      | Credential Access                  | **T1558.003**             | Rubeus-like `asktgt /aes256` executed for user `Mohammed` with AES256 key injection       |
| **Service Execution via SC Create / Automate-Basic-Monitoring.exe** | Persistence / Privilege Escalation | **T1543.003 / T1574.009** | New vulnerable service created and abused to escalate privileges                          |
| **File Creation (fun.exe, dropped by PowerShell)**                  | Defense Evasion / Execution        | **T1105 / T1059.001**     | Sysmon Event ID 11 shows download of `fun.exe` at 2023-05-10 05:08                        |
| **Kerberos Delegation Abuse (S4U2self/S4U2proxy)**                  | Lateral Movement                   | **T1550.003**             | `Microsoft-Update.exe` command abused `http/client03` service delegation for Admin access |
| **Remote Services (WinRM / WSMProvHost)**                           | Lateral Movement                   | **T1021.006**             | On `Client03`, attacker spawned `wsmprovhost.exe` for remote PowerShell session           |
| **Golden Ticket (Kerberos Ticket Forgery)**                         | Persistence / Privilege Escalation | **T1558.001**             | Forged ticket `trust-test2.kirbi` using Mimikatz `kerberos::golden` targeting parent DC   |




## Question 1 What is the name of the compromised account?
In the scenario it is said that the compromised account was accessed by a pass-the-hash attack following a dcsync attack. A dcsync attack works when an attacker has privileges to Replicating Directory Services permissions, this can be enumerated using tools such as bloodhound
and once found if the account can be comrpomised in anyway then the attacker can make replication requests to legitimate domain controllers, masquerading themselves as a legitimate domain controller looking to update its information. This works using the Directory Replication Services
remote protocol

### Steps of a DCSync Attack

1. The attacker uses the stolen privileged account to send a **DRSGetNCChanges** request via the **MS-DRSR** protocol. This is the same request Domain Controllers use to replicate Active Directory data.

2. The legitimate DC believes it’s talking to another DC and returns the sensitive AD data:


- Usernames


- Password hashes (NTLM)


- Kerberos keys (AES/RC4)


- KRBTGT account hash (used to forge Golden Tickets)

3. The attacker extracts the credentials locally (often using Mimikatz lsadump::dcsync).With these credentials, the attacker can:


- Perform Pass-the-Hash attacks.


- Create Golden Tickets (for long-term persistence).


- Access any user’s account, including Domain Admins.

 A full Playbook detailing detecting and investigating DCsyn attacks will be available here: [link here]

 The attacker then used a pass-the-hash attack (Lateral Movement) to authenticate to another computer in the domain.

### Steps of a PtH Attack
1. Initial Compromise: Attacker gains access to a Windows machine (via phishing, malware, exploit, etc.).

2. Extract the Hash

- Windows stores password hashes in memory (LSASS process), in the SAM database, or in NTDS.dit on Domain Controllers.

- Tools like Mimikatz, Impacket, or crackmapexec can dump these hashes.

3. Reuse the Hash

- Instead of cracking the hash to recover the plaintext password, the attacker injects the hash into an authentication session.

- The attacker tells the system: “Here’s my NTLM response,” using the stolen hash directly.

4. Authenticate via NTLM

- If the target system or service accepts NTLM authentication (LogonType=3 network logons, SMB, WMI, RDP in some cases), the authentication succeeds.

- No password needed — the hash itself is enough.

5. Move Laterally

- Using the stolen hash, the attacker connects to other systems across the network.

- If the hash belongs to a privileged account (e.g., Domain Admin), they can quickly gain domain-wide access.

5. Why It Works

- NTLM challenge-response only proves you know the hash, not the plaintext password.

- Windows doesn’t differentiate between a user presenting a password vs. a hash.

6. Detection Pointers

- Windows Event ID 4624 with:

- AuthenticationPackageName=NTLM

- LogonType=3 (network) or LogonType=9 (new credentials) or LogonType=10(RDP)
- Filter out SYSTEM and NULL SID accounts
- LogonProcessName=NtlmSsp or LogonProcessName=seclogo

Look for:

- Repeated NTLM logons where Kerberos would normally be used.

- Same user logging in from multiple different IPs in short succession.

- Lateral movement tools (e.g., wmiexec.py, psexec, smbexec).

In short:
- Pass-the-Hash = steal NTLM hash → reuse it as credentials → authenticate & move laterally without knowing the real password.

Pass-the-hash attacks can take numerous forms, and each of them requires its own separate query to identify them within our logs. The best approach to detect all pass-the-hash attacks involves:
- Looking for Logon Types (3,9,10)
- Authentication Packages used: NTLM(classic authentication no kerberos setup)/ Negotiate(Kerberos attempted, defaulted to NTLM)
- NTLMssp when authentication is done with NTLM challenge/response, and seclogo when Kerberos is attempted and NTLM is defaulted

We can craft a query capable of capturing any type of pass-the-hash attack like so:
`index=folks sourcetype=XmlWinEventLog EventCode=4624 
(LogonType=3 OR LogonType=9 OR LogonType=10) 
(AuthenticationPackageName=NTLM OR AuthenticationPackageName=Negotiate) 
(LogonProcessName=NtLmSsp OR LogonProcessName=seclogo) 
SubjectUserSid!="SYSTEM" SubjectUserSid!="NULL SID"
| table _time ComputerName SubjectUserName SubjectDomainName SubjectUserSid LogonType LogonProcessName AuthenticationPackageName IpAddress`

Screenshot: <img width="1916" height="850" alt="image" src="https://github.com/user-attachments/assets/3c329b72-133e-4e1c-8df1-65827aaf3bcf" />

From this, we can see that all authentication attempts were successful, and NTLM was used to there was no option for Kerberos.

Answer: Abdullah-work\HelpDesk

## Question 2: What is the name of the compromised machine?

Answer: Client02

## Question 3: What tool did the attacker use to enumerate the environment?
When it comes to enumerating Active Directory networks, no tool comes up more than BloodHound, capable of enumerating entire Active Directory forests and identifying attack paths with how users, groups, domains and computers are configured.
BloodHound maps Active Directory like a graph and shows you the fastest path from “where I am” to “owning the domain.”

We know that the user has taken over the Client02 computer in the Abdullah.Ali.Alhakami domain, with this knowledge, we can look for any PowerShell scripts being executed involving BloodHound. Event code 4104 is generated when ScriptBlock Logging is enabled and
will even decode base64 encoded commands used by attackers. We know that the ScriptBlockText will likely reference Bloodhound, so we can simply search for any occurrences in the PowerShell scripts.

The Final Query: `index=folks sourcetype=XmlWinEventLog EventCode=4104 ScriptBlockText="*bloodhound*" Computer="Client02.Abdullah.Ali.Alhakami" 
|  table _time, User, Computer, ScriptBlockText`

Screenshot: <img width="1912" height="930" alt="image" src="https://github.com/user-attachments/assets/e2ce9869-7a2a-4fb4-8ad3-7fd021d35dd5" />

Answer: bloodhound

## Question 4: The attacker used an Unquoted Service Path to escalate privileges. What is the name of the vulnerable service?
In this instance, the scenario says the attacker discovered an unquoted service path vulnerability whilst enumerating Client02. This will be used for the attacker to insert their own script in the directory above the service and execute that, giving them full system privileges
on the machine, typically in a privileged shell.

Finding unquoted service path vulnerabilities within logs can be done by looking for EventID 7045, which indicates a service being installed on the system. This returns the name of the service created, the account that created it and the path to the service executable

We can utilise the image path as a way to determine if an unquoted service path vulnerability exists; if there are spaces in it, then it can be exploited.

Typically, these services are installed under C:\Program Files, and all legitimate services should be installed here. When they are installed, if there are any spaces in the path to the service,e they should be properly quoted 

If they aren't quoted, then the attacker can abuse the space to install an executable in say C:\Program.exe.exe, which will be run before the other service is found

The way Windows reads paths to services if it finds a space, it will append .exe to the text before the space and try to run this before going further down the path to find the service.

If an attacker can write to C:\ and create a program with the path C:\Program.exe then this will be run when the service starts.

With the program executed it is granted SYSTEM privileges like most services have access to; this is used to spawn an elevated privileges reverse shell, which the attacker uses to execute commands.

The final Query: `index=folks host="CLIENT02" EventCode=7045 | where like(ImagePath, "C:\\Program Files%") AND NOT like(ImagePath, "\"%\"")
| table _time Computer, ServiceName,ImagePath,AccountName`



Screenshot: <img width="1915" height="702" alt="image" src="https://github.com/user-attachments/assets/824ea18b-bc7a-4277-aa6b-ba1e047a860f" />

We can also try and find the command related to installing a vulnerable service on the system
The Final Query: `index="folks" EventCode=1 Image="C:\\Windows\\System32\\sc.exe"
| search CommandLine="*create*"
| table _time, Computer, User, Image, ParentImage, CommandLine, SHA256
| sort _time desc

Screenshot: <img width="1914" height="835" alt="image" src="https://github.com/user-attachments/assets/12e68210-bb3e-4559-8029-d673f9dc6104" />

Answer: Automate-Basic-Monitoring.exe
## Question 5: What is the SHA256 of the executable that escalates the attacker's privileges?

The Final Query: `index="folks" host=CLIENT02 process="*Automate-Basic-Monitoring.exe*" | table _time process SHA256 CommandLine`
Screenshot: <img width="1896" height="882" alt="image" src="https://github.com/user-attachments/assets/1bc55180-ba12-48c3-904b-054e8ac67353" />

Answer: 8ACC5D98CFFE8FE7D85DE218971B18D49166922D079676729055939463555BD2

## Question 6: When did the attacker download fun.exe?
We can look for any file creation events on the system by filtering for Sysmon Event ID 11, that have fun.exe in their targetfilename
`index=folks host=CLIENT02  TargetFilename="*fun.exe*" | reverse  | search EventID=11 | table  _time, TargetFilename`
Screenshot: <img width="1911" height="841" alt="image" src="https://github.com/user-attachments/assets/ebba0093-cd52-4bb6-b6d1-4514ef88a8c9" />

Answer: 2023-05-10 05:08

## Question 7: What is the command line used to launch the DCSync attack
Knowing that the attacker downloaded fun we can investigate any command line arguments involving the binary that may reveal what the attacker was doing, we can filter for fun.exe in the CommandLine and look for process creation Sysmon Event ID 1
`index=folks host=CLIENT02 EventID=1  CommandLine="*fun.exe*" | table  _time, User, Computer, CommandLine`

This returns all commands being ran that include fun.exe, we can see that one of the results at the end involves using what looks like Mimikatz modules to perfrom a LSA Dump as an administrator
Mimikatz Execution used for DCsysnc attack: `"C:\Users\HelpDesk\fun.exe" "lsadump::dcsync /user:Abdullah-work\Administrator"`
Screenshot: <img width="1913" height="615" alt="image" src="https://github.com/user-attachments/assets/50bf7d95-f0cd-4d1b-a215-d2a4e891b3e6" />

## Question 8: What is the original name of fun.exe?
`index=folks host=CLIENT02 EventID=1  CommandLine="*fun.exe*" | table  _time, User, Computer, CommandLine, OriginalFileName  | reverse`
Screenshot: <img width="1915" height="824" alt="image" src="https://github.com/user-attachments/assets/3688273a-a686-4863-94ef-6c5e10fb8533" />

Answer: mimikatz.exe

## Question 9: The attacker performed the Over-Pass-The-Hash technique. What is the AES256 hash of the account he attacked?

To prevent tickets being brute forced it is recommended to use the strongest encryption available to Encrypt the kerberos ticket which is AES256, this encryption type is denoted with 0x17 in the TicketEncryptionType field. We can use this field as a way to detect
insecure tickets that fall outwith the security posture.

`index="folks" EventCode="4768" TicketEncryptionType=0x17 | table  _time user`
This finds event id 4768 which is triggered every time a Kerberos Authentication Ticket (TGT) was requested

Screenshot: <img width="1890" height="374" alt="image" src="https://github.com/user-attachments/assets/615df80c-25a3-4163-856c-b8f262b45f1d" />

With the user available we can now look for any process creations ran by Mohammed and we can find the command used to gain an interactive shell by the attacker, we can also omit the Mohammed query and see all authentication attempts performed by the Helpdesk User

Final Query: `index="folks" CommandLine="*aes256*" Mohammed EventID=1 
| table _time, Computer, User, CommandLine`
Screenshot: <img width="1910" height="916" alt="image" src="https://github.com/user-attachments/assets/ef8e17c2-29e7-408b-9dc0-2868b65356ec" />


Final query: `index="folks" CommandLine="*aes256*" EventID=1 
| table _time, Computer, User, CommandLine`
Screenshot: <img width="1893" height="726" alt="image" src="https://github.com/user-attachments/assets/d2644cec-9a57-4baa-9b9b-785c777d340c" />

Command Ran `"C:\Users\HelpDesk\Microsoft-Update.exe" asktgt /user:Mohammed /aes256:facca59ab6497980cbb1f8e61c446bdbd8645166edd83dac0da2037ce954d379 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`

This gives us access to the command prompt for the user Mohammed

Answer:facca59ab6497980cbb1f8e61c446bdbd8645166edd83dac0da2037ce954d379

## Question 10: What service did the attacker abuse to access the Client03 machine as Administrator?

Finding the service being abused to access client03 is as simple as looking for any access to CLIENT03 from CLIENT02 in the command line arguments where the attacker likely authenticated from

`index="folks" host="CLIENT02" CommandLine="*CLIENT03*" 
|  table CommandLine`

Command ran: `"C:\Users\HelpDesk\Microsoft-Update.exe" s4u /user:Client02$ /aes256:0a87dfe150dc1da194b965a620e2acd94aea917185c7bb6731aa323470f357d9 /msdsspn:http/Client03 /impersonateuser:Administrator /ptt`

This is a classic abuse of Delegation using s4u2self and s4u2proxy where the attacker impersonates a user when connecting to a service to acess a shell with the privileges of the impersonated user
**Setup / Precondition**

In AD, Client02 (a computer account) is trusted for constrained delegation to http/Client03.That means the KDC will allow Client02 to impersonate any user (including Administrator) to the HTTP service on Client03.

**Attacker Control**

- Attacker compromises Client02 (local SYSTEM or computer account hash).

- They extract the AES256 Kerberos key (or RC4/NTLM hash) for Client02 from LSASS or AD.

**S4U Abuse**

- Attacker uses S4U2self: “As Client02, give me a Kerberos ticket for Administrator (to myself).”

- This gives them a service ticket that proves “Administrator authenticated to me.”

- Attacker uses S4U2proxy: “Now, as Client02, give me a service ticket for Administrator to http/Client03.”

- KDC checks AD and says:  allowed, because Client02 is trusted to delegate to http/Client03.

- Now the attacker has a Kerberos service ticket to Client03 — as Administrator.

**Pass-the-Ticket (PTT)**

- Attacker injects this forged/abused ticket into their current session (klist, mimikatz, Rubeus).

- They connect to Client03’s HTTP service (or other enabled services).

- If Administrator has local admin on Client03, they can spawn a shell as Administrator.

**Why This Works**

- Constrained Delegation (KCD) still trusts the front-end service (Client02) to request tickets on behalf of any user — even privileged ones like Administrator.

- By stealing the computer account key of Client02, the attacker becomes the delegating service.

- Kerberos won’t distinguish between “real” delegation and “abused” delegation — if the key is valid, the KDC complies.

**Security Implications**

This is essentially Privilege Escalation + Lateral Movement:

- Escalation: Attacker elevates from “just Client02 SYSTEM” to Administrator on Client03.

- Lateral: Moves across the network without needing user passwords.

Screenshot: <img width="1901" height="835" alt="image" src="https://github.com/user-attachments/assets/ba5878ad-c001-4a40-a61a-db9def99a560" />

Answer: http/client03
## Question 11: The Client03 machine spawned a new process when the attacker logged on remotely. What is the process name?

There are many windows processes used for executing command remotely, we can check through each of these in the CommandLine or Image fields to find cases where they are used by known compromised accounts 
`index=folks Computer="Client03.Abdullah.Ali.Alhakami" host=CLIENT03 (CommandLine="*wsmprovhost.exe*" OR ParentCommandLine="*wsmprovhost.exe*")
|  table ParentCommandLine ParentImage CommandLine Image`

Screenshot: <img width="1903" height="846" alt="image" src="https://github.com/user-attachments/assets/583c028c-4232-4f13-831b-4b6e6a3d29d8" />

Answer: wsmprovhost.exe

## Question 12: The attacker compromises the it-support account. What was the logon type?
We know the attacker used the overpass-the-hash technique to compromise previous accounts and we know RunAs uses LogonType 9

Answer: 9

## Question 13 What ticket name did the attacker generate to access the parent DC as Administrator?
Currently all of the tactics and techniques employed by the attacker have focused on targeting accounts, services and computers to perform lateral movement around the Abdullah.Ali.Alhakami domain which is a child domain
of Ali.Alhakami the root of the forest. We know the attacker is trying to access the Parent Domain from the child domain and therefore must try to escalate their privileges by abusing Kerberos. A common privilege escalation attack vector used to gain access to an entire domain by abusing kerberos is the Golden Ticket Attack. 

### Steps of a Golden Ticket Attack
**Compromise a Domain Controller**

- The attacker first needs Domain Controller–level access (or any system where the krbtgt account hash can be obtained).

- They usually dump credentials from LSASS or the NTDS.dit Active Directory database.

**Steal the krbtgt Account Key**

- The krbtgt account stores the encryption keys used to sign and encrypt all Kerberos Ticket Granting Tickets (TGTs).

- The attacker extracts the NTLM/AES key of krbtgt.

- This is the crown jewel — with it, they can forge tickets.

**Forge a TGT (“Golden Ticket”)**

- Using the stolen key, the attacker generates a fake TGT.

- They can set:

  - User account name (even a nonexistent account).

  - Domain SID.

  - Group memberships (Domain Admins, Enterprise Admins, etc.).

  - Ticket lifetime (can be arbitrarily long — even 10 years).

**Inject and Use the Ticket**

- The forged ticket is injected into memory on a compromised machine.

- From there, the attacker can present it to any domain service (SMB, RDP, LDAP, SQL, etc.).

- Since the TGT is signed by the krbtgt key, all DCs in the domain trust it.

**Persistence and Lateral Movement**

Because the attacker controls the trust root (krbtgt), they can:

- Impersonate any account.

- Maintain access indefinitely, even if admin passwords are reset.

- Move laterally across the domain and trusted forests.


We know the attacker has used Mimikatz previously which is know for having a module dedicated to creating golden tickets given the attacker obtained the keys from LSASS, we can search for command line arguments synonymous with the golden ticket attack in mimikatz.

`index="folks" host=CLIENT02 (CommandLine="*kerberos::golden*" OR CommandLine="*ticket*" AND CommandLine="*Administrator*")
| table _time CommandLine`

This looks for the signature module from mimikatz but falls back to finding any commands that include strings ticket and Administrator

Screenshot: <img width="1912" height="927" alt="image" src="https://github.com/user-attachments/assets/9c76a4e7-e278-417b-bdfe-b24633aaff8f" />

We can see three attempts to perform the golden ticket attack to access the parent domain one that uses the AES256 key and then the other which goes to the less secure RC4 key

Command Run: `"C:\Users\HelpDesk\Better-to-trust.exe" "kerberos::golden /user:Administrator /domain:Abdullah.Ali.Alhakami /sid:S-1-5-21-1316629931-576095952-2750207263 /sids:S-1-5-21-2314577697-1335098093-3289815499-519 /rc4:8a1a8ab21f32a13a8d83254d33448424 service:krbtgt /target:Ali.Alhakami /ticket:trust-test2.kirbi"`

Answer: trust-test2.kirbi

##  Conclusion

This investigation reconstructed the attacker’s activities across the Abdullah.Ali.Alhakami Active Directory forest, revealing their tactics, techniques, and procedures (TTPs).  
The intrusion path leveraged service misconfigurations, credential dumping, Kerberos abuse, and lateral movement techniques to escalate from a workstation compromise (`Client02`) to full domain dominance, including the parent domain controller.

The timeline demonstrates how chained privilege escalation, credential access, and delegation abuse enabled persistent, stealthy access.

##  Recommendations for Prevention & Detection

### 1. Active Directory Hardening
- Remove **unnecessary replication rights** (e.g., prevent HelpDesk accounts from holding `Replicating Directory Changes` permissions).
- Regularly audit **domain and enterprise admin group memberships**.
- Enforce **strong AES encryption (AES256)** for Kerberos tickets and disable RC4/NTLM fallback where possible.
- Monitor **delegation settings** in AD; restrict constrained delegation only where absolutely required.

### 2. Credential Protection
- Enable **LSASS protection (RunAsPPL)** to prevent direct memory dumping by tools like Mimikatz.
- Deploy **Credential Guard** (Windows 10+) to block hash and ticket theft.
- Rotate **krbtgt account passwords twice** after compromise, ensuring forged Golden Tickets are invalidated.
- Regularly reset **local administrator passwords** using LAPS.

### 3. Service & Application Security
- Audit all services for **unquoted service paths** (Event ID 7045) and ensure binaries are properly quoted.
- Restrict write permissions on `C:\` and `Program Files\` to prevent path hijacking.
- Sign and verify executables to prevent execution of untrusted binaries.

### 4. Logging & Monitoring
- Ensure **Sysmon** is deployed with detailed configuration (Event IDs 1, 11, 4688, 4624, 4768).
- Monitor:
  - **DCSync attempts**: Event IDs 4662 (replication requests).
  - **Pass-the-Hash**: 4624 with NTLM, LogonTypes 3/9/10.
  - **Golden Ticket usage**: 4768/4769 anomalies, unusual lifetime tickets.
  - **Delegation abuse**: S4U2self and S4U2proxy requests.
- Use Splunk/ELK queries to correlate suspicious **CommandLine arguments** (`mimikatz`, `bloodhound`, `asktgt`, `kerberos::golden`).

### 5. Network Segmentation & Lateral Movement Controls
- Restrict **administrative sessions** to hardened jump servers (PAWs).
- Limit SMB, WMI, and WinRM to specific administrative networks.
- Monitor and restrict **service ticket requests** across domain trusts.

### 6. Incident Response Preparedness
- Regularly test **Golden Ticket** and **Pass-the-Hash** detection playbooks.
- Train SOC staff to identify anomalies in **Kerberos traffic** vs. NTLM authentication.
- Maintain and review **Splunk correlation rules** for credential dumping and privilege escalation.

---

**In summary:**  
The compromise highlights how misconfigurations in Active Directory and lack of monitoring enable attackers to pivot from a single endpoint compromise to total domain takeover. Proactive hardening, continuous monitoring, and enforcing least privilege are critical to preventing such breaches in the future.



