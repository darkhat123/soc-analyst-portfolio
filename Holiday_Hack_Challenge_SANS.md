# Holiday Hack Challenge

# Scenario 1: Dosis Neighborhood SOC
This room tasks us with reading phishing emails sent by the gnomes to infiltrate the network, we as the SOC analyst are tasked with making sure that we can extract the malicious IOC's such as IP's, emails, url 
and Domains, we want to then make sure we can trasnfer these between department whilst ensuring they remain neutralised and cant be detonated by mistake. This involves defanging the malicious components.


## Creating our regex
Using regex's alone will not filter only malicious domains and IP's it is up to the SOC analyst to utilise context to determine the malicious components.

IP regex: `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`
Domain Regex: `[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+`
URL regex HTTPS : `https://[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?(/[^\s]*)?`
URL regex HTTP: `http://[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?(/[^\s]*)?`
Email Regex `b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`

## Using SED to Defang, chaining commands
Command: `s/\./[.]/g; s/:\//[://]/g; s/http/hxxp/g; s/@/[@]/g`
Submission: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/78e28963-fd5e-44a9-8bba-08c0a72a1978" />

# Scenario 2: Owner
In this side quest we are tasked with looking at the Role based Access controls of the HOA, supposedly they have all elevated access using PIM to ensure that no users are assigned admin capabilities with the owner role.
This would give the user unlimited admin access and causes serious implications for that resource and other connected resources. PIM allows just in time administration capabilties and only allows those privileges
for the requested task and mitigates assigning ownership to a member then not removing them from it later on. 

In order to do this we must use the azure cli.

Step 1: Identify all the subscriptions for the tenant
Command: `az account list --query "[].name"`

Step 2: Find subscriptions in use and add their ids to a list

Subscriptions
2b0942f3-9bca-484b-a508-abdae2db5e64
4d9dbf2a-90b4-4d40-a97f-dc51f3c3d46e
065cc24a-077e-40b9-b666-2f4dd9f3a617
681c0111-ca84-47b2-808d-d8be2325b380

Step 3: Iterate through the subscriptions and check for Owner assignment

Command: `az role assignment list --scope "/subscriptions/{ID of first Subscription}" --query [?roleDefinition=='Owner']`
az role assignment list --scope "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64" --query [?roleDefinition=='Owner'] && az role assignment list --scope "/subscriptions/4d9dbf2a-90b4-4d40-a97f-dc51f3c3d46e" --query [?roleDefinition=='Owner'] && az role assignment list --scope "/subscriptions/065cc24a-077e-40b9-b666-2f4dd9f3a617" --query [?roleDefinition=='Owner'] && az role assignment list --scope "/subscriptions/681c0111-ca84-47b2-808d-d8be2325b380" --query [?roleDefinition=='Owner']


We find that one of the subscriptions has an owner thats not in the PIM Admins group,instead it is assigned to IT admins with an id `6b982f2f-78a0-44a8-b915-79240b2b4796`

We need to know why the IT admins group is assigned on this resource, is it possible that the IT admins is a member of a certian group thats allowing them to be an owner of this subscription

Step 4: Find out the members of this group
Command `az ad group member list --group 6b982f2f-78a0-44a8-b915-79240b2b4796`

We can see that the IT admins are a member of the Subcription Admins group due to a nested group misconfiguration, effectively giving them total access over the subscription and its include resources

Step 5: Identify the members of the misconfigured group

Submission: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e22f27f8-6a9c-471a-9194-c9c6ab16b658" />

# Scenario 3: Restoring the Fire alarm by regaining Admin privileges
This scenario provied us a low privilege user shell which we can use to enumerate the system for possible privilege escalation entry points due to permisisons misconfigurations or the user being able to run sudo without providing a password, or world writable dirtectories.

## Check for any sudoer rights over scripts 
Typically administrators work by the principal of least privilege when assigning admn rights, much like the PIM model, the sudoers group can be used to grant granular access to resources or commands with administrative privileges, this prevent spawmning a persistent root shell where the access to resources is rarley constrained, however sudoers can be abused to allow an attacker to spawn a privileged shell
sometimes without even being prompted for a password. Sudoers configured correctly and other mechanisms in place can allow easy administration flexibility between users. However when these settings are misconfigured in sequence an attacker can leverage this misconfiguration to acheive an elevated shell

We will run some discovery commands on the machine to determine what access we have

Command: `sudo -l`

Output: `Matching Defaults entries for chiuser on 4668f4b40fac:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty,
    secure_path=/home/chiuser/bin\:/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+="API_ENDPOINT API_PORT RESOURCE_ID HHCUSERNAME", env_keep+=PATH
User chiuser may run the following commands on 4668f4b40fac:
    (root) NOPASSWD: /usr/local/bin/system_status.sh`

From this we immediately see:

- env_reset - used to reset the environment variables to strictly whats necessary and trusted before running the sudo command, this prevents any manipulation of PATH environment variables and other environment variables used to control the loading order of shared libraries and inject a malicious library that gives them access to system and malloc.

- Two secure paths
  - secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty
  - secure_path=/home/chiuser/bin\:/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
- env_keep for $PATH
This together creates a strom, then env_reset would have prevented any of our privilege escalation possibilities via abuse of the PATH variable ordering, and the secure_path enforces a PATH that cant be changed, however the second configuration is what introduces the order vulnerability. The env-keep ensures this PATH is used by our user when running sudo, meaning if we create a script in our home
  irectory we can run any command with effective sudo prviileges.

We can look and see how the PATH variable will be applied for our user, we can see that our user home directory comes first in the PATH variable which means if a resource, with the same name as the one we attempt to access exists in our directory it will be run before the intended script
Command: `echo $PATH | tr ':' '\n'`
Output: `/home/chiuser/bin
/usr/local/sbin
/usr/local/bin
/usr/sbin
/usr/bin
/sbin
/bin`

Okay so we need to create a file with a name identical to one of the commands thats run in the script, preferably this command is ran without arguments, and is stored in /bin or /usr/bin

We can check where these commands are using the which utility we have a few options but for best results well use the first listed, df, we will create our own version in the bin folder within the home directory, the file will have the shebang line, then the intended file will be executed with root privileges
File contents: `#!/bin/bash
sudo /etc/firealarm/restore_fire_alarm`

Submission: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/43df665b-c008-45d0-a841-b0abe46bc98a" />


# Scenario 5: Acces gift tracker system
The intern wants to connect to the tracker system which used to run on port 8080, we need to see what ports are listening on the machine to determine where the tracker is.

We can use the ss command to disoplay all listening tcp sockets on the computer
Command: ss -tlnp

We can then connect to the port in the output using:
Telnet command: `telnet 0.0.0.0 12321`
Curl command: `curl 0.0.0.0:12321`

And success we can connect to the tracker system

## Scenario 6: The HOA hosts a static webpage on azure storage, An admin accidentally uploaded an infrastructure config file that contains a long-lived SAS token. We must locate it and report back

A shared access signature is a token that grants limited access to a single resource in azure storage, this allows the user to connect to the resource and perform read or write operations without giving
them the account key that logs them in. These should be rotated frequently and never disclosed to anyone other than the intended recipient, with the config file being available to the public anyone can open
developer tools and see that file, and thus the sas token that grants access to this resource, compromising the page, leadingto possible defacement or intelligence gathering.

## List resource groups in azure
Command: `az group list -o table`

## Find storage accounts within a certain reqource group
Command: `az storage account list --resource-group rg-the-neighborhood -o table`

## List the properties of a storage account
Command: `az storage blob service-properties show --account-name neighborhoodhoa --auth-mode login`

If this returns enabled=true this means that all the contents of the $web folder are publicly accessible

## View the storage containers of a given storage account
Command: `az storage container list --account-name neighborhoodhoa --auth-mode login`

We can see a $web container, the default container, we can also see an additional public container that must have been added by the hoa

## List the contents of the storage containers
Command: `az storage blob list \
  --container-name '$web' \
  --account-name neighborhoodhoa \
  --auth-mode login \
  --output table`

  This will return a file with a non standard extension, lets have a look at this 

## Print the files contents to stdout
Command:`az storage blob download --account-name neighborhoodhoa --container-name '$web' --name iac/terraform.tfvars --auth-mode login --file /dev/stdout | less`

We have found the SAS token

Submission: <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/f2cace23-aadc-4b7b-bf42-97208f04e09d" />

## Scenario 7: Visual networking
Easily completed

## Scenario 8: 
