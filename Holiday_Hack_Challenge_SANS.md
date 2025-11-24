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

# Scenario 3: 
