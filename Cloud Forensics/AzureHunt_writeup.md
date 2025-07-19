# Scenario
A finance company's Azure environment has flagged multiple failed login attempts from an unfamiliar geographic location, followed by a successful authentication. Shortly after, logs indicate access to sensitive Blob Storage files and a virtual machine start action. Investigate authentication logs, storage access patterns, and VM activity to determine the scope of the compromise.

## Question 1 As a US-based company, the security team has observed significant suspicious activity from an unusual country. What is the name of the country from which the attack originated?
Determining where the attack originated from can be useful in determining where the attacker is based and what their TTPS may be, to determine the origin of the attack we can use the fields provided to identify any spikes in traffic from
an unlikley source, if we use the **source.geo.country_name.keyword** we can see that there are many entries for germany, france is also there but isnt utilised as frequently as germany, looking at the results that are returned
from the filter we can see that there are logs related to authentication, storage and networking. It can be gathered that this Germany is the attackers origin country.
<img width="1917" height="909" alt="image" src="https://github.com/user-attachments/assets/3c41a1a3-4325-4dfe-b4b9-bf63efaf9de3" />

Answer: Germany

## Question 2 To establish an accurate incident timeline, what is the timestamp of the initial activity originating from the country?
One of the default fields available is the timestamp and is crucial in creating a timeline of the events that took place during the attack, we can filter Old to New and the first timestamp is available as the first result

<img width="1914" height="920" alt="image" src="https://github.com/user-attachments/assets/79e045cd-276c-4ae0-8b3b-5c9a98dc5974" />

Answer:2023-10-05 15:09

## Question 3 To assess the scope of compromise, we must determine the attacker's entry point. What is the display name of the compromised user account?
Now that we know what logs to look at, we can begin to identify what the attacker done to begin their attack, the first result available shows a successful authentication attempt for the user alice. We can filter for all logs related
to signin activity using the **event.action** field.
`source.geo.country_name.keyword : "Germany" AND event.action : "Sign-in activity"`
<img width="1907" height="923" alt="image" src="https://github.com/user-attachments/assets/a0d0bae0-5033-4111-9bf0-e5aa3044dbc8" />
Answer: Alice

## Question 4 To gain insights into the attacker's tactics and enumeration strategy, what is the name of the script file the attacker accessed within blob storage?
To determine what script was accessed by the attacker within blob storage we must first find all events related to the read requests to the Azure storage account, this will return any read request made to the sotrage account, however to truly filter for access to blob storage we must filter for any resource type that is related to blob storage, this will return any resources accessed specifically from blob storage, finally in order to determine which script was acessed by the attacker we can add the object key or name of the file to the columns in the results, scrolling through we can see multiple requests being made to a powershell script saved in blob storage
<img width="1917" height="983" alt="image" src="https://github.com/user-attachments/assets/04a34984-177f-47b8-9f60-5d49485027db" />

Answer: service-config.ps1

## Question 5 For a detailed analysis of the attacker's actions, what is the name of the storage account housing the script file?
With the entry available for the script file being accessed we can now add some additional columns to the results to determine more about the request, we can add the callerip which gives us the public address the request was made from and the accountname of the storage account the request was sent to. Together these columns can determine what ip accessed what specific storage account, we can see now which one was accessed.
<img width="1915" height="923" alt="image" src="https://github.com/user-attachments/assets/19c238f3-dda0-4651-9a4c-ec680542daff" />


Answer: cactusstorage2023

## Question 6 Tracing the attacker's movements across our infrastructure, what is the User Principal Name (UPN) of the second user account the attacker compromised?
With knowledge that the attacker had access to one of the accounts it is useful to determine if any other requests originated from this suspicious source that involved signing into any other azure accounts, if we scroll through the results chronologically we can see that the attacker did indeed access another account. We can also add the ip addresses as a column and observe that multiple ip addresses are used to access these accounts, indicative of the attacker trying to evade detection by dynamically changing their IP

<img width="1917" height="915" alt="image" src="https://github.com/user-attachments/assets/efb65f95-b442-44dc-8fbf-5a614a1d210b" />

Answer: it.admin1@cybercactus.onmicrosoft.com

## Question 7 Analyzing the attacker's impact on our environment, what is the name of the Virtual Machine (VM) the attacker started?
Any activity related to the starting and stopping of VM's is located within the activity logs, we can filter for VM starting operations which can be found with the following filter `azure.activitylogs.identity.authorization.action.keyword: Microsoft.Compute/virtualMachines/start/action`. With this we have now filtered it down to 6 results, we know that the IT Admin account had been compromised by the attacker so we can also filter for requests originating from that user using `azure.activitylogs.identity.claims_initiated_by_user.fullname.keyword: IT Admin`. Now we can add the resource name as a column using `azure.resource.name`. We now have the name of the VM.
<img width="1912" height="919" alt="image" src="https://github.com/user-attachments/assets/428f13a9-1ef9-4dbd-9f5e-f012039951b7" />

Answer: DEV01VM
