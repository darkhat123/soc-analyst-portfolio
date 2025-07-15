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
