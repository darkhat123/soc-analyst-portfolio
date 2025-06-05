# Synopsis
We're currently in the midst of a murder investigation, and we've obtained the victim's phone as a key piece of evidence. After conducting interviews with witnesses and those in the victim's inner circle, your objective is to meticulously analyse the information we've gathered and diligently trace the evidence to piece together the sequence of events leading up to the incident.

# Introduction
From the description, we can see that this will involve analysing a phone forensically and navigating its filesystem to determine what the murderer was doing just before the murder. Cyberdefenders recommend using ALEAPP (Android Logs Events And Protobuf Parser) to 
analyse the Android phone. The table below details what artefacts can be found using ALEAPP

| Category              | Examples                                     |
| --------------------- | -------------------------------------------- |
| **App Usage**         | App activity history, usage stats            |
| **User Activity**     | Screenshots, clipboard events, notifications |
| **System Logs**       | Battery usage, recent tasks, boot logs       |
| **Location Data**     | WiFi location history, GNSS logs             |
| **Accounts**          | Logged-in accounts, tokens                   |
| **Protobuf Files**    | Decodes Google's binary log formats          |
| **Downloads / Files** | Downloads folder, shared files               |

These will all provide crucial details of the murderer's connections, behaviour and location,n all of which can be used to prove their guilt.

## Question 1 Based on the accounts of the witnesses and individuals close to the victim, it has become clear that the victim was interested in trading. This has led him to invest all of his money and acquire debt. Can you identify the SHA256 of the trading application the victim primarily used on his phone?
Finding the applications that the user has downloaded is trivial once we pass the data to ALEAPP, by accessing the report generated and scrolling through the options and find the associated category, in our case the installed apps section proves useful. From a quickscan of the
installed apps, we can see an option for Olymptrade, a trading app.
![image](https://github.com/user-attachments/assets/915e135e-9e6c-486a-818a-07c7b43f8c6d)

Answer: Olymptrade

## Question 2 According to the testimony of the victim's best friend, he said, "While we were together, my friend got several calls he avoided. He said he owed the caller a lot of money but couldn't repay now". How much does the victim owe this person?
To answer this question, I first tried to identify the number that was trying to call the user multiple times by viewing their call logs. I could see many missed and rejected calls from the number 201172137258. This didnt tell me how much they owed but was useful in
identifying the phone number of the caller.
![image](https://github.com/user-attachments/assets/226dddc2-969a-4999-809d-ec0895ac01e9)

I then viewed the sms messages to see if there was any hard record of the amount owed. Upon opening them, I could see a message asking for 250000 Egyptian pounds
![image](https://github.com/user-attachments/assets/adc50d4e-bc67-41c7-a452-a7d15b5e2884)

Answer: 250000

## Question 3: What is the name of the person to whom the victim owes money?
Using the number we gathered earlier, which is also accessible in the sms messages, we can go to the user's contacts and see if they have them saved
Upon investigation, we can see a user with the corresponding number
![image](https://github.com/user-attachments/assets/b2c778c1-6b8a-43a3-ba90-e25dab76ab5f)

Answer: Shady Wahab

## Question 4 Based on the statement from the victim's family, they said that on September 20, 2023, he departed from his residence without informing anyone of his destination. Where was the victim located at that moment?
To determine the location of the user we have many possible location sections, locations can be found due to being tracked by certain apps. In our case there is no google maps timeline section or other key sections logged by apps. Instead if we view the recent activity we
can see an entry for google maps that was taken at the time the user was said to be in the undisclosed location, upon investigation of the snapshot the location is discovered
![image](https://github.com/user-attachments/assets/d2aa900e-62d1-4a47-aad5-303f8cf1c3c6)

Answer: The Nile Ritz-Carlton

## Question 5 The detective continued his investigation by questioning the hotel lobby. She informed him that the victim had reserved the room for 10 days and had a flight scheduled thereafter. The investigator believes that the victim may have stored his ticket information on his phone. Look for where the victim intended to travel
To determine where the user was flying to i was looking for either screenshots of the phyiscal tickets or photos of locations which would be useful for a reverse image search. i finally stumbled upon the answer when i checked the discord chats saved on the phone where
a discussion details the meeting place and the user booking the ticket for a specific time, with knowledge of what landmark they were meeting at i was able to determine the state using google images

![image](https://github.com/user-attachments/assets/1b430bbf-1d70-417e-a748-97ecfefcfc32)
![image](https://github.com/user-attachments/assets/1fb5fe6d-daf3-47dd-bcfb-878e3c24a683)

Answer: Las Vegas

## Question 6 After examining the victim's Discord conversations, we discovered he had arranged to meet a friend at a specific location. Can you determine where this meeting was supposed to occur?
This is just the location we used to determine the state.

Answer: The Mob Museum

#Conclusion
