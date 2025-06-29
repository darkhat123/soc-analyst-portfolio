# Introduction
Splunk is a powerful SIEM solution that provides the ability to search and explore machine data. Search Processing Language (SPL) is used to make the search more effective. It comprises various functions and commands used together to form complex yet effective search queries to get optimized results.

This room will dive deep into some key fundamentals of searching capability, like chaining SPL queries to construct simple to complex queries.

Learning Objectives

This room will teach the following topics:

What are Search processing Language?
How to apply filters to narrow down results.
Using transformational commands.
Changing the order of the results.
Room Prerequisites

This room is based on the SIEM concepts covered in Intro to SIEM and Splunk: Basics rooms. Complete these rooms and continue to the next task.

# Search & Reporting App Overview
## Question 1 What is the name of the host in the Data Summary tab?
The useful feature of splunk is the fields it populates based on the logs it is ingesting, typically when beginning an investigation we will want to idenitfy the hostnames, IP's and Usernames involved in the malicious traffic, this will become the basis for all our other
searches that we make using filters to show only traffic relevant to the invovled machines.

Finding the hostname can be done by searching through the avilable fields in splunk, under the **host** field we can see a single entry.
![image](https://github.com/user-attachments/assets/48029a51-1e45-493d-ac99-13141ed06376)

Answer: cyber-host

## Question 2 In the search History, what is the 7th search query in the list? (excluding your searches from today)
Knowing our past searches can help us use useful queries that weve used before and helps keep track of the investigation process.

We can see the 7th item
![image](https://github.com/user-attachments/assets/c8755571-67a7-456d-a5ce-b8ef46412c72)

Answer: index=windowslogs | chart count(EventCode) by Image

## Question 3 In the left field panel, which Source IP has recorded max events?
We know that all the fields available are listed in the left fields section, these can be searched through to find any fields related to source ip addresses, we can see an entry **SourceAddress** which contains the top values for Source ip adddresses in the logs.
We know that the first few addresses are `0.0.0.0` for all destination addresses, '127.0.0.1' for localhost, the first non-reserved IP address can be seen below these
![image](https://github.com/user-attachments/assets/364d9fec-08cd-4851-9f80-fc52667bfa93)
Answer: 172.90.12.11

## Question 4 How many events are returned when we apply the time filter to display events on 04/15/2022 and Time from 08:05 AM to 08:06 AM?
Knowing how to filter events within a specific time range can be useful when we know when an attack occured and ended or even just when it began as this allows us to remove all traffic unrelated to the incident
![image](https://github.com/user-attachments/assets/18050c19-9769-4187-9797-92037ec22edd)

Answer: 134
# Splunk Processing Language Overview
## Question 5 How many Events are returned when searching for Event ID 1 AND User as *James*?
As shown in the tutorial a key feature of splunk is its ability to chain filters to build more and more complexe queries, we can use the Boolean Operator and to filter for both conditions.
![image](https://github.com/user-attachments/assets/51321a50-d868-4e47-ad74-6f83dd4e0797)

Answer: 4

## Question 6 How many events are observed with Destination IP 172.18.39.6 AND destination Port 135?
![image](https://github.com/user-attachments/assets/ee556fbd-71b3-45e2-9033-969cb5cbf4ae)

Answer: 4

## Question 7 What is the Source IP with highest count returned with this Search query?
Search Query: index=windowslogs  Hostname="Salena.Adam" DestinationIp="172.18.38.5"
![image](https://github.com/user-attachments/assets/95e06f45-2a25-4379-9f77-6fee9ee6ab27)
Answer: 172.90.12.11

## Question 8 In the index windowslogs, search for all the events that contain the term cyber how many events returned?
![image](https://github.com/user-attachments/assets/fe606ea9-6172-442b-a23a-cac127fe34e5)

This searches for the occurence of the word cyber wihtout any leading or trailing characters

Answer: 0

## Question 9 Now search for the term cyber*, how many events are returned?
We can also look for occurences where a word starts with cyber 
![image](https://github.com/user-attachments/assets/55ee6534-30b5-4c57-802f-89debbe3ebb5)

Answer: 12256

# Filtering the Results in SPL

## Question 10 What is the third EventID returned against this search query?
Applying filters allows us to se only the results we are truly interested in and helps remove the noise from investigations. It can also be useful in formatting the data presented to us in a more digestable format such as a table.
Using the provided query:
index=windowslogs | table _time EventID Hostname SourceName | reverse

We are telling splunk to crate a table using time to order the results newest to oldest, then were asking to only see the eventid, the hostname and the sourcename. This is then piped to the reverse command to reverse the order of time to oldest to newest.
![image](https://github.com/user-attachments/assets/f57fff6f-c6d3-4c1c-8a46-bfb079d77498)

Answer: 4103

## Question 11 Use the dedup command against the Hostname field before the reverse command in the query mentioned in Question 1. What is the first username returned in the Hostname field?
When we want to identify the unique hostnames beign used in a large amount fo traffic so we can begin to understand exactly what usernames were used in the capture we can usee the dedup command in our previous filter to display only the first result for each unique hostname. Whilst this removes alot of information it also allows us to narrow down the amount of users available to determine if any are malicious actors.
![image](https://github.com/user-attachments/assets/e5f9d2d5-631c-4184-995e-69fc9034f15b)

Answer: Salena.Adam

# SPL - Structuring the Search Results

## Question 12 Using the Reverse command with the search query index=windowslogs | table _time EventID Hostname SourceName - what is the HostName that comes on top?
Alongside being able to filter the results to contain exactly what we need we can also perform operations to sort the results as we see fit. If we need to see the oldest events we can use the reverse command. If we want to view results based on specific fields we can sue the sort command to order them as we see fit

In this example we are flipping the oldest time events to the top so we can see how the attack began

![image](https://github.com/user-attachments/assets/9410bfbe-02df-4dd1-8d46-00f67f3c68e9)

Answer:James.browne

## Question 13 What is the last EventID returned when the query in question 1 is updated with the tail command?
The tail command by default displays the last ten rows within our results and is useful to get an idea of the final actions taken for a specific search query.
![image](https://github.com/user-attachments/assets/ff3faf12-075e-4931-b1e0-547e0cc5293c)

Answer: 4103

## Question 14 Sort the above query against the SourceName. What is the top SourceName returned?
Finally we can use any field available to us to begin sorting the results by that field, by default it works in ascending order, for numerical fields this will go from 0 onwards, and for text it will go from A-Z
We can append this to the end of our query like so
![image](https://github.com/user-attachments/assets/011455a5-6ecb-4d8c-ae96-9091bab85bd0)

Answer: Microsoft-Windows-Directory-Services-SAM

# Transformational Commands in SPL
These commands are used to perform some sort of statistics on the results of our query, this can be as simple as counting the top and bottom occurence values for a field or higlighting relevant fields in the results.
It can also take on a more advanced statistical evaluation with the STATS command which include average, sum, count max and min. Furthermore we can use chart and timechart to produce graphical representations of the query results.


## Question 15 List the top 8 Image processes using the top command -  what is the total count of the 6th Image?
![image](https://github.com/user-attachments/assets/a7d5034e-56d1-433c-bf6b-f7e09749e49c)

Answer: 196

## Question 16 Using the rare command, identify the user with the least number of activities captured?
![image](https://github.com/user-attachments/assets/b8be91dc-82c0-4a33-9b3c-edb28b7d92f3)

Answer: James 

## Question 17 Create a pie-chart using the chart command - what is the count for the conhost.exe process?
![image](https://github.com/user-attachments/assets/f789b686-ac83-41e2-b42b-ebc08465e23f)

Answer: 70

# Conclusion
In this lab we learned how to perform spl queries which can be searched, filtered and visualised using the operators we leanred about today. This is useful for future investigations where we will use these commands to drilldown into logs to find occurences of evil. This was the basic Splunk introduction which equipped us with enough syntax to be able to reduce the noise in situations where logs are in abundance.

