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

## Question 10 
