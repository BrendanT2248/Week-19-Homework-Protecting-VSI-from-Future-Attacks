# Week-19-Homework-Protecting-VSI-from-Future-Attacks

## Scenario
_In the previous class,  you set up your SOC and monitored attacks from JobeCorp. Now, you will need to design mitigation strategies to protect VSI from future attacks._

_You are tasked with using your findings from the Master of SOC activity to answer questions about mitigation strategies._

## System Requirements
_You will be using the Splunk app located in the Ubuntu VM._

## Logs
_Use the same log files you used during the Master of SOC activity:_

- [Windows Logs](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Log%20Files/windows_server_logs.csv)
- [Windows Attack Logs](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Log%20Files/windows_server_attack_logs.csv)
- [Apache Webserver Logs](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Log%20Files/apache_logs.txt)
- [Apache Webserver Attack Logs](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Log%20Files/apache_attack_logs.txt)

## Part 1: Windows Server Attack
_Note: This is a public-facing windows server that VSI employees access._

### Question 1

- **Several users were impacted during the attack on March 25th.**

From the 'Windows Server Attack Logs', we can see there were numerous attempts of attempting to reset an accounts password and 
accounts being locked out. 

We know this if we filter for the top signatures recorded in the log files by entering the query `source="windows_server_attack_logs.csv" | top limit=20 signature`

![Windows signatures count](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/windows%20attack%20signatures%20count.PNG)

We can then drill into these signature attempts and when they occurred throughout March 25th. 

By entering `source="windows_server_attack_logs.csv" signature="An attempt was made to reset an accounts password"` we can see a timeline hour by hour and at around 9am there were around 1258 attempts made to reset a user accounts password. 

![Windows reset passwords count](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/windows%20attack%20signature%20reset%20password%20attempts.png)

There were also 805 user account lockouts that occurred at 1am, 8 hours previous to the attempts to reset the accounts passwords by entering `source="windows_server_attack_logs.csv" signature="A user account was locked out"`

![Windows User Locket count](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/windows%20user%20lockout%20count.png)

We also want to find out which users are affected. By entering `source="windows_server_attack_logs.csv"| top limit=20 user`, we are able to see the count for users affected by these events. 

![Windows user event count](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/windows%20attack%20user%20count.PNG)

As we can see `user_k` and `user_a` have the highest counts of 2118 and 1878 over this period of time. However, there are also several other accounts that do have quite a high count. 

I also created a dashboard to reflect the count of signatures and users affected. See below: 

![Windows Dash 1](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/windows%20attack%20logs%20dash%201.PNG)

![Windows Dash 2](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/windows%20attack%20logs%20dash%202.PNG)

- **Based on the attack signatures, what mitigations would you recommend to protect each user account? Provide global mitigations that the whole company can use and individual mitigations that are specific to each user.**



### Question 2

- **VSI has insider information that JobeCorp attempted to target users by sending "Bad Logins" to lock out every user.
What sort of mitigation could you use to protect against this?**


## Part 2: Apache Webserver Attack:

### Question 1

- **Based on the geographic map, recommend a firewall rule that the networking team should implement.
Provide a "plain english" description of the rule.**

  - **For example: "Block all incoming HTTP traffic where the source IP comes from the city of Los Angeles."**

- **Provide a screen shot of the geographic map that justifies why you created this rule.**

### Question 2

- **VSI has insider information that JobeCorp will launch the same webserver attack but use a different IP each time in order to avoid being stopped by the rule you just created.**

- **What other rules can you create to protect VSI from attacks against your webserver?**

  - **Conceive of two more rules in "plain english".**
  - **Hint: Look for other fields that indicate the attacker.**




Guidelines for your Submission:
In a word document, provide the following:

Answers for all questions.
Screenshots where indicated
