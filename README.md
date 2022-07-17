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

**Global Mitigations**

As this is a brute force attack, there are several global mitigation strategies that could be put in place here:

- Keep all systems up to date with the latest security updates and patches. This is important to combat against the latest cyber threats.
- Have endpoint protection installed on all machines to detect any potential malicous files users could of accidentally downloaded.
- Develop a password policy that is strong. This can include the user needing to change their password every 3 months, having a long minimum character limit such as 10 and the password required needs to include an upper-case, lower-case, number and symbol.
- A firewall to filter out users accidentally navigating to potentially malicious sites. 
- Enable automatic scanning of files when received externally either through email or FTP

**Individual Mitigations**

- Limit account lockouts for individual accounts for up to 3 hours if there is up to 10 incorrect logins within the hour. If attempts continue, escalte time as needed.
- Educate employees on the dangers of cyber threats, such as simulated phishing scenarios, the importance of user account security and other cyber awareness training sessions. 
- Enforce two-factor authentication for all individuals for work accounts. Ensure this is enforced by going through the process with each individual user and make sure they understand what two-factor is and not to accept any notifcation if it is not them attempting a log in. 

### Question 2

- **VSI has insider information that JobeCorp attempted to target users by sending "Bad Logins" to lock out every user.
What sort of mitigation could you use to protect against this?**

I would implement the following mitigation strategies:

- Ensure two-factor authentication is set up for every user. As well as this, back it up with a phone number to increase user account security. 
- Ensure the password policy is in place and effective. Complexity levels are met as well as the user needing to change their password every 3 months. 
- Ensure account lockouts are set up - if an account attempts a login up to 10 times in the hour unsuccssfully.
- To protect against users accidentally sending their password out on the Internet we can encrypt cookies and enable the 'do not remember' password function within the browser. 

## Part 2: Apache Webserver Attack:

### Question 1

- **Based on the geographic map, recommend a firewall rule that the networking team should implement.
Provide a "plain english" description of the rule.**

  - **For example: "Block all incoming HTTP traffic where the source IP comes from the city of Los Angeles."**

- **Provide a screen shot of the geographic map that justifies why you created this rule.**

Firstly, we need to gather some information and understand where all these HTTP requests are coming from. From there we can create a rule to block all incoming HTTP traffic from that location. 

By entering `source="apache_attack_logs.txt"  | iplocation clientip  | search NOT Country IN ("United States") | top limit=10 Country`, we are able to see the top 10 countries that are sending HTTP traffic from their client IP address. This search also filters out the United States, as we do not need to know the count of this as this is the native country. 

![Apache iplocation 1](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/apache%20iplocation%20count.PNG)

We can see from the above image that the Ukraine is sending a suspicously high amount of HTTP traffic for an external country. There is a total count of 877 requests being sent from Ukraine, significantly higher than the next external country of Sweden with 198. The column chart below also displays this:

![Apache iplocation 2](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/apache%20iplocation%20count%202.png)

We can also see that alot of these requests came at a particular time. This could be an indicator of some sort of attack, since multiple HTTP requests are being sent in a short amount of time from one specific country - the Ukraine.

![Apache iplocation 3](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/apache%20iplocation%20count%204.png)

To gain a visual view of this, we can look at these statitics on a visual map, by using the query `source="apache_attack_logs.txt"  | iplocation clientip  | search NOT Country IN ("United States") | geostats count`

![Apache geostats 1](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/apache%20geostats%201.png)

We can zoom in further on the map:

![Apache geostats 2](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/apache%20geostats%202.png)

From this, I believe a solid firewall rule would be to block all incoming HTTP traffic wherbey the source IP is from the Ukraine.

I also created a dashboard to display this information as well as further information, such as most common HTTP methods over time and different user agent count:

![Apache dash 1](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/apache%20dash%201.PNG)

![Apache dash 2](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/apache%20dash%202.PNG)

![Apache dash 3](https://github.com/BrendanT2248/Week-19-Homework-Protecting-VSI-from-Future-Attacks/blob/main/Images/apache%20dash%203.PNG)

### Question 2

- **VSI has insider information that JobeCorp will launch the same webserver attack but use a different IP each time in order to avoid being stopped by the rule you just created.**

- **What other rules can you create to protect VSI from attacks against your webserver?**

  - **Conceive of two more rules in "plain english".**
  - **Hint: Look for other fields that indicate the attacker.**
