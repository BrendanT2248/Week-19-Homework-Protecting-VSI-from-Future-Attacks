# Week-19-Homework-Protecting-VSI-from-Future-Attacks

## Scenario
_In the previous class,  you set up your SOC and monitored attacks from JobeCorp. Now, you will need to design mitigation strategies to protect VSI from future attacks._

_You are tasked with using your findings from the Master of SOC activity to answer questions about mitigation strategies._

## System Requirements
_You will be using the Splunk app located in the Ubuntu VM._

## Part 1: Windows Server Attack
_Note: This is a public-facing windows server that VSI employees access._

### Question 1

- **Several users were impacted during the attack on March 25th.**

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
