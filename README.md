# Email Phishing Challenge

Welcome to the Email Phishing Challenge! In this challenge, you will analyze an email sample to determine if it is a phishing attempt. The task involves extracting key details from the email and investigating the associated domain to assess its legitimacy. Could you follow the steps and answer the questions below?

## Challenge Overview

You are provided a **sample email file** uploaded to this repository. To access the file, use the following password:  
**Password: phishing**

## Questions to Answer:

1. **What is the return path of the email?**
   - Locate the return path in the email headers. This address is usually found in the “Return-Path” or “Reply-To” field.

2. **What is the domain name of the URL in this email?**
   - Identify any URLs in the email body and extract the domain name. You can use regular expressions or a URL parsing tool to assist in this task.

3. **Is the domain mentioned in the previous question suspicious?**
   - Investigate the domain using online tools like [VirusTotal](https://www.virustotal.com/), [URLVoid](https://www.urlvoid.com/), or a WHOIS lookup service. Check if the domain has been flagged or is newly registered, as phishing domains often have a limited history.

4. **What is the body SHA-256 of the domain?**
   - Generate the SHA-256 hash for the email body using a hash generator. This can help in comparing the email content to known phishing campaigns.

5. **Is this email a phishing email?**
   - Summarize your analysis and provide your conclusion. Be sure to back up your decision with the evidence you've gathered from the return path, URL domain, and email content.

## Tools & Resources

- [Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx): Use this tool to extract and analyze email headers.
- [VirusTotal](https://www.virustotal.com/): For scanning URLs and domains for malicious behavior.
- [WHOIS Lookup](https://whois.domaintools.com/): To gather information about the domain registration and owner.
