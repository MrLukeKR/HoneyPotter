#!/bin/python

# AbuseIPDB Cateogries
# --------------------
# 1	    DNS Compromise	    Altering DNS records resulting in improper redirection.
# 2	    DNS Poisoning	    Falsifying domain server cache (cache poisoning).
# 3	    Fraud Orders	    Fraudulent orders.
# 4	    DDoS Attack	        Participating in distributed denial-of-service (usually part of botnet).
# 5	    FTP Brute-Force	
# 6	    Ping of Death	    Oversized IP packet.
# 7	    Phishing	        Phishing websites and/or email.
# 8	    Fraud VoIP	
# 9	    Open Proxy	        Open proxy, open relay, or Tor exit node.
# 10	Web Spam	        Comment/forum spam, HTTP referer spam, or other CMS spam.
# 11	Email Spam	        Spam email content, infected attachments, and phishing emails. Note: Limit comments to only relevent information (instead of log dumps) and be sure to remove PII if you want to remain anonymous.
# 12	Blog Spam	        CMS blog comment spam.
# 13	VPN IP	            Conjunctive category.
# 14	Port Scan	        Scanning for open ports and vulnerable services.
# 15	Hacking	
# 16	SQL Injection	    Attempts at SQL injection.
# 17	Spoofing	        Email sender spoofing.
# 18	Brute-Force	        Credential brute-force attacks on webpage logins and services like SSH, FTP, SIP, SMTP, RDP, etc. This category is seperate from DDoS attacks.
# 19	Bad Web Bot	        Webpage scraping (for email addresses, content, etc) and crawlers that do not honor robots.txt. Excessive requests and user agent spoofing can also be reported here.
# 20	Exploited Host	    Host is likely infected with malware and being used for other attacks or to host malicious content. The host owner may not be aware of the compromise. This category is often used in combination with other attack categories.
# 21	Web App Attack	    Attempts to probe for or exploit installed web applications such as a CMS like WordPress/Drupal, e-commerce solutions, forum software, phpMyAdmin and various other software plugins/solutions.
# 22	SSH	                Secure Shell (SSH) abuse. Use this category in combination with more specific categories.
# 23	IoT Targeted	    Abuse was targeted at an "Internet of Things" type device. Include information about what type of device was targeted in the comments.

import json
import requests
import urllib
import os

abuseIPDBKey=""
reported_ips = []

def reportIP(ip_address, abuse_types, comment):
    global abuseIPDBKey, reported_ips

    if ip_address in reported_ips:
        return

    data = {"ip": ip_address, "categories": abuse_types, "comment": comment}
    headers = {"Key": abuseIPDBKey, "Accept": "application/json"}

    resp = requests.post("https://api.abuseipdb.com/api/v2/report", data=data, headers=headers)
    
    reported_ips.append(ip_address)

    with open("reported_ips.txt", "a") as ipfile:
        ipfile.write(ip_address + '\n')    
    
    print(resp.text)
    print ("IP ADDRESS REPORTED")
        

def main():
    global abuseIPDBKey, reported_ips

    if not os.path.exists("reported_ips.txt"):
        open("reported_ips.txt", "w")

    with open("reported_ips.txt", "r") as ipfile:
        reported = ipfile.readlines()
        for line in reported:
            reported_ips.append(line.replace('\n',''))
            print(reported_ips)

    with open("reportAbuseAPIKey.txt", "r") as apikey:
        abuseIPDBKey = apikey.read().replace('\n','')

    with open("../opencanary.log", "r") as infile:
        lines = infile.readlines()

        for line in lines:
            data = json.loads(line)
            logtype = data['logtype']
            report_ip=""
            report_type=""
            report_comment=""
                
            if logtype == 4002: # SSH login attempt
                print("SSH LOGIN ATTEMPT:")
                print("\tUsername: " + data['logdata']['USERNAME'])
                print("\tPassword: " + data['logdata']['PASSWORD'])
                print("\tIP Address: " + data['src_host'])
                
                report_ip = data['src_host']
                report_type=(18,22)

                report_comment += "UTC Time: " + data['utc_time'] + '\n'
                report_comment += "Username: " + data['logdata']['USERNAME'] + '\n'
                report_comment += "Password: " + data['logdata']['PASSWORD'] + '\n'
                report_comment += "Local SSH: " + data['logdata']['LOCALVERSION'] + '\n'
                report_comment += "Remote SSH: " + data['logdata']['REMOTEVERSION']
                
            if (report_ip != "" and report_ip not in reported_ips):
                reportIP(report_ip, report_type, report_comment)

if __name__ == "__main__":
    main()