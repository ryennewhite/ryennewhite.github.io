---
title: Intro to Web App Attacks
date: 2024-01-15 08:35:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Web App Attack tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Intro to Web App Attacks

With the knowledge of common web app vulnerabilities, such as what we can learn from [OWASP Top 10](https://owasp.org/www-project-top-ten/), we will leverage Nmap, Wappalyzer, Gobuster, and Burp Suite to conduct testing.

## Web Application Assessment Tools

### Fingerprinting Web Servers with Nmap
```console
$ sudo nmap -p80 -sV 111.111.111.111
$ sudo nmap -p80 --script=http-enum 111.111.111.111    // script performs initial fingerprinting of webserver
```

### Tech Stack Identification with Wappalyzer
