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
[Create a free account.](https://www.wappalyzer.com)

Perform a Technology Lookup on your target domain.

Results show details about the technology stack supporting the web server, including JavaScript libraries, many of which are vulnerable.

### Directory Brute Force with Gobuster
Gobuster enumerates publically-accessible files and directories using wordlists.

```console
$ gobuster dir -u 111.111.111.111 -w /usr/share/wordlists/dirb/common.txt -t 5
```

### Burp Suite
```console
$ burpsuite
```
#### Proxy Tool
Intercept requests from the browser before they are passed to the server.

Burp's default proxy listener is on port 8080, so set up both the Burp Proxy > Options and your internet browser's Network Proxy Settings to localhost:8080.

The Proxy > HTTP History shows requests and responses. 

In Proxy > HTTP History, select an entry, right click, and Send to Repeater. This allows you to modify requests in History and resend them.

#### Intruder
Intruder automates various attacks.

We need to configure our local Kali's hosts file to statically assign the IP to the target website.
```console
$ sudo nano /etc/hosts

// add line for target

$ cat etc/hosts
...
111.111.111.111 targetsite
```
Example Brute Force attack:


Navigate to a login page and enter any username and password, like "admin" and "test". Submit.

In Proxy > HTTP History, right click the POST to the login page and Send to Intruder.

In the Intruder tab, select the POST to modify and move to the Positions sub-tab.

Press Clear on the right hand side to remove all fields.

Select the password key value and press "Add".

In the Payloads tab, paste your chosen word list in the Payload Opetions [Simple list] section.

Click "Start Attack".

In the Results tab, look for requests that have different Status codes or Lengths.

## Web Application Enumeration

Firefox's Debugger tool in the Web Developer menu shows page resources and content, like JavaScript frameworks, hidden input fields, software versions, and client-side controls.

Right clicking on a field and navigating to the Inspect tool, we can see the related HTML, often showing us hidden form fields to test.
