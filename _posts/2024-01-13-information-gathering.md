---
title: Information Gathering
date: 2024-01-13 10:04:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---

*The Information Gathering tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Information Gathering

## Passive Information Gathering - OSINT

### Whois

Whois uses TCP to gather information on a domain name, like its registrar and name server.

```console
$ whois target.com -h ipofmywhoisserver
$ whois targetip -h ipofmywhoisserver
```


### Google Hacking

Google Hacking uses the Google Search Engine to refine search query results and uncover critical information using special operators.

Within the Google Search Engine Bar, try:

```
site:target.com filetype:php
-filetype:html  // the "-" sign here excludes html pages from search results
intitle:"index of" "parent directory"
```

Additional Resources:
- https://dorksearch.com/
- https://www.exploit-db.com/google-hacking-database


### Netcraft

[Netcraft](https://searchdns.netcraft.com) discovers the specific technologies used on a server and identifies neighboring hosts on an IP netblock.


### Open-Source Code

We can search open-source code for credentials and other sensitive information left behind by developers.

GitHub Search

```
owner:targetorg
path:users
```

[Gitleaks](https://github.com/gitleaks/gitleaks)

```console
$ ./gitleaks -v -r=https://github/com/targetrepository
```

[Gitrob](https://github.com/michenriksen/gitrob)

```console
$ ./gitrob targetuser
```


### Shodan

[Shodan](https://www.shodan.io/) crawls the internet for connected servers, routers, IoT, and more, discovering IPs, ports, running services, and technologies.

Within the Shodan search engine, try:

```
hostname:target.com
```


### Security Headers and SSL/TLS

[Security Headers](https://securityheaders.com/) looks at HTTP response headers and provides a report on a site's security.

This includes information on the missing security headers we can attempt to leverage in our penetration test, like X-Frame-Options and Content-Security-Policy.

[SSL Server Test](https://www.ssllabs.com/ssltest/) compares a site's SSL/TLS config against industry standard best practices.


## Active Information Gatherting

### DNS Enumeration

DNS translates domain names into IP addresses.

DNS Record Types:

- NS: Nameserver
- A: IPv4 Address
- AAAA: IPv6 Address
- MX: Mail Exchange
- PTR: Used in reverse lookup zones and finds records associated with an IP
- CNAME: Canonical Name, creates aliases for other host records
- TXT: Various purposes, can contain arbitrary data

```console
$ host www.target.com
$ host -t mx target.com
$ host -t txt target.com

// Automate:

$ nano list.txt
www
ftp
mail
owa
proxy
router

$ for ip in $(cat list.txt); do host $ip.target.com;done
$ for ip in $(seq 200 254); do host 111.111.111.$ip; done | grep -v "not found"

// You can also try seclists: https://installati.one/install-seclists-kalilinux/
```

[DNSRecon](https://github.com/darkoperator/dnsrecon)
```console
$ dnsrecon -d target.com -t std  // -d for domain and -t std for type = standard
$ dnsrecon -d target.com -D ~/list.txt -t brt
```

DNSenum
```console
$ dnsenum target.com
```

Nslookup
```console
$ nslookup mail.target.com
$ nslookup -type=TXT info.target.com targetip
```


### TCP/UDP Port Scanning Theory

Netcat

```console
$ nc -nvv -w 1 -z targetip 3388-3390  // -w for timeout, -z for zero-I/O mode
$ nc -nv -u -z -w 1 targetip 120-123  // -u for UDP scan
```


### Port Scanning with Nmap

Nmap

```console
$ nmap targetip
$ nmap -p 1-65535 targetip
$ sudo nmap -sS targetip  // stealth SYN scan
$ nmap -sT targetip  // TCP full-connect scan (non-stealth)
$ sudo nmap -sU targetip  // UDP scan
$ sudo nmap -sU -sS targetip  // UDP and TCP scan
$ nmap -sn 111.111.111.1-253  // network sweep, verifies if host is up
$ nmap -v -sn 111.111.111.1-253 -oG ping-sweep.txt  // -oG for greppable output
   $ grep UP ping-sweep.txt | cut -d " " -f 2
$ nmap -p 80 111.111.111.1-253 -oG web-sweep.txt  // more accurate than ping-sweep
   $ grep open web-sweep.txt | cut -d" " -f2
$ nmap -sT -A --top-ports=20 111.111.111.1-253 -oG top-port-sweep.txt // -A for OS version detection, script scanning, and traceroute
$ sudo nmap -O targetip --ossscan-guess  // -O for OS fingerprinting, --osscan-guess to force nmap to print guess even if it may not be accurate
$ nmap -sT -A targetip  // -A to run OS and service enum scripts
$ nmap -sV -A targetip  // -sV for plain service scan
```

Nmap Scripting Engine (NSE) - /usr/share/nmap/scripts

```console
$ nmap --script http-headers targetip  // connects to http service on target and reports supported headers

```

On Windows? Use PowerShell:

```console
> Test-NetConnection -Port 445 targetip  // SMB port 445
> 1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("targetip", $_)) "TCP port $_ is open"} 2>$null  // one-liner to scan first 1024 ports
```


### SMB Enumeration

```console
$ nmap -v -p 139,445 -oG smb.txt 111.111.111.1-254  // enumerates SMB and NetBIOS over TCP
```

nbtscan - identifies NetBIOS information
```console
$ sudo nbtscan -r 111.111.111.0/24
$ ls -1 /usr/share/nmap/scripts/smb*  // find nmap NSE scripts for discovery & enum
$ nmap -v -p 139,445 --script smb-os-discovery targetip
```

On Windows? 
```console
> net view \\dc01 /all  // net view lists domains, resources, and computers belonging to a host
```

Enumerate what you found:
```console
$ enum4linux -a 111.111.111.0/24
```


### SMTP Enumeration

Found a host listening for SMTP? Try connecting and checking for users.
```console
$ nc -nv targetip 25
$ VRFY root  // any username
```

To automate with python:
```python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)

print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)

print(result)

# Close the socket
s.close()

```

Run script:
```console
$ python3 smtp.py root targetip
$ python3 smtp.py johndoe targetip
```

On Windows?
```console
> Test-NetConnection -Port 25 targetip  // cannot interact with SMTP Service

// so, install Telnet (requires admin privs)
> dism /online /Enable-Feature /FeatureName:TelnetClient

// don't have admin? pull a copy from another machine: c:\windows\system32\telnet.exe
> telnet 192.168.50.8 25
```


### SNMP Enumeration

SMTP uses UDP, making it stateless and vulnerable to spoofing and relays. It is also often not encrypted, allowing us to intercept creds and other sensitive information.

SNMP MIB Trees contain network management information.

<img width="232" alt="image" src="https://github.com/ryennewhite/study-oscp/assets/112822039/f6c4740d-fa75-4029-8af1-5d94546d9d7d">


```console
$ sudo nmap -sU --open -p 161 111.111.111.1-254 -oG open-snmp.txt  // scan for open snmp ports (use -U for UDP!)
```

Or, we can use onesixtyone to brute force a list of IPs.
```console
$ echo public > community
$ echo private >> community
$ echo manager >> community
$ for ip in $(seq 1 254); do echo 111.111.111.$ip; done > ips
$ onesixtyone -c community -i ips
```

Using MIB values from the above screenshot, we can enumerate further.
```console
$ snmpwalk -c public -v1 -t 10 targetip  // -c to enum the entire MIB tree
$ snmpwalk -c public -v1 targetip 1.3.6.1.4.1.77.1.2.25  // enums users
$ snmpwalk -c public -v1 targetip 1.3.6.1.2.1.25.4.2.1.2  // enums running processes
$ snmpwalk -c public -v1 targetip 1.3.6.1.2.1.25.6.3.1.2  // enums all installed software
$ snmpwalk -c public -v1 targetip 1.3.6.1.2.1.6.13.1.3 // enums all current TCP listening ports
```
