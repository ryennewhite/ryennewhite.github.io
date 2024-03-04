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
