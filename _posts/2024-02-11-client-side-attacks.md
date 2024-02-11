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

NOTE: MOTW is not added to files on FAT32-formatted devices.
NOTE: We can avoid the MOTW flag by providing our malicious file in a 7zip, ISO, or IMG.

It is important to note that some Microsoft Office programs, like Publisher, don't have Protected View, but we are also less likely to find them installed.

Microsoft has blocked macros by default on most versions of PowerPoint, Word, Excel, Access, and Visio since Office 2013. This removes the user's ability to click one button on the yellow warning banner to enable the content, and they must unlock the macro by checking Unblock under file properties.

### Installing Microsoft Office

NOTE: On Windows 11, NLA is default-enabled for RDP connections, and if our target machine is not domain-joined, rdestop will not connect to it. Instead, use xfreerdp, which supported NLA for non-domain-joined machines.

```console
$ xfreerdp /u:offsec /p:lab /v:192.168.195.196
```

### Leveraging Microsoft Word Macros

Office apps like Excel and Word allow embedded macros that are a series of commands and instructions in a group that accompish some task programatically.

NOTE: We can write macros from scratch in Visual Basic for Applications (VBA) which has full access to ActiveX objects and the Windows Script Host, similar to JS in HTML apps.

Let's use an embedded macro in Word for a reverse shell! 

NOTE Older client-side attack vectors, like Dynamic Data Exchange (DDE) and various Object Linking and Embedding (OLE) methods will work poorly without modifying our target system significantly.

