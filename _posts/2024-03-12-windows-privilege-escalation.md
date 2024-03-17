---
title: Windows Privilege Escalation
date: 2024-03-12 03:53:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Windows Privilege Escalation tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Windows Privilege Escalation

We often gain footholds on Windows systems as an unprivileged user. 

## Enumerating Windows

While we may use some technical attack vectors to escalate privileges, it can often be enough to just review information that users and the system leave behind, like when they store passwords in a .txt or when Windows records the input of a password in PowerShell.

### Understanding Windows Privileges and Access Control Mechanisms
