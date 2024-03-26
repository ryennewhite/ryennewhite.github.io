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
