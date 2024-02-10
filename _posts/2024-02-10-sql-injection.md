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

```sql
SELECT * FROM users WHERE user_name='bob'
```
