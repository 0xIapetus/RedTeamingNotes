# GitHub Cheatsheet for PowerShell Commands

## Summary
- [General](#general)
- [Initial Recognition](#initial-recognition)
- [Domain Enumeration](#domain-enumeration)

## General
Commands to bypass execution policy and other general PowerShell commands.
- `powershell–ExecutionPolicy bypass`
- `powershell–c <cmd>`
- `powershell–encodedcommand`
- `$env:PSExecutionPolicyPreference="bypass"`

## Initial Recognition
Commands for initial reconnaissance including system info, network stats, and user privileges.
- **Netstat:** `netstat -na`
- **ARP Table:** `arp -a`
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
- **LDAP Enumeration:** Examples with 
`Get-ADUser -Filter * -SearchBase "CN=Users,DC=EIMAIREDTEAM,DC=COM"`Using the SearchBase option, we specify a specific Common-Name CN,The DN consists of Domain Component (DC), OrganizationalUnitName (OU), Common Name (CN)

- **AV Detection:** `wmic /namespace:\root\securitycenter2 path antivirusproduct` and `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct` Windows servers may not have SecurityCenter2 namespace, but workstations have
- **File and Directory Permissions:** Owner of a directory `Get-Acl c:/`, View the permissions set on a directory `icacls <directory>`, give full perms on dir`icacls c:\users /grant joe:f` , Remove a users' permissions on a directory
`icacls c:\users /remove joe` and `Get-Location` = pwd
- **Processes** `Get-Process`
- **Listening Ports and Installed Updates:** `Get-NetTCPConnection | Where-Object -Property state -Match Listen `, `wmic qfe get Caption, Description`, and `Get-HotFix`, `Get-Hotfix -Id KB4023834`
- **Scheduled Tasks:** Examples with `Get-ScheduledTask -TaskName new-sched-task` and `schtasks /query /tn vulntask /fo list /v`
- **File Searches:** ``Get-ChildItem -Path C:\ -Include *interesting-fle.txt* -File -Recurse -ErrorAction SilentlyContinue` and `Get-Content "C:\Program Files\interestingfile.txt.txt"` for specific files

## Domain Enumeration
Commands specific to domain enumeration, including user and group listings, domain controllers, and policies.
- **Current Domain Information:** `Get-Domain` (PowerView), `Get-ADDomain` (ActiveDirectory Module)
- **Domain SID and Policy:** `Get-Domain–Domain moneycorp.local`, `Get-DomainPolicyData`
- **Domain Controllers:** Listing and discovering domain controllers with `Get-DomainController`, `Get-ADDomainController`
- **User Listings:** Examples with `Get-DomainUser`, `Get-ADUser`
- **Group Listings:** Commands to list groups, including admin groups, with `Get-DomainGroup`, `Get-ADGroup`
- **Group Memberships:** Detailed commands to list group memberships and properties
- **Active Users and Logon Counts:** Identifying active users and checking for high logon counts
- **Computer Listings:** Enumerating computers in the domain with `Get-DomainComputer`, `Get-ADComputer`
- **Local Group Memberships:** Examples with `Get-NetLocalGroup`, `Get-NetLocalGroupMember`
- **Logged and Last Logged Users:** Identifying currently and last logged users with `Get-NetLoggedon`, `Get-LoggedonLocal`, `Get-LastLoggedOn`
