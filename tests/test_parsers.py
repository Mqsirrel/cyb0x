"""Unit tests for scanner parsers (Nmap XML, Gnmap, Text, Rustscan, Masscan, NetExec)."""

import pytest
from synapse.parsers.masscan_parser import parse_masscan_json
from synapse.parsers.netexec_parser import parse_netexec_output
from synapse.parsers.nmap_parser import parse_nmap_gnmap, parse_nmap_text, parse_nmap_xml
from synapse.parsers.rustscan_parser import parse_rustscan_json

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC -p 22,80 10.10.11.50" start="1600000000">
<host starttime="1600000000" endtime="1600000010">
<status state="up" reason="syn-ack"/>
<address addr="10.10.11.50" addrtype="ipv4"/>
<hostnames>
  <hostname name="target.htb" type="user"/>
</hostnames>
<ports>
  <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="8.4p1 Debian 5+deb11u1" extrainfo="Debian Linux; protocol 2.0"/>
  </port>
  <port protocol="tcp" portid="80">
    <state state="open" reason="syn-ack"/>
    <service name="http" product="Apache httpd" version="2.4.56" extrainfo="(Debian)"/>
    <script id="http-title" output="Login - Vulnerable Portal"/>
  </port>
  <port protocol="tcp" portid="443">
    <state state="closed" reason="reset"/>
  </port>
</ports>
<os>
  <osmatch name="Linux 5.4 - 5.10" accuracy="95"/>
</os>
</host>
</nmaprun>
"""

SAMPLE_GNMAP = """# Nmap 7.94 scan initiated
Host: 10.10.11.60 (srv.local) Ports: 21/open/tcp//ftp//vsftpd 3.0.3/, 445/open/tcp//microsoft-ds//Samba 4.9.5/
# Nmap done
"""

SAMPLE_NMAP_TEXT = """
Nmap scan report for dev.local (10.10.11.70)
Host is up (0.045s latency).
Not shown: 998 closed tcp ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
8080/tcp open  http    Apache Tomcat 9.0.41
OS details: Linux 4.15 - 5.6
"""

SAMPLE_RUSTSCAN = """
Open 10.10.11.80:21
Open 10.10.11.80:80
Open 10.10.11.80:3306
"""

SAMPLE_MASSCAN_JSON = """[
  { "ip": "10.10.11.90", "ports": [ {"port": 80, "proto": "tcp"}, {"port": 443, "proto": "tcp"} ] }
]"""

SAMPLE_NETEXEC_LOG = """
SMB         10.10.11.100    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL)
SMB         10.10.11.100    445    DC01             [+] CORP.LOCAL\\administrator:aad3b435b51404eeaad3b435b51404ee (Pwn3d!)
WINRM       10.10.11.100   5985    DC01             [+] CORP.LOCAL\\jsmith:Welcome2024!
SMB         10.10.11.101    445    [*] Windows Server 2016 (name:FILE01) (domain:CORP.LOCAL)
SMB         10.10.11.101    445    [+] CORP.LOCAL\\backup_svc:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 (Pwn3d!)
SSH         10.10.11.102     22    srv01            [+] local\\bob:Complex Pass(1)!
"""


def test_parse_nmap_xml():
    results = parse_nmap_xml(SAMPLE_NMAP_XML)
    assert len(results) == 1
    target = results[0]
    assert target["ip"] == "10.10.11.50"
    assert target["hostname"] == "target.htb"
    assert "Linux" in target["os"]
    assert len(target["services"]) == 2

    ssh = target["services"][0]
    assert ssh["port"] == 22
    assert ssh["name"] == "ssh"
    assert "OpenSSH" in ssh["product"]

    http = target["services"][1]
    assert http["port"] == 80
    assert "http-title" in http["banner"]


def test_parse_nmap_gnmap():
    results = parse_nmap_gnmap(SAMPLE_GNMAP)
    assert len(results) == 1
    target = results[0]
    assert target["ip"] == "10.10.11.60"
    assert target["hostname"] == "srv.local"
    assert len(target["services"]) == 2
    assert target["services"][0]["port"] == 21
    assert target["services"][1]["port"] == 445


def test_parse_nmap_text():
    results = parse_nmap_text(SAMPLE_NMAP_TEXT)
    assert len(results) == 1
    target = results[0]
    assert target["ip"] == "10.10.11.70"
    assert target["hostname"] == "dev.local"
    assert len(target["services"]) == 2
    assert target["services"][1]["port"] == 8080


def test_parse_rustscan():
    results = parse_rustscan_json(SAMPLE_RUSTSCAN)
    assert len(results) == 1
    target = results[0]
    assert target["ip"] == "10.10.11.80"
    assert len(target["services"]) == 3
    ports = [s["port"] for s in target["services"]]
    assert ports == [21, 80, 3306]


def test_parse_masscan():
    results = parse_masscan_json(SAMPLE_MASSCAN_JSON)
    assert len(results) == 1
    target = results[0]
    assert target["ip"] == "10.10.11.90"
    assert len(target["services"]) == 2


def test_parse_netexec():
    res = parse_netexec_output(SAMPLE_NETEXEC_LOG)
    targets = res["targets"]
    creds = res["credentials"]

    assert len(targets) == 3
    assert targets[0]["ip"] == "10.10.11.100"
    assert targets[0]["hostname"] == "DC01"
    assert "Windows" in targets[0]["os"]

    assert targets[1]["ip"] == "10.10.11.101"
    assert targets[1]["hostname"] == "FILE01"

    assert len(creds) == 4
    admin_cred = creds[0]
    assert admin_cred["username"] == "administrator"
    assert admin_cred["cred_type"] == "ntlm_hash"
    assert admin_cred["is_admin"] is True

    user_cred = creds[1]
    assert user_cred["username"] == "jsmith"
    assert user_cred["secret"] == "Welcome2024!"
    assert user_cred["cred_type"] == "password"

    lm_ntlm_cred = creds[2]
    assert lm_ntlm_cred["username"] == "backup_svc"
    assert lm_ntlm_cred["cred_type"] == "ntlm_hash"

    spaced_cred = creds[3]
    assert spaced_cred["username"] == "bob"
    assert spaced_cred["secret"] == "Complex Pass(1)!"
