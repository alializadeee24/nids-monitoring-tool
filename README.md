# Task 4 - Network Intrusion Detection System (Suricata)
**Pipeline:** traffic -> Suricata (rules) -> `eve.json` -> `nids_tool.py` (live alerts, auto-block, dashboard).

## 1. Install (Ubuntu/Kali)
```
sudo apt install suricata
sudo suricata-update                       # download ET Open rules
```
## 2. Configure
In `/etc/suricata/suricata.yaml`: set `HOME_NET: "[192.168.0.0/16]"`, `af-packet: - interface: eth0`, and add under `rule-files:` -> `local.rules`.
```
sudo cp local.rules /var/lib/suricata/rules/local.rules
sudo suricata -T -c /etc/suricata/suricata.yaml      # test config
sudo systemctl restart suricata
```
## 3. Monitor + respond
```
sudo python3 nids_tool.py monitor --eve /var/log/suricata/eve.json          # dry-run
sudo python3 nids_tool.py monitor --eve /var/log/suricata/eve.json --block  # real iptables block
python3 nids_tool.py dashboard      # then open dashboard.html
```
## 4. Test (own lab only)
`nmap -sS <target-ip>` (scan rule), `curl "http://target/?id=1 union select 1"` (SQLi), `hydra`/repeated ssh attempts (brute force). No lab? `python3 nids_tool.py demo --eve demo.json && python3 nids_tool.py dashboard --eve demo.json`.

## Rules covered
Ping flood, SYN scan, SSH/FTP brute force, SQLi, XSS, directory traversal, scanner user-agents, DNS tunnelling, reverse shell port, Telnet.
## Response mechanisms
3 alerts in 60 s from one IP -> iptables DROP for 1 h, whitelist for trusted hosts, dry-run safety mode.
