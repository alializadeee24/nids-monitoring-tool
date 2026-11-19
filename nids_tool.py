#!/usr/bin/env python3
"""CodeAlpha Task 4 - response + visualisation layer on top of Suricata.
  python3 nids_tool.py monitor  --eve /var/log/suricata/eve.json [--block]   # live alerts + auto-response
  python3 nids_tool.py dashboard --eve /var/log/suricata/eve.json            # builds dashboard.html
  python3 nids_tool.py demo                                                  # fake eve.json to test
Auto-block is DRY-RUN unless --block is given (needs root, uses iptables)."""
import argparse, json, subprocess, time, ipaddress, html, random, datetime
from collections import Counter, defaultdict

WHITELIST = {"127.0.0.1", "192.168.1.1"}       # never block these
THRESHOLD, WINDOW, BAN_SECONDS = 3, 60, 3600    # 3 alerts/60s from one IP -> block 1h
SEV = {1: "\033[91mHIGH\033[0m", 2: "\033[93mMED\033[0m", 3: "\033[96mLOW\033[0m"}

def alerts(path, follow=False):
    with open(path) as f:
        if follow:
            f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                if not follow:
                    return
                time.sleep(0.5); continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("event_type") == "alert":
                yield e

def block(ip, enforce):
    cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    if not enforce:
        print(f"   [DRY-RUN] would run: {' '.join(cmd)}"); return
    subprocess.run(cmd, check=False)
    print(f"   [BLOCKED] {ip} for {BAN_SECONDS}s")
    subprocess.Popen(f"sleep {BAN_SECONDS} && iptables -D INPUT -s {ip} -j DROP", shell=True)

def monitor(a):
    hits, banned = defaultdict(list), set()
    print("Monitoring alerts... Ctrl+C to stop")
    for e in alerts(a.eve, follow=True):
        src, al = e.get("src_ip"), e["alert"]
        print(f"[{e.get('timestamp','')[:19]}] {SEV.get(al.get('severity'),'?')} {al['signature']}  {src} -> {e.get('dest_ip')}:{e.get('dest_port','')}")
        now = time.time()
        hits[src] = [t for t in hits[src] if now - t < WINDOW] + [now]
        try:
            ok = not ipaddress.ip_address(src).is_multicast
        except (ValueError, TypeError):
            ok = False
        if ok and src not in WHITELIST and src not in banned and len(hits[src]) >= THRESHOLD:
            banned.add(src); block(src, a.block)

def dashboard(a):
    ev = list(alerts(a.eve))
    sig = Counter(e["alert"]["signature"] for e in ev)
    src = Counter(e.get("src_ip") for e in ev)
    sev = Counter(e["alert"].get("severity", 3) for e in ev)
    hour = Counter(e["timestamp"][11:13] for e in ev if "timestamp" in e)
    def bars(c, n=8):
        m = max(c.values(), default=1)
        return "".join(f"<div class=r><span>{html.escape(str(k))}</span><i style='width:{v/m*100:.0f}%'></i><b>{v}</b></div>" for k, v in c.most_common(n))
    rows = "".join(f"<tr><td>{html.escape(e['timestamp'][:19])}</td><td>{e['alert'].get('severity')}</td><td>{html.escape(e['alert']['signature'])}</td><td>{e.get('src_ip')}</td><td>{e.get('dest_ip')}</td></tr>" for e in ev[-15:][::-1])
    page = f"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>NIDS Dashboard</title>
<style>body{{background:#0d1117;color:#e6edf3;font:14px system-ui;margin:0;padding:16px}}h1{{color:#f0b429}}.g{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}}
.c{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px}}.k{{font-size:34px;color:#f85149}}.r{{display:flex;gap:8px;align-items:center;margin:6px 0}}
.r span{{width:42%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.r i{{background:#f0b429;height:10px;border-radius:5px;display:block}}table{{width:100%;border-collapse:collapse;font-size:12px}}td,th{{padding:4px;border-bottom:1px solid #30363d;text-align:left}}.s{{overflow-x:auto}}</style>
<h1>NIDS Dashboard</h1><div class=g>
<div class=c>Total alerts<div class=k>{len(ev)}</div>High: {sev[1]} | Med: {sev[2]} | Low: {sev[3]}</div>
<div class=c><b>Top signatures</b>{bars(sig)}</div><div class=c><b>Top attackers</b>{bars(src)}</div><div class=c><b>Alerts by hour</b>{bars(hour,24)}</div></div>
<div class="c s" style=margin-top:12px><b>Latest alerts</b><table><tr><th>Time<th>Sev<th>Signature<th>Src<th>Dst</tr>{rows}</table></div>"""
    open("dashboard.html", "w").write(page); print("dashboard.html created from", len(ev), "alerts")

def demo(a):
    sigs = [("CA TCP SYN port scan", 2), ("CA SSH brute force", 1), ("CA SQL injection attempt", 1), ("CA XSS attempt", 2), ("CA ICMP ping sweep/flood", 3)]
    ips = ["203.0.113.7", "198.51.100.23", "192.0.2.99"]
    with open(a.eve, "w") as f:
        for i in range(80):
            s, v = random.choice(sigs)
            t = datetime.datetime.now() - datetime.timedelta(minutes=random.randint(0, 600))
            f.write(json.dumps({"timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000000+0000"), "event_type": "alert", "src_ip": random.choice(ips), "dest_ip": "192.168.1.10", "dest_port": 22, "alert": {"signature": s, "severity": v}}) + "\n")
    print("demo log written to", a.eve)

if __name__ == "__main__":
    p = argparse.ArgumentParser(); p.add_argument("cmd", choices=["monitor", "dashboard", "demo"])
    p.add_argument("--eve", default="/var/log/suricata/eve.json"); p.add_argument("--block", action="store_true")
    a = p.parse_args(); {"monitor": monitor, "dashboard": dashboard, "demo": demo}[a.cmd](a)
