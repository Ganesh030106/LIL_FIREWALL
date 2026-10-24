import urllib.request
import json

def get(path):
    url = "http://127.0.0.1:8000" + path
    req = urllib.request.Request(url, headers={"User-Agent": "TestClient"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))

print("=== 1. HEALTH CHECK ===")
print(json.dumps(get("/api/health"), indent=2))

print("\n=== 2. LIVE SYSTEM SOCKETS & CONNECTIONS ===")
conns = get("/api/current/connections")
conn_list = conns.get("connections", [])
print(f"Total live sockets reported: {len(conn_list)}")
for c in conn_list[:6]:
    print(" ", c.get("src"), "->", c.get("dst"), c.get("status"), c.get("protocol"), "|", c.get("process"))

print("\n=== 3. LIVE DNS & WEB DOMAIN LOGS ===")
searches = get("/api/history/searches")
search_list = searches.get("searches", [])
print(f"Total live DNS entries: {len(search_list)}")
for s in search_list[:6]:
    print(" ", s.get("who"), "|", s.get("query"), "|", s.get("url"))

print("\n=== 4. LIVE FILE SYSTEM / WATCHDOG LOGS ===")
files = get("/api/history/file-shares")
file_list = files.get("file_shares", [])
print(f"Total live file entries: {len(file_list)}")
for f in file_list[:6]:
    print(" ", f.get("who"), "|", f.get("filename"))

print("\n=== 5. LIVE DISCOVERED NETWORK DEVICES ===")
devices = get("/api/risk/devices")
print(f"Total live discovered devices: {len(devices)}")
for d in devices[:8]:
    print(" ", d.get("mac"), "|", d.get("ip"), "|", d.get("type"), "| Risk:", d.get("risk"))

print("\n=== 6. LIVE RISK STATS ===")
print(json.dumps(get("/api/risk/stats"), indent=2))

print("\n=== 7. LIVE SESSIONS ===")
sessions = get("/api/sessions")
print(f"Total active sessions: {len(sessions)}")
for s in sessions[:6]:
    print(" ", s.get("src_ip"), ":", s.get("src_port"), "->", s.get("dst_ip"), ":", s.get("dst_port"), s.get("state"), "|", s.get("process"))

print("\n=== 8. THREAT SUMMARY ===")
print(json.dumps(get("/api/threat-summary"), indent=2))

print("\n=== 9. RECENT THREATS ===")
threats = get("/api/threats/recent")
print(f"Total recent threat clusters: {len(threats)}")
for t in threats[:3]:
    print(" ", t.get("id"), "|", t.get("title"), "|", t.get("severity"), "| Confidence:", t.get("confidence"))
