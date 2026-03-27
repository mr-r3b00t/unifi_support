#!/usr/bin/env python3
"""
Generate an HTML report from a decrypted UniFi OS v2 backup.

Reads the extracted backup directory (from decrypt_unifi_backup.py) and
produces a self-contained HTML report covering all configuration.

Usage:
    python3 report_unifi_backup.py [extracted_backup_dir]
"""

import sys
import os
import io
import json
import gzip
import struct
import datetime
import html as html_mod
from pathlib import Path
from collections import defaultdict

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ─── BSON Parser ───────────────────────────────────────────────────────

BSON_TYPES = {
    0x01: 'double', 0x02: 'string', 0x03: 'document', 0x04: 'array',
    0x05: 'binary', 0x06: 'undefined', 0x07: 'objectid', 0x08: 'bool',
    0x09: 'datetime', 0x0A: 'null', 0x0B: 'regex', 0x10: 'int32',
    0x11: 'timestamp', 0x12: 'int64', 0xFF: 'minkey', 0x7F: 'maxkey',
}


def parse_bson_doc(data, offset=0):
    if offset + 4 > len(data):
        return None, 0
    doc_len = struct.unpack_from('<I', data, offset)[0]
    if doc_len < 5 or offset + doc_len > len(data):
        return None, 0
    result = {}
    pos = offset + 4
    end = offset + doc_len - 1
    while pos < end:
        elem_type = data[pos]; pos += 1
        name_end = data.index(b'\x00', pos)
        name = data[pos:name_end].decode('utf-8', errors='replace'); pos = name_end + 1
        if elem_type == 0x01:
            val = struct.unpack_from('<d', data, pos)[0]; pos += 8
        elif elem_type == 0x02:
            sl = struct.unpack_from('<I', data, pos)[0]; pos += 4
            val = data[pos:pos+sl-1].decode('utf-8', errors='replace'); pos += sl
        elif elem_type == 0x03:
            val, c = parse_bson_doc(data, pos); pos += c
        elif elem_type == 0x04:
            val, c = parse_bson_array(data, pos); pos += c
        elif elem_type == 0x05:
            bl = struct.unpack_from('<I', data, pos)[0]; pos += 5
            val = data[pos:pos+bl].hex(); pos += bl
        elif elem_type == 0x07:
            val = data[pos:pos+12].hex(); pos += 12
        elif elem_type == 0x08:
            val = data[pos] != 0; pos += 1
        elif elem_type == 0x09:
            ms = struct.unpack_from('<q', data, pos)[0]; pos += 8
            try: val = datetime.datetime.fromtimestamp(ms/1000, tz=datetime.timezone.utc).isoformat()
            except: val = f"epoch_ms:{ms}"
        elif elem_type == 0x0A:
            val = None
        elif elem_type == 0x0B:
            pe = data.index(b'\x00', pos); pat = data[pos:pe].decode('utf-8', errors='replace'); pos = pe+1
            oe = data.index(b'\x00', pos); opt = data[pos:oe].decode('utf-8', errors='replace'); pos = oe+1
            val = f"/{pat}/{opt}"
        elif elem_type == 0x10:
            val = struct.unpack_from('<i', data, pos)[0]; pos += 4
        elif elem_type == 0x11:
            val = struct.unpack_from('<Q', data, pos)[0]; pos += 8
        elif elem_type == 0x12:
            val = struct.unpack_from('<q', data, pos)[0]; pos += 8
        elif elem_type in (0xFF, 0x7F, 0x06):
            val = None
        else:
            break
        result[name] = val
    return result, doc_len


def parse_bson_array(data, offset=0):
    doc, consumed = parse_bson_doc(data, offset)
    if doc is None: return [], consumed
    return [doc[k] for k in sorted(doc.keys(), key=lambda x: int(x) if x.isdigit() else 0)], consumed


def parse_bson_stream(data):
    offset = 0
    while offset < len(data) - 4:
        doc, consumed = parse_bson_doc(data, offset)
        if doc is None or consumed == 0: break
        yield doc
        offset += consumed


def load_network_db(db_gz_path):
    with gzip.open(db_gz_path, 'rb') as f:
        data = f.read()
    collections = defaultdict(list)
    current = None
    for doc in parse_bson_stream(data):
        if doc.get('__cmd') == 'select' and 'collection' in doc:
            current = doc['collection']
        elif current:
            collections[current].append(doc)
    return dict(collections)


def load_yaml_file(path):
    with open(path, 'r', errors='replace') as f:
        text = f.read()
    if HAS_YAML:
        try: return yaml.safe_load(text)
        except: return text
    return text


# ─── Helpers ───────────────────────────────────────────────────────────

def esc(s):
    return html_mod.escape(str(s)) if s is not None else ""

def ts_to_str(ts):
    if ts is None: return "N/A"
    if isinstance(ts, str): return ts
    if ts > 1e12: ts = ts / 1000
    try: return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except: return str(ts)

def mask(value, show=4):
    if not value or not isinstance(value, str): return str(value) if value else ""
    if len(value) <= show: return "****"
    return "\u2022" * (len(value) - show) + value[-show:]

def badge(text, colour="gray"):
    return f'<span class="badge badge-{colour}">{esc(text)}</span>'

def severity_badge(level, text):
    colours = {"ok": "green", "info": "blue", "warn": "orange", "critical": "red"}
    return f'<span class="badge badge-{colours.get(level, "gray")}">{esc(text)}</span>'


# ─── HTML Builder ──────────────────────────────────────────────────────

class HTMLReport:
    def __init__(self):
        self.sections = []
        self.toc = []

    def add_section(self, title, content, section_id=None):
        if section_id is None:
            section_id = title.lower().replace(" ", "-").replace("/", "-")
        self.toc.append((section_id, title))
        self.sections.append((section_id, title, content))

    def build(self, meta):
        toc_html = "\n".join(
            f'<li><a href="#{sid}">{esc(title)}</a></li>' for sid, title in self.toc
        )
        sections_html = "\n".join(
            f'<section id="{sid}"><h2>{esc(title)}</h2>{content}</section>'
            for sid, title, content in self.sections
        )
        return HTML_TEMPLATE.format(
            title=esc(meta.get("title", "UniFi Backup Report")),
            generated=esc(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            hostname=esc(meta.get("hostname", "")),
            hardware=esc(meta.get("hardware", "")),
            firmware=esc(meta.get("firmware", "")),
            toc=toc_html,
            sections=sections_html,
        )


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
:root {{
  --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
  --border: #475569; --text: #e2e8f0; --text2: #94a3b8;
  --accent: #3b82f6; --accent2: #60a5fa;
  --green: #22c55e; --orange: #f59e0b; --red: #ef4444; --blue: #3b82f6;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg); color:var(--text); line-height:1.6; }}
.container {{ max-width:1200px; margin:0 auto; padding:20px; }}
header {{ background:linear-gradient(135deg,#1e3a5f,#0f172a); padding:30px; border-radius:12px;
  margin-bottom:24px; border:1px solid var(--border); }}
header h1 {{ font-size:1.8rem; margin-bottom:8px; }}
header .meta {{ color:var(--text2); font-size:0.9rem; }}
header .meta span {{ margin-right:20px; }}
nav {{ background:var(--surface); padding:16px 20px; border-radius:10px;
  margin-bottom:24px; border:1px solid var(--border); }}
nav h3 {{ margin-bottom:10px; color:var(--accent2); font-size:0.85rem; text-transform:uppercase; letter-spacing:1px; }}
nav ul {{ list-style:none; display:flex; flex-wrap:wrap; gap:6px 16px; }}
nav a {{ color:var(--accent2); text-decoration:none; font-size:0.88rem; }}
nav a:hover {{ text-decoration:underline; }}
section {{ background:var(--surface); border-radius:10px; padding:24px;
  margin-bottom:20px; border:1px solid var(--border); }}
section h2 {{ font-size:1.3rem; margin-bottom:16px; padding-bottom:8px;
  border-bottom:2px solid var(--accent); }}
h3 {{ font-size:1.05rem; margin:18px 0 10px; color:var(--accent2); }}
table {{ width:100%; border-collapse:collapse; margin:10px 0; font-size:0.88rem; }}
th {{ background:var(--surface2); text-align:left; padding:8px 12px; font-weight:600;
  border-bottom:2px solid var(--border); white-space:nowrap; }}
td {{ padding:8px 12px; border-bottom:1px solid var(--border); vertical-align:top; }}
tr:hover td {{ background:rgba(59,130,246,0.05); }}
.badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.78rem;
  font-weight:600; text-transform:uppercase; letter-spacing:0.5px; }}
.badge-green {{ background:rgba(34,197,94,0.15); color:var(--green); }}
.badge-orange {{ background:rgba(245,158,11,0.15); color:var(--orange); }}
.badge-red {{ background:rgba(239,68,68,0.15); color:var(--red); }}
.badge-blue {{ background:rgba(59,130,246,0.15); color:var(--blue); }}
.badge-gray {{ background:rgba(148,163,184,0.15); color:var(--text2); }}
.badge-purple {{ background:rgba(168,85,247,0.15); color:#a855f7; }}
.card-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); gap:14px; }}
.card {{ background:var(--surface2); border-radius:8px; padding:16px; border:1px solid var(--border); }}
.card h4 {{ margin-bottom:8px; font-size:0.95rem; }}
.card .row {{ display:flex; justify-content:space-between; margin-bottom:4px; font-size:0.85rem; }}
.card .row .label {{ color:var(--text2); }}
.stat-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:12px; margin-bottom:16px; }}
.stat {{ background:var(--surface2); border-radius:8px; padding:14px; text-align:center; border:1px solid var(--border); }}
.stat .num {{ font-size:1.6rem; font-weight:700; color:var(--accent2); }}
.stat .lbl {{ font-size:0.78rem; color:var(--text2); text-transform:uppercase; letter-spacing:0.5px; }}
.finding {{ padding:10px 14px; margin:6px 0; border-radius:6px; font-size:0.88rem; border-left:4px solid; }}
.finding-ok {{ background:rgba(34,197,94,0.08); border-color:var(--green); }}
.finding-info {{ background:rgba(59,130,246,0.08); border-color:var(--blue); }}
.finding-warn {{ background:rgba(245,158,11,0.08); border-color:var(--orange); }}
.finding-critical {{ background:rgba(239,68,68,0.08); border-color:var(--red); }}
.mono {{ font-family:'SF Mono',Consolas,monospace; font-size:0.84rem; }}
.sensitive {{ color:var(--orange); cursor:help; }}
.muted {{ color:var(--text2); }}
details {{ margin:6px 0; }}
summary {{ cursor:pointer; color:var(--accent2); font-weight:500; padding:4px 0; }}
summary:hover {{ text-decoration:underline; }}
@media(max-width:768px) {{
  .card-grid {{ grid-template-columns:1fr; }}
  .stat-grid {{ grid-template-columns:repeat(2,1fr); }}
  table {{ font-size:0.8rem; }}
  th,td {{ padding:6px 8px; }}
}}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>{title}</h1>
  <div class="meta">
    <span>Generated: {generated}</span>
    <span>Hostname: <strong>{hostname}</strong></span>
    <span>Hardware: <strong>{hardware}</strong></span>
    <span>Firmware: <strong>{firmware}</strong></span>
  </div>
</header>
<nav>
  <h3>Contents</h3>
  <ul>{toc}</ul>
</nav>
{sections}
</div>
</body>
</html>"""


# ─── Section builders ──────────────────────────────────────────────────

def build_overview(meta, db, backup_dir):
    net_count = len(db.get("networkconf", []))
    wlan_count = len(db.get("wlanconf", []))
    device_count = len(db.get("device", []))
    client_count = len(db.get("user", []))
    fw_rule_count = len(db.get("firewallrule", []))
    fw_policy_count = len(db.get("firewall_policy", []))
    pf_count = len(db.get("portforward", []))
    vpn_count = len(db.get("wireguard_user", []))
    teleport_count = len(db.get("teleport_client", []))

    h = '<div class="stat-grid">'
    for num, lbl in [
        (net_count, "Networks/VLANs"), (wlan_count, "WiFi SSIDs"),
        (device_count, "Devices"), (client_count, "Known Clients"),
        (fw_rule_count + fw_policy_count, "Firewall Rules"), (pf_count, "Port Forwards"),
        (vpn_count, "VPN Users"), (teleport_count, "Teleport Clients"),
    ]:
        h += f'<div class="stat"><div class="num">{num}</div><div class="lbl">{lbl}</div></div>'
    h += '</div>'

    # App versions
    pkg_path = os.path.join(backup_dir, "backup/package-versions.json")
    if os.path.exists(pkg_path):
        with open(pkg_path) as f:
            pkg = json.load(f)
        h += '<h3>Application Versions</h3><table><tr><th>Application</th><th>Version</th></tr>'
        for app, ver in sorted({**pkg.get("controllers", {}), **pkg.get("services", {})}.items()):
            h += f'<tr><td>{esc(app.title())}</td><td class="mono">{esc(ver)}</td></tr>'
        h += '</table>'

    # Console settings
    settings_path = os.path.join(backup_dir, "backup/ucore/config/settings.yaml")
    if os.path.exists(settings_path):
        settings = load_yaml_file(settings_path)
        if isinstance(settings, dict):
            h += '<h3>Console Settings</h3><table>'
            loc = settings.get("location", {})
            rows = [
                ("Name", settings.get("name", "")),
                ("Timezone", settings.get("timezone", "")),
                ("Location", loc.get("text", "") if isinstance(loc, dict) else ""),
                ("Coordinates", f'{loc.get("lat","")}, {loc.get("long","")}' if isinstance(loc, dict) and loc.get("lat") else ""),
                ("Auto Backup", settings.get("autoBackupEnabled", "")),
                ("Update Schedule", f'{settings.get("updateSchedule",{}).get("frequency","")}' if isinstance(settings.get("updateSchedule"), dict) else ""),
                ("Storage RAID", settings.get("ustorage",{}).get("currentSettings",{}).get("raid","") if isinstance(settings.get("ustorage"), dict) else ""),
            ]
            for k, v in rows:
                if v not in (None, ""):
                    h += f'<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>'
            h += '</table>'

    # System data
    sys_path = os.path.join(backup_dir, "backup/ucore/system-data.json")
    if os.path.exists(sys_path):
        with open(sys_path) as f:
            sysdata = json.load(f)
        h += '<h3>System</h3><table>'
        h += f'<tr><td>Hostname</td><td><strong>{esc(sysdata.get("hostname",""))}</strong></td></tr>'
        h += f'<tr><td>SSH Enabled</td><td>{badge("Enabled","orange") if sysdata.get("sshEnabled") else badge("Disabled","green")}</td></tr>'
        if sysdata.get("hashedSshPassword"):
            h += f'<tr><td>SSH Password Hash</td><td class="mono sensitive" title="Hashed password present">{esc(sysdata["hashedSshPassword"][:50])}...</td></tr>'
        h += '</table>'

    return h


def build_users(backup_dir):
    users_path = os.path.join(backup_dir, "backup/ucore/config/cache/users.json")
    if not os.path.exists(users_path):
        return '<p class="muted">No cached users found.</p>'
    with open(users_path) as f:
        users = json.load(f)
    if not isinstance(users, list):
        users = [users] if isinstance(users, dict) else []

    h = f'<p>Total accounts: <strong>{len(users)}</strong></p><div class="card-grid">'
    for u in users:
        roles = [r.get("name", "?") for r in u.get("roles", []) if isinstance(r, dict)]
        perms = u.get("permissions", {})
        admin_perms = sorted([k for k, v in perms.items() if isinstance(v, list) and "admin" in v]) if isinstance(perms, dict) else []
        role_badges = " ".join(badge(r, "purple") for r in roles)

        h += f'''<div class="card">
          <h4>{esc(u.get("full_name","Unknown"))} {role_badges}</h4>
          <div class="row"><span class="label">Email</span><span>{esc(u.get("email",""))}</span></div>
          <div class="row"><span class="label">SSO Username</span><span class="mono">{esc(u.get("sso_username",""))}</span></div>
          <div class="row"><span class="label">Status</span><span>{badge(u.get("status",""),"green" if u.get("status")=="ACTIVE" else "gray")}</span></div>
          <div class="row"><span class="label">Last Login</span><span>{esc(ts_to_str(u.get("login_time")))}</span></div>
          <div class="row"><span class="label">Created</span><span>{esc(ts_to_str(u.get("create_time")))}</span></div>'''
        if admin_perms:
            h += f'<div class="row"><span class="label">Admin</span><span style="font-size:0.8rem">{esc(", ".join(admin_perms))}</span></div>'
        h += '</div>'
    h += '</div>'
    return h


def build_networks(db):
    nets = db.get("networkconf", [])
    if not nets:
        return '<p class="muted">No networks configured.</p>'

    # Build a lookup for network IDs -> names
    net_lookup = {n.get("_id", ""): n.get("name", "") for n in nets}

    # Separate by purpose
    wans = [n for n in nets if n.get("purpose") == "wan"]
    vpns = [n for n in nets if n.get("purpose") in ("remote-user-vpn", "site-vpn")]
    lans = [n for n in nets if n.get("purpose") not in ("wan", "remote-user-vpn", "site-vpn")]

    h = ""
    if wans:
        h += '<h3>WAN Interfaces</h3><table><tr><th>Name</th><th>Type</th><th>WAN IP</th></tr>'
        for w in wans:
            h += f'<tr><td>{esc(w.get("name",""))}</td><td>{esc(w.get("wan_type","dhcp"))}</td><td class="mono">{esc(w.get("wan_ip","DHCP"))}</td></tr>'
        h += '</table>'

    if lans:
        h += '<h3>LAN Networks</h3>'
        h += '<table><tr><th>Name</th><th>VLAN</th><th>Subnet</th><th>Purpose</th><th>DHCP Range</th><th>DNS</th><th>Domain</th></tr>'
        for n in sorted(lans, key=lambda x: x.get("vlan", x.get("vlan_tag", 0) or 0)):
            vlan = n.get("vlan") or n.get("vlan_tag") or n.get("vlan_id", "")
            dhcp = f'{n.get("dhcpd_start","")}&nbsp;-&nbsp;{n.get("dhcpd_stop","")}' if n.get("dhcpd_enabled") else '<span class="muted">Off</span>'
            dns_list = [n.get(f"dhcpd_dns_{i}","") for i in (1,2,3)]
            dns = ", ".join(d for d in dns_list if d) or ""
            h += f'''<tr>
              <td><strong>{esc(n.get("name",""))}</strong></td>
              <td>{esc(vlan)}</td>
              <td class="mono">{esc(n.get("ip_subnet",""))}</td>
              <td>{badge(n.get("purpose",""), "blue")}</td>
              <td class="mono">{dhcp}</td>
              <td class="mono" style="font-size:0.8rem">{esc(dns)}</td>
              <td>{esc(n.get("domain_name",""))}</td>
            </tr>'''
        h += '</table>'

    if vpns:
        h += '<h3>VPN Networks</h3>'
        h += '<table><tr><th>Name</th><th>Type</th><th>Subnet</th><th>DNS</th></tr>'
        for v in vpns:
            dns_list = [v.get(f"dhcpd_dns_{i}","") for i in (1,2,3)]
            dns = ", ".join(d for d in dns_list if d) or ""
            h += f'''<tr>
              <td><strong>{esc(v.get("name",""))}</strong></td>
              <td>{badge(v.get("purpose",""),"purple")}</td>
              <td class="mono">{esc(v.get("ip_subnet",""))}</td>
              <td class="mono">{esc(dns)}</td>
            </tr>'''
        h += '</table>'

    return h


def build_wlans(db):
    wlans = db.get("wlanconf", [])
    if not wlans:
        return '<p class="muted">No wireless networks configured.</p>'

    h = '<div class="card-grid">'
    for w in sorted(wlans, key=lambda x: x.get("name", "")):
        sec = w.get("security", "open")
        wpa = w.get("wpa_mode", "")
        enc = w.get("wpa_enc", "")
        pw = w.get("x_passphrase", "")
        enabled = w.get("enabled", True)
        guest = w.get("is_guest", False)
        hidden = w.get("hide_ssid", False)
        pmf = w.get("pmf_mode", "")
        band = w.get("wlan_band", "both")

        sec_text = f"{sec}" + (f" / {wpa} / {enc}" if wpa else "")
        en_badge = badge("Active", "green") if enabled else badge("Disabled", "gray")
        flags = []
        if guest: flags.append(badge("Guest", "orange"))
        if hidden: flags.append(badge("Hidden", "gray"))

        h += f'''<div class="card">
          <h4>{esc(w.get("name",""))} {en_badge} {" ".join(flags)}</h4>
          <div class="row"><span class="label">Security</span><span>{esc(sec_text)}</span></div>
          <div class="row"><span class="label">Passphrase</span><span class="mono sensitive">{esc(mask(pw,4))}</span></div>
          <div class="row"><span class="label">Band</span><span>{esc(band)}</span></div>
          <div class="row"><span class="label">PMF (802.11w)</span><span>{esc(pmf or "N/A")}</span></div>'''
        if w.get("mac_filter_enabled"):
            h += f'<div class="row"><span class="label">MAC Filter</span><span>{badge("Enabled","orange")}</span></div>'
        if w.get("radius_profile_id"):
            h += f'<div class="row"><span class="label">RADIUS</span><span>Configured</span></div>'
        h += '</div>'
    h += '</div>'
    return h


def build_devices(db):
    devices = db.get("device", [])
    if not devices:
        return '<p class="muted">No devices found.</p>'

    type_icons = {"udm": "Gateway", "usw": "Switch", "uap": "Access Point", "ugw": "Gateway"}

    h = '<table><tr><th>Name</th><th>Model</th><th>Type</th><th>IP Address</th><th>MAC</th><th>Firmware</th><th>Adopted</th></tr>'
    for d in sorted(devices, key=lambda x: x.get("name", x.get("hostname", "zzz"))):
        name = d.get("name", d.get("hostname", ""))
        dtype = d.get("type", "")
        type_label = type_icons.get(dtype, dtype)
        adopted = d.get("adopted", False)
        config_ip = d.get("config_network", {}).get("ip", "") if isinstance(d.get("config_network"), dict) else ""
        ip_display = d.get("ip", "")
        if config_ip and config_ip != ip_display:
            ip_display += f' <span class="muted">({config_ip})</span>'

        h += f'''<tr>
          <td><strong>{esc(name) or '<span class="muted">Unnamed</span>'}</strong></td>
          <td class="mono">{esc(d.get("model",""))}</td>
          <td>{badge(type_label, "blue")}</td>
          <td class="mono">{ip_display}</td>
          <td class="mono">{esc(d.get("mac",""))}</td>
          <td class="mono">{esc(d.get("version",""))}</td>
          <td>{badge("Yes","green") if adopted else badge("No","red")}</td>
        </tr>'''
    h += '</table>'
    return h


def build_clients(db):
    clients = db.get("user", [])
    if not clients:
        return '<p class="muted">No known clients.</p>'

    named = [c for c in clients if c.get("name") or c.get("hostname")]
    unnamed = [c for c in clients if not c.get("name") and not c.get("hostname")]

    h = f'<p>Total known clients: <strong>{len(clients)}</strong> ({len(named)} named, {len(unnamed)} unnamed)</p>'

    h += '<table><tr><th>Name</th><th>MAC</th><th>Fixed IP</th><th>Note</th><th>Flags</th></tr>'
    for c in sorted(clients, key=lambda x: x.get("name", x.get("hostname", x.get("mac", "")))):
        name = c.get("name", c.get("hostname", ""))
        mac = c.get("mac", "")
        fixed_ip = c.get("fixed_ip", "") if c.get("use_fixedip") else ""
        note = c.get("note", "")
        blocked = c.get("blocked", False)
        flags = badge("BLOCKED", "red") if blocked else ""

        h += f'''<tr>
          <td>{esc(name) or f'<span class="muted">{esc(mac)}</span>'}</td>
          <td class="mono">{esc(mac)}</td>
          <td class="mono">{esc(fixed_ip)}</td>
          <td style="font-size:0.82rem">{esc(note)}</td>
          <td>{flags}</td>
        </tr>'''
    h += '</table>'
    return h


def build_firewall(db):
    groups = db.get("firewallgroup", [])
    rules = db.get("firewallrule", [])
    policies = db.get("firewall_policy", [])
    predefined = db.get("predefined_firewall_rule", [])

    h = ""
    if groups:
        h += f'<h3>Firewall Groups ({len(groups)})</h3>'
        h += '<table><tr><th>Name</th><th>Type</th><th>Members</th></tr>'
        for g in sorted(groups, key=lambda x: x.get("name", "")):
            members = g.get("group_members", [])
            member_str = ", ".join(str(m) for m in members[:15]) if isinstance(members, list) else ""
            if isinstance(members, list) and len(members) > 15:
                member_str += f" ... +{len(members)-15} more"
            h += f'<tr><td><strong>{esc(g.get("name",""))}</strong></td><td>{esc(g.get("group_type",""))}</td><td class="mono" style="font-size:0.82rem">{esc(member_str)}</td></tr>'
        h += '</table>'

    if rules:
        h += f'<h3>Custom Firewall Rules ({len(rules)})</h3>'
        h += '<table><tr><th>Name</th><th>Ruleset</th><th>Action</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Port</th><th>Enabled</th></tr>'
        for r in sorted(rules, key=lambda x: (x.get("ruleset",""), x.get("rule_index",0))):
            en = r.get("enabled", True)
            h += f'''<tr>
              <td>{esc(r.get("name",""))}</td>
              <td class="mono">{esc(r.get("ruleset",""))}</td>
              <td>{badge(r.get("action",""), "red" if r.get("action")=="drop" else "green" if r.get("action")=="accept" else "gray")}</td>
              <td>{esc(r.get("protocol","all"))}</td>
              <td class="mono" style="font-size:0.82rem">{esc(r.get("src_address",r.get("src_firewallgroup_ids","any")))}</td>
              <td class="mono" style="font-size:0.82rem">{esc(r.get("dst_address",r.get("dst_firewallgroup_ids","any")))}</td>
              <td class="mono">{esc(r.get("dst_port",""))}</td>
              <td>{badge("Yes","green") if en else badge("No","gray")}</td>
            </tr>'''
        h += '</table>'
    elif not policies:
        h += '<p class="muted">No custom firewall rules configured.</p>'

    if policies:
        h += f'<h3>Firewall Policies ({len(policies)})</h3>'
        h += '<table><tr><th>Name</th><th>Action</th><th>Enabled</th><th>Index</th></tr>'
        for p in sorted(policies, key=lambda x: x.get("index", 0)):
            en = p.get("enabled", True)
            h += f'''<tr>
              <td>{esc(p.get("name",p.get("description","")))}</td>
              <td>{badge(p.get("action",""), "red" if p.get("action") in ("BLOCK","DROP","REJECT") else "green")}</td>
              <td>{badge("Yes","green") if en else badge("No","gray")}</td>
              <td>{esc(p.get("index",""))}</td>
            </tr>'''
        h += '</table>'

    return h


def build_port_forwarding(db):
    fwds = db.get("portforward", [])
    if not fwds:
        return '<p class="muted">No port forwarding rules configured.</p>'

    h = '<table><tr><th>Name</th><th>Protocol</th><th>Ext Port</th><th>Destination</th><th>Int Port</th><th>Source</th><th>Enabled</th></tr>'
    for pf in sorted(fwds, key=lambda x: x.get("name", "")):
        en = pf.get("enabled", True)
        src = pf.get("src", "any")
        h += f'''<tr>
          <td><strong>{esc(pf.get("name",""))}</strong></td>
          <td>{esc(pf.get("proto","tcp_udp"))}</td>
          <td class="mono">{esc(pf.get("dst_port",""))}</td>
          <td class="mono">{esc(pf.get("fwd",""))}</td>
          <td class="mono">{esc(pf.get("fwd_port",""))}</td>
          <td class="mono">{esc(src)}</td>
          <td>{badge("Yes","green") if en else badge("No","gray")}</td>
        </tr>'''
    h += '</table>'
    return h


def build_vpn(db):
    wg_users = db.get("wireguard_user", [])
    teleport = db.get("teleport_client", [])

    h = ""
    if wg_users:
        h += f'<h3>WireGuard VPN Users ({len(wg_users)})</h3>'
        h += '<table><tr><th>Name</th><th>IP</th><th>Enabled</th></tr>'
        for u in sorted(wg_users, key=lambda x: x.get("name", "")):
            en = u.get("enabled", True)
            h += f'''<tr>
              <td>{esc(u.get("name",""))}</td>
              <td class="mono">{esc(u.get("ip",""))}</td>
              <td>{badge("Yes","green") if en else badge("No","gray")}</td>
            </tr>'''
        h += '</table>'

    if teleport:
        h += f'<h3>Teleport Clients ({len(teleport)})</h3>'
        h += '<table><tr><th>Name</th><th>IP</th><th>Status</th></tr>'
        for t in sorted(teleport, key=lambda x: x.get("name", "")):
            h += f'''<tr>
              <td>{esc(t.get("name",""))}</td>
              <td class="mono">{esc(t.get("ip",""))}</td>
              <td>{esc(t.get("status",""))}</td>
            </tr>'''
        h += '</table>'

    if not h:
        h = '<p class="muted">No VPN users configured.</p>'
    return h


def build_radius(db):
    profiles = db.get("radiusprofile", [])
    accounts = db.get("account", [])
    h = ""
    if profiles:
        h += f'<h3>RADIUS Profiles ({len(profiles)})</h3>'
        h += '<table><tr><th>Name</th><th>VLAN</th><th>Auth Servers</th></tr>'
        for p in profiles:
            servers = p.get("auth_servers", [])
            server_str = ", ".join(s.get("ip","") + ":" + str(s.get("port","")) for s in servers if isinstance(s, dict)) if isinstance(servers, list) else ""
            h += f'<tr><td>{esc(p.get("name",""))}</td><td>{esc(p.get("use_usg_auth_server",""))}</td><td class="mono">{esc(server_str)}</td></tr>'
        h += '</table>'
    if accounts:
        h += f'<h3>RADIUS Accounts ({len(accounts)})</h3>'
        h += '<table><tr><th>Name</th><th>Tunnel Type</th><th>VLAN</th></tr>'
        for a in accounts:
            h += f'<tr><td>{esc(a.get("name",""))}</td><td>{esc(a.get("tunnel_type",""))}</td><td>{esc(a.get("vlan",""))}</td></tr>'
        h += '</table>'
    if not h:
        return '<p class="muted">No RADIUS configuration found.</p>'
    return h


def build_settings(db):
    settings = db.get("setting", [])
    if not settings:
        return '<p class="muted">No settings found.</p>'

    display_keys = {
        "super_mgmt": "Management",
        "connectivity": "Connectivity",
        "dpi": "Deep Packet Inspection",
        "ips": "Intrusion Prevention",
        "guest_access": "Guest Access",
        "radius": "RADIUS",
        "ntp": "NTP",
        "usg": "Gateway (USG)",
        "auto_speedtest": "Speed Test",
        "country": "Country",
        "locale": "Locale",
        "mgmt": "Device Management",
    }

    h = '<div class="card-grid">'
    for s in sorted(settings, key=lambda x: x.get("key", "")):
        key = s.get("key", "")
        if key not in display_keys:
            continue
        label = display_keys[key]
        fields = {k: v for k, v in s.items() if k not in ("_id", "key", "site_id") and v is not None and v != "" and v != []}
        if not fields:
            continue

        h += f'<div class="card"><h4>{esc(label)}</h4>'
        for k, v in sorted(fields.items()):
            if "password" in k.lower() or "secret" in k.lower() or k.startswith("x_"):
                v = mask(str(v)) if isinstance(v, str) and v else v
                cls = ' class="mono sensitive"'
            else:
                cls = ""
            display_val = v
            if isinstance(v, bool):
                display_val = badge("Enabled", "green") if v else badge("Disabled", "gray")
            elif isinstance(v, (dict, list)):
                display_val = f'<span class="mono" style="font-size:0.8rem">{esc(json.dumps(v)[:200])}</span>'
            else:
                display_val = esc(v)
            h += f'<div class="row"><span class="label">{esc(k)}</span><span{cls}>{display_val}</span></div>'
        h += '</div>'
    h += '</div>'
    return h


def build_alarms(backup_dir):
    alarms_path = os.path.join(backup_dir, "backup/uos/alarms/network/alarms.json")
    if not os.path.exists(alarms_path):
        return '<p class="muted">No alarms configured.</p>'
    with open(alarms_path) as f:
        alarms = json.load(f)
    if not isinstance(alarms, list):
        return '<p class="muted">Unexpected format.</p>'

    h = '<table><tr><th>Alert Rule</th><th>Triggers</th><th>Status</th></tr>'
    for a in alarms:
        triggers = []
        for tg in a.get("triggers_data", [[]]):
            if isinstance(tg, list):
                for t in tg:
                    if isinstance(t, dict):
                        triggers.append(t.get("id", "?"))
        paused = a.get("is_paused", False)
        h += f'''<tr>
          <td><strong>{esc(a.get("title",""))}</strong></td>
          <td class="mono" style="font-size:0.82rem">{esc(", ".join(triggers))}</td>
          <td>{badge("Paused","orange") if paused else badge("Active","green")}</td>
        </tr>'''
    h += '</table>'
    return h


def build_dns(db):
    static_dns = db.get("static_dns", [])
    h = ""
    if static_dns:
        h += '<table><tr><th>Name</th><th>Record Type</th><th>Value</th><th>Enabled</th></tr>'
        for d in static_dns:
            en = d.get("enabled", True)
            h += f'''<tr>
              <td class="mono">{esc(d.get("key",""))}</td>
              <td>{esc(d.get("record_type","A"))}</td>
              <td class="mono">{esc(d.get("value",""))}</td>
              <td>{badge("Yes","green") if en else badge("No","gray")}</td>
            </tr>'''
        h += '</table>'
    else:
        h = '<p class="muted">No static DNS entries.</p>'
    return h


def build_certificates(backup_dir):
    certs = []
    keys = []
    for root, dirs, files in os.walk(os.path.join(backup_dir, "backup")):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, backup_dir)
            if f.endswith(('.crt', '.pem')): certs.append(rel)
            elif f.endswith('.key'): keys.append(rel)

    h = ""
    if certs:
        h += '<h3>Certificates</h3><table><tr><th>Path</th></tr>'
        for c in sorted(certs):
            h += f'<tr><td class="mono">{esc(c)}</td></tr>'
        h += '</table>'
    if keys:
        h += '<h3>Private Keys</h3><table><tr><th>Path</th><th>Status</th></tr>'
        for k in sorted(keys):
            h += f'<tr><td class="mono">{esc(k)}</td><td>{badge("SENSITIVE","red")}</td></tr>'
        h += '</table>'
    if not h:
        h = '<p class="muted">No certificates found.</p>'
    return h


def build_security(db, backup_dir):
    findings = []

    # SSH
    sys_path = os.path.join(backup_dir, "backup/ucore/system-data.json")
    if os.path.exists(sys_path):
        with open(sys_path) as f:
            sd = json.load(f)
        if sd.get("sshEnabled"):
            findings.append(("info", "SSH is enabled on the console"))

    for s in db.get("setting", []):
        if s.get("key") == "ips":
            if not s.get("enabled"):
                findings.append(("warn", "Intrusion Prevention System (IPS/IDS) is DISABLED"))
            else:
                findings.append(("ok", f"IPS/IDS is enabled (mode: {s.get('mode','ids')})"))
                if s.get("restrict_tor"):
                    findings.append(("ok", "Tor traffic restriction enabled"))
                if s.get("ad_blocking_enabled"):
                    findings.append(("ok", f"Ad blocking enabled (mode: {s.get('ad_blocking_mode','N/A')})"))
                else:
                    findings.append(("info", "Ad blocking is disabled"))
                if not s.get("honeypot_enabled"):
                    findings.append(("info", "Honeypot is disabled"))
                else:
                    findings.append(("ok", "Honeypot enabled"))
        if s.get("key") == "dpi":
            if s.get("enabled"):
                findings.append(("ok", "Deep Packet Inspection (DPI) enabled"))
            else:
                findings.append(("info", "Deep Packet Inspection (DPI) disabled"))

    for w in db.get("wlanconf", []):
        if not w.get("enabled", True): continue
        name = w.get("name", "")
        if w.get("security", "open") == "open":
            findings.append(("warn", f"SSID '{name}' has no encryption (open network)"))
        pw = w.get("x_passphrase", "")
        if pw and len(pw) < 12:
            findings.append(("warn", f"SSID '{name}' has a short WiFi password ({len(pw)} chars)"))
        if w.get("wpa_mode") == "wpa2" and not w.get("wpa3_support"):
            findings.append(("info", f"SSID '{name}' uses WPA2 only (no WPA3)"))
        if w.get("pmf_mode") == "disabled":
            findings.append(("info", f"SSID '{name}' has PMF (802.11w) disabled"))

    fwds = [pf for pf in db.get("portforward", []) if pf.get("enabled", True)]
    if fwds:
        findings.append(("info", f"{len(fwds)} active port forwarding rule(s) expose internal services"))
        for pf in fwds:
            port = pf.get("dst_port", "?")
            fwd = pf.get("fwd", "?")
            src = pf.get("src", "any")
            src_note = f" (restricted to {src})" if src and src != "any" else " (ANY source)"
            findings.append(("info" if src and src != "any" else "warn", f"Port {port} forwarded to {fwd}{src_note}"))

    blocked = [c for c in db.get("user", []) if c.get("blocked")]
    if blocked:
        findings.append(("info", f"{len(blocked)} blocked client(s)"))

    key_count = sum(1 for _, _, files in os.walk(os.path.join(backup_dir, "backup")) for f in files if f.endswith('.key'))
    if key_count:
        findings.append(("warn", f"Backup contains {key_count} private key file(s) — store securely"))

    cloud_path = os.path.join(backup_dir, "backup/ucore/config/cloud.yaml")
    if os.path.exists(cloud_path):
        findings.append(("warn", "Cloud credentials (deviceAuth, RSA private key) present in backup"))

    if not findings:
        return '<p class="muted">No findings.</p>'

    h = ""
    for level, text in findings:
        h += f'<div class="finding finding-{level}">{severity_badge(level, level.upper())} {esc(text)}</div>'
    return h


# ─── Main ──────────────────────────────────────────────────────────────

def find_backup_dir():
    candidates = [c for c in Path(".").glob("*_extracted") if c.is_dir() and (c / "backup").is_dir()]
    if len(candidates) == 1: return str(candidates[0])
    if len(candidates) > 1:
        print("Multiple extracted backups found:")
        for c in candidates: print(f"  {c}")
        sys.exit(1)
    return None


def main():
    backup_dir = sys.argv[1] if len(sys.argv) >= 2 else find_backup_dir()
    if not backup_dir or not os.path.isdir(backup_dir):
        print(f"Usage: {sys.argv[0]} <extracted_backup_dir>")
        print("Run decrypt_unifi_backup.py first to extract the backup.")
        sys.exit(1)

    print(f"Analysing: {os.path.abspath(backup_dir)}")

    # Load metadata
    meta = {"title": "UniFi Backup Report", "hostname": "", "hardware": "", "firmware": ""}
    meta_path = os.path.join(backup_dir, "backup/metadata.json")
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            m = json.load(f)
        meta["hardware"] = m.get("hardware_shortname", "")
        meta["firmware"] = m.get("firmware_version", "")
        meta["title"] = f"UniFi Backup Report — {m.get('hardware_shortname', '')}"
    sys_path = os.path.join(backup_dir, "backup/ucore/system-data.json")
    if os.path.exists(sys_path):
        with open(sys_path) as f:
            meta["hostname"] = json.load(f).get("hostname", "")

    # Load network DB
    db_path = os.path.join(backup_dir, "backup/network/db.gz")
    db = load_network_db(db_path) if os.path.exists(db_path) else {}
    print(f"  Loaded {sum(len(v) for v in db.values())} documents across {len(db)} collections")

    # Build report
    report = HTMLReport()
    report.add_section("Overview", build_overview(meta, db, backup_dir))
    report.add_section("Admin Users", build_users(backup_dir))
    report.add_section("Networks / VLANs", build_networks(db))
    report.add_section("Wireless (SSIDs)", build_wlans(db))
    report.add_section("Devices", build_devices(db))
    report.add_section("Clients", build_clients(db))
    report.add_section("Firewall", build_firewall(db))
    report.add_section("Port Forwarding", build_port_forwarding(db))
    report.add_section("VPN Users", build_vpn(db))
    report.add_section("RADIUS", build_radius(db))
    report.add_section("Static DNS", build_dns(db))
    report.add_section("Controller Settings", build_settings(db))
    report.add_section("Alarms / Alerts", build_alarms(backup_dir))
    report.add_section("Certificates & Keys", build_certificates(backup_dir))
    report.add_section("Security Findings", build_security(db, backup_dir))

    html = report.build(meta)

    output_path = os.path.join(os.path.dirname(backup_dir) or ".", "unifi_backup_report.html")
    with open(output_path, "w") as f:
        f.write(html)

    print(f"  Report written to: {os.path.abspath(output_path)}")
    print(f"  Size: {os.path.getsize(output_path):,} bytes")


if __name__ == "__main__":
    main()
