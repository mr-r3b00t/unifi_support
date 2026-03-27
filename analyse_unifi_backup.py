#!/usr/bin/env python3
"""
Analyse a decrypted UniFi OS v2 backup.

Reads the extracted backup directory (from decrypt_unifi_backup.py) and
produces a comprehensive report of the network configuration including:
  - Console/hardware info
  - Sites, networks, VLANs
  - WiFi networks (SSIDs, security, bands)
  - Firewall rules and groups
  - Port forwarding / NAT rules
  - Routing / static routes
  - Devices (APs, switches, gateways)
  - Users and clients
  - Certificates and keys
  - Alarms / alert configuration
  - UCore database tables
  - Security observations

Usage:
    python3 analyse_unifi_backup.py [extracted_backup_dir]

If no directory is specified, auto-detects *_extracted in the current dir.
"""

import sys
import os
import io
import json
import gzip
import struct
import tarfile
import zlib
import datetime
from pathlib import Path
from collections import defaultdict

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ─── BSON Parser (minimal, no external deps) ───────────────────────────

BSON_DOUBLE = 0x01
BSON_STRING = 0x02
BSON_DOCUMENT = 0x03
BSON_ARRAY = 0x04
BSON_BINARY = 0x05
BSON_UNDEFINED = 0x06
BSON_OBJECTID = 0x07
BSON_BOOL = 0x08
BSON_DATETIME = 0x09
BSON_NULL = 0x0A
BSON_REGEX = 0x0B
BSON_INT32 = 0x10
BSON_TIMESTAMP = 0x11
BSON_INT64 = 0x12
BSON_MINKEY = 0xFF
BSON_MAXKEY = 0x7F


def parse_bson_doc(data, offset=0):
    """Parse a single BSON document. Returns (dict, bytes_consumed)."""
    if offset + 4 > len(data):
        return None, 0
    doc_len = struct.unpack_from('<I', data, offset)[0]
    if doc_len < 5 or offset + doc_len > len(data):
        return None, 0

    result = {}
    pos = offset + 4
    end = offset + doc_len - 1  # last byte is 0x00 terminator

    while pos < end:
        elem_type = data[pos]
        pos += 1

        # Read element name (cstring)
        name_end = data.index(b'\x00', pos)
        name = data[pos:name_end].decode('utf-8', errors='replace')
        pos = name_end + 1

        if elem_type == BSON_DOUBLE:
            val = struct.unpack_from('<d', data, pos)[0]
            pos += 8
        elif elem_type == BSON_STRING:
            str_len = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            val = data[pos:pos + str_len - 1].decode('utf-8', errors='replace')
            pos += str_len
        elif elem_type == BSON_DOCUMENT:
            val, consumed = parse_bson_doc(data, pos)
            pos += consumed
        elif elem_type == BSON_ARRAY:
            val, consumed = parse_bson_array(data, pos)
            pos += consumed
        elif elem_type == BSON_BINARY:
            bin_len = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            _subtype = data[pos]
            pos += 1
            val = data[pos:pos + bin_len].hex()
            pos += bin_len
        elif elem_type == BSON_OBJECTID:
            val = data[pos:pos + 12].hex()
            pos += 12
        elif elem_type == BSON_BOOL:
            val = data[pos] != 0
            pos += 1
        elif elem_type == BSON_DATETIME:
            ms = struct.unpack_from('<q', data, pos)[0]
            pos += 8
            try:
                val = datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc).isoformat()
            except (OSError, ValueError):
                val = f"epoch_ms:{ms}"
        elif elem_type == BSON_NULL:
            val = None
        elif elem_type == BSON_REGEX:
            pat_end = data.index(b'\x00', pos)
            pattern = data[pos:pat_end].decode('utf-8', errors='replace')
            pos = pat_end + 1
            opt_end = data.index(b'\x00', pos)
            options = data[pos:opt_end].decode('utf-8', errors='replace')
            pos = opt_end + 1
            val = f"/{pattern}/{options}"
        elif elem_type == BSON_INT32:
            val = struct.unpack_from('<i', data, pos)[0]
            pos += 4
        elif elem_type == BSON_TIMESTAMP:
            val = struct.unpack_from('<Q', data, pos)[0]
            pos += 8
        elif elem_type == BSON_INT64:
            val = struct.unpack_from('<q', data, pos)[0]
            pos += 8
        elif elem_type in (BSON_MINKEY, BSON_MAXKEY, BSON_UNDEFINED):
            val = None
        else:
            # Unknown type — skip rest of doc
            break

        result[name] = val

    return result, doc_len


def parse_bson_array(data, offset=0):
    """Parse a BSON array. Returns (list, bytes_consumed)."""
    doc, consumed = parse_bson_doc(data, offset)
    if doc is None:
        return [], consumed
    return [doc[k] for k in sorted(doc.keys(), key=lambda x: int(x) if x.isdigit() else 0)], consumed


def parse_bson_stream(data):
    """Parse a stream of BSON documents. Yields dicts."""
    offset = 0
    while offset < len(data) - 4:
        doc, consumed = parse_bson_doc(data, offset)
        if doc is None or consumed == 0:
            break
        yield doc
        offset += consumed


# ─── BSON Database Parser ──────────────────────────────────────────────

def load_network_db(db_gz_path):
    """Load and parse the network BSON database (db.gz).

    UniFi stores the database as a sequence of BSON documents.
    The first doc of each collection is a command doc with __cmd=select
    and collection=<name>. Subsequent docs are the collection rows until
    the next command doc.
    """
    with gzip.open(db_gz_path, 'rb') as f:
        data = f.read()

    collections = defaultdict(list)
    current_collection = None

    for doc in parse_bson_stream(data):
        if doc.get('__cmd') == 'select' and 'collection' in doc:
            current_collection = doc['collection']
        elif current_collection:
            collections[current_collection].append(doc)

    return dict(collections)


# ─── YAML loader (fallback to raw text) ────────────────────────────────

def load_yaml_file(path):
    """Load a YAML file. Falls back to returning raw text if PyYAML unavailable."""
    with open(path, 'r', errors='replace') as f:
        text = f.read()
    if HAS_YAML:
        try:
            return yaml.safe_load(text)
        except Exception:
            return text
    return text


# ─── Report helpers ────────────────────────────────────────────────────

def section(title):
    width = 70
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def subsection(title):
    print(f"\n--- {title} ---")


def kv(key, value, indent=2):
    pad = " " * indent
    print(f"{pad}{key}: {value}")


def mask_sensitive(value, show_chars=4):
    """Mask a sensitive string, showing only last N chars."""
    if not value or not isinstance(value, str):
        return value
    if len(value) <= show_chars:
        return "****"
    return "*" * (len(value) - show_chars) + value[-show_chars:]


def ts_to_str(ts):
    """Convert a Unix timestamp (seconds or milliseconds) to readable string."""
    if ts is None:
        return "N/A"
    if isinstance(ts, str):
        return ts
    if ts > 1e12:
        ts = ts / 1000
    try:
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OSError, ValueError):
        return str(ts)


# ─── Analysis Functions ────────────────────────────────────────────────

def analyse_metadata(backup_dir):
    section("CONSOLE / HARDWARE INFO")
    meta_path = os.path.join(backup_dir, "backup/metadata.json")
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)
        kv("Hardware", meta.get("hardware_shortname", "Unknown"))
        kv("MAC Address", meta.get("mac", "Unknown"))
        kv("Firmware", meta.get("firmware_version", "Unknown"))
        kv("Timezone", meta.get("timezone", "Unknown"))
        kv("Backup Created", ts_to_str(meta.get("created_at")))
        kv("Owner SSO ID", meta.get("owner_id", "Unknown"))

    pkg_path = os.path.join(backup_dir, "backup/package-versions.json")
    if os.path.exists(pkg_path):
        with open(pkg_path) as f:
            pkg = json.load(f)
        subsection("Application Versions")
        for app, ver in sorted(pkg.get("controllers", {}).items()):
            kv(app.title(), ver, indent=4)
        for app, ver in sorted(pkg.get("services", {}).items()):
            kv(app.title(), ver, indent=4)

    sys_path = os.path.join(backup_dir, "backup/ucore/system-data.json")
    if os.path.exists(sys_path):
        with open(sys_path) as f:
            sysdata = json.load(f)
        subsection("System Settings")
        kv("Hostname", sysdata.get("hostname", "Unknown"))
        kv("SSH Enabled", sysdata.get("sshEnabled", False))
        if sysdata.get("hashedSshPassword"):
            kv("SSH Password Hash", sysdata["hashedSshPassword"][:40] + "...")

    settings_path = os.path.join(backup_dir, "backup/ucore/config/settings.yaml")
    if os.path.exists(settings_path):
        settings = load_yaml_file(settings_path)
        if isinstance(settings, dict):
            subsection("Console Settings")
            kv("Name", settings.get("name", ""))
            kv("Location", settings.get("location", {}).get("text", "") if isinstance(settings.get("location"), dict) else "")
            lat = settings.get("location", {}).get("lat", "") if isinstance(settings.get("location"), dict) else ""
            lon = settings.get("location", {}).get("long", "") if isinstance(settings.get("location"), dict) else ""
            if lat and lon:
                kv("Coordinates", f"{lat}, {lon}")
            kv("Auto Backup", settings.get("autoBackupEnabled", ""))
            update = settings.get("updateSchedule", {})
            if isinstance(update, dict):
                kv("Update Schedule", f"{update.get('frequency', '')} (day {update.get('day', '')}, hour {update.get('hour', '')})")
            storage = settings.get("ustorage", {})
            if isinstance(storage, dict):
                current = storage.get("currentSettings", {})
                if isinstance(current, dict):
                    kv("Storage RAID", current.get("raid", ""))


def analyse_users(backup_dir):
    section("USERS / ACCOUNTS")
    users_path = os.path.join(backup_dir, "backup/ucore/config/cache/users.json")
    if not os.path.exists(users_path):
        print("  No cached users found.")
        return

    with open(users_path) as f:
        users = json.load(f)

    if not isinstance(users, list):
        users = [users] if isinstance(users, dict) else []

    print(f"  Total accounts: {len(users)}")
    for u in users:
        subsection(u.get("full_name", "Unknown"))
        kv("Email", u.get("email", ""))
        kv("SSO Username", u.get("sso_username", ""))
        kv("SSO UUID", u.get("sso_uuid", ""))
        kv("Status", u.get("email_status", ""))
        kv("Account Status", u.get("status", ""))
        kv("Last Login", ts_to_str(u.get("login_time")))
        kv("Created", ts_to_str(u.get("create_time")))
        roles = u.get("roles", [])
        if roles:
            role_names = [r.get("name", "?") for r in roles if isinstance(r, dict)]
            kv("Roles", ", ".join(role_names))
        perms = u.get("permissions", {})
        if isinstance(perms, dict):
            admin_perms = [k for k, v in perms.items() if isinstance(v, list) and "admin" in v]
            if admin_perms:
                kv("Admin Permissions", ", ".join(sorted(admin_perms)))


def analyse_sites(db):
    section("SITES")
    sites = db.get("site", [])
    if not sites:
        print("  No sites found.")
        return
    for s in sites:
        subsection(s.get("name", "Unknown"))
        kv("Site ID", s.get("_id", ""))
        kv("Description", s.get("desc", ""))


def analyse_networks(db):
    section("NETWORKS / VLANs")
    nets = db.get("networkconf", [])
    if not nets:
        print("  No networks found.")
        return

    print(f"  Total networks: {len(nets)}")
    for n in sorted(nets, key=lambda x: x.get("vlan", x.get("vlan_tag", 0) or 0)):
        name = n.get("name", "Unknown")
        purpose = n.get("purpose", "")
        vlan = n.get("vlan") or n.get("vlan_tag") or n.get("vlan_id", "")
        subnet = n.get("ip_subnet", "")
        dhcp_start = n.get("dhcpd_start", "")
        dhcp_stop = n.get("dhcpd_stop", "")
        dhcp_enabled = n.get("dhcpd_enabled", False)
        igmp = n.get("igmp_snooping", False)
        domain = n.get("domain_name", "")
        enabled = n.get("enabled", True)
        ipv6 = n.get("ipv6_interface_type", "")

        subsection(f"{name} (VLAN {vlan})" if vlan else name)
        kv("Purpose", purpose)
        kv("Subnet", subnet)
        kv("Enabled", enabled)
        if dhcp_enabled:
            kv("DHCP Range", f"{dhcp_start} - {dhcp_stop}")
        else:
            kv("DHCP", "Disabled")
        if n.get("dhcpd_dns_enabled") and n.get("dhcpd_dns_1"):
            dns = [n.get("dhcpd_dns_1", ""), n.get("dhcpd_dns_2", ""), n.get("dhcpd_dns_3", "")]
            kv("DNS Servers", ", ".join([d for d in dns if d]))
        if domain:
            kv("Domain", domain)
        if igmp:
            kv("IGMP Snooping", "Enabled")
        if ipv6:
            kv("IPv6", ipv6)
        if n.get("dhcpd_gateway_enabled") and n.get("dhcpd_gateway"):
            kv("DHCP Gateway Override", n["dhcpd_gateway"])


def analyse_wlans(db):
    section("WIRELESS NETWORKS (SSIDs)")
    wlans = db.get("wlanconf", [])
    if not wlans:
        print("  No wireless networks found.")
        return

    print(f"  Total SSIDs: {len(wlans)}")
    for w in sorted(wlans, key=lambda x: x.get("name", "")):
        name = w.get("name", "Unknown")
        enabled = w.get("enabled", True)
        security = w.get("security", "open")
        wpa_mode = w.get("wpa_mode", "")
        wpa_enc = w.get("wpa_enc", "")
        passphrase = w.get("x_passphrase", "")
        is_guest = w.get("is_guest", False)
        band = w.get("wlan_band", "both")
        vlan = w.get("networkconf_id", "")
        hide_ssid = w.get("hide_ssid", False)
        mac_filter = w.get("mac_filter_enabled", False)
        pmf = w.get("pmf_mode", "")
        band_steering = w.get("band_steering_mode", "")
        min_rate = w.get("minrate_ng_enabled", False)

        subsection(name)
        kv("Enabled", enabled)
        kv("Security", f"{security} (WPA mode: {wpa_mode}, Encryption: {wpa_enc})" if wpa_mode else security)
        if passphrase:
            kv("Passphrase", mask_sensitive(passphrase, 4))
        kv("Guest Network", is_guest)
        kv("Band", band)
        kv("Hidden SSID", hide_ssid)
        if mac_filter:
            kv("MAC Filtering", "Enabled")
        if pmf:
            kv("PMF (802.11w)", pmf)
        if band_steering:
            kv("Band Steering", band_steering)
        if w.get("radius_profile_id"):
            kv("RADIUS Profile", w["radius_profile_id"])


def analyse_firewall(db):
    section("FIREWALL RULES")
    rules = db.get("firewallrule", [])
    groups = db.get("firewallgroup", [])

    if groups:
        subsection(f"Firewall Groups ({len(groups)})")
        for g in sorted(groups, key=lambda x: x.get("name", "")):
            name = g.get("name", "")
            gtype = g.get("group_type", "")
            members = g.get("group_members", [])
            if isinstance(members, list):
                print(f"    {name} ({gtype}): {', '.join(str(m) for m in members[:10])}")
                if len(members) > 10:
                    print(f"      ... and {len(members) - 10} more")
            else:
                print(f"    {name} ({gtype})")

    if rules:
        subsection(f"Firewall Rules ({len(rules)})")
        for r in sorted(rules, key=lambda x: (x.get("ruleset", ""), x.get("rule_index", 0))):
            name = r.get("name", "Unnamed")
            action = r.get("action", "")
            ruleset = r.get("ruleset", "")
            enabled = r.get("enabled", True)
            protocol = r.get("protocol", "all")
            src = r.get("src_address", r.get("src_firewallgroup_ids", "any"))
            dst = r.get("dst_address", r.get("dst_firewallgroup_ids", "any"))
            dst_port = r.get("dst_port", "")

            status = "" if enabled else " [DISABLED]"
            print(f"    [{ruleset}] {action.upper()} {name}{status}")
            print(f"      Proto: {protocol}  Src: {src}  Dst: {dst}" + (f"  Port: {dst_port}" if dst_port else ""))
    else:
        print("  No custom firewall rules found.")


def analyse_port_forwarding(db):
    section("PORT FORWARDING / NAT")
    forwards = db.get("portforward", [])
    if not forwards:
        print("  No port forwarding rules found.")
        return

    print(f"  Total rules: {len(forwards)}")
    for pf in sorted(forwards, key=lambda x: x.get("name", "")):
        name = pf.get("name", "Unnamed")
        enabled = pf.get("enabled", True)
        proto = pf.get("proto", "tcp_udp")
        src = pf.get("src", "any")
        dst_port = pf.get("dst_port", "")
        fwd_ip = pf.get("fwd", "")
        fwd_port = pf.get("fwd_port", "")
        status = "" if enabled else " [DISABLED]"

        print(f"  {name}{status}: {proto} :{dst_port} -> {fwd_ip}:{fwd_port}" + (f" (src: {src})" if src != "any" else ""))


def analyse_routing(db):
    section("STATIC ROUTES")
    routes = db.get("routing", [])
    if not routes:
        print("  No static routes found.")
        return

    for r in routes:
        name = r.get("name", "")
        rtype = r.get("type", "")
        network = r.get("static-route_network", "")
        nexthop = r.get("static-route_nexthop", "")
        iface = r.get("static-route_interface", "")
        enabled = r.get("enabled", True)
        status = "" if enabled else " [DISABLED]"
        print(f"  {name}{status}: {network} -> {nexthop or iface} ({rtype})")


def analyse_devices(db):
    section("NETWORK DEVICES")
    devices = db.get("device", [])
    if not devices:
        print("  No devices in database.")
        return

    print(f"  Total devices: {len(devices)}")
    for d in sorted(devices, key=lambda x: x.get("name", x.get("hostname", ""))):
        name = d.get("name", d.get("hostname", "Unknown"))
        model = d.get("model", "")
        mac = d.get("mac", "")
        ip = d.get("ip", "")
        dev_type = d.get("type", "")
        adopted = d.get("adopted", False)
        version = d.get("version", "")
        site_id = d.get("site_id", "")

        subsection(f"{name} ({model})")
        kv("Type", dev_type)
        kv("MAC", mac)
        kv("IP", ip)
        kv("Firmware", version)
        kv("Adopted", adopted)
        if d.get("config_network", {}).get("ip"):
            kv("Config IP", d["config_network"]["ip"])


def analyse_clients(db):
    section("KNOWN CLIENTS / STATIONS")
    clients = db.get("user", [])  # 'user' collection = network clients
    if not clients:
        print("  No known clients found.")
        return

    print(f"  Total known clients: {len(clients)}")
    # Show summary table
    for c in sorted(clients, key=lambda x: x.get("name", x.get("hostname", x.get("mac", "")))):
        name = c.get("name", c.get("hostname", ""))
        mac = c.get("mac", "")
        note = c.get("note", "")
        fixed_ip = c.get("fixed_ip", "")
        use_fixedip = c.get("use_fixedip", False)
        blocked = c.get("blocked", False)
        network_id = c.get("network_id", "")

        display_name = name or mac
        extras = []
        if use_fixedip and fixed_ip:
            extras.append(f"fixed:{fixed_ip}")
        if blocked:
            extras.append("BLOCKED")
        if note:
            extras.append(f'note:"{note}"')

        extra_str = f" ({', '.join(extras)})" if extras else ""
        print(f"    {display_name:30s} {mac:20s}{extra_str}")


def analyse_settings(db):
    section("CONTROLLER SETTINGS")
    settings = db.get("setting", [])
    if not settings:
        print("  No settings found.")
        return

    interesting_keys = {
        "super_mgmt": ["autobackup_enabled", "autobackup_cron_expr", "discoverable",
                       "override_inform_host", "x_ssh_username", "x_ssh_enabled"],
        "connectivity": ["enabled", "uplink_type"],
        "dpi": ["enabled"],
        "ips": ["enabled", "mode", "honeypot_enabled", "restrict_tor",
                "restrict_dns_over_tls", "ad_blocking_enabled", "ad_blocking_mode"],
        "country": ["code"],
        "locale": ["timezone"],
        "radius": ["auth_port", "acct_port", "enabled"],
        "guest_access": ["auth", "redirect_enabled", "redirect_url"],
        "ntp": ["ntp_server_1", "ntp_server_2"],
        "usg": ["broadcast_ping", "dns_cache_enabled"],
        "auto_speedtest": ["enabled", "interval"],
    }

    for s in sorted(settings, key=lambda x: x.get("key", "")):
        key = s.get("key", "")
        if key in interesting_keys:
            subsection(key)
            for field in interesting_keys[key]:
                if field in s:
                    val = s[field]
                    if "password" in field.lower() or "secret" in field.lower() or field.startswith("x_"):
                        if isinstance(val, str) and val:
                            val = mask_sensitive(val)
                    kv(field, val, indent=4)
        elif key == "mgmt":
            subsection("Management")
            for field in ["syslog_enabled", "unifi_idp_enabled", "auto_upgrade", "led_enabled"]:
                if field in s:
                    kv(field, s[field], indent=4)


def analyse_port_profiles(db):
    section("PORT PROFILES / SWITCH CONFIG")
    profiles = db.get("portconf", [])
    if not profiles:
        print("  No port profiles found.")
        return

    print(f"  Total port profiles: {len(profiles)}")
    for p in sorted(profiles, key=lambda x: x.get("name", "")):
        name = p.get("name", "")
        poe = p.get("poe_mode", "")
        native_vlan = p.get("native_networkconf_id", "")
        tagged = p.get("voice_networkconf_id", "")
        stp = p.get("stormctrl_enabled", False)
        speed = p.get("speed", "")
        print(f"    {name}: speed={speed or 'auto'} poe={poe or 'N/A'}" + (f" stp_ctrl={stp}" if stp else ""))


def analyse_alarms(backup_dir):
    section("ALARM / ALERT CONFIGURATION")
    alarms_path = os.path.join(backup_dir, "backup/uos/alarms/network/alarms.json")
    if not os.path.exists(alarms_path):
        print("  No network alarms found.")
        return

    with open(alarms_path) as f:
        alarms = json.load(f)

    if not isinstance(alarms, list):
        print("  Unexpected alarms format.")
        return

    print(f"  Total alarm rules: {len(alarms)}")
    for a in alarms:
        title = a.get("title", "Unnamed")
        paused = a.get("is_paused", False)
        triggers = a.get("triggers_data", [[]])
        trigger_names = []
        for tg in triggers:
            if isinstance(tg, list):
                for t in tg:
                    if isinstance(t, dict):
                        trigger_names.append(t.get("id", "?"))

        status = " [PAUSED]" if paused else ""
        print(f"    {title}{status}")
        if trigger_names:
            print(f"      Triggers: {', '.join(trigger_names)}")


def analyse_certificates(backup_dir):
    section("CERTIFICATES & KEYS")
    cert_files = []
    key_files = []
    for root, dirs, files in os.walk(os.path.join(backup_dir, "backup")):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, backup_dir)
            if f.endswith(('.crt', '.pem')):
                cert_files.append(rel)
            elif f.endswith(('.key',)):
                key_files.append(rel)

    if cert_files:
        subsection(f"Certificates ({len(cert_files)})")
        for c in sorted(cert_files):
            print(f"    {c}")
    if key_files:
        subsection(f"Private Keys ({len(key_files)})")
        for k in sorted(key_files):
            print(f"    {k}  [SENSITIVE]")


def analyse_ucore_db(backup_dir):
    section("UCORE DATABASE (PostgreSQL)")
    dbinfo_path = os.path.join(backup_dir, "backup/ucore/database/dbinfo.json")
    if not os.path.exists(dbinfo_path):
        print("  No UCore database found.")
        return

    with open(dbinfo_path) as f:
        dbinfo = json.load(f)

    tables = dbinfo.get("tables", [])
    migration = dbinfo.get("migrationVersion", "")
    print(f"  Migration version: {migration}")
    print(f"  Tables: {', '.join(tables)}")

    # Check for device data
    db_dir = os.path.join(backup_dir, "backup/ucore/database")
    for dat_file in sorted(Path(db_dir).glob("*.dat.gz")):
        try:
            with gzip.open(str(dat_file), 'rb') as f:
                content = f.read()
            if len(content) > 10:
                lines = content.decode('utf-8', errors='replace').strip().split('\n')
                print(f"  {dat_file.name}: {len(lines)} rows, {len(content):,} bytes")
        except Exception:
            pass


def analyse_security(db, backup_dir):
    section("SECURITY OBSERVATIONS")
    findings = []

    # Check SSH
    sys_path = os.path.join(backup_dir, "backup/ucore/system-data.json")
    if os.path.exists(sys_path):
        with open(sys_path) as f:
            sysdata = json.load(f)
        if sysdata.get("sshEnabled"):
            findings.append("[INFO] SSH is enabled on the console")

    # Check IPS/IDS
    for s in db.get("setting", []):
        if s.get("key") == "ips":
            if not s.get("enabled"):
                findings.append("[WARN] Intrusion Prevention System (IPS/IDS) is DISABLED")
            else:
                mode = s.get("mode", "ids")
                findings.append(f"[OK] IPS/IDS is enabled (mode: {mode})")
                if s.get("restrict_tor"):
                    findings.append("[OK] Tor traffic restriction enabled")
                if s.get("ad_blocking_enabled"):
                    findings.append(f"[OK] Ad blocking enabled (mode: {s.get('ad_blocking_mode', 'N/A')})")
        if s.get("key") == "dpi":
            if s.get("enabled"):
                findings.append("[OK] Deep Packet Inspection (DPI) is enabled")
            else:
                findings.append("[INFO] Deep Packet Inspection (DPI) is disabled")

    # Check WiFi security
    for w in db.get("wlanconf", []):
        if not w.get("enabled", True):
            continue
        security = w.get("security", "open")
        name = w.get("name", "")
        if security == "open":
            findings.append(f"[WARN] SSID '{name}' has NO encryption (open)")
        passphrase = w.get("x_passphrase", "")
        if passphrase and len(passphrase) < 12:
            findings.append(f"[WARN] SSID '{name}' has a short WiFi password ({len(passphrase)} chars)")

    # Check for port forwarding
    forwards = db.get("portforward", [])
    enabled_fwd = [pf for pf in forwards if pf.get("enabled", True)]
    if enabled_fwd:
        findings.append(f"[INFO] {len(enabled_fwd)} active port forwarding rules expose internal services")
        for pf in enabled_fwd:
            port = pf.get("dst_port", "?")
            fwd = pf.get("fwd", "?")
            findings.append(f"  -> Port {port} forwarded to {fwd}")

    # Check for blocked clients
    blocked = [c for c in db.get("user", []) if c.get("blocked")]
    if blocked:
        findings.append(f"[INFO] {len(blocked)} blocked client(s)")

    # Check for private keys
    key_count = 0
    for root, dirs, files in os.walk(os.path.join(backup_dir, "backup")):
        for f in files:
            if f.endswith('.key'):
                key_count += 1
    if key_count:
        findings.append(f"[WARN] Backup contains {key_count} private key file(s) — handle with care")

    # Check cloud config for exposed credentials
    cloud_path = os.path.join(backup_dir, "backup/ucore/config/cloud.yaml")
    if os.path.exists(cloud_path):
        findings.append("[INFO] Cloud credentials (deviceAuth, privateKey) present in backup")

    if not findings:
        print("  No specific observations.")
    else:
        for f in findings:
            print(f"  {f}")


# ─── Main ──────────────────────────────────────────────────────────────

def find_backup_dir():
    """Auto-detect extracted backup directory."""
    candidates = list(Path(".").glob("*_extracted"))
    candidates = [c for c in candidates if c.is_dir() and (c / "backup").is_dir()]
    if len(candidates) == 1:
        return str(candidates[0])
    elif len(candidates) > 1:
        print("Multiple extracted backups found:")
        for c in candidates:
            print(f"  {c}")
        sys.exit(1)
    return None


def main():
    if len(sys.argv) >= 2:
        backup_dir = sys.argv[1]
    else:
        backup_dir = find_backup_dir()

    if not backup_dir or not os.path.isdir(backup_dir):
        print(f"Usage: {sys.argv[0]} <extracted_backup_dir>")
        print("Run decrypt_unifi_backup.py first to extract the backup.")
        sys.exit(1)

    print(f"Analysing backup: {os.path.abspath(backup_dir)}")
    print("=" * 70)

    # Load the network BSON database
    db_path = os.path.join(backup_dir, "backup/network/db.gz")
    if os.path.exists(db_path):
        print("Loading network database (BSON)...")
        db = load_network_db(db_path)
        collections = {k: len(v) for k, v in db.items()}
        print(f"  Collections: {json.dumps(collections, indent=4)}")
    else:
        print("  WARNING: No network database found (backup/network/db.gz)")
        db = {}

    # Run all analysis sections
    analyse_metadata(backup_dir)
    analyse_users(backup_dir)
    analyse_sites(db)
    analyse_networks(db)
    analyse_wlans(db)
    analyse_devices(db)
    analyse_clients(db)
    analyse_firewall(db)
    analyse_port_forwarding(db)
    analyse_routing(db)
    analyse_port_profiles(db)
    analyse_settings(db)
    analyse_alarms(backup_dir)
    analyse_certificates(backup_dir)
    analyse_ucore_db(backup_dir)
    analyse_security(db, backup_dir)

    print("\n" + "=" * 70)
    print("  Analysis complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
