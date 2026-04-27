"""
=============================================================
  Windows Registry Change Monitoring System
  Full Toolkit - registry_monitor.py
  For educational / blue-team lab use only.
=============================================================
"""

import winreg
import json
import hashlib
import os
import time
import datetime
import csv

# ─────────────────────────────────────────────
# 1.  CONFIGURATION  – edit freely
# ─────────────────────────────────────────────

BASELINE_FILE   = "registry_baseline.json"
LOG_FILE        = "registry_changes.log"
REPORT_FILE     = "registry_report.csv"
POLL_INTERVAL   = 30          
MAX_CYCLES      = 10         

HKCU = winreg.HKEY_CURRENT_USER
HKLM = winreg.HKEY_LOCAL_MACHINE

MONITORED_KEYS = [
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),

    (HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender"),
    (HKLM, r"SOFTWARE\Microsoft\Windows Defender\Features"),

    (HKLM, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"),

    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),

    (HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    (HKCU, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),

    (HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),

    (HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
]

MALWARE_PATTERNS = {
    "DisableAntiSpyware":     ("1", "Windows Defender AntiSpyware disabled"),
    "DisableRealtimeMonitoring": ("1", "Real-time monitoring disabled"),
    "EnableFirewall":         ("0", "Firewall disabled"),
    "DisableFirewall":        ("1", "Firewall explicitly disabled"),
    "Shell":                  (None, "Shell replacement detected – possible hijack"),
    "Userinit":               (None, "Userinit modified – possible hijack"),
    "DisableTaskMgr":         ("1", "Task Manager disabled"),
    "DisableCMD":             ("1", "Command Prompt disabled"),
    "DisableRegistryTools":   ("1", "Registry editor disabled"),
    "ConsentPromptBehaviorAdmin": ("0", "UAC fully disabled for admins"),
    "EnableLUA":              ("0", "User Account Control disabled"),
}

# ─────────────────────────────────────────────
# 2.  HELPER UTILITIES
# ─────────────────────────────────────────────

def hive_name(hive):
    return {HKCU: "HKCU", HKLM: "HKLM"}.get(hive, "UNKNOWN")


def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(message, level="INFO"):
    entry = f"[{timestamp()}] [{level}]  {message}"
    print(entry)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")


# ─────────────────────────────────────────────
# 3.  REGISTRY READER
# ─────────────────────────────────────────────

def read_key(hive, subkey):
    """
    Returns a dict  { value_name: (data, reg_type) }
    Returns {}  if the key doesn't exist or access is denied.
    """
    values = {}
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                name, data, reg_type = winreg.EnumValue(key, i)
                values[name] = (str(data), reg_type)
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except FileNotFoundError:
        pass          
    except PermissionError:
        log(f"Access denied: {hive_name(hive)}\\{subkey}", "WARN")
    return values


def snapshot_all():
    """Capture the current state of every monitored key."""
    snap = {}
    for hive, subkey in MONITORED_KEYS:
        label = f"{hive_name(hive)}\\{subkey}"
        snap[label] = read_key(hive, subkey)
    return snap


# ─────────────────────────────────────────────
# 4.  BASELINE  (create / load)
# ─────────────────────────────────────────────

def create_baseline():
    snap = snapshot_all()
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(snap, f, indent=2)
    log(f"Baseline created → {BASELINE_FILE}")
    return snap


def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        log("No baseline found – creating one now.", "WARN")
        return create_baseline()
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        log(f"Baseline loaded ← {BASELINE_FILE}")
        return json.load(f)


def baseline_checksum():
    """SHA-256 of the baseline file – for tamper detection."""
    if not os.path.exists(BASELINE_FILE):
        return None
    with open(BASELINE_FILE, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ─────────────────────────────────────────────
# 5.  CHANGE DETECTOR
# ─────────────────────────────────────────────

def compare_snapshots(old, new):
    """
    Returns a list of change dicts:
        { key, type, name, old_value, new_value, malware_flag, alert_msg }
    """
    changes = []

    all_keys = set(old.keys()) | set(new.keys())

    for key in all_keys:
        old_vals = old.get(key, {})
        new_vals = new.get(key, {})

        # Deleted values
        for name in old_vals:
            if name not in new_vals:
                changes.append(_make_change(key, "DELETED", name,
                                            old_vals[name][0], ""))

        # Added values
        for name in new_vals:
            if name not in old_vals:
                changes.append(_make_change(key, "ADDED", name,
                                            "", new_vals[name][0]))

        # Modified values
        for name in new_vals:
            if name in old_vals and old_vals[name][0] != new_vals[name][0]:
                changes.append(_make_change(key, "MODIFIED", name,
                                            old_vals[name][0],
                                            new_vals[name][0]))
    return changes


def _make_change(key, change_type, name, old_val, new_val):
    malware_flag = False
    alert_msg    = ""

    if name in MALWARE_PATTERNS:
        pattern_val, desc = MALWARE_PATTERNS[name]
        if pattern_val is None or new_val == pattern_val:
            malware_flag = True
            alert_msg    = desc

    return {
        "timestamp":    timestamp(),
        "key":          key,
        "type":         change_type,
        "name":         name,
        "old_value":    old_val,
        "new_value":    new_val,
        "malware_flag": malware_flag,
        "alert_msg":    alert_msg,
    }


# ─────────────────────────────────────────────
# 6.  MALWARE-PATTERN CHECKER  (standalone scan)
# ─────────────────────────────────────────────

def scan_malware_patterns():
    """
    Scan the live registry for known malicious values
    regardless of baseline differences.
    """
    log("─── Malware-Pattern Scan ───────────────────────────────")
    hits = []
    snap = snapshot_all()
    for key_label, values in snap.items():
        for name, (data, _) in values.items():
            if name in MALWARE_PATTERNS:
                pattern_val, desc = MALWARE_PATTERNS[name]
                if pattern_val is None or data == pattern_val:
                    msg = f"[MALWARE-PATTERN] {key_label} → {name} = {data!r}  ({desc})"
                    log(msg, "ALERT")
                    hits.append({"key": key_label, "name": name,
                                 "value": data, "description": desc})
    if not hits:
        log("No malware patterns found in current registry state.", "INFO")
    return hits


# ─────────────────────────────────────────────
# 7.  AUTORUN DETECTOR
# ─────────────────────────────────────────────

AUTORUN_KEYS = [
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]

SUSPICIOUS_PATHS = [
    r"\appdata\local\temp",
    r"\appdata\roaming",
    r"\users\public",
    r"\windows\temp",
    r"\programdata",
]

def detect_autoruns():
    log("─── Autorun Detection ─────────────────────────────────")
    findings = []
    for hive, subkey in AUTORUN_KEYS:
        label  = f"{hive_name(hive)}\\{subkey}"
        values = read_key(hive, subkey)
        for name, (data, _) in values.items():
            data_lower = data.lower()
            suspicious = any(p in data_lower for p in SUSPICIOUS_PATHS)
            flag = "SUSPICIOUS" if suspicious else "INFO"
            msg  = f"Autorun → [{name}] = {data}"
            if suspicious:
                msg += "  ← SUSPICIOUS PATH"
            log(f"{label}: {msg}", flag)
            findings.append({"key": label, "name": name, "value": data,
                              "suspicious": suspicious})
    return findings


# ─────────────────────────────────────────────
# 8.  INTEGRITY CHECKER
# ─────────────────────────────────────────────

def integrity_check(baseline):
    """Full comparison: baseline vs live registry."""
    log("─── Integrity Check ───────────────────────────────────")
    current = snapshot_all()
    changes = compare_snapshots(baseline, current)

    if not changes:
        log("Integrity check PASSED – no changes detected.", "INFO")
    else:
        log(f"Integrity check FAILED – {len(changes)} change(s) detected.", "ALERT")
        for c in changes:
            flag = "ALERT" if c["malware_flag"] else "WARN"
            log(
                f"  [{c['type']}] {c['key']}\\{c['name']}  "
                f"| old={c['old_value']!r} → new={c['new_value']!r}"
                + (f"  ⚠ {c['alert_msg']}" if c["alert_msg"] else ""),
                flag,
            )
    return changes


# ─────────────────────────────────────────────
# 9.  REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_report(changes):
    fieldnames = ["timestamp", "key", "type", "name",
                  "old_value", "new_value", "malware_flag", "alert_msg"]
    with open(REPORT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(changes)
    log(f"Report saved → {REPORT_FILE}  ({len(changes)} record(s))")


# ─────────────────────────────────────────────
# 10. CONTINUOUS MONITOR
# ─────────────────────────────────────────────

def continuous_monitor(baseline, cycles=MAX_CYCLES, interval=POLL_INTERVAL):
    """
    Polls the registry every `interval` seconds.
    If cycles == 0 it runs forever (Ctrl-C to stop).
    """
    log(f"Starting continuous monitor  |  interval={interval}s  |  "
        f"cycles={'∞' if cycles == 0 else cycles}")
    all_changes = []
    previous    = baseline
    cycle       = 0

    try:
        while True:
            cycle += 1
            log(f"── Scan cycle #{cycle} ──────────────────────────────────────")
            current = snapshot_all()
            changes = compare_snapshots(previous, current)

            if changes:
                for c in changes:
                    flag = "ALERT" if c["malware_flag"] else "WARN"
                    log(
                        f"  [{c['type']}] {c['key']}\\{c['name']}  "
                        f"old={c['old_value']!r} → new={c['new_value']!r}"
                        + (f"  ⚠ {c['alert_msg']}" if c["alert_msg"] else ""),
                        flag,
                    )
                all_changes.extend(changes)
            else:
                log("  No changes in this cycle.", "INFO")

            previous = current

            if cycles and cycle >= cycles:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        log("Monitor stopped by user (Ctrl-C).")

    generate_report(all_changes)
    return all_changes


# ─────────────────────────────────────────────
# 11. MAIN  –  INTERACTIVE MENU
# ─────────────────────────────────────────────

def print_banner():
    print("""
╔══════════════════════════════════════════════════════╗
║   Windows Registry Change Monitoring System          ║
║   Blue-Team Toolkit  |  Educational Use Only         ║
╚══════════════════════════════════════════════════════╝
""")

def main():
    print_banner()
    baseline = load_baseline()

    while True:
        print("""
  ┌─ MENU ──────────────────────────────────────────┐
  │  1. Create / Refresh Baseline                   │
  │  2. One-time Integrity Check (vs baseline)      │
  │  3. Detect Autorun Entries                      │
  │  4. Scan for Malware Patterns                   │
  │  5. Start Continuous Monitor                    │
  │  6. Generate CSV Report (from log)              │
  │  7. Show Baseline Checksum                      │
  │  0. Exit                                        │
  └─────────────────────────────────────────────────┘""")

        choice = input("  Enter choice: ").strip()

        if choice == "1":
            baseline = create_baseline()

        elif choice == "2":
            changes = integrity_check(baseline)
            if changes:
                generate_report(changes)

        elif choice == "3":
            detect_autoruns()

        elif choice == "4":
            scan_malware_patterns()

        elif choice == "5":
            try:
                cycles   = int(input("  Scan cycles (0 = infinite): ").strip())
                interval = int(input(f"  Interval in seconds [{POLL_INTERVAL}]: ").strip()
                               or POLL_INTERVAL)
            except ValueError:
                cycles, interval = MAX_CYCLES, POLL_INTERVAL
            continuous_monitor(baseline, cycles, interval)

        elif choice == "6":
            # re-generate report from all_changes (session-only if not in memory)
            log("Use option 5 to generate a full report after a monitor session.")

        elif choice == "7":
            chk = baseline_checksum()
            log(f"Baseline SHA-256: {chk}")

        elif choice == "0":
            log("Exiting. Goodbye.")
            break

        else:
            print("  Invalid choice, try again.")


if __name__ == "__main__":
    main()
