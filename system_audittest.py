import win32evtlog
import win32evtlogutil
import subprocess
import json
import re
import sqlite3
import csv
import hashlib
from pathlib import Path
from datetime import datetime, timedelta


# Convert Chrome/Edge timestamps
def chrome_time_to_datetime(webkit_timestamp):
    """
    Convert Chrome/Edge WebKit timestamp (µs since 1601) 
    into a human-readable datetime string.
    """
    if not webkit_timestamp:
        return ""

    try:
        epoch_start = datetime(1601, 1, 1)
        converted = epoch_start + timedelta(microseconds=int(webkit_timestamp))
        return converted.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return ""


# Read Windows Event Logs
def read_event_log(log_name, count=50):
    server = "localhost"
    handle = win32evtlog.OpenEventLog(server, log_name)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(handle, flags, 0)

    extracted = []

    if events:
        for event in events[:count]:
            record = {
                "TimeGenerated": str(event.TimeGenerated),
                "EventID": event.EventID & 0xFFFF,
                "SourceName": event.SourceName,
                "EventType": event.EventType,
                "Category": event.EventCategory,
                "Message": win32evtlogutil.SafeFormatMessage(event, log_name)
            }
            extracted.append(record)

    win32evtlog.CloseEventLog(handle)
    return extracted


# Installed Applications
def get_installed_apps():
    try:
        output = subprocess.check_output(
            'reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" /s',
            shell=True, text=True, errors='ignore'
        )

        apps = []
        current_app = {}

        for line in output.splitlines():
            line = line.strip()

            if line.startswith("HKEY_LOCAL_MACHINE"):
                if current_app:
                    apps.append(current_app)
                current_app = {"RegistryKey": line}

            match = re.match(r"(\w+)\s+REG_\w+\s+(.*)", line)
            if match:
                key, value = match.groups()
                current_app[key] = value

        if current_app:
            apps.append(current_app)

        return apps

    except Exception as e:
        return [{"Error": f"Unable to read installed apps: {e}"}]


# Save Installed Apps CSV
def save_installed_apps_to_csv(apps, filename):
    filename = Path(filename)
    columns = [
        "RegistryKey", "DisplayName", "DisplayVersion",
        "Publisher", "InstallDate", "InstallLocation", "UninstallString"
    ]

    with filename.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        for app in apps:
            writer.writerow({col: app.get(col, "") for col in columns})


# Login History (Event 4624)
def get_login_history():
    try:
        output = subprocess.check_output(
            r'wevtutil qe Security /q:"*[System/EventID=4624]" /f:xml /c:50',
            shell=True, text=True, errors="ignore"
        )

        events = []
        raw_events = output.strip().split("</Event>")

        for evt in raw_events:
            evt = evt.strip()
            if "<Event" not in evt:
                continue

            evt = evt + "</Event>"

            t = re.search(r"<TimeCreated SystemTime=\"(.*?)\"/>", evt)
            u = re.search(r"<Data Name=\"TargetUserName\">(.*?)</Data>", evt)
            ip = re.search(r"<Data Name=\"IpAddress\">(.*?)</Data>", evt)

            events.append({
                "TimestampUTC": t.group(1) if t else "",
                "Username": u.group(1) if u else "",
                "SourceIP": ip.group(1) if ip else ""
            })

        return events

    except Exception as e:
        return [{"Error": f"Unable to read logins: {e}"}]

# Read Chrome History
def read_chrome_history():
    db_path = Path.home() / r"AppData/Local/Google/Chrome/User Data/Default/History"
    return read_browser_history_generic(db_path)


# Read Edge History
def read_edge_history():
    db_path = Path.home() / r"AppData/Local/Microsoft/Edge/User Data/Default/History"
    return read_browser_history_generic(db_path)

# Generic Browser History Reader
def read_browser_history_generic(db_path):
    if not db_path.exists():
        return []

    temp_copy = Path("temp_browser.db")
    with open(db_path, "rb") as src, open(temp_copy, "wb") as dst:
        dst.write(src.read())

    results = []
    try:
        conn = sqlite3.connect(temp_copy)
        c = conn.cursor()
        c.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls ORDER BY last_visit_time DESC LIMIT 50
        """)

        for url, title, visit_count, last_time in c.fetchall():
            results.append({
                "url": url,
                "title": title,
                "visit_count": visit_count,
                "last_visit_time": chrome_time_to_datetime(last_time)
            })

    except Exception as e:
        print("History read error:", e)

    finally:
        conn.close()
        temp_copy.unlink(missing_ok=True)

    return results


# Save Browser History CSV
def save_browser_history_to_csv(history, filename):
    filename = Path(filename)
    columns = ["URL", "Title", "VisitCount", "LastVisitTime"]

    with filename.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        for entry in history:
            writer.writerow({
                "URL": entry.get("url", ""),
                "Title": entry.get("title", ""),
                "VisitCount": entry.get("visit_count", ""),
                "LastVisitTime": entry.get("last_visit_time", "")
            })



# Make Audit Folder (Works)
def get_audit_folder():
    folder = Path.home() / "Desktop" / "Audit"
    folder.mkdir(exist_ok=True)
    return folder


# SHA256 Generator (Pray)
def save_file_hash(file_path):
    sha = hashlib.sha256()

    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha.update(block)

    hash_value = sha.hexdigest()
    hash_file = str(file_path) + ".sha256"

    with open(hash_file, "w") as f:
        f.write(hash_value)

    return hash_file


# MAIN (fun maybe)
def main():
    audit = get_audit_folder()

    system_logs = read_event_log("System")
    application_logs = read_event_log("Application")
    logins = get_login_history()
    apps = get_installed_apps()
    chrome = read_chrome_history()
    edge = read_edge_history()

    # JSON output
    json_file = audit / "system_audit_output.json"
    with json_file.open("w", encoding="utf-8") as f:
        json.dump({
            "SystemLogs": system_logs,
            "ApplicationLogs": application_logs,
            "SecurityLoginEvents": logins,
            "InstalledApplications": apps,
            "ChromeHistory": chrome,
            "EdgeHistory": edge
        }, f, indent=4)
    save_file_hash(json_file)

    # Installed apps CSV
    apps_csv = audit / "installed_apps.csv"
    save_installed_apps_to_csv(apps, apps_csv)
    save_file_hash(apps_csv)

    # Chrome CSV
    if chrome:
        chrome_csv = audit / "chrome_history.csv"
        save_browser_history_to_csv(chrome, chrome_csv)
        save_file_hash(chrome_csv)

    # Edge CSV
    if edge:
        edge_csv = audit / "edge_history.csv"
        save_browser_history_to_csv(edge, edge_csv)
        save_file_hash(edge_csv)

    print(f"✔ Audit complete! Files saved to: {audit}")


if __name__ == "__main__":
    main()
