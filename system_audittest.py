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


# ========================
# BLAST LIST CONFIGURATION
# ========================

# Blacklist patterns for inappropriate/NSFW content detection
BLAST_LIST = [
    "porn", "xxx", "adult", "nsfw", "sex", "nude", "onlyfans",
    "xvideos", "pornhub", "redtube", "xhamster", "youporn",
    "camgirl", "livejasmin", "chaturbate", "stripchat",
    "escort", "hookup", "dating", "tinder", "bumble",
    "gambling", "casino", "poker", "betting", "slots",
    "torrent", "pirate", "crack", "warez", "keygen"
]

# Normal URLs for testing the detection system
NORMAL_URLS = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.amazon.com",
    "https://www.microsoft.com",
    "https://www.wikipedia.org",
    "https://www.reddit.com",
    "https://www.linkedin.com",
    "https://www.office.com"
]


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


# Check URL Against Blast List
def check_url_against_blast_list(url):
    """
    Check if a URL contains any patterns from the BLAST_LIST.
    Returns a tuple: (is_flagged: bool, matched_patterns: list)
    """
    if not url:
        return (False, [])

    url_lower = url.lower()
    matched = []

    for pattern in BLAST_LIST:
        if pattern in url_lower:
            matched.append(pattern)

    return (len(matched) > 0, matched)


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


# Save Browser History CSV with Blast List Detection
def save_browser_history_to_csv(history, filename):
    filename = Path(filename)
    columns = ["URL", "Title", "VisitCount", "LastVisitTime", "Flagged", "MatchedPatterns"]

    flagged_count = 0

    with filename.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        for entry in history:
            url = entry.get("url", "")
            is_flagged, matched_patterns = check_url_against_blast_list(url)

            if is_flagged:
                flagged_count += 1

            writer.writerow({
                "URL": url,
                "Title": entry.get("title", ""),
                "VisitCount": entry.get("visit_count", ""),
                "LastVisitTime": entry.get("last_visit_time", ""),
                "Flagged": "YES" if is_flagged else "NO",
                "MatchedPatterns": ", ".join(matched_patterns) if matched_patterns else ""
            })

        # Add summary section
        writer.writerow({})  # Empty row for separation
        writer.writerow({
            "URL": "=== BLAST LIST DETECTION SUMMARY ===",
            "Title": "",
            "VisitCount": "",
            "LastVisitTime": "",
            "Flagged": "",
            "MatchedPatterns": ""
        })
        writer.writerow({
            "URL": f"Total URLs Scanned: {len(history)}",
            "Title": "",
            "VisitCount": "",
            "LastVisitTime": "",
            "Flagged": "",
            "MatchedPatterns": ""
        })
        writer.writerow({
            "URL": f"Flagged URLs: {flagged_count}",
            "Title": "",
            "VisitCount": "",
            "LastVisitTime": "",
            "Flagged": "",
            "MatchedPatterns": ""
        })
        writer.writerow({
            "URL": f"Clean URLs: {len(history) - flagged_count}",
            "Title": "",
            "VisitCount": "",
            "LastVisitTime": "",
            "Flagged": "",
            "MatchedPatterns": ""
        })
        writer.writerow({})  # Empty row
        writer.writerow({
            "URL": "=== BLAST LIST PATTERNS ===",
            "Title": "",
            "VisitCount": "",
            "LastVisitTime": "",
            "Flagged": "",
            "MatchedPatterns": ""
        })
        for pattern in BLAST_LIST:
            writer.writerow({
                "URL": pattern,
                "Title": "",
                "VisitCount": "",
                "LastVisitTime": "",
                "Flagged": "",
                "MatchedPatterns": ""
            })

    return flagged_count



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

    # Chrome CSV with Blast List Detection
    chrome_flagged = 0
    if chrome:
        chrome_csv = audit / "chrome_history.csv"
        chrome_flagged = save_browser_history_to_csv(chrome, chrome_csv)
        save_file_hash(chrome_csv)

    # Edge CSV with Blast List Detection
    edge_flagged = 0
    if edge:
        edge_csv = audit / "edge_history.csv"
        edge_flagged = save_browser_history_to_csv(edge, edge_csv)
        save_file_hash(edge_csv)

    # Display results
    print(f"✔ Audit complete! Files saved to: {audit}")
    print(f"\n📊 BLAST LIST DETECTION RESULTS:")
    if chrome:
        print(f"   Chrome: {chrome_flagged} flagged URLs out of {len(chrome)} total")
    if edge:
        print(f"   Edge: {edge_flagged} flagged URLs out of {len(edge)} total")
    print(f"   Total Flagged: {chrome_flagged + edge_flagged}")
    print(f"\n⚠️  Flagged URLs have been marked in the CSV files.")


if __name__ == "__main__":
    main()
