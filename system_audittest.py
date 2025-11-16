import win32evtlog
import win32evtlogutil
import win32con
import subprocess
import os
import json
import re
import sqlite3
import csv
from pathlib import Path
from datetime import datetime, timedelta

# Read Event Logs
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

# Installed applications (from registry)
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

            # A new registry key (application)
            if line.startswith("HKEY_LOCAL_MACHINE"):
                if current_app:
                    apps.append(current_app)
                current_app = {"RegistryKey": line}

            # Parse values
            match = re.match(r"(\w+)\s+REG_\w+\s+(.*)", line)
            if match:
                key, value = match.groups()
                current_app[key] = value

        if current_app:
            apps.append(current_app)

        return apps

    except Exception as e:
        return f"Unable to read installed apps: {e}"



# Putting it into a CSV please work
def save_installed_apps_to_csv(apps, filename):
    # Define the columns we want to keep and the order they should appear
    columns = [
        "RegistryKey",
        "DisplayName",
        "DisplayVersion",
        "Publisher",
        "InstallDate",
        "InstallLocation",
        "UninstallString"
    ]

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        for app in apps:
            row = {col: app.get(col, "") for col in columns}
            writer.writerow(row)
#Login History please work
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
            if not evt or "<Event" not in evt:
                continue
            evt = evt + "</Event>"

            timestamp_match = re.search(r"<TimeCreated SystemTime=\"(.*?)\"/>", evt)
            target_match = re.search(r"<Data Name=\"TargetUserName\">(.*?)</Data>", evt)
            ip_match = re.search(r"<Data Name=\"IpAddress\">(.*?)</Data>", evt)

            events.append({
                "TimestampUTC": timestamp_match.group(1) if timestamp_match else "",
                "Username": target_match.group(1) if target_match else "",
                "SourceIP": ip_match.group(1) if ip_match else ""
            })

        return events

    except Exception as e:
        return [{"Error": f"Unable to read logins: {str(e)}"}]


#TIME CONVERSION
def chrome_time_to_datetime(webkit_timestamp):
    """
    Convert Chrome/Edge WebKit timestamp (µs since 1601) 
    into a human-readable datetime string.
    """
    if not webkit_timestamp:
        return ""
    
    # WebKit epoch starts at January 1, 1601
    epoch_start = datetime(1601, 1, 1)

    try:
        converted = epoch_start + timedelta(microseconds=webkit_timestamp)
        return converted.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return ""
    

# Edge Browser History
def read_edge_history():
    edge_db_path = Path.home() / r"AppData/Local/Microsoft/Edge/User Data/Default/History"

    if not edge_db_path.exists():
        return []

    temp_copy = Path("edge_history_temp.db")
    with open(edge_db_path, "rb") as src, open(temp_copy, "wb") as dst:
        dst.write(src.read())

    history = []
    try:
        conn = sqlite3.connect(temp_copy)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time 
            FROM urls 
            ORDER BY last_visit_time DESC 
            LIMIT 50
        """)

        for url, title, visit_count, last_visit_time in cursor.fetchall():
            history.append({
                "url": url,
                "title": title,
                "visit_count": visit_count,
                "last_visit_time": chrome_time_to_datetime(last_visit_time)
            })

    except Exception as e:
        print("Edge history error:", e)

    finally:
        conn.close()
        temp_copy.unlink(missing_ok=True)

    return history


#Chrome History please work
def read_chrome_history():
    chrome_db_path = Path.home() / r"AppData/Local/Google/Chrome/User Data/Default/History"

    if not chrome_db_path.exists():
        return []

    temp_copy = Path("chrome_history_temp.db")
    with open(chrome_db_path, "rb") as src, open(temp_copy, "wb") as dst:
        dst.write(src.read())

    history = []
    try:
        conn = sqlite3.connect(temp_copy)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time 
            FROM urls 
            ORDER BY last_visit_time DESC 
            LIMIT 50
        """)

        for url, title, visit_count, last_visit_time in cursor.fetchall():
            history.append({
                "url": url,
                "title": title,
                "visit_count": visit_count,
                "last_visit_time": chrome_time_to_datetime(last_visit_time)
            })

    except Exception as e:
        print("Chrome history error:", e)

    finally:
        conn.close()
        temp_copy.unlink(missing_ok=True)

    return history


#Browser History to CSV please work
def save_browser_history_to_csv(history, filename):
    columns = ["URL", "Title", "VisitCount", "LastVisitTime"]

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        for entry in history:
            row = {
                "URL": entry.get("url", ""),
                "Title": entry.get("title", ""),
                "VisitCount": entry.get("visit_count", ""),
                "LastVisitTime": entry.get("last_visit_time", "")
            }
            writer.writerow(row)


# MAIN
def main():
    # Collect data
    system_logs = read_event_log("System")
    application_logs = read_event_log("Application")
    login_events = get_login_history()
    installed_apps = get_installed_apps()
    edge_history = read_edge_history()
    chrome_history = read_chrome_history()

    # Save JSON
    results = {
        "SystemLogs": system_logs,
        "ApplicationLogs": application_logs,
        "SecurityLoginEvents": login_events,
        "InstalledApplications": installed_apps,
        "EdgeHistory": edge_history,
        "ChromeHistory": chrome_history
    }

    with open("system_audit_output.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print("Audit complete! Output saved to system_audit_output.json")

    # ✔ Export CSV files
    save_installed_apps_to_csv(installed_apps, "installed_apps.csv")

    if edge_history:
        save_browser_history_to_csv(edge_history, "edge_history.csv")

    if chrome_history:
        save_browser_history_to_csv(chrome_history, "chrome_history.csv")

if __name__ == "__main__":
    main()
