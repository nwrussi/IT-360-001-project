# IT-360-001-project

This repository contains a Python-based Windows System Audit tool. The script collects event logs, installed applications, login activity, and browser history, then exports the results into organized JSON and CSV files. All output files are automatically hashed using SHA-256 for integrity verification.

The script works both as a standard .py file and when packaged as an executable.

Overview

The audit script gathers the following information:

System and Application Event Logs

Retrieves the latest 50 entries from:

System log

Application log

Includes event metadata and the full event message text.

Installed Applications

Extracts installed software information from the Windows Registry.

Exports key information to installed_apps.csv, including:

Display name

Version

Publisher

Install date

Install location and uninstall string

Login Activity (Security Log)

Reads successful login events (Event ID 4624).

Captures:

Timestamp (UTC)

Username

Source IP address

Browser History (Chrome and Edge)

Copies locked browser database files before parsing to prevent access errors.

Extracts:

URL

Title

Visit count

Converted timestamp

Writes results to chrome_history.csv and edge_history.csv if detected.

Output File Hashing

Each generated output file includes an accompanying .sha256 file containing its SHA-256 hash for integrity verification.

Output Files

All audit outputs are stored in an automatically created Audit folder. The script attempts the following locations in order:

Desktop

Documents

Script/executable directory (fallback)

Generated files include:

File	Description
system_audit_output.json	Consolidated audit results
installed_apps.csv	Installed applications
chrome_history.csv	Chrome browser history (if available)
edge_history.csv	Edge browser history (if available)
*.sha256	Hash files for each generated output
Project Structure
/  
├── system_audit.py  
├── README.md  
├── Audit/                      (created automatically)
│   ├── system_audit_output.json
│   ├── system_audit_output.json.sha256
│   ├── installed_apps.csv
│   ├── installed_apps.csv.sha256
│   ├── chrome_history.csv
│   ├── chrome_history.csv.sha256
│   ├── edge_history.csv
│   └── edge_history.csv.sha256

Requirements

Windows operating system

Python 3

pywin32 library

Permissions to read:

Windows Event Logs

Windows Registry

Browser history files

Administrator privileges are recommended for full access, including Security log events.

Notes

Chrome and Edge history data is copied to a temporary database to bypass file-locking issues.

Some registry keys may not contain all fields, resulting in blank values in the CSV.

Only the most recent 50 entries are collected for logs, login events, and browser history.

Works both as a Python script and when packaged into an executable.
