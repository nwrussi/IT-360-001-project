# IT-360-001-project

Windows System Audit Script

This repository contains a Python script that performs a basic system audit on Windows. It collects event logs, installed applications, login activity, and browser history, then exports the results into JSON and CSV files for further review or analysis.

Overview

The script gathers the following information:

- System and Application Event Logs (latest 50 entries)
- Installed applications from the Windows Registry
- Login events (Event ID 4624), including timestamp, username, and source IP
- Chrome and Edge browser history (URLs, titles, visit count, and converted timestamps)
- A combined output file named `system_audit_output.json`

All generated files appear in the same directory where the script is executed.

Features

Event Logs  
Retrieves recent entries from Windows system and application logs, including detailed event messages.

Installed Software  
Reads software information from the registry and exports key fields to `installed_apps.csv`.

Login Activity  
Extracts successful login events from the Security log using Event ID 4624.

Browser History  
Creates temporary copies of Chrome and Edge history databases to avoid file locking issues, then parses recent visit records.

Output Formats  
Produces the following files after execution:
- `system_audit_output.json`
- `installed_apps.csv`
- `chrome_history.csv`
- `edge_history.csv`

Project Structure
/
├── system_audit.py
├── README.md
├── system_audit_output.json        (created after running)
├── installed_apps.csv              (created after running)
├── chrome_history.csv              (created after running)
└── edge_history.csv                (created after running)


Running with Administrator privileges is recommended for full access to Security logs.

Requirements

- Windows operating system  
- Python 3  
- `pywin32` library  
- Sufficient permissions to read Windows event logs  

Notes

- Browser history files are normally locked while the browser is running; the script works around this by copying the files before reading them.

- Some registry entries may not contain all fields, so missing values will appear blank in exported files.

- Only the most recent 50 successful login events are included.

