Log Parser – Cross-Platform Log Analysis Tool
This is a GUI-based Python application designed to parse and filter logs from Windows Event Logs and file-based sources like Apache, IIS and custom text logs. It is tailored for cybersecurity analysts, SOC teams, students, and system administrators to rapidly extract insights from structured and unstructured log sources.

Features
- Multi-source log support: Windows Event Logs, Apache, IIS, `.log` and `.txt` files
- Search & filter:
  - Event ID
  - Keyword match (case-insensitive)
  - Date range (From/To)
- Auto-date recognition for ISO, Apache, and standard timestamp formats
- File path presets for common log types
- Formatted GUI output for easy reading and copy-paste
- Offline mode for reading raw log files

```python
# Example filter:
Event ID: 4624
Message Contains: login
From: 2025-07-01
To: 2025-07-25
