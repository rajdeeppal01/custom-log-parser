import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime
import win32evtlog
import os
import re

# GUI setup
root = tk.Tk()
root.title("Unified Event & Log Viewer")
root.geometry("1200x850")

# --- Function to parse date from log line ---
def extract_date_from_line(line):
    patterns = [
        r'\[(\d{2}/[A-Za-z]{3}/\d{4}):',  # Apache format
        r'(\d{4}-\d{2}-\d{2})',           # ISO format
        r'\[(\d{4}-\d{2}-\d{2})',        # [YYYY-MM-DD]
    ]
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            try:
                for fmt in ["%d/%b/%Y", "%Y-%m-%d"]:
                    try:
                        return datetime.strptime(match.group(1), fmt)
                    except:
                        continue
            except:
                pass
    return None

# --- Function to Fetch Logs ---
def fetch_logs():
    output_text.delete("1.0", tk.END)
    log_types = [log_listbox.get(idx) for idx in log_listbox.curselection()]
    event_id = event_id_entry.get().strip()
    keyword = keyword_entry.get().strip().lower()
    from_date = from_date_entry.get().strip()
    to_date = to_date_entry.get().strip()
    use_file = use_file_logs.get()
    file_paths = custom_log_entry.get("1.0", tk.END).strip().splitlines()

    try:
        from_dt = datetime.strptime(from_date, "%Y-%m-%d") if from_date else None
        to_dt = datetime.strptime(to_date, "%Y-%m-%d") if to_date else None
    except ValueError:
        messagebox.showerror("Invalid Date", "Please enter dates in YYYY-MM-DD format.")
        return

    if use_file:
        for path in file_paths:
            if not os.path.isfile(path):
                output_text.insert(tk.END, f"[FILE] ERROR: No such file: {path}\n")
                continue
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                for line in lines:
                    if keyword and keyword not in line.lower():
                        continue
                    evt_dt_obj = extract_date_from_line(line)
                    if from_dt and evt_dt_obj and evt_dt_obj < from_dt:
                        continue
                    if to_dt and evt_dt_obj and evt_dt_obj > to_dt:
                        continue
                    output_text.insert(tk.END, f"[FILE: {os.path.basename(path)}] {line}")
            except Exception as e:
                output_text.insert(tk.END, f"[FILE: {path}] ERROR: {str(e)}\n")
        return

    if not log_types:
        messagebox.showwarning("No Logs Selected", "Please select at least one Windows log type.")
        return

    for log_type in log_types:
        try:
            hand = win32evtlog.OpenEventLog('localhost', log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = 0

            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break

                for event in events:
                    msg_parts = event.StringInserts
                    message = '\n    '.join(str(part).strip() for part in msg_parts if part) if msg_parts else "(No message)"
                    evt_dt = event.TimeGenerated.Format()
                    evt_dt_obj = datetime.strptime(str(evt_dt), '%a %b %d %H:%M:%S %Y')

                    if event_id and str(event.EventID) != event_id:
                        continue
                    if keyword and keyword not in message.lower():
                        continue
                    if from_dt and evt_dt_obj < from_dt:
                        continue
                    if to_dt and evt_dt_obj > to_dt:
                        continue

                    formatted = (
                        "\u2500"*60 + "\n"
                        f"[Windows:{log_type}] Time     : {evt_dt_obj}\n"
                        f"Event ID : {event.EventID}\n"
                        f"Source   : {event.SourceName}\n"
                        f"Message  :\n    {message}\n"
                        + "\u2500"*60 + "\n\n"
                    )
                    output_text.insert(tk.END, formatted)
                    total += 1

            if total == 0:
                output_text.insert(tk.END, f"[{log_type}] No matching events found.\n\n")

        except Exception as e:
            output_text.insert(tk.END, f"[{log_type}] ERROR: {str(e)}\n\n")

# --- Browse Button Function ---
def browse_file():
    filepaths = filedialog.askopenfilenames(title="Select Log Files", filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")])
    if filepaths:
        custom_log_entry.delete("1.0", tk.END)
        custom_log_entry.insert("1.0", "\n".join(filepaths))

# --- File Type Selection Callback ---
def preset_log_path(event):
    filetype = log_type_dropdown.get()
    paths = {
        "Apache": "C:/xampp/apache/logs/access.log",
        "IIS": "C:/inetpub/logs/LogFiles/W3SVC1/u_exYYMMDD.log",
        "Custom": ""
    }
    current = custom_log_entry.get("1.0", tk.END).strip()
    if not current:
        custom_log_entry.insert("1.0", paths.get(filetype, ""))

# --- GUI Layout ---
tk.Label(root, text="Select Windows Logs:").grid(row=0, column=0, sticky='w')
log_listbox = tk.Listbox(root, selectmode=tk.MULTIPLE, height=5)
for log in ["Application", "System", "Security", "Setup", "ForwardedEvents"]:
    log_listbox.insert(tk.END, log)
log_listbox.grid(row=1, column=0, padx=5, pady=5)

tk.Label(root, text="Event ID:").grid(row=0, column=1, sticky='w')
event_id_entry = tk.Entry(root)
event_id_entry.grid(row=1, column=1, padx=5)

tk.Label(root, text="Message Contains:").grid(row=0, column=2, sticky='w')
keyword_entry = tk.Entry(root)
keyword_entry.grid(row=1, column=2, padx=5)

tk.Label(root, text="From (YYYY-MM-DD):").grid(row=2, column=0, sticky='w')
from_date_entry = tk.Entry(root)
from_date_entry.grid(row=3, column=0, padx=5)

tk.Label(root, text="To (YYYY-MM-DD):").grid(row=2, column=1, sticky='w')
to_date_entry = tk.Entry(root)
to_date_entry.grid(row=3, column=1, padx=5)

# File log additions
tk.Label(root, text="Log File Type:").grid(row=2, column=3, sticky='w')
log_type_dropdown = tk.StringVar()
log_type_menu = tk.OptionMenu(root, log_type_dropdown, "Apache", "IIS", "Custom", command=preset_log_path)
log_type_menu.grid(row=3, column=3, sticky='w')
log_type_dropdown.set("Custom")

tk.Label(root, text="Log File Paths (one per line):").grid(row=0, column=3, columnspan=2, sticky='w')
custom_log_entry = tk.Text(root, width=40, height=4)
custom_log_entry.grid(row=1, column=3, columnspan=2, padx=5)
browse_button = tk.Button(root, text="Browse", command=browse_file)
browse_button.grid(row=2, column=4, padx=5)

use_file_logs = tk.BooleanVar()
tk.Checkbutton(root, text="Read from file", variable=use_file_logs).grid(row=2, column=2, sticky='w')

# Fetch button
fetch_button = tk.Button(root, text="Fetch Logs", command=fetch_logs)
fetch_button.grid(row=3, column=2, padx=5, pady=5)

# Output text
output_text = tk.Text(root, wrap=tk.WORD, width=140, height=35)
output_text.grid(row=4, column=0, columnspan=5, padx=10, pady=10)

root.mainloop()
