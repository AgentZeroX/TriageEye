import subprocess
import time
import json
import os
import xml.etree.ElementTree as ET
import psutil
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

print(Fore.CYAN + Style.BRIGHT + """
╔════════════════════════════════════════════╗
║          TriageEye - Dynamic Analyzer      ║
║         Built for quick malware triage     ║
╚════════════════════════════════════════════╝
""")

def run_command(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

def start_etw():
    providers = ["Microsoft-Windows-Kernel-Process", "Microsoft-Windows-Kernel-File"]
    for p in providers:
        run_command(f'logman start "{p}" -p {p} -ets')
    print(Fore.GREEN + "[+] ETW tracing started")

def stop_etw():
    providers = ["Microsoft-Windows-Kernel-Process", "Microsoft-Windows-Kernel-File"]
    for p in providers:
        run_command(f'logman stop "{p}" -ets')
    print(Fore.GREEN + "[+] ETW tracing stopped")

def parse_etw_output():
    run_command('tracerpt *.etl -of XML -o trace.xml')
    try:
        tree = ET.parse('trace.xml')
        return tree.getroot()
    except Exception as e:
        print(Fore.YELLOW + f"[!] Failed to parse ETW XML: {e}")
        return None

def get_running_processes():
    return {p.pid: p.name().lower() for p in psutil.process_iter(['pid', 'name']) if p.info['name']}

def analyze_sample(target=None, duration=30, mode="launch-exe", pid=None, proc_name=None):
    print(Fore.YELLOW + f"[*] Starting analysis in mode: {mode}")
    if target:
        print(Fore.YELLOW + f"    Target: {target}")
    if pid:
        print(Fore.YELLOW + f"    Attaching to PID: {pid}")
    if proc_name:
        print(Fore.YELLOW + f"    Waiting for process name: {proc_name}")

    start_etw()
    start_time = datetime.now()

    proc = None

    if mode == "launch-exe":
        if not target or not os.path.isfile(target):
            print(Fore.RED + "[!] Invalid or missing executable path")
            return
        try:
            proc = subprocess.Popen(target, creationflags=subprocess.CREATE_NEW_CONSOLE)
            print(Fore.GREEN + f"[+] Launched: {target} (PID: {proc.pid})")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to launch executable: {e}")
            return

    elif mode == "open-doc":
        if not target or not os.path.isfile(target):
            print(Fore.RED + "[!] Invalid or missing document path")
            return
        try:
            os.startfile(target)
            print(Fore.GREEN + f"[+] Opened document: {target}")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to open document: {e}")
            return

    elif mode == "attach-pid":
        if not pid or not psutil.pid_exists(pid):
            print(Fore.RED + f"[!] PID {pid} does not exist or is invalid")
            return
        print(Fore.GREEN + f"[+] Attached to existing PID: {pid}")

    elif mode == "attach-name":
        if not proc_name:
            print(Fore.RED + "[!] No process name provided")
            return
        print(Fore.YELLOW + f"[*] Waiting for process '{proc_name}' to appear...")
        timeout = 60
        start_wait = time.time()
        while time.time() - start_wait < timeout:
            procs = get_running_processes()
            found = [p for p, n in procs.items() if proc_name.lower() in n]
            if found:
                pid = found[0]
                print(Fore.GREEN + f"[+] Found '{proc_name}' → PID: {pid}")
                break
            time.sleep(1)
        else:
            print(Fore.RED + f"[!] Timeout: '{proc_name}' not found after {timeout}s")
            return

    elif mode == "wait-for-name":
        # Similar to attach-name but can be used standalone
        pass  # logic same as above

    print(Fore.CYAN + f"[*] Monitoring for {duration} seconds...")
    time.sleep(duration)

    stop_etw()
    root = parse_etw_output()

    # Collect minimal data
    data = {
        "target": target or "N/A",
        "mode": mode,
        "duration_seconds": duration,
        "start_time": start_time.isoformat(),
        "end_time": datetime.now().isoformat(),
        "processes": [],
        "network": [],
        "files": [],
        "registry": [],
        "juicy_score": 0
    }

    # Network snapshot (all active connections)
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED' and conn.raddr:
            data["network"].append(
                f"{conn.laddr.ip}:{conn.laddr.port} → {conn.raddr.ip}:{conn.raddr.port} "
                f"(PID: {conn.pid or 'N/A'})"
            )

    # Basic ETW parsing placeholder (expand later)
    if root is not None:
        print(Fore.GREEN + "[+] ETW data parsed (basic)")
        # You can add real event extraction here in future

    # Save reports
    timestamp = int(time.time())
    json_file = f"TriageEye_Report_{timestamp}.json"
    html_file = f"TriageEye_Report_{timestamp}.html"

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    html_content = f"""
    <html>
    <head><title>TriageEye Report</title>
    <style>
        body {{font-family:Arial, sans-serif; background:#0d1117; color:#e0e0e0; padding:20px;}}
        h1 {{color:#58a6ff;}}
        h2 {{color:#3fb950;}}
        ul {{list-style-type:disc;}}
        .section {{margin-bottom:20px;}}
    </style>
    </head>
    <body>
    <h1>TriageEye Analysis Report</h1>
    <div class="section">
        <h2>Target & Mode</h2>
        <p><b>Target:</b> {data['target']}</p>
        <p><b>Mode:</b> {data['mode']}</p>
        <p><b>Duration:</b> {data['duration_seconds']} seconds</p>
    </div>
    <div class="section">
        <h2>Network Connections ({len(data['network'])})</h2>
        <ul>{''.join(f'<li>{n}</li>' for n in data['network'])}</ul>
    </div>
    <div class="section">
        <h3>Juicy Score: {data['juicy_score']}/100</h3>
        <p>(Higher = more suspicious behavior detected)</p>
    </div>
    <p><small>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
    </body>
    </html>
    """

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(Fore.GREEN + Style.BRIGHT + "\n[+] Analysis finished!")
    print(Fore.CYAN + f"    JSON report → {json_file}")
    print(Fore.CYAN + f"    HTML report → {html_file}")
    print(Fore.MAGENTA + "    Open the HTML file in your browser for a readable view\n")

# ────────────────────────────────────────────────
if __name__ == "__main__":
    print(Fore.WHITE + "Choose analysis mode:")
    print("  1 = Launch EXE and monitor")
    print("  2 = Open Office document (docx, xlsx, pptx) and monitor")
    print("  3 = Attach to existing PID")
    print("  4 = Attach to process by name (wait until it appears)")
    print()

    choice = input(Fore.WHITE + "Enter mode number (1–4): ").strip()

    target = None
    pid = None
    proc_name = None
    duration = int(input(Fore.WHITE + "Duration in seconds [30]: ") or 30)

    if choice == "1":
        mode = "launch-exe"
        target = input(Fore.WHITE + "Full path to EXE: ").strip()
    elif choice == "2":
        mode = "open-doc"
        target = input(Fore.WHITE + "Full path to Office document: ").strip()
    elif choice == "3":
        mode = "attach-pid"
        pid_str = input(Fore.WHITE + "Enter PID to attach: ").strip()
        pid = int(pid_str) if pid_str.isdigit() else None
    elif choice == "4":
        mode = "attach-name"
        proc_name = input(Fore.WHITE + "Process name to wait for (e.g. explorer.exe): ").strip()
    else:
        print(Fore.RED + "[!] Invalid mode. Exiting.")
        exit(1)

    if (mode in ["launch-exe", "open-doc"] and not target) or \
       (mode == "attach-pid" and not pid) or \
       (mode == "attach-name" and not proc_name):
        print(Fore.RED + "[!] Missing required input. Exiting.")
        exit(1)

    analyze_sample(target=target, duration=duration, mode=mode, pid=pid, proc_name=proc_name)