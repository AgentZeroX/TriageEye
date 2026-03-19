import subprocess, time, json, os, xml.etree.ElementTree as ET, psutil
from datetime import datetime
from colorama import init, Fore, Style
init(autoreset=True)

print(Fore.CYAN + Style.BRIGHT + """
╔════════════════════════════════════════════╗
║          TriageEye - Dynamic Analyzer      ║   
║             Built for quick triage         ║
╚════════════════════════════════════════════╝
""")

def run_command(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

def start_etw():
    providers = ["Microsoft-Windows-Kernel-Process", "Microsoft-Windows-Kernel-File"]
    for p in providers:
        run_command(f'logman start "{p}" -p {p} -ets')
    print(Fore.GREEN + "[+] ETW sessions started")

def stop_etw():
    providers = ["Microsoft-Windows-Kernel-Process", "Microsoft-Windows-Kernel-File"]
    for p in providers:
        run_command(f'logman stop "{p}" -ets')
    print(Fore.GREEN + "[+] ETW sessions stopped")

def parse_etw_output():
    run_command('tracerpt *.etl -of XML -o trace.xml')
    try:
        tree = ET.parse('trace.xml')
        return tree.getroot()
    except:
        return None

def analyze_sample(target_path, duration=30, mode="exe"):
    print(Fore.YELLOW + f"[*] Starting analysis of: {target_path}")
    
    start_etw()
    start_time = datetime.now()

    if mode == "exe":
        proc = subprocess.Popen(target_path, creationflags=subprocess.CREATE_NEW_CONSOLE)
    elif mode == "office":
        subprocess.Popen(['start', target_path], shell=True)
        proc = None
    else:
        proc = None

    time.sleep(duration)

    stop_etw()
    root = parse_etw_output()

    # Collect data
    data = {
        "target": target_path,
        "duration": duration,
        "timestamp": datetime.now().isoformat(),
        "processes": [],
        "network": [],
        "files": [],
        "registry": [],
        "juicy_score": 0
    }

    # Simple parsing (you can extend this)
    if root is not None:
        for event in root.findall(".//Event"):
            # Basic extraction logic (process, file, etc.)
            pass  # Full parser can be expanded later

    # Network snapshot
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            data["network"].append(f"{conn.laddr}:{conn.lport} → {conn.raddr}")

    # Generate report
    report_file = f"MalMon_Report_{int(time.time())}.json"
    with open(report_file, "w") as f:
        json.dump(data, f, indent=4)

    # HTML report
    html = f"""
    <html><head><title>TriageEye Report</title>
    <style>body{{font-family:Arial;background:#0d1117;color:#fff;}} table{{border-collapse:collapse;width:100%;}} th,td{{padding:8px;border:1px solid #333;}}</style>
    </head><body>
    <h1>TriageEye Report - {target_path}</h1>
    <h2>Network Connections ({len(data['network'])})</h2>
    <ul>{"".join(f"<li>{n}</li>" for n in data['network'])}</ul>
    <h3>Juicy Score: {data['juicy_score']}/100</h3>
    </body></html>
    """
    with open("report.html", "w") as f:
        f.write(html)

    print(Fore.GREEN + Style.BRIGHT + f"[+] Analysis complete!")
    print(Fore.CYAN + f"    JSON  → {report_file}")
    print(Fore.CYAN + f"    HTML  → report.html")
    print(Fore.MAGENTA + "    Open report.html in browser for nice view")

# ====================== USAGE ======================
if __name__ == "__main__":
    target = input(Fore.WHITE + "Enter full path to sample (exe/doc): ").strip()
    dur = int(input(Fore.WHITE + "Duration in seconds [30]: ") or 30)
    
    analyze_sample(target, dur, "exe" if target.lower().endswith(".exe") else "office")