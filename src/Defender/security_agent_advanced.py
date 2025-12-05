"""
Advanced Security Agent (prototype)
Features:
- Ransomware detection (heuristics)
- Quarantine suspicious files
- Automatic network blocking (best-effort)
- USB auto-block (detect mount -> unmount/quarantine)

Run as: python security_agent_advanced.py
Run with admin/root for blocking/unmounting to work.
"""

import os
import time
import shutil
import hashlib
import math
import platform
import subprocess
import threading
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil

# ---------------- CONFIG ----------------
MONITOR_FOLDERS = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Desktop"),
    "/tmp" if platform.system() != "Windows" else os.environ.get("TEMP", os.path.expanduser("~/AppData/Local/Temp"))
]

QUARANTINE_DIR = os.path.join(os.getcwd(), "quarantine")
LOG_FILE = os.path.join(os.getcwd(), "agent.log")

# Ransomware heuristics
MOD_WINDOW_SECONDS = 10        # sliding window to count modifications
MOD_THRESHOLD = 50            # if > this many file mods in window -> alert
ENTROPY_THRESHOLD = 7.5       # entropy above this suggests encrypted/random file
EXTENSION_CHANGE_THRESHOLD = 20  # many same new extension in short time

# Network block defaults
BLOCK_PORTS = [445, 139, 3389]  # smb and rdp commonly abused
# How often to poll things
POLL_INTERVAL = 3

# ---------------- HELPERS / LOGGING ----------------
def log(msg):
    s = f"[{time.ctime()}] {msg}"
    print(s)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(s + "\n")
    except Exception:
        pass

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def shannon_entropy(data_bytes):
    if not data_bytes:
        return 0.0
    size = len(data_bytes)
    freq = {}
    for b in data_bytes:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    for count in freq.values():
        p = count / size
        ent -= p * math.log2(p)
    return ent

# ---------------- QUARANTINE ----------------
def ensure_quarantine():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)

def quarantine_file(path, reason="suspicious"):
    ensure_quarantine()
    try:
        base = os.path.basename(path)
        # include timestamp and short hash
        h = sha256(path) or "nohash"
        dest = os.path.join(QUARANTINE_DIR, f"{int(time.time())}_{h[:8]}_{base}")
        shutil.move(path, dest)
        # make read-only to prevent accidental execution
        try:
            os.chmod(dest, 0o444)
        except Exception:
            pass
        log(f"[QUARANTINE] Moved {path} -> {dest} (reason={reason})")
        return dest
    except Exception as e:
        log(f"[QUARANTINE-FAILED] {path} -> {e}")
        return None

# ---------------- RANSOMWARE DETECTION ----------------
# We keep a sliding window of recent modifications for heuristic scoring.
recent_mods = deque()  # entries: (timestamp, path, new_ext, old_ext_or_none)

ext_change_counter = defaultdict(lambda: deque())  # ext -> deque of timestamps

def record_mod(path, old_ext=None):
    ts = time.time()
    new_ext = os.path.splitext(path)[1].lower()
    recent_mods.append((ts, path, new_ext, old_ext))
    # purge old
    while recent_mods and recent_mods[0][0] < ts - MOD_WINDOW_SECONDS:
        recent_mods.popleft()

    # track extension-change heuristics
    if old_ext is not None and old_ext != new_ext:
        ext_change_counter[new_ext].append(ts)
        # purge old timestamps for this ext
        dq = ext_change_counter[new_ext]
        while dq and dq[0] < ts - MOD_WINDOW_SECONDS:
            dq.popleft()

    evaluate_ransomware_heuristics()

def evaluate_ransomware_heuristics():
    ts = time.time()
    mod_count = len(recent_mods)
    # 1) Mass modifications
    if mod_count >= MOD_THRESHOLD:
        log(f"[RANSOMWARE-ALERT] High modification rate detected: {mod_count} mods in last {MOD_WINDOW_SECONDS}s.")
        handle_ransomware_alert(reason=f"high_mod_rate_{mod_count}")

    # 2) Mass extension changes to same extension
    for ext, dq in list(ext_change_counter.items()):
        if len(dq) >= EXTENSION_CHANGE_THRESHOLD:
            log(f"[RANSOMWARE-ALERT] Many files changed to {ext}: {len(dq)} in {MOD_WINDOW_SECONDS}s.")
            handle_ransomware_alert(reason=f"mass_ext_{ext}")

def analyze_file_entropy(path):
    try:
        with open(path, "rb") as f:
            data = f.read(8192)  # sample first chunk
        ent = shannon_entropy(data)
        return ent
    except Exception:
        return 0.0

def handle_ransomware_alert(reason="unknown"):
    # Actions: block network, snapshot current modified files, quarantine recent suspicious files
    log(f"[ACTION] Handling ransomware alert: {reason}")
    # block network quickly (best-effort)
    block_common_ports()
    # attempt to quarantine recently modified files with high entropy or suspicious extension
    snapshot = list(recent_mods)
    for ts, path, new_ext, old_ext in snapshot:
        # only quarantine if file still exists and looks suspicious
        if os.path.exists(path):
            ent = analyze_file_entropy(path)
            if ent >= ENTROPY_THRESHOLD or new_ext in [".locked", ".crypted", ".enc", ".encrypt", ".encrypted"] or new_ext in [".exe", ".vbs", ".ps1"]:
                quarantine_file(path, reason=f"ransomware-{reason}-entropy{ent:.2f}")

# ---------------- FILESYSTEM WATCHER ----------------
class AgentHandler(FileSystemEventHandler):
    # keep small map for old extension guesses (when file is renamed)
    rename_map = {}

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        log(f"[FS] Created: {path}")
        # quick entropy check on newly created suspicious types
        ext = os.path.splitext(path)[1].lower()
        if ext in [".exe", ".ps1", ".vbs", ".bat", ".js"] :
            ent = analyze_file_entropy(path)
            log(f"[FS] Entropy({path})={ent:.2f}")
            if ent >= ENTROPY_THRESHOLD:
                quarantine_file(path, reason="high_entropy_on_create")
        # record mod (create is a mod)
        record_mod(path, old_ext=None)

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path
        log(f"[FS] Modified: {path}")
        # evaluate entropy if file size not too big (sample)
        ent = analyze_file_entropy(path)
        log(f"[FS] Entropy({path})={ent:.2f}")
        # if entropy high -> quarantine
        if ent >= ENTROPY_THRESHOLD:
            quarantine_file(path, reason="high_entropy_on_modify")
        # record mod (can't tell old extension here)
        record_mod(path, old_ext=None)

    def on_moved(self, event):
        # moved/renamed can signal encryption (old_ext -> new_ext)
        if event.is_directory:
            return
        src = event.src_path
        dest = event.dest_path
        old_ext = os.path.splitext(src)[1].lower()
        new_ext = os.path.splitext(dest)[1].lower()
        log(f"[FS] Renamed: {src} -> {dest}")
        record_mod(dest, old_ext=old_ext)
        # if extension changed to suspicious extension, quarantine
        if new_ext in [".locked", ".crypted", ".enc", ".encrypt", ".encrypted"]:
            quarantine_file(dest, reason="rename_to_locked_ext")

def start_folder_monitors():
    observer = Observer()
    handler = AgentHandler()
    scheduled_folders = []
    for folder in MONITOR_FOLDERS:
        try:
            if os.path.exists(folder):
                observer.schedule(handler, folder, recursive=True)
                log(f"[MONITOR] Watching {folder}")
                scheduled_folders.append(folder)
        except Exception as e:
            log(f"[MONITOR-ERR] {folder} -> {e}")
    
    if not scheduled_folders:
        log("[MONITOR] No folders could be scheduled for monitoring.")
        return None
    
    try:
        observer.start()
    except PermissionError as e:
        log(f"[MONITOR-ERR] Permission denied when starting observer: {e}")
        log("[MONITOR] Try running as Administrator or remove protected folders from MONITOR_FOLDERS")
        # Try again with only accessible folders
        observer = Observer()
        for folder in scheduled_folders:
            try:
                # Test if we can actually access the folder
                os.listdir(folder)
                observer.schedule(handler, folder, recursive=True)
                log(f"[MONITOR] Re-scheduled: {folder}")
            except (PermissionError, OSError) as e:
                log(f"[MONITOR-SKIP] Skipping {folder} due to permission error: {e}")
        try:
            observer.start()
        except Exception as e:
            log(f"[MONITOR-ERR] Failed to start observer: {e}")
            return None
    
    return observer

# ---------------- NETWORK BLOCKING (best-effort) ----------------
def is_windows():
    return platform.system().lower().startswith("win")

def run_cmd(cmd):
    try:
        log(f"[CMD] {cmd}")
        completed = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if completed.returncode != 0:
            log(f"[CMD-ERR] rc={completed.returncode} out={completed.stdout} err={completed.stderr}")
        else:
            log(f"[CMD-OK] {completed.stdout.strip()}")
        return completed.returncode == 0
    except Exception as e:
        log(f"[CMD-EXC] {e}")
        return False

def block_common_ports():
    # quick attempt to block known lateral-movement ports
    if is_windows():
        # create firewall rule to block outbound to these ports
        for p in BLOCK_PORTS:
            cmd = f'netsh advfirewall firewall add rule name="BlockPort{p}_by_agent" dir=out action=block protocol=TCP localport=any remoteport={p}'
            run_cmd(cmd)
    else:
        # Linux: use iptables (requires root)
        for p in BLOCK_PORTS:
            cmd = f"iptables -I OUTPUT -p tcp --dport {p} -j DROP"
            run_cmd(cmd)

# ---------------- USB AUTO-BLOCK ----------------
# We keep a list of known partitions and detect new ones as "insertion"
known_partitions = set()

def scan_partitions_once():
    parts = psutil.disk_partitions(all=False)
    # Represent partitions by device+mountpoint
    return set((p.device, p.mountpoint) for p in parts)

def handle_new_usb(device, mountpoint):
    log(f"[USB] New removable device detected: {device} mounted at {mountpoint}")
    # Attempt to unmount/eject (best-effort)
    if is_windows():
        # Windows: attempt to lock/eject using powershell (may require admin)
        cmd = f'powershell -command "Try {{ (Get-Volume -FileSystemLabel * | Where-Object {{$_.Path -eq \\\"{mountpoint}\\\"}} ) ; }} Catch {{ }} "'
        # simple approach: call mountvol to remove
        # NOTE: real eject requires more complex Win32 API; we attempt to deny access by creating a deny ACL or move suspicious files
        run_cmd(f'powershell -command "Stop-Process -Name explorer -ErrorAction SilentlyContinue"')  # not ideal, only demonstration
        # try to remove (not always effective)
        run_cmd(f'mountvol {mountpoint} /D')
        log("[USB] Tried mountvol /D (Windows).")
    else:
        # Linux: try unmount immediately (requires root)
        run_cmd(f"umount '{mountpoint}'")
        # try to block by adding a temporary iptables or udev (not done here)
    # scan files on device (if accessible briefly) and quarantine suspicious files
    try:
        for root, dirs, files in os.walk(mountpoint):
            for fname in files:
                path = os.path.join(root, fname)
                ext = os.path.splitext(path)[1].lower()
                # quick heuristics: executable/script on removable media likely suspicious
                if ext in [".exe", ".scr", ".bat", ".vbs", ".ps1", ".js", ".msi"]:
                    quarantine_file(path, reason="usb_autoblock_suspicious_ext")
    except Exception as e:
        log(f"[USB] scanning failed: {e}")

def usb_monitor_loop():
    global known_partitions
    known_partitions = scan_partitions_once()
    log(f"[USB] Initial partitions: {known_partitions}")
    while True:
        time.sleep(POLL_INTERVAL)
        try:
            current = scan_partitions_once()
            added = current - known_partitions
            removed = known_partitions - current
            for dev, mount in added:
                # heuristics: removable device often has mountpoint outside root or device name like /dev/sd*
                handle_new_usb(dev, mount)
            for dev, mount in removed:
                log(f"[USB] Removed device: {dev} ({mount})")
            known_partitions = current
        except Exception as e:
            log(f"[USB-LOOP-ERR] {e}")

# ---------------- NETWORK CONNECTION MONITOR (process-level) ----------------
def network_connection_monitor():
    # look for processes with many outgoing connections to random endpoints, or listening on risky ports
    conns = psutil.net_connections(kind='inet')
    # map pid -> count
    pid_count = defaultdict(int)
    for c in conns:
        if c.raddr:
            pid_count[c.pid] += 1
            # listening/established on SMB/RDP ports -> suspicious
            if c.laddr and c.laddr.port in BLOCK_PORTS:
                log(f"[NET] Process PID {c.pid} listening on risky port {c.laddr.port}")
    for pid, count in pid_count.items():
        if count > 50:
            try:
                p = psutil.Process(pid)
                log(f"[NET-ALERT] PID {pid} ({p.name()}) has {count} remote connections; taking action")
                # best-effort: kill and block ports
                p.kill()
                block_common_ports()
            except Exception as e:
                log(f"[NET-ERR] Could not kill {pid}: {e}")

# ---------------- MAIN ----------------
def periodic_checks_loop():
    while True:
        try:
            network_connection_monitor()
        except Exception as e:
            log(f"[PERIODIC-ERR] {e}")
        time.sleep(POLL_INTERVAL)

def main():
    log("=== Advanced Security Agent Starting ===")
    ensure_quarantine()
    # folders monitor
    observer = start_folder_monitors()
    if observer is None:
        log("[ERROR] Failed to start folder monitors. Exiting.")
        return
    # start usb monitor thread
    t_usb = threading.Thread(target=usb_monitor_loop, daemon=True)
    t_usb.start()
    # start periodic checks
    t_periodic = threading.Thread(target=periodic_checks_loop, daemon=True)
    t_periodic.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("Shutting down...")
        if observer:
            observer.stop()
            observer.join()

if __name__ == "__main__":
    main()
