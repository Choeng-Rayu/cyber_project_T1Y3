"""
Folder Access Monitor
- Monitors locked folders for access attempts
- Automatically shows password GUI when folder is accessed
- Runs in background
"""

import os
import sys
import time
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from encrypData import FolderLockerGUI, MultiFolderLockerGUI, is_folder_locked, LOCK_FILE


class LockedFolderMonitor(FileSystemEventHandler):
    """Monitor for access to locked folders"""
    
    def __init__(self, folder_path, on_access=None):
        self.folder_path = folder_path
        self.on_access = on_access
        self.last_access_time = 0
        self.access_cooldown = 2  # Prevent multiple triggers in 2 seconds
    
    def on_any_event(self, event):
        """Called on any file system event"""
        current_time = time.time()
        
        # Ignore rapid repeated events (cooldown)
        if current_time - self.last_access_time < self.access_cooldown:
            return
        
        # Ignore events on the lock file itself
        if event.src_path.endswith(LOCK_FILE):
            return
        
        # Only trigger on modification or access
        if event.event_type in ['modified', 'accessed', 'opened']:
            self.last_access_time = current_time
            
            print(f"[!] Folder access detected: {event.src_path}")
            print(f"[*] Event type: {event.event_type}")
            
            if self.on_access:
                self.on_access(self.folder_path)


class FolderAccessMonitorThread(threading.Thread):
    """Thread that monitors folder access"""
    
    def __init__(self, folder_paths, daemon=True):
        super().__init__(daemon=daemon)
        self.folder_paths = folder_paths if isinstance(folder_paths, list) else [folder_paths]
        self.observers = []
        self.running = False
    
    def run(self):
        """Run the folder monitoring"""
        self.running = True
        
        try:
            # Create observer for each folder
            for folder_path in self.folder_paths:
                if not is_folder_locked(folder_path):
                    print(f"[!] Folder not locked: {folder_path}")
                    continue
                
                print(f"[*] Monitoring locked folder: {folder_path}")
                
                observer = Observer()
                handler = LockedFolderMonitor(folder_path, on_access=self.on_folder_access)
                observer.schedule(handler, folder_path, recursive=True)
                observer.start()
                self.observers.append(observer)
            
            # Keep observers running
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            print(f"[-] Monitor error: {e}")
        finally:
            self.stop()
    
    def on_folder_access(self, folder_path):
        """Handle folder access - show password GUI"""
        print(f"[!] User accessing locked folder: {folder_path}")
        
        # Show password GUI in main thread
        try:
            # Determine if single or multiple folders
            if len(self.folder_paths) == 1:
                gui = FolderLockerGUI(folder_path, auto_close=True)
            else:
                gui = MultiFolderLockerGUI(self.folder_paths, auto_close=True)
            
            # Run GUI (blocking)
            gui.run()
            
        except Exception as e:
            print(f"[-] Error showing password GUI: {e}")
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        for observer in self.observers:
            try:
                observer.stop()
                observer.join()
            except:
                pass
        print("[*] Folder monitoring stopped")


def start_monitor(folder_paths, daemon=True):
    """Start monitoring folders for access"""
    monitor = FolderAccessMonitorThread(folder_paths, daemon=daemon)
    monitor.start()
    return monitor


def monitor_forever(folder_paths):
    """Monitor folders indefinitely (blocking)"""
    monitor = FolderAccessMonitorThread(folder_paths, daemon=False)
    monitor.run()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Folder Access Monitor')
    parser.add_argument('folders', nargs='+', help='Folders to monitor')
    parser.add_argument('--daemon', '-d', action='store_true', help='Run as daemon')
    
    args = parser.parse_args()
    
    print("[*] Starting folder access monitor...")
    print(f"[*] Monitoring {len(args.folders)} folder(s)")
    
    for folder in args.folders:
        if is_folder_locked(folder):
            print(f"[+] {folder} is locked")
        else:
            print(f"[-] {folder} is NOT locked")
    
    if args.daemon:
        monitor = start_monitor(args.folders, daemon=True)
        print("[+] Monitor started in daemon mode")
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping monitor...")
            monitor.stop()
    else:
        monitor_forever(args.folders)


if __name__ == '__main__':
    main()
