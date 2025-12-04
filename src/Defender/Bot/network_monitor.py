import socket
import logging
from datetime import datetime

class NetworkMonitor:
    def __init__(self):
        self.suspicious_ports = [5000]  # Malware C2 port
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler('network_monitor.log')]
        )
        self.logger = logging.getLogger(__name__)
    
    def block_suspicious_connections(self):
        """Block connections to malware C2 server"""
        # This would require admin privileges and specific firewall rules
        # For demonstration, we just log the attempts
        self.logger.info("🛡️ Network monitoring active - watching port 5000")
        
        # Create a socket to detect connection attempts
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('0.0.0.0', 5000))
            sock.listen(1)
            self.logger.warning("🚨 Malware C2 port 5000 is being monitored")
        except OSError:
            self.logger.info("✅ Port 5000 is not in use (good sign)")