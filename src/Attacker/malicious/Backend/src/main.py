"""
Main entry point for the Backend server
Run this file to start the server
"""

import sys
import os

# Add parent directory to path to import server module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import app, init_database, PORT, FILES_DIR, logger

def main():
    """Main function to start the server"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║           Backend Server - Data Collection                ║
    ║                                                           ║
    ║  Endpoints:                                               ║
    ║  • POST /api/receive      - Receive JSON data             ║
    ║  • POST /api/receive/batch - Receive batch JSON data      ║
    ║  • GET  /api/transfer/file - Download file                ║
    ║  • POST /api/transfer/upload - Upload file                ║
    ║  • GET  /api/health       - Health check                  ║
    ║  • GET  /api/data         - View stored data              ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Ensure files directory exists
    os.makedirs(FILES_DIR, exist_ok=True)
    
    # Initialize database
    try:
        init_database()
        print("[✓] Database initialized successfully")
    except Exception as e:
        print(f"[!] Warning: Could not initialize database: {e}")
        print("    Server will start but database operations may fail")
    
    # Start server
    print(f"\n[*] Starting server on http://0.0.0.0:{PORT}")
    print("[*] Press Ctrl+C to stop the server\n")
    
    app.run(
        host='0.0.0.0',
        port=PORT,
        debug=True
    )


if __name__ == '__main__':
    main()
