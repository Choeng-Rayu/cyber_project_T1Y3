const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mysql = require('mysql2/promise');

// Configuration
const PORT = process.env.PORT || 5000;
const HOST = '0.0.0.0'; // Listen on all network interfaces

// Database Configuration (Aiven Cloud)
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'defaultdb',
    ssl: process.env.DB_HOST ? {
        rejectUnauthorized: true
    } : false,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// Create database connection pool
let pool;

async function initDatabase() {
    try {
        pool = mysql.createPool(dbConfig);
        
        // Test connection
        const connection = await pool.getConnection();
        console.log('✅ Connected to Aiven MySQL database');
        
        // Create uploads table if not exists
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS uploads (
                id INT AUTO_INCREMENT PRIMARY KEY,
                original_name VARCHAR(255) NOT NULL,
                stored_name VARCHAR(255) NOT NULL,
                file_size BIGINT,
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                client_ip VARCHAR(45)
            )
        `);
        console.log('✅ Uploads table ready');
        
        connection.release();
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        console.log('⚠️ Server will continue without database logging');
    }
}

// Upload directory
const uploadsDir = path.join(__dirname, 'uploads');

// Make uploads folder if not exist
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log(`📁 Uploads directory created at: ${uploadsDir}`);
} else {
    console.log(`📁 Uploads directory exists at: ${uploadsDir}`);
}

// Logging middleware
const requestLogger = (req, res, next) => {
    const timestamp = new Date().toLocaleTimeString();
    console.log(`\n[${timestamp}] ${req.method} ${req.path}`);
    next();
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        console.log(`  📤 Receiving file: ${file.originalname}`);
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const newName = Date.now() + "-" + file.originalname;
        cb(null, newName);
    }
});
const upload = multer({ storage });

const app = express();
app.use(express.json());
app.use(requestLogger);

app.get('/ping', (req, res) => {
    console.log(`  ✅ Ping received - server is alive`);
    res.json({ message: "Server is alive" });
});

// Upload endpoint
app.post('/upload', upload.single('file'), async (req, res) => {
    try {
        const filename = req.file.filename;
        const fileSize = (req.file.size / 1024).toFixed(2);
        const clientIP = req.ip || req.connection.remoteAddress;
        
        console.log(`  ✅ File uploaded successfully`);
        console.log(`     - Original name: ${req.file.originalname}`);
        console.log(`     - Stored as: ${filename}`);
        console.log(`     - Size: ${fileSize} KB`);
        console.log(`     - Client IP: ${clientIP}`);
        
        // Save to database
        if (pool) {
            await pool.execute(
                'INSERT INTO uploads (original_name, stored_name, file_size, client_ip) VALUES (?, ?, ?, ?)',
                [req.file.originalname, filename, req.file.size, clientIP]
            );
            console.log(`     - Saved to database ✅`);
        }
        
        res.json({
            status: "success",
            originalName: req.file.originalname,
            storedName: req.file.filename,
            size: req.file.size
        });
    } catch (error) {
        console.error(`  ❌ Upload error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

// Get all uploads from database
app.get('/uploads', async (req, res) => {
    try {
        if (!pool) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const [rows] = await pool.execute('SELECT * FROM uploads ORDER BY upload_time DESC');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Database health check
app.get('/health', async (req, res) => {
    try {
        if (pool) {
            await pool.execute('SELECT 1');
            res.json({ status: 'healthy', database: 'connected' });
        } else {
            res.json({ status: 'healthy', database: 'disconnected' });
        }
    } catch (error) {
        res.status(500).json({ status: 'unhealthy', error: error.message });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.log(`  ❌ Error: ${err.message}`);
    res.status(500).json({ error: err.message });
});

// Server start
async function startServer() {
    // Initialize database first
    await initDatabase();
    
    const server = app.listen(PORT, HOST, () => {
        const os = require('os');
        const networkInterfaces = os.networkInterfaces();
        let localIP = 'localhost';
        
        for (const name of Object.keys(networkInterfaces)) {
            for (const iface of networkInterfaces[name]) {
                if (iface.family === 'IPv4' && !iface.internal) {
                    localIP = iface.address;
                    break;
                }
            }
        }
        
        const baseUrl = `http://${localIP}:${PORT}`;
        console.log(`\n${'='.repeat(60)}`);
        console.log(`🚀 Attacker Server is running!`);
        console.log(`${'='.repeat(60)}`);
        console.log(`\n📍 Server URL: ${baseUrl}`);
        console.log(`\n🔗 For remote clients, use: http://${localIP}:${PORT}`);
        console.log(`\n📌 Available endpoints:`);
        console.log(`   - Ping:    ${baseUrl}/ping`);
        console.log(`   - Health:  ${baseUrl}/health`);
        console.log(`   - Upload:  POST ${baseUrl}/upload`);
        console.log(`   - Uploads: GET ${baseUrl}/uploads`);
        console.log(`\n${'='.repeat(60)}\n`);
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
        console.log('\n\n⛔ Shutting down server...');
        if (pool) {
            await pool.end();
            console.log('✅ Database connection closed');
        }
        server.close(() => {
            console.log('✅ Server closed');
            process.exit(0);
        });
    });
}

startServer();
