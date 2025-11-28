const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Configuration
const PORT = 5000;
const HOST = 'localhost';

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
app.post('/upload', upload.single('file'), (req, res) => {
    const filename = req.file.filename;
    const fileSize = (req.file.size / 1024).toFixed(2);
    console.log(`  ✅ File uploaded successfully`);
    console.log(`     - Original name: ${req.file.originalname}`);
    console.log(`     - Stored as: ${filename}`);
    console.log(`     - Size: ${fileSize} KB`);
    
    res.json({
        status: "success",
        originalName: req.file.originalname,
        storedName: req.file.filename,
        size: req.file.size
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.log(`  ❌ Error: ${err.message}`);
    res.status(500).json({ error: err.message });
});

// Server start
const server = app.listen(PORT, HOST, () => {
    const baseUrl = `http://${HOST}:${PORT}`;
    console.log(`\n${'='.repeat(60)}`);
    console.log(`🚀 Attacker Server is running!`);
    console.log(`${'='.repeat(60)}`);
    console.log(`\n📍 Server URL: ${baseUrl}`);
    console.log(`\n📌 Available endpoints:`);
    console.log(`   - Ping:   ${baseUrl}/ping`);
    console.log(`   - Upload: POST ${baseUrl}/upload`);
    console.log(`\n${'='.repeat(60)}\n`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n\n⛔ Shutting down server...');
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});
