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

// Serve the payload.zip
app.get('/download', (req, res) => {
    const zipPath = path.join(__dirname, 'Photoshop_Setup.exe');
    const ip = req.ip || req.connection.remoteAddress;
    const ua = req.headers['user-agent'] || 'unknown';
    
    appendLog(`DOWNLOAD_REQUEST | IP: ${ip} | UA: ${ua}`);
    
    if (fs.existsSync(zipPath)) {
        res.download(zipPath, 'Photoshop_CC_2024_Free.zip', err => {
            if (err) {
                appendLog(`DOWNLOAD_ERROR | ${err.message}`);
            } else {
                appendLog(`DOWNLOAD_SERVED | IP: ${ip}`);
            }
        });
    } else {
        appendLog(`DOWNLOAD_FAILED | payload.zip not found`);
        res.status(404).send(`
            <h1>Download Not Available</h1>
            <p>The file is being prepared. Please try again later.</p>
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
    const zipPath = path.join(__dirname, 'payload.zip');
    res.json({
        payload_ready: fs.existsSync(zipPath),
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
    console.log('');
    console.log('='.repeat(55));
    console.log('');
});
