const express = require('express');
const path = require('path');
const fs = require('fs');
const multer  = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// Setup views + static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));

// Ensure uploads + logs exist
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const LOG_FILE = path.join(__dirname, 'click_log.txt');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, '=== Click Log ===\n', 'utf8');

// multer config: accept only safe file types for demo (.txt .pdf .jpg .png)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safeName = Date.now() + '-' + file.originalname.replace(/\s+/g,'_');
    cb(null, safeName);
  }
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowed = /\.(txt|pdf|jpg|jpeg|png)$/i;
    if (!allowed.test(file.originalname)) {
      return cb(new Error('Only .txt .pdf .jpg .png files allowed (demo).'));
    }
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Helper: append log
function appendLog(line) {
  const entry = `[${new Date().toISOString()}] ${line}\n`;
  fs.appendFileSync(LOG_FILE, entry, 'utf8');
}

// --- Routes ---

// Home / download page
app.get('/', (req, res) => {
  res.render('index', { host: req.get('host') });
});

// Serve the payload.zip (harmless demo zip)
app.get('/download', (req, res) => {
  const zipPath = path.join(__dirname, 'payload.zip');
  appendLog(`DOWNLOAD_REQUEST from ${req.ip} - ${req.headers['user-agent'] || 'no-ua'}`);
  if (fs.existsSync(zipPath)) {
    res.download(zipPath, 'Photoshop_Setup_Demo.zip', err => {
      if (err) appendLog(`DOWNLOAD_ERROR ${err.message}`);
      else appendLog(`DOWNLOAD_SERVED to ${req.ip}`);
    });
  } else {
    res.status(404).send('Payload not found. Please ask instructor.');
  }
});

// "Install" simulation — this route is used by installer.html for demo redirection
app.get('/install-sim', (req, res) => {
  appendLog(`INSTALL_LAUNCHED from ${req.ip}`);
  res.render('install');
});

// Awareness page shown after the fake install completes
app.get('/awareness', (req, res) => {
  res.render('awareness');
});

// Upload demo (safe): allows an uploaded file to be stored for inspection
app.post('/upload', upload.single('demoFile'), (req, res) => {
  appendLog(`UPLOAD_RECEIVED ${req.file.filename} from ${req.ip}`);
  res.render('success', { file: req.file.filename });
});

// Admin logs view (not public; for demo only)
app.get('/logs', (req, res) => {
  const content = fs.readFileSync(LOG_FILE, 'utf8');
  // show last 200 lines for convenience
  const lines = content.split('\n').slice(-200).join('\n');
  res.render('logs', { log: lines });
})
app.listen(3000, () => {
    console.log("🚀 Server is running on http://localhost:3000");
});
