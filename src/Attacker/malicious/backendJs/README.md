# Backend Server (Node.js/Express)

Backend Server for Data Collection - Refactored from Python Flask to Node.js Express.

## Features

- Receives JSON data and stores in Aiven Cloud MySQL Database
- Handles file transfers (exe files)
- RESTful API endpoints
- Production-ready for DigitalOcean deployment

## Installation

```bash
npm install
```

## Configuration

Create a `.env` file with the following variables:

```env
# Aiven Cloud Database Configuration
DB_HOST=your-database-host
DB_PORT=21011
DB_USER=your-username
DB_PASSWORD=your-password
DB_NAME=your-database

# Server Configuration
PORT=5000
NODE_ENV=development
```

## Running the Server

### Production
```bash
npm start
```

### Development (with auto-reload)
```bash
npm run dev
```

## DigitalOcean Deployment

### Option 1: App Platform (Recommended)

1. Push your code to GitHub
2. Go to DigitalOcean App Platform
3. Create new app → Select your GitHub repo
4. Set source directory to `src/Attacker/malicious/backendJs`
5. Configure environment variables:
   - `DB_HOST` (Secret)
   - `DB_PORT`: `21011`
   - `DB_USER` (Secret)
   - `DB_PASSWORD` (Secret)
   - `DB_NAME`: `defaultdb`
   - `PORT`: `5000`
   - `NODE_ENV`: `production`
6. Deploy!

### Option 2: Using doctl CLI

```bash
# Install doctl and authenticate
doctl auth init

# Deploy using app.yaml
doctl apps create --spec app.yaml
```

### Option 3: Docker on Droplet

```bash
# Build Docker image
docker build -t backend-server .

# Run container
docker run -d \
  -p 5000:5000 \
  -e DB_HOST=your-host \
  -e DB_PORT=21011 \
  -e DB_USER=your-user \
  -e DB_PASSWORD=your-password \
  -e DB_NAME=defaultdb \
  -e NODE_ENV=production \
  --name backend-server \
  backend-server
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Root endpoint - shows available endpoints |
| POST | `/api/receive` | Receive JSON data and store in database |
| POST | `/api/receive/batch` | Receive multiple JSON records at once |
| GET | `/api/transfer/file` | Download file (query: `filename`) |
| POST | `/api/transfer/upload` | Upload file to server |
| GET | `/api/health` | Health check endpoint |
| GET | `/api/data` | Retrieve all stored data |

## Usage Examples

### Receive JSON Data
```bash
curl -X POST http://localhost:5000/api/receive \
  -H "Content-Type: application/json" \
  -d '{"key": "value", "data": "example"}'
```

### Receive Batch Data
```bash
curl -X POST http://localhost:5000/api/receive/batch \
  -H "Content-Type: application/json" \
  -d '[{"item": 1}, {"item": 2}, {"item": 3}]'
```

### Download File
```bash
curl -O http://localhost:5000/api/transfer/file?filename=payload.exe
```

### Upload File
```bash
curl -X POST http://localhost:5000/api/transfer/upload \
  -F "file=@/path/to/file.exe"
```

### Health Check
```bash
curl http://localhost:5000/api/health
```

### Get All Data
```bash
curl http://localhost:5000/api/data
```

## Database Tables

### received_data
| Column | Type | Description |
|--------|------|-------------|
| id | INT | Auto-increment primary key |
| data | JSON | Stored JSON data |
| source_ip | VARCHAR(50) | IP address of sender |
| received_at | TIMESTAMP | When data was received |
| data_type | VARCHAR(100) | Type of data |

### file_transfers
| Column | Type | Description |
|--------|------|-------------|
| id | INT | Auto-increment primary key |
| filename | VARCHAR(255) | Name of transferred file |
| target_ip | VARCHAR(50) | IP address of recipient |
| transferred_at | TIMESTAMP | When file was transferred |
| status | VARCHAR(50) | Transfer status |
