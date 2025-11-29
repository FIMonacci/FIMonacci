# FIMonacci Client

Standalone client for scanning local file system and uploading file hashes to FIMonacci server.

**No registration required!** The client automatically generates a unique ID on first run and connects to the server.

## Installation

1. **Python 3.7+** required

2. **Run setup script (recommended):**

**Linux/macOS:**
```bash
chmod +x setup.sh
./setup.sh
```

**Windows:**
```cmd
setup.bat
```

The setup script will:
- Create a virtual environment (`.venv`)
- Install all dependencies automatically
- Configure everything for you

3. **Manual installation (alternative):**

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# OR
.venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

Or install manually:
```bash
pip install requests urllib3
```

## Quick Start

### 1. Setup (First Time Only)

```bash
# Linux/macOS
chmod +x setup.sh
./setup.sh

# Windows
setup.bat
```

### 2. Activate Virtual Environment

```bash
# Linux/macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

### 3. Run Client

**One-time scan:**
```bash
python client.py -u http://localhost:5000 -p /path/to/folder
```

**Continuous monitoring (recommended):**
```bash
python client.py -u http://localhost:5000 -p /path/to/folder --continuous
```

**Custom scan interval (default: 60 seconds):**
```bash
python client.py -u http://localhost:5000 -p /path/to/folder --continuous --interval 30
```

That's it! The client will:
- ✅ Automatically generate a unique client ID
- ✅ Detect your hostname
- ✅ Save configuration to `client_config.json`
- ✅ Register with the server automatically
- ✅ Scan the specified folder(s)
- ✅ Calculate MD5 hashes for all files
- ✅ Upload file hashes to server

### Scan Multiple Folders

```bash
python client.py -u http://localhost:5000 -p /home/user/docs -p /home/user/pics
```

### Remote Server

```bash
python client.py -u https://your-server.com -p /var/www/html
```

## Usage

### Activate Virtual Environment (if not already activated)

```bash
# Linux/macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

### Basic Command

```bash
python client.py -u <SERVER_URL> -p <FOLDER_PATH> [-p <FOLDER_PATH2> ...]
```

**Parameters:**
- `-u, --url`: **Required** - FIMonacci server URL (e.g., `http://localhost:5000` or `https://your-server.com`)
- `-p, --path`: **Required** - Folder path to scan (can be used multiple times for multiple folders)
- `-c, --continuous`: **Optional** - Run continuously and monitor for file changes
- `-i, --interval`: **Optional** - Interval in seconds between scans when running continuously (default: 60)

**Example:**
```bash
python client.py -u http://localhost:5000 -p /home/user/documents
```

**Multiple Folders:**
```bash
python client.py -u http://localhost:5000 -p /home/user/docs -p /home/user/pics -p /home/user/videos
```

### Deactivate Virtual Environment (when done)

```bash
deactivate
```

### What Happens

1. **First Run:**
   - Creates a unique client ID automatically
   - Detects your system hostname
   - Saves configuration to `client_config.json`
   - Registers with the server
   - Scans the specified folder(s)
   - Calculates MD5 hashes for all files
   - Uploads file hashes to server

2. **Subsequent Runs:**
   - Uses saved client ID from `client_config.json`
   - Updates registration with server
   - Scans and uploads files from specified folder(s)

## Configuration

The client automatically saves configuration to `client_config.json` in the same directory:

```json
{
  "client_id": "your-unique-client-id-here",
  "hostname": "your-computer-name",
  "created_at": "2025-11-29T00:00:00.000000"
}
```

**Note:** 
- Client ID is generated once and reused for all future runs
- You can delete `client_config.json` to create a new client ID
- No manual configuration needed!

## Features

- ✅ **Automatic Registration** - No manual setup required
- ✅ **Unique Client ID** - Automatically generated and saved
- ✅ **Hostname Detection** - Automatically detects your computer name
- ✅ **Batch Upload** - Efficiently uploads files in batches
- ✅ **Error Handling** - Robust error handling and retry logic
- ✅ **Progress Display** - Real-time progress updates
- ✅ **Multiple Folders** - Scan and upload multiple folders at once

## Troubleshooting

### Connection Errors

If you get connection errors:

1. **Check server is running:**
   ```bash
   # Make sure the FIMonacci server is running
   curl http://localhost:5000
   ```

2. **Check URL format:**
   - Use `http://` for local servers
   - Use `https://` for remote servers
   - Include port number if not default (e.g., `:5000`)

3. **Check firewall/network:**
   - Ensure firewall allows connection
   - Check network connectivity

### Permission Errors

If you get permission errors:

- Make sure you have read access to the folders you're scanning
- Some system folders may require elevated permissions

### File Not Found

- Ensure folder paths are correct
- Use absolute paths for best results
- Check that folders exist and are accessible

## Examples

### Local Development

```bash
python client.py -u http://localhost:5000 -p ~/Documents
```

### Production Server

```bash
python client.py -u https://fimonacci.example.com -p /var/www/html
```

### Multiple Folders

```bash
python client.py -u http://localhost:5000 \
  -p /home/user/documents \
  -p /home/user/pictures \
  -p /home/user/videos
```

The client will scan the specified folder(s) and upload file hashes to the server.

## Support

For issues or questions, check the main FIMonacci documentation or contact your administrator.
