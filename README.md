# FIMonacci

High-speed File Integrity Monitoring (FIM) system with real-time alerts, built with Flask, MD5 hashing, and WebSocket support.
## Credentials
- admin: infat
- password: salam123
- url: https://fimonacci.vercel.app

## 🚀 Features

- 🔒 **Real-time File Monitoring**: Continuous monitoring of file system changes using `watchdog` on both server and client sides
- 🔐 **MD5 Hash Verification**: Fast MD5 hashing for file integrity checks with automatic periodic verification
- 📊 **Advanced Admin Dashboard**: Beautiful, modern admin interface with real-time updates and neon effects
- 🌐 **WebSocket Alerts**: Real-time notifications via Flask-SocketIO for instant event notifications
- 👥 **Multi-Client Support**: Standalone client application for remote monitoring (no registration required)
- 📈 **Analytics & Charts**: Interactive system activity charts and event distribution visualization using Chart.js
- 🎨 **Modern UI**: Glassmorphism design with neon effects, dark/light mode support, and smooth animations
- 📱 **Responsive Design**: Fully responsive interface that works on all devices
- 🔍 **Advanced Search**: Real-time search functionality across clients and alerts
- 📋 **Activity Timeline**: Chronological view of all file integrity events with filtering
- 📊 **Agent Status**: Real-time monitoring with system activity charts and event distribution
- 📝 **System Logs**: Comprehensive logging system with filtering and auto-refresh
- ⚙️ **Settings Panel**: Comprehensive configuration options for monitoring, alerts, and system settings

## 📁 Project Structure

```
fimonacci/
├── app/                    # Main Flask application
│   ├── __init__.py        # App initialization & background threads
│   ├── admin.py           # Admin panel routes & API endpoints
│   ├── auth.py            # Authentication & API token management
│   ├── database.py          # Database models (User, Client, FileHash, etc.)
│   ├── monitor.py        # Core FIM monitoring logic & hash verification
│   ├── routes.py         # Main routes & API endpoints for clients
│   └── templates/        # HTML templates
│       ├── admin.html    # Admin dashboard (main UI)
│       └── login.html    # Login page
├── clients/               # Standalone client application
│   ├── client.py         # Client monitoring script
│   ├── README.md         # Client documentation
│   └── requirements.txt  # Client dependencies
├── .gitignore            # Git ignore file
├── requirements.txt      # Server dependencies
├── run.py                # Application entry point
└── README.md             # This file
```

## 🚀 Quick Deploy (Vercel)

FIMonacci-i Vercel-də deploy etmək üçün:

1. **GitHub-a push edin** (repo public və ya private ola bilər)
2. **Vercel.com**-a daxil olun və yeni proyekt yaradın
3. **GitHub repo-nuzu seçin** və deploy edin
4. **PostgreSQL database əlavə edin** (external service, məsələn Railway, Supabase)
5. **Environment variables təyin edin** (`DATABASE_URL`, `SECRET_KEY`)
6. **Database initialize edin** (Vercel Functions-dan və ya local-dan)
7. **Admin user yaradın** (Vercel Functions-dan və ya local-dan)

**Qeyd:** Vercel-də WebSocket (real-time alerts) və background threads işləməyəcək. Əsas funksiyalar (admin panel, API) işləyəcək.

Detallı təlimatlar üçün `VERCEL_DEPLOY.md` faylına baxın.

## 🛠️ Installation

### Server Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd fimonacci
   ```

2. **Create virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure database**
   
   Set `DATABASE_URL` environment variable:
   ```bash
   export DATABASE_URL="postgresql://user:password@host:port/database"
   ```
   
   Or modify `app/__init__.py` to use your database connection string directly.

5. **Initialize database**
   ```bash
   python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()"
   ```

6. **Create admin user**
   ```bash
   python -c "from app import create_app, db; from app.database import User; from werkzeug.security import generate_password_hash; app = create_app(); app.app_context().push(); user = User(username='admin', email='admin@example.com', password_hash=generate_password_hash('your_password'), is_admin=True); db.session.add(user); db.session.commit()"
   ```

7. **Run the server**
   ```bash
   python run.py
   ```

The server will start on `http://0.0.0.0:5000`

### Client Setup

See `clients/README.md` for detailed client installation and usage instructions.

**Quick Start:**
```bash
cd clients
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python client.py -u http://server-url:5000 -p /path/to/monitor
```

## 📖 Usage

### Admin Dashboard

1. Navigate to `http://localhost:5000` (or your server URL)
2. Login with admin credentials
3. Access the admin dashboard with the following features:

   **Dashboard Tab:**
   - Real-time summary cards (Modified, Deleted, Created, Accessed)
   - Recent alerts table with live updates
   - Activity timeline with chronological events
   - Auto-refresh every 10 seconds

   **All Clients Tab:**
   - View all connected clients with statistics
   - Client details modal (hashes, folders, alerts, stats)
   - Search functionality
   - Export data as JSON

   **Alerts Tab:**
   - Detailed alerts view with filtering
   - Filter by event type and severity
   - Complete file integrity event history

   **Timeline Tab:**
   - Chronological view of all events
   - Filter by event type
   - Adjustable limit (10-500 events)

   **Agent Status Tab:**
   - System activity chart (24h events & CPU)
   - Event distribution pie chart
   - Real-time updates every 30 seconds
   - Neon-styled visualizations

   **Logs Tab:**
   - System and event logs
   - Filter by level (Info, Warning, Error, Success)
   - Filter by type (File Events, Client Activity, System)
   - Clear old logs (older than 7 days)
   - Auto-refresh every 5 seconds

   **Settings Tab:**
   - Monitoring settings (scan intervals, hash algorithm)
   - Alert settings (notifications, retention)
   - Client settings (timeout, max files)
   - System settings (backup, log level)
   - Security settings (session timeout, API rate limit)

### Client Application

The client application runs independently and automatically connects to the server:

**Basic usage:**
```bash
python client.py -u http://server-url:5000 -p /path/to/monitor
```

**Multiple paths:**
```bash
python client.py -u http://server-url:5000 -p /path1 -p /path2 -p /path3
```

**Features:**
- Automatic client ID generation (no registration needed)
- Real-time file system monitoring with `watchdog`
- Automatic hash calculation and upload
- Periodic hash verification (every 1 minute)
- Event detection (created, modified, deleted)
- Automatic reconnection on connection loss

## ⚙️ Configuration

### Environment Variables

- `DATABASE_URL`: PostgreSQL connection string (required)
  - Format: `postgresql://user:password@host:port/database`
- `SECRET_KEY`: Flask secret key for sessions (optional, auto-generated if not set)

### Database Models

- **User**: Admin users for dashboard access (username, email, password_hash, is_admin)
- **Client**: Anonymous clients identified by unique ID and hostname
- **FileHash**: MD5 hashes of monitored files with paths and timestamps
- **MonitoredFolder**: Folders being monitored by clients
- **FileIntegrity**: File integrity alerts and events (modified, created, deleted, hash_mismatch)

### Monitoring Configuration

- **Active Scan Interval**: Default 60 seconds (configurable in settings)
- **Hash Verification Interval**: Default 60 seconds (configurable in settings)
- **Real-time Monitoring**: Enabled by default using `watchdog`

## 🎨 UI Features

- **Dark/Light Mode**: Toggle between themes with persistent storage
- **Glassmorphism**: Modern glass effect with backdrop blur
- **Neon Effects**: Advanced neon styling on Agent Status page
- **Smooth Animations**: CSS transitions and animations throughout
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Real-time Updates**: WebSocket-based live updates without page refresh
- **Interactive Charts**: Chart.js-powered visualizations with hover effects

## 🔧 Technologies

- **Backend**: 
  - Flask (web framework)
  - Flask-SQLAlchemy (ORM)
  - Flask-SocketIO (WebSocket support)
  - Flask-Login (authentication)
  - Flask-WTF (form handling)
- **Database**: PostgreSQL (via psycopg2-binary)
- **Monitoring**: watchdog (file system events)
- **Frontend**: 
  - HTML5, CSS3, JavaScript
  - Chart.js (data visualization)
  - Font Awesome (icons)
- **Real-time**: WebSockets (Flask-SocketIO)
- **Security**: werkzeug (password hashing)

## 🔐 Security

- Password hashing using werkzeug
- Session-based authentication for admin users
- API token authentication for clients
- Admin-only access to dashboard
- Secure file path handling
- SQL injection protection via SQLAlchemy

## 📝 API Endpoints

### Client API (Token Required)
- `POST /api/client/register` - Register or update client
- `POST /api/upload/hashes` - Upload file hashes
- `POST /api/upload/event` - Upload file event alerts

### Admin API (Login Required)
- `GET /admin/api/clients` - Get all clients
- `GET /admin/api/client/<id>/hashes` - Get client file hashes
- `GET /admin/api/client/<id>/folders` - Get client monitored folders
- `GET /admin/api/client/<id>/alerts` - Get client alerts
- `GET /admin/api/client/<id>/stats` - Get client statistics
- `GET /admin/api/charts/activity` - Get activity chart data
- `GET /admin/api/charts/distribution` - Get distribution chart data
- `GET /admin/api/logs` - Get system logs
- `POST /admin/api/logs/clear` - Clear old logs

## 🐛 Troubleshooting

### Database Connection Issues
- Verify `DATABASE_URL` environment variable is set correctly
- Check PostgreSQL server is running and accessible
- Verify credentials and network connectivity

### Client Connection Issues
- Verify server URL is correct and accessible
- Check firewall settings
- Ensure client can reach server on port 5000

### Admin Login Issues
- Verify admin user exists in database
- Check `is_admin` flag is set to `True`
- Reset password if needed

## 📄 License

This project is proprietary software.

## 🤝 Support

For issues and questions, please contact the development team.

## 🔄 Version

Current version: 1.0.0

---

**FIMonacci** - High-speed File Integrity Monitoring System
