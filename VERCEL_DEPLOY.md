# Vercel Deploy Guide - FIMonacci

## ⚠️ XƏBƏRDARLIQ

Vercel Flask üçün məhdud dəstək verir:
- ❌ **WebSocket (Flask-SocketIO) işləməyə bilər** - Real-time alerts işləməyə bilər
- ❌ **Background threads işləmir** - File monitoring və hash verification işləməyə bilər
- ❌ **File system monitoring məhduddur** - watchdog tam işləməyə bilər
- ✅ **Basic Flask routes işləyir** - Admin panel və API endpoints işləyə bilər

**Tövsiyə:** Railway.app istifadə edin (tam dəstək)

## Vercel Konfiqurasiyası

### 1. Build Settings

**Build Command:**
```
pip install -r requirements.txt
```

Və ya boş qoyun (None) - Vercel avtomatik install edəcək

**Output Directory:**
```
N/A
```
(boş qoyun)

**Install Command:**
```
pip install -r requirements.txt
```
✅ **Aktiv edin** (toggle ON)

### 2. Environment Variables

Aşağıdakı environment variables əlavə edin:

**DATABASE_URL** (Tələb olunur):
```
postgresql://user:password@host:port/database
```

**SECRET_KEY** (Tövsiyə olunur):
```
python -c "import secrets; print(secrets.token_hex(32))"
```

**DISABLE_MONITORING** (Vercel üçün):
```
1
```
Bu background threads-i deaktiv edir (Vercel-də işləmir)

### 3. Root Directory

```
./
```
(dəyişməyin)

### 4. Framework Preset

```
Flask
```
(artıq seçilib)

## Deploy Sonrası

1. **Database initialize edin:**
   - Vercel Functions-dan və ya local-dan:
   ```bash
   python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()"
   ```

2. **Admin user yaradın:**
   ```bash
   python -c "from app import create_app, db; from app.database import User; from werkzeug.security import generate_password_hash; app = create_app(); app.app_context().push(); user = User(username='admin', email='admin@example.com', password_hash=generate_password_hash('your_password'), is_admin=True); db.session.add(user); db.session.commit()"
   ```

## Problemlər

### WebSocket işləmir
- Real-time alerts işləməyə bilər
- Dashboard-da SocketIO connection error görünə bilər
- Həll: Railway.app istifadə edin

### Background threads işləmir
- File monitoring işləməyə bilər
- Hash verification loop işləməyə bilər
- Həll: `DISABLE_MONITORING=1` təyin edin

### Database connection problemi
- PostgreSQL connection string-i yoxlayın
- Vercel-də external database istifadə edin (Railway, Supabase, etc.)

## Alternativ: Railway.app

Railway tam dəstək verir:
- ✅ WebSocket dəstəyi
- ✅ Background threads
- ✅ PostgreSQL database
- ✅ File system access

`RAILWAY_DEPLOY.md` faylına baxın.

