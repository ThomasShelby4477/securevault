# 🚀 SecureVault Deployment Guide

## Free Deployment Options

Deploy your SecureVault file locker to the internet **for free**.

---

## Option 1: Ngrok (Quickest - 5 minutes)

**Best for:** Testing, demos, temporary access

### Steps:

1. **Download ngrok** from https://ngrok.com/download

2. **Sign up** for free at https://ngrok.com (get auth token)

3. **Configure ngrok:**
```cmd
ngrok config add-authtoken YOUR_AUTH_TOKEN
```

4. **Start your app locally:**
```cmd
cd "e:\Personal(E drive)\E4\Extras\Antigravity\File_Locker"
start_production.bat
```

5. **In new terminal, start ngrok:**
```cmd
ngrok http 5000
```

6. **Access your app** at the URL shown (e.g., `https://abc123.ngrok.io`)

✅ HTTPS included automatically
⚠️ URL changes each restart (paid plan for fixed URL)

---

## Option 2: Render.com (Best Free Option)

**Best for:** Production, always-on hosting

### Steps:

1. **Push to GitHub:**
```cmd
cd "e:\Personal(E drive)\E4\Extras\Antigravity\File_Locker"
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/securevault.git
git push -u origin main
```

2. **Create `render.yaml`** in project root (I'll create this)

3. **Go to** https://render.com → Sign up free

4. **New → Web Service → Connect GitHub repo**

5. **Configure:**
   - Name: `securevault`
   - Region: Singapore/Oregon
   - Runtime: Python 3
   - Build: `pip install -r requirements.txt`
   - Start: `gunicorn app:app`

6. **Add Environment Variables:**
   - `SECRET_KEY` = (generate random string)
   - `FLASK_ENV` = production

7. **Deploy!**

✅ Free HTTPS (https://securevault.onrender.com)
✅ 750 free hours/month
⚠️ Sleeps after 15 min inactivity

---

## Option 3: PythonAnywhere (Easiest)

**Best for:** Beginners, Python-native hosting

### Steps:

1. **Sign up** at https://www.pythonanywhere.com (free tier)

2. **Upload files** via Files tab or git clone

3. **Create Web App:**
   - Dashboard → Web → Add new web app
   - Choose Flask
   - Python 3.10

4. **Configure WSGI file:**
```python
import sys
path = '/home/yourusername/securevault'
if path not in sys.path:
    sys.path.append(path)

from app import create_app
application = create_app('production')
```

5. **Install packages** in Bash console:
```bash
pip install --user -r requirements.txt
```

6. **Reload** web app

✅ Free subdomain (yourusername.pythonanywhere.com)
✅ Always on
⚠️ 512MB storage on free tier

---

## Option 4: Railway.app (Modern & Simple)

### Steps:

1. **Go to** https://railway.app → Sign up with GitHub

2. **New Project → Deploy from GitHub**

3. **Select your repo**

4. **Add variables:**
   - `SECRET_KEY`
   - `FLASK_ENV=production`

5. **Railway auto-detects Python & deploys!**

✅ Free $5/month credit
✅ Custom domain support
✅ Auto HTTPS

---

## Required Files for Deployment

### Create these files:

**`Procfile`** (for Heroku/Render):
```
web: gunicorn app:app
```

**`runtime.txt`**:
```
python-3.11.0
```

**`render.yaml`**:
```yaml
services:
  - type: web
    name: securevault
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: gunicorn app:app
    envVars:
      - key: SECRET_KEY
        generateValue: true
      - key: FLASK_ENV
        value: production
```

---

## 🔐 Security Checklist for Production

- [ ] Set strong `SECRET_KEY` environment variable
- [ ] Use HTTPS only (all options above include it)
- [ ] Set `FLASK_ENV=production`
- [ ] Use PostgreSQL instead of SQLite for production
- [ ] Enable Cloudflare for DDoS protection (free)
- [ ] Set up regular backups

---

## Quick Start: ngrok (Fastest Way)

```cmd
REM Terminal 1: Start app
cd "e:\Personal(E drive)\E4\Extras\Antigravity\File_Locker"
start_production.bat

REM Terminal 2: Expose to internet
ngrok http 5000
```

Access from anywhere: `https://xxxxx.ngrok.io` 🌐
