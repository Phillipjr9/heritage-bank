# Heritage Bank

A modern digital banking application.

## Deploy to Render.com

### Step 1: Create Web Service
1. Go to [render.com](https://render.com) and sign up/login
2. Click **New +** → **Web Service**
3. Connect your GitHub account
4. Select repository: `Phillipjr9/heritage-bank`

### Step 2: Configure Service
- **Name**: `heritage-bank` (or any name)
- **Region**: Choose closest to you
- **Branch**: `main`
- **Root Directory**: *(leave empty)*
- **Runtime**: `Node`
- **Build Command**: `cd backend && npm install`
- **Start Command**: `node backend/server.js`

### Step 3: Add Environment Variables
Click **Advanced** → **Add Environment Variable** for each:

| Key | Value |
|-----|-------|
| `DB_HOST` | `gateway02.us-east-1.prod.aws.tidbcloud.com` |
| `DB_PORT` | `4000` |
| `DB_USER` | `JFuLJ45NfRfBSN9.root` |
| `DB_PASSWORD` | `Nt8gO8tMGu4T8mJ1ui9X` |
| `DB_NAME` | `S7YJ2XbutEnzhih9Qut8LJ` |
| `JWT_SECRET` | `heritage-bank-secret-2024` |
| `ADMIN_EMAIL` | `admin@heritagebank.com` |
| `ADMIN_PASSWORD` | `AdminPass123456` |

### Step 4: Deploy
Click **Create Web Service**

Your app will be live at: `https://heritage-bank.onrender.com`

---

## Features
- User registration and authentication
- Account management with unique account numbers
- Fund transfers (via email or account number)
- Bill payments
- Admin panel for user management

## Admin Access
- **Email**: admin@heritagebank.com
- **Password**: AdminPass123456
