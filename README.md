# Heritage Bank

A modern digital banking application.

## Deploy to Render (recommended)

A **single Render Web Service** hosts both the API and the frontend:
`backend/server.js` serves the static HTML/CSS/JS from the repository root, so
the frontend talks to the API **same-origin** — there is no backend URL to
hard-code anywhere.

### Option A — Blueprint (uses `render.yaml`)
1. Push this repo to GitHub.
2. Render Dashboard → **New** → **Blueprint** → select this repository.
3. Render reads `render.yaml` and prompts for the secret env vars below.

### Option B — Manual
Render Dashboard → **New** → **Web Service** → connect the repo, then set:

| Setting | Value |
|---|---|
| Runtime | Node |
| Build Command | `npm install --prefix backend --omit=dev` |
| Start Command | `node backend/server.js` |
| Health Check Path | `/api/health` |

### Required environment variables
Set these in **Render → your service → Environment**:

```
NODE_ENV=production
JWT_SECRET=<long random string>
ADMIN_EMAIL=<your admin email>
ADMIN_PASSWORD=<strong password>
DB_HOST=<mysql/tidb host>
DB_PORT=4000          # 3306 for plain MySQL
DB_USER=<db user>
DB_PASSWORD=<db password>
DB_NAME=heritage_bank
```

> Do **not** set `PORT` — Render injects it and the server reads `process.env.PORT`.
> `NODE_ENV=production` makes the server refuse to boot without `JWT_SECRET`,
> `ADMIN_EMAIL` and `ADMIN_PASSWORD`, which is intentional.
> TLS to the database is on by default; set `DB_SSL=false` only if your
> provider doesn't support it.

### Verifying a deploy
```bash
curl https://<your-service>.onrender.com/api/health
```
```jsonc
{ "status": "ok", "database": "connected" }   // ✅ logins will work
{ "status": "ok", "database": "disconnected", "databaseError": "..." }  // ⚠️ API is up, DB is not
```

The server **binds its port before connecting to the database** and retries the
connection every 30s. A database outage therefore degrades the app (DB-backed
routes return `503 DB_UNAVAILABLE`) instead of killing the process — which is
what previously turned a database problem into a completely dead host.

> **Free plan note:** Render free web services sleep after ~15 minutes idle; the
> first request afterwards takes ~30-60s to wake. Use a paid instance to avoid this.

---

## Deploy to Firebase

### Prerequisites
- Firebase project on the **Blaze (pay-as-you-go)** plan (required for outbound DB connections)
- Firebase CLI: `npm install -g firebase-tools`
- Logged in: `firebase login`

### Step 1: Install dependencies
```bash
cd functions && npm install
```

### Step 2: Set environment variables (Secret Manager)
Run each command and enter the value when prompted:
```bash
firebase functions:secrets:set DB_HOST
firebase functions:secrets:set DB_PORT
firebase functions:secrets:set DB_USER
firebase functions:secrets:set DB_PASSWORD
firebase functions:secrets:set DB_NAME
firebase functions:secrets:set JWT_SECRET
firebase functions:secrets:set ADMIN_EMAIL
firebase functions:secrets:set ADMIN_PASSWORD
```

### Step 3: Deploy
```bash
firebase deploy
```
This deploys both:
- **Hosting** → your frontend from `public/`
- **Cloud Function** → your Express API at `/api/**`

Your app will be live at: `https://<your-project>.web.app`

> **Database**: Your MySQL/TiDB database is unchanged. The Cloud Function connects to it using the same env vars.

### Local development (emulator)
```bash
cd functions && npm install
firebase emulators:start
```
Frontend: http://localhost:5000  
API: http://localhost:5001/<project-id>/us-central1/api

---

## Features
- User registration and authentication
- Account management with unique account numbers
- Fund transfers (via email or account number)
- Bill payments
- Admin panel for user management

## Admin Access
- **Email**: admin@heritagebank.com
- **Password**: Set via `ADMIN_PASSWORD` in your Render environment variables (do not hardcode in the repo).
