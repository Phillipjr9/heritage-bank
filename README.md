# Heritage Bank

A modern digital banking application.

## Architecture

The frontend and backend are hosted **separately**:

| Part | Host | Serves |
|---|---|---|
| Frontend | **Vercel** (static) | the `public/` folder |
| Backend | **Render** (Node web service) | `backend/server.js` — Express API + MySQL/TiDB |

Vercel is static-only and cannot run Express, so the frontend calls the API
**cross-origin** by absolute URL. That URL is defined in exactly one place:

```js
// public/config.js
const BACKEND_URL = 'https://heritage-bank-api.onrender.com';  // ← set to your Render URL
```

Every page loads `config.js` and reads `window.API_URL` from it. **Never
hard-code a backend URL in an individual page.**

> To test against a different backend without redeploying, run this in the
> browser console: `localStorage.setItem('apiUrl', 'https://other.onrender.com')`

## Deploy the backend to Render

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
> first request afterwards takes ~30-60s to wake. The first login of the day
> will look like a hang. Use a paid instance to avoid this.

### CORS
The backend automatically trusts `*.vercel.app` (production **and** preview
deploys), `*.pages.dev`, `*.netlify.app` and `*.onrender.com`. For a custom
domain, set `CORS_ORIGIN=https://yourdomain.com` on the Render service.

## Deploy the frontend to Vercel

1. Set `BACKEND_URL` in `public/config.js` to your Render URL and commit.
2. Vercel → **New Project** → import this repo. `vercel.json` does the rest:
   - `outputDirectory: public` — only the frontend is uploaded
   - `cleanUrls: true` — `/signin` serves `signin.html`
   - `config.js` is sent `no-store` so a changed backend URL takes effect immediately

### Checklist when login fails
1. `curl https://<render-service>.onrender.com/api/health` → expect `"database":"connected"`.
2. Browser console on the sign-in page → `[Config] API_URL = ...` must show the
   Render URL, **not** the Vercel/Pages domain.
3. Network tab → the login POST must go to the Render host and return JSON.
   HTML back means the request hit the static host instead of the API.

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
