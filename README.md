# Heritage Bank

A modern digital banking application.

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
