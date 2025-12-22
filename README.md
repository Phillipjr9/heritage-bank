# Heritage Bank

A modern digital banking application with unified frontend and backend deployment.

## Quick Deploy to Render.com (Recommended - Free)

1. Go to [render.com](https://render.com) and sign up
2. Click **New** → **Web Service**
3. Connect your GitHub account and select this repository
4. Configure:
   - **Name**: `heritage-bank`
   - **Root Directory**: `backend`
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
5. Add Environment Variables:
   ```
   DB_HOST=your-database-host
   DB_PORT=4000
   DB_USER=your-db-username
   DB_PASSWORD=your-db-password
   DB_NAME=your-database-name
   JWT_SECRET=your-secret-key
   ADMIN_EMAIL=admin@heritagebank.com
   ADMIN_PASSWORD=YourAdminPassword
   ```
6. Click **Create Web Service**

Your app will be live at `https://heritage-bank.onrender.com`

## Alternative Platforms

### Railway.app
1. Connect GitHub repo
2. Set root directory to `backend`
3. Add environment variables
4. Deploy

### Cyclic.sh
1. Import from GitHub
2. Set root to `backend`
3. Add env vars
4. Deploy instantly

## Local Development

```bash
# Install dependencies
cd backend
npm install

# Copy and configure environment
cp .env.example .env
# Edit .env with your database credentials

# Start server (serves both frontend and API)
npm start
```

Access at `http://localhost:3001`

## Features

- ✅ User registration and authentication
- ✅ Account management with unique account numbers
- ✅ Fund transfers (via email or account number)
- ✅ Bill payments (8+ billers)
- ✅ Admin panel for user management
- ✅ JWT authentication
- ✅ TiDB Cloud database

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/auth/login` | User login |
| POST | `/api/auth/register` | User registration |
| GET | `/api/user/profile` | Get user profile |
| POST | `/api/user/transfer` | Transfer funds |
| GET | `/api/bills/billers` | Get billers list |
| POST | `/api/bills/pay` | Pay a bill |
| GET | `/api/admin/users-with-balances` | Get all users (admin) |
| POST | `/api/admin/fund-user` | Fund user account (admin) |
| POST | `/api/admin/create-user` | Create user (admin) |

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DB_HOST` | Database host | Yes |
| `DB_PORT` | Database port (default: 4000) | No |
| `DB_USER` | Database username | Yes |
| `DB_PASSWORD` | Database password | Yes |
| `DB_NAME` | Database name | Yes |
| `JWT_SECRET` | Secret for JWT tokens | Yes |
| `ADMIN_EMAIL` | Admin account email | No |
| `ADMIN_PASSWORD` | Admin account password | No |
| `PORT` | Server port (default: 3001) | No |
