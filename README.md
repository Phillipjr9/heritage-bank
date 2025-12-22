# Heritage Bank

A modern digital banking application.

## Setup

### Backend

1. Navigate to backend folder:
   ```bash
   cd backend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Copy environment example and configure:
   ```bash
   cp .env.example .env
   ```

4. Edit `.env` with your database credentials:
   - `DB_HOST` - Your database host
   - `DB_USER` - Database username
   - `DB_PASSWORD` - Database password
   - `DB_NAME` - Database name
   - `JWT_SECRET` - Secret key for JWT tokens
   - `ADMIN_EMAIL` - Admin account email
   - `ADMIN_PASSWORD` - Admin account password

5. Start the server:
   ```bash
   npm start
   ```

### Frontend

Serve the root directory with any static file server:
```bash
npx http-server -p 8000
```

## Features

- User registration and authentication
- Account management
- Fund transfers (via email or account number)
- Bill payments
- Admin panel for user management

## API Endpoints

- `GET /api/health` - Health check
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `GET /api/user/profile` - Get user profile
- `POST /api/user/transfer` - Transfer funds
- `GET /api/bills/billers` - Get available billers
- `POST /api/bills/pay` - Pay a bill
- `GET /api/admin/users-with-balances` - Get all users (admin)
- `POST /api/admin/fund-user` - Fund user account (admin)
- `POST /api/admin/create-user` - Create user (admin)

## Security

- All sensitive credentials stored in environment variables
- JWT authentication with 24-hour expiration
- Password hashing with bcrypt
- SSL database connections
