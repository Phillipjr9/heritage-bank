# Banking Functionality Testing Guide (Admin ↔ User)

This guide verifies the core banking flows:
- Create account / create user
- Credit / debit / fund accounts
- Admin transfer between any two accounts
- User-to-user transfer
- Transactions listing and receipts
- Account closure / deletion (where supported)

> **Note:** The full banking feature set lives in `backend/server.js`.
> Production should run that server (see `Procfile` and root `package.json`).

---

## 1) Base URL

- **Local**: `http://localhost:3001`
- **Render**: `https://<your-service>.onrender.com`

Health check:
- `GET /api/health`

---

## 2) Authentication

### Admin login
`POST /api/auth/login`

Body:
- `email`: `admin@heritagebank.com`
- `password`: your admin password

Returns:
- `token`
- `user` object

### User login
Same endpoint: `POST /api/auth/login`

---

## 3) Account creation

### A) User self-service registration (recommended)
`POST /api/auth/register`

Typical body (minimum):
- `firstName`, `lastName`, `email`, `password`, `phone`
- `accountType` (e.g. `checking`)
- `initialDeposit` (minimum enforced by backend; commonly $50)

Expected:
- user row created in DB
- initial deposit transaction created

### B) Admin-created user
`POST /api/admin/create-user`

Body:
- `firstName`, `lastName`, `email`, `password`
- optional: `initialBalance`, `accountType`

Expected:
- user row created in DB
- account number generated

---

## 4) Admin money operations

### Credit a user
`POST /api/admin/credit-account`

Body:
- `email` or `accountNumber`
- `amount`
- `reason`
- `notes`

Expected:
- user balance increases
- a transaction is inserted with a useful `description`

### Debit a user
`POST /api/admin/debit-account`

Body:
- `email` or `accountNumber`
- `amount`
- `reason`
- `notes`
- optional: `forceDebit` (if supported)

Expected:
- user balance decreases
- transaction inserted

### Admin transfer between any two users
`POST /api/admin/transfer`

Body:
- Sender: `fromEmail` or `fromAccountNumber`
- Recipient: `toEmail` or `toAccountNumber`
- `amount`
- `description` ✅ (verify it persists into transactions)
- optional: `bypassBalanceCheck`

Expected:
- balances update for both accounts
- `transactions` entry created with type like `admin_transfer`

---

## 5) User transfer

### User → user transfer
`POST /api/user/transfer`

Body:
- `fromUserId`
- recipient: `toEmail` or `toAccountNumber`
- `amount`
- `description` ✅

Expected:
- balances update
- transaction inserted with the provided description

---

## 6) Transactions & receipts

### User transaction history
`GET /api/user/:userId/transactions`

Expected:
- returns the last ~100 transactions involving that user
- each item contains `amount`, `type` (credit/debit), and `description`

### Admin transaction search/list
Depending on server version, these exist:
- `GET /api/transactions` (recent)
- `GET /api/transactions/all` (larger list)
- `GET /api/admin/search-transactions?...`

### Receipt download
`GET /api/transactions/:id/receipt`

- Requires header: `Authorization: Bearer <token>`
- User must be sender or recipient (or admin)

---

## 7) Account status, closure & deletion

### Update account status (Admin)
`PUT /api/admin/account-status/:userId`

Body:
- `status`: `active` | `frozen` | `suspended` | `closed`

Expected:
- status updates in DB
- frozen/suspended/closed users are blocked from certain actions

### Delete user (Admin)
`DELETE /api/admin/users/:id`

Expected:
- user removed (or soft-deleted depending on server)
- related transactions referencing that user may also be removed depending on implementation

### User-initiated deletion (if enabled)
In the full backend server, look for privacy/deletion endpoints like:
- `POST /api/user/privacy/delete-request`
- `POST /api/user/privacy/delete-account`

---

## 8) Quick PowerShell smoke test (copy/paste friendly)

If you want, tell me your Render base URL and I’ll generate a ready-to-run PowerShell script that:
- logs in as admin
- creates two users
- credits one
- performs user transfer + admin transfer
- verifies descriptions show up in user history
- downloads a receipt
- cleans up the test users
