# Heritage Bank - Development Guidelines

## Code Quality Standards

### Formatting & Style
- 4-space indentation in backend JS; 2-space or 4-space in frontend JS (inconsistent, follow the file you're editing)
- `const`/`let` everywhere — no `var` in backend; `var` only appears in `sw.js` (legacy service worker)
- Single-quote strings in backend (`require('...')`); template literals for SQL and messages
- Arrow functions for callbacks and short helpers; `async function` declarations for route handlers and named utilities
- Trailing semicolons throughout

### Naming Conventions
- **Functions**: camelCase (`getUserByEmail`, `initializeSchema`, `requireAdmin`)
- **Variables**: camelCase (`passwordColumn`, `tokenBlacklist`, `dbCfg`)
- **Constants**: camelCase for runtime values, UPPER_SNAKE_CASE for true config constants (`JWT_SECRET`, `ROUTING_NUMBER`, `ADMIN_INITIAL_BALANCE`, `CTR_THRESHOLD`)
- **DB columns**: camelCase in JS objects (`firstName`, `isAdmin`, `createdAt`); camelCase in SQL as well
- **API routes**: kebab-case path segments (`/api/auth/forgot-password`, `/api/admin/users-with-balances`)
- **Frontend globals**: functions exposed to HTML via `window.functionName = functionName`

### Comments & Documentation
- JSDoc-style `/** ... */` block comments on module-level functions in `db.js`
- Inline `//` comments explaining non-obvious decisions (e.g., timing-safe bcrypt, backfill logic, PCI DSS CVV note)
- Section headers using `// ==================== SECTION ====================` delimiters in long files
- Environment variable comments at top of server files documenting supported formats

---

## Structural Conventions

### Backend Route Handlers
All route handlers follow this exact pattern:
```js
app.METHOD('/api/path', middlewares..., async (req, res) => {
    try {
        // ... logic ...
        res.json({ success: true, ... });
    } catch (error) {
        console.error('[TAG] error description:', error);
        res.status(500).json({
            success: false,
            message: 'An internal error occurred. Please try again later.'
        });
    }
});
```
- Every handler is `async` with a `try/catch`
- Error responses always include `{ success: false, message: '...' }`
- Success responses always include `{ success: true, ... }`
- `process.env.NODE_ENV === 'development'` gates returning `error.message` to client

### Middleware Chain (server-old.js / server.js)
```
helmet → rate limiters → CORS → bodyParser → CSRF content-type check → no-cache headers → static files → routes
```
- `requireAuth` / `authenticateToken` extracts Bearer token, verifies JWT, attaches `req.auth` or `req.user`
- `requireAdmin` is a separate middleware that queries DB to confirm `isAdmin`
- Financial endpoints get their own `financialLimiter`; auth endpoints get `authLimiter`

### Database Access Pattern
- Always acquire connection from pool: `const connection = await pool.getConnection()`
- Always release in `finally`: `await connection.release()`
- For multi-step financial operations: use explicit `connection.beginTransaction()` / `connection.commit()` / `connection.rollback()` with row locking (`SELECT ... FOR UPDATE`)
- Parameterized queries only — never string-interpolated SQL for user input
- Use `pool.execute()` for single-use queries (prepared statement), `pool.query()` only when limit is interpolated as a validated integer

### Response Shape
```js
// Success
res.json({ success: true, data/user/token/message: ... });

// Error
res.status(4xx/5xx).json({ success: false, message: 'User-facing message' });
```
- HTTP status codes: 200 (ok), 201 (created), 400 (bad input), 401 (unauth), 403 (forbidden), 404 (not found), 415 (wrong content-type), 429 (rate limited), 500/503 (server error)

---

## Security Patterns

### Authentication
- JWT signed with `JWT_SECRET` (env var), `expiresIn: '7d'` (login) or `'8h'` (default) or `'24h'` (register)
- Token stored in `localStorage` as `'token'` on the frontend
- Authorization header: `Authorization: Bearer <token>`
- In-memory token blacklist (`Set`) for logout; DB-backed `user_session_revocations` for persistence
- Timing-safe: always run `bcrypt.compare` even when user is not found

### Input Validation
- Required field checks before DB queries; return 400 with specific messages
- Email validated with `/^[^\s@]+@[^\s@]+\.[^\s@]+$/`
- Password: min 8 chars, must have upper + lower + digit + special char
- Phone: `/^[\d\s\-\+\(\)]{7,20}$/`
- Free-text inputs sanitized with `sanitizeTextInput(value, maxLength)`
- HTML output escaped with `escapeHtml()` in frontend to prevent XSS

### Anti-Enumeration
- Login, register, and forgot-password use generic messages ("Invalid credentials", "Unable to create account. Please contact support") to prevent user enumeration
- bcrypt is always run on login failure paths to prevent timing attacks

### Financial Operations
- Use DB transactions with row locking for balance updates
- Check sufficient funds before deducting
- Validate amount: `!Number.isFinite(amount) || amount <= 0`
- Transfer restrictions checked before allowing transfers (`transferRestricted` flag)

### Card Security (PCI DSS)
- Card numbers encrypted with AES-256-GCM (`CARD_ENCRYPTION_KEY` env var required in production)
- CVV never stored — shown once at issuance then discarded (`cvv: '***'` stored)
- Card number stored as `cardNumber` (encrypted) + `cardNumberMasked` (display)

---

## Frontend API Call Pattern

All frontend pages use this pattern:
```js
const token = localStorage.getItem('token');
const res = await fetch(`${API_URL}/api/endpoint`, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(payload)
});
const data = await res.json();
if (data.success) {
    // handle success
} else {
    showAlert(data.message || 'Error', 'error');
}
```

- `API_URL` is derived from `window.location.origin` (or `localhost:3001` in dev)
- Auth redirect on 401: `window.location.href = 'signin.html'`
- `showAlert(message, type)` is the standard feedback function (type: `'success'` | `'error'`)
- Functions called from HTML `onclick` are exposed via `window.functionName = functionName`

---

## Service Worker (PWA) Patterns

- API calls (`/api/*`) are **never cached** — network only
- Authenticated pages (dashboard, settings, etc.) are **network first**, fall back to `/404.html`
- Static assets (CSS, JS, public pages) use **stale-while-revalidate**
- Cache versioned with integer (`CACHE_VERSION`) — increment to bust old caches
- Old caches cleaned on `activate` event

---

## Schema Evolution Pattern

For production-safe schema migrations:
```js
// Best-effort column addition — safe to ignore if column already exists
try { await connection.execute('ALTER TABLE users ADD COLUMN newCol TYPE DEFAULT val'); } catch (e) {}
```
- New columns are always added with `try/catch` wrapping to avoid breaking existing deployments
- New tables use `CREATE TABLE IF NOT EXISTS`
- Data backfills run at startup with similar `try/catch` guards

---

## Frequently Used Code Idioms

```js
// Safe float parsing
parseFloat(user.balance) // always wrap DB decimal values

// Null coalescing for optional fields
user.accountNumber || null

// Dynamic SQL column list (createUser)
const columns = ['email', 'firstName'];
const placeholders = columns.map(() => '?').join(', ');
const sql = `INSERT INTO users (${columns.join(', ')}) VALUES (${placeholders})`;

// Sanitize admin transfer type against whitelist
const ADMIN_TRANSFER_TYPES = new Set([...]);
ADMIN_TRANSFER_TYPES.has(t) ? t : 'direct_deposit';

// Environment variable with fallback
const PORT = process.env.PORT || 3000;

// Detect DB connectivity errors for 503 response
function isDbUnavailableError(err) {
    const code = String(err.code || '').toUpperCase();
    return ['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT', ...].includes(code);
}
```

---

## Admin Endpoints Pattern

All admin endpoints:
1. Require `authenticateToken` / `requireAuth` middleware
2. Require `requireAdmin` middleware (checks `isAdmin` in DB)
3. Some also double-check admin inline: `const [admins] = await pool.execute('SELECT * FROM users WHERE id = ? AND isAdmin = true', [req.auth.id])`
4. Return `{ success: true, ... }` or standard error shape
5. Log actions via `logAdminAction()` (server-old.js) for audit trail

## Environment-Dependent Behavior

| Condition | Behavior |
|---|---|
| `NODE_ENV === 'production'` | JWT_SECRET required or process exits; error details hidden from API responses |
| `NODE_ENV !== 'production'` | Ephemeral JWT secret generated; `error.message` returned in responses |
| `DB_SSL=false` | SSL disabled for local/dev databases |
| `ADMIN_PASSWORD` set | Admin user seeded on first boot |
| `SMTP_*` vars set | Transactional email enabled |
| `CARD_ENCRYPTION_KEY` missing in production | Process exits |
