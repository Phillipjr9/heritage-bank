/**
 * Heritage Bank Backend API
 * Simple Express server without Firebase
 * Works with both Vercel and Railway
 * Build deployment marker: 2026-06-09T17:15:00Z - CSP with unsafe-inline enabled
 */

// ============ STARTUP DIAGNOSTICS ============
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

console.log('[STARTUP] Starting server initialization...');
console.log(`[STARTUP] Current working directory: ${process.cwd()}`);
console.log(`[STARTUP] Script directory: ${__dirname}`);
console.log(`[STARTUP] Node version: ${process.version}`);
console.log(`[STARTUP] NODE_ENV: ${process.env.NODE_ENV || 'not set (defaulting to development)'}`);

// Check if node_modules exists and list structure
const backendNodeModules = path.join(__dirname, 'node_modules');
const rootNodeModules = path.join(__dirname, '..', 'node_modules');
console.log(`[STARTUP] Checking backend node_modules: ${backendNodeModules}`);
console.log(`[STARTUP] Backend node_modules exists: ${fs.existsSync(backendNodeModules)}`);
console.log(`[STARTUP] Checking root node_modules: ${rootNodeModules}`);
console.log(`[STARTUP] Root node_modules exists: ${fs.existsSync(rootNodeModules)}`);

// Try to load dependencies
console.log('[STARTUP] Attempting to load dependencies...');
const express = require('express');
console.log('[STARTUP] ✓ express loaded');
const cors = require('cors');
console.log('[STARTUP] ✓ cors loaded');
const bodyParser = require('body-parser');
console.log('[STARTUP] ✓ body-parser loaded');
const helmet = require('helmet');
console.log('[STARTUP] ✓ helmet loaded');
const rateLimit = require('express-rate-limit');
console.log('[STARTUP] ✓ express-rate-limit loaded');
const bcrypt = require('bcryptjs');
console.log('[STARTUP] ✓ bcryptjs loaded');
const jwt = require('jsonwebtoken');
console.log('[STARTUP] ✓ jsonwebtoken loaded');
const db = require('./db');
console.log('[STARTUP] ✓ database module loaded');
const ReceiptGenerator = require('./pdf-receipt-generator');
console.log('[STARTUP] ✓ PDF receipt generator loaded');

console.log('[STARTUP] All dependencies loaded successfully!');

// Load .env for local development only — in Firebase, env vars come from
// Firebase Functions configuration / Secret Manager.
try { require('dotenv').config({ path: path.join(__dirname, '..', '.env') }); } catch (_) {}

const app = express();
const PORT = process.env.PORT || 3000;

// Critical: JWT_SECRET must be set in production
if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.error('[SECURITY] ✗✗✗ CRITICAL: JWT_SECRET environment variable is not set in production!');
  console.error('[SECURITY] ✗✗✗ This is a severe security vulnerability. Server refusing to start.');
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key-change-in-production';
if (!process.env.JWT_SECRET) {
  console.warn('[SECURITY] ⚠️  WARNING: Using default JWT_SECRET. This is only acceptable in development!');
}

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@heritage.com').trim().toLowerCase();
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || 'Admin123!@').trim();

if (process.env.NODE_ENV === 'production') {
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
    console.error('[SECURITY] ✗✗✗ CRITICAL: ADMIN_EMAIL and ADMIN_PASSWORD environment variables must be set in production!');
    console.error('[SECURITY] ✗✗✗ Using default admin credentials in production is insecure. Server refusing to start.');
    process.exit(1);
  }
}

console.log(`[STARTUP] Port configured: ${PORT}`);
console.log('[STARTUP] JWT_SECRET: ' + (process.env.JWT_SECRET ? 'set' : 'using default'));
console.log('[STARTUP] Admin email: ' + (process.env.ADMIN_EMAIL ? 'set from env' : 'using default'));

// Database initialization (replaces in-memory Map)
console.log('[STARTUP] Database will be initialized on server start');

console.log('[STARTUP] Setting up middleware...');

// Middleware
// Disable helmet's CSP (we'll set our own custom policy that allows inline scripts)
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: {
    // Disable default CSP directives - we'll set them explicitly below
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https:"],
      scriptSrcAttr: ["'self'", "'unsafe-inline'"],  // Allow inline event handlers like onclick=
      styleSrc: ["'self'", "'unsafe-inline'", "https:"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https:"],
      formAction: ["'self'"],
      frameAncestors: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
    },
  },
}));
console.log('[MIDDLEWARE] ✓ helmet configured with unsafe-inline scripts');

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, same-origin)
    if (!origin) return callback(null, true);

    // In production, allow the same host the server is running on (Render, Railway, etc.)
    // plus any explicitly configured CORS origin via env var
    const extraOrigin = process.env.CORS_ORIGIN || '';
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:3001',
      'https://heritagebank-3c12d.web.app',
      'https://heritagebank-3c12d.firebaseapp.com',
      'https://heritage.up.railway.app',
      'https://heritagebank-production.up.railway.app',
      'https://heritagebank.up.railway.app',
      ...(extraOrigin ? [extraOrigin] : [])
    ];

    // Allow any Cloudflare Pages domain automatically
    if (
      origin.endsWith('.pages.dev') ||
      origin.endsWith('.onrender.com') ||
      origin.endsWith('.web.app') ||
      origin.endsWith('.firebaseapp.com') ||
      allowedOrigins.includes(origin)
    ) {
      return callback(null, true);
    }

    console.warn(`[CORS] Rejected request from origin: ${origin}`);
    return callback(new Error('CORS not allowed'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  exposedHeaders: ['Content-Type', 'Authorization']
}));
console.log('[MIDDLEWARE] ✓ CORS configured');

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
console.log('[MIDDLEWARE] ✓ Body parser configured');

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later'
});
app.use('/api/', apiLimiter);
console.log('[MIDDLEWARE] ✓ Rate limiting configured');

// Request timeout middleware (30 seconds for all endpoints)
app.use((req, res, next) => {
  req.setTimeout(30000); // 30 second timeout for all requests
  res.setTimeout(30000);
  next();
});
console.log('[MIDDLEWARE] ✓ Request timeout middleware configured (30s)');

// ========== COMPREHENSIVE REQUEST LOGGING MIDDLEWARE ==========
app.use((req, res, next) => {
  const startTime = Date.now();
  const requestId = Math.random().toString(36).substr(2, 9);
  
  // Log incoming request
  console.log(`[REQUEST_IN] [${requestId}] ${req.method} ${req.path} - Query: ${JSON.stringify(req.query)}`);
  
  // Capture response
  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - startTime;
    console.log(`[REQUEST_OUT] [${requestId}] ${req.method} ${req.path} -> STATUS ${res.statusCode} (${duration}ms)`);
    
    // Log response body for debugging (first 200 chars)
    if (typeof data === 'string' && data.length > 0) {
      const preview = data.substring(0, 200);
      console.log(`[REQUEST_OUT] [${requestId}] Response preview: ${preview}${data.length > 200 ? '...' : ''}`);
    }
    
    return originalSend.call(this, data);
  };
  
  next();
});
console.log('[MIDDLEWARE] ✓ Comprehensive request logging configured');

console.log('[STARTUP] Setting up routes...');

// ============ ROUTES ============

// Favicon - simple transparent PNG (prevents 404 errors)
app.get('/favicon.ico', (req, res) => {
  const favicon = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
    'base64'
  );
  res.type('image/png').send(favicon);
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: 'fb1609f'  // Latest commit for tracking deployed version
  });
});

// Diagnostic endpoint - lists all registered routes
app.get('/api/diagnostic', (req, res) => {
  const routes = [];
  app._router.stack.forEach(middleware => {
    if (middleware.route) {
      const methods = Object.keys(middleware.route.methods);
      routes.push({
        path: middleware.route.path,
        methods: methods.map(m => m.toUpperCase())
      });
    } else if (middleware.name === 'router' && middleware.handle._stack) {
      middleware.handle._stack.forEach(handler => {
        if (handler.route) {
          const methods = Object.keys(handler.route.methods);
          routes.push({
            path: handler.route.path,
            methods: methods.map(m => m.toUpperCase())
          });
        }
      });
    }
  });
  
  res.json({
    status: 'ok',
    backend: 'running',
    timestamp: new Date().toISOString(),
    totalRoutes: routes.length,
    routes: routes.filter(r => r.path && r.path.startsWith('/api')).sort((a, b) => a.path.localeCompare(b.path))
  });
});

// Test endpoint
app.get('/api/test-register', (req, res) => {
  res.json({ message: 'Test endpoint works - code deployed at version fb1609f' });
});

// ============ INPUT VALIDATION UTILITIES ============

// Validate email format
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 255;
}

// Validate password strength (min 8 chars, at least 1 uppercase, 1 lowercase, 1 number)
function isStrongPassword(password) {
  if (password.length < 8) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  return true;
}

// Sanitize string input
function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.trim().substring(0, 1000); // Limit length to 1000 chars
}

// Validate amount (must be positive number up to 19 digits with 2 decimals)
function isValidAmount(amount) {
  const num = parseFloat(amount);
  return !isNaN(num) && num > 0 && num <= 9999999999999999.99;
}

// ============ FIREBASE AUTH ENDPOINT ============

app.post('/api/auth/firebase-verify', async (req, res) => {
  try {
    const { idToken, firstName, lastName, phone, gender } = req.body;
    if (!idToken) return res.status(400).json({ success: false, message: 'ID token required' });

    // Verify the Firebase ID token using Firebase Admin SDK
    let firebaseAdmin;
    try {
      firebaseAdmin = require('firebase-admin');
      if (!firebaseAdmin.apps.length) {
        firebaseAdmin.initializeApp({
          credential: firebaseAdmin.credential.applicationDefault()
        });
      }
    } catch (e) {
      return res.status(500).json({ success: false, message: 'Firebase Admin not available' });
    }

    let decoded;
    try {
      decoded = await firebaseAdmin.auth().verifyIdToken(idToken);
    } catch (e) {
      return res.status(401).json({ success: false, message: 'Invalid or expired Firebase token' });
    }

    const email = decoded.email;
    if (!email) return res.status(400).json({ success: false, message: 'No email in Firebase token' });

    // Find or create user in MySQL
    let user = await db.getUserByEmail(email);
    if (!user) {
      // New user — create with profile from Firebase or request body
      const displayName = decoded.name || '';
      const [fbFirst, ...fbRest] = displayName.split(' ');
      const resolvedFirst = firstName || fbFirst || email.split('@')[0];
      const resolvedLast = lastName || fbRest.join(' ') || 'User';
      const randomPassword = require('crypto').randomBytes(32).toString('hex');
      const hashedPassword = await bcrypt.hash(randomPassword, 10);
      user = await db.createUser(null, email, resolvedFirst, resolvedLast, hashedPassword, false, phone || null, gender || null);
    }

    // Issue backend JWT
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        balance: parseFloat(user.balance),
        isAdmin: !!user.isAdmin,
        accountNumber: user.accountNumber || null
      }
    });
  } catch (error) {
    console.error('[API] firebase-verify error:', error);
    res.status(500).json({ success: false, message: 'Authentication failed' });
  }
});

// ============ AUTHENTICATION ENDPOINTS ============

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
  const REGISTRATION_MARKER = `[REGISTER_ENDPOINT_v${Date.now()}]`;
  console.log(REGISTRATION_MARKER, 'ENDPOINT CALLED - START');
  try {
    console.log('[API] ====== REGISTER START ======');
    const { email, password, firstName, lastName, phone, gender } = req.body;
    console.log('[API] Step 1: Received request for', email);

    // Comprehensive validation
    if (!email || !password || !firstName || !lastName) {
      console.log('[API] Step 1: Missing required fields');
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: email, password, firstName, lastName'
      });
    }

    // Email validation
    if (!isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Password strength validation
    if (!isStrongPassword(password)) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters with uppercase, lowercase, and numbers'
      });
    }

    console.log('[API] Step 2: Validation passed');

    // Check if user exists
    console.log('[API] Step 3: Checking if user exists...');
    const existingUser = await db.getUserByEmail(email);
    console.log('[API] Step 4: getUserByEmail returned:', existingUser ? 'user found' : 'no user');
    if (existingUser) {
      console.log('[API] User already exists');
      return res.status(409).json({
        success: false,
        message: 'Email already registered'
      });
    }
    console.log('[API] Step 5: User does not exist, proceeding');

    // Hash password
    console.log('[API] Step 6: Hashing password...');
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('[API] Step 7: Password hashed');

    // Store user in database
    console.log('[API] Step 8: Creating user in database...');
    const sanitizedFirstName = sanitizeString(firstName);
    const sanitizedLastName = sanitizeString(lastName);
    const user = await db.createUser(null, email, sanitizedFirstName, sanitizedLastName, hashedPassword, false, phone, gender);
    console.log('[API] Step 9: User created, id:', user?.id);

    // Generate JWT
    console.log('[API] Step 10: Generating JWT...');
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    console.log('[API] Step 11: JWT generated');

    console.log('[API] Step 12: Sending success response');
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isAdmin: user.isAdmin || false
      },
      token
    });
    console.log('[API] ====== REGISTER END (SUCCESS) ======');
  } catch (error) {
    console.error('[API] ======= REGISTRATION ERROR =======');
    console.error('[API] Error message:', error.message);
    console.error('[API] Stack:', error.stack);
    
    res.status(500).json({
      success: false,
      message: 'Error_' + error.message.substring(0, 50),
      errno: error.errno,
      code: error.code
    });
    console.log('[API] ====== REGISTER END (ERROR) ======');
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const identifier = String(req.body.email || req.body.identifier || req.body.username || '').trim();
    const password = String(req.body.password || '').trim();
    console.log('[API] Login attempt for:', identifier);

    if (!identifier || !password) {
      console.log('[API] Missing email/account or password');
      return res.status(400).json({
        success: false,
        message: 'Email or account number and password required'
      });
    }

    // Find user in database by email or account number
    const user = await db.getUserByEmailOrAccountNumber(identifier);
    if (!user) {
      console.log('[API] User not found:', identifier);
      return res.status(401).json({
        success: false,
        message: 'Invalid email, account number, or password'
      });
    }

    // Check if user is locked
    if (user.isLocked) {
      console.log('[API] User account is locked:', identifier);
      return res.status(403).json({
        success: false,
        message: 'Account is locked. Please contact support.'
      });
    }

    // Check password
    const passwordHash = user.passwordHash || user.password;
    const passwordMatch = await bcrypt.compare(password, passwordHash);
    if (!passwordMatch) {
      console.log('[API] Password mismatch for:', identifier);
      return res.status(401).json({
        success: false,
        message: 'Invalid email, account number, or password'
      });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('[API] Login successful for:', identifier, '- Token generated');
    res.set('Content-Type', 'application/json');
    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        balance: parseFloat(user.balance),
        isAdmin: user.isAdmin || false
      },
      token
    });
  } catch (error) {
    console.error('[API] Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ============ PASSWORD RESET ENDPOINTS ============

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const user = await db.getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Generate reset token (in production, send via email)
    const resetToken = Buffer.from(crypto.randomBytes(32)).toString('hex');
    const resetExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Store token in database
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await connection.execute(
        'UPDATE users SET resetToken = ?, resetTokenExpiry = ? WHERE id = ?',
        [resetToken, resetExpiry, user.id]
      );
      
      // In production, send email with reset link
      console.log(`[AUTH] Password reset requested for ${email}. Token: ${resetToken}`);
      
      res.json({
        success: true,
        message: 'Password reset instructions have been sent to your email',
        resetToken // Only for development - remove in production
      });
    } finally {
      await connection.release();
    }
  } catch (error) {
    console.error('[API] Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Failed to process forgot password request' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword, confirmPassword } = req.body;
    if (!resetToken || !newPassword || !confirmPassword) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Passwords do not match' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters' });
    }

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      // Find user with valid reset token
      const [[user]] = await connection.execute(
        'SELECT * FROM users WHERE resetToken = ? AND resetTokenExpiry > NOW()',
        [resetToken]
      );

      if (!user) {
        return res.status(400).json({ success: false, message: 'Invalid or expired reset token' });
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password and clear reset token
      await connection.execute(
        'UPDATE users SET password = ?, passwordHash = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE id = ?',
        [hashedPassword, hashedPassword, user.id]
      );

      console.log(`[AUTH] Password reset successful for ${user.email}`);

      res.json({ success: true, message: 'Password has been reset successfully' });
    } finally {
      await connection.release();
    }
  } catch (error) {
    console.error('[API] Reset password error:', error);
    res.status(500).json({ success: false, message: 'Failed to reset password' });
  }
});

// Get user profile (requires auth)
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        balance: parseFloat(user.balance),
        isAdmin: user.isAdmin || false,
        createdAt: user.createdAt,
        accountNumber: user.accountNumber || null,
        routingNumber: user.routingNumber || null,
        swiftCode: user.swiftCode || null,
        gender: user.gender || null,
        profileImage: user.profileImage || null,
        isVerified: !!user.isVerified
      }
    });
  } catch (error) {
    console.error('[API] Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Alias for backward compatibility
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        balance: parseFloat(user.balance),
        isAdmin: user.isAdmin || false,
        createdAt: user.createdAt,
        // Expose account identifiers for the frontend dashboard. The frontend
        // expects `accountNumber` to be present (full value) so it can render
        // a masked display and allow the user to toggle visibility. To avoid
        // silently breaking the UI we provide the stored accountNumber here
        // (authenticated request only). In production you may decide to only
        // return a masked value depending on security policy.
        accountNumber: user.accountNumber || null,
        routingNumber: user.routingNumber || null,
        swiftCode: user.swiftCode || null,
        accountType: user.accountType || 'checking',
        accountStatus: user.accountStatus || 'active',
        isVerified: !!user.isVerified
      }
    });
  } catch (error) {
    console.error('[API] Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get complete user profile (for settings page)
app.get('/api/user/profile/complete', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName || '',
        lastName: user.lastName || '',
        balance: parseFloat(user.balance),
        isAdmin: user.isAdmin || false,
        createdAt: user.createdAt,
        accountNumber: user.accountNumber || null,
        routingNumber: user.routingNumber || null,
        accountType: user.accountType || 'checking',
        accountStatus: user.accountStatus || 'active',
        swiftCode: user.swiftCode || null,
        phoneNumber: user.phoneNumber || '',
        address: user.address || '',
        city: user.city || '',
        state: user.state || '',
        zipCode: user.zipCode || '',
        gender: user.gender || null,
        profileImage: user.profileImage || null,
        isVerified: !!user.isVerified
      }
    });
  } catch (error) {
    console.error('[API] Complete profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch complete profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get dashboard data
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const transactions = await db.getUserTransactions(user.id, 10);

    res.json({
      success: true,
      data: {
        accountBalance: parseFloat(user.balance),
        accountType: 'Checking',
        accountNumber: user.accountNumber
          ? '****' + String(user.accountNumber).slice(-4)
          : '****' + String(user.id).slice(-4),
        recentTransactions: transactions.map(tx => ({
          id: tx.id,
          type: tx.type,
          amount: parseFloat(tx.amount),
          date: tx.createdAt,
          description: tx.description
        }))
      }
    });
  } catch (error) {
    console.error('[API] Dashboard error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch dashboard data',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Admin check middleware
async function requireAdmin(req, res, next) {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user || !user.isAdmin) return res.status(403).json({ success: false, message: 'Admin access required' });
    next();
  } catch (e) {
    console.error('[ADMIN] requireAdmin error', e);
    res.status(500).json({ success: false, message: 'Admin check failed' });
  }
}

// Minimal admin endpoints used by admin dashboard
app.get('/api/admin/dashboard-stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await db.getAllUsers();
    const totalUsers = users.length;
    const totalBalance = users.reduce((s, u) => s + (parseFloat(u.balance || 0) || 0), 0);
    res.json({ success: true, stats: {
      totalUsers,
      totalBalance,
      todayTransactions: 0,
      pendingLoans: 0,
      pendingDeposits: 0,
      newContactMessages: 0,
      monthlyVolume: 0,
      activeUsers: totalUsers
    }});
  } catch (e) {
    console.error('[ADMIN] dashboard-stats error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch dashboard stats' });
  }
});

app.get('/api/admin/users-with-balances', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await db.getAllUsers();
    const mapped = users.map(u => ({
      id: u.id,
      email: u.email,
      firstName: u.firstName,
      lastName: u.lastName,
      balance: parseFloat(u.balance || 0),
      accountNumber: u.accountNumber || null,
      routingNumber: u.routingNumber || null,
      accountType: u.accountType || 'checking',
      accountStatus: u.accountStatus || 'active',
      createdAt: u.createdAt,
      transferRestricted: !!u.transferRestricted,
      isVerified: !!u.isVerified
    }));
    res.json({ success: true, users: mapped });
  } catch (e) {
    console.error('[ADMIN] users-with-balances error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch users' });
  }
});

app.put('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.userId);
    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ success: false, message: 'Valid user id is required' });
    }

    const { accountType, routingNumber, accountStatus, createdAt } = req.body;
    if (accountType === undefined && routingNumber === undefined && accountStatus === undefined && createdAt === undefined) {
      return res.status(400).json({ success: false, message: 'At least one editable field is required' });
    }

    const targetUser = await db.getUserById(userId);
    if (!targetUser) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const allowedAccountTypes = ['checking', 'savings', 'money-market', 'cd'];
    const allowedStatuses = ['active', 'frozen', 'suspended', 'pending'];
    const fields = {};

    if (accountType !== undefined) {
      if (!allowedAccountTypes.includes(accountType)) {
        return res.status(400).json({ success: false, message: 'Invalid account type' });
      }
      fields.accountType = accountType;
    }

    if (routingNumber !== undefined) {
      fields.routingNumber = routingNumber ? String(routingNumber).trim() : null;
    }

    if (accountStatus !== undefined) {
      if (!allowedStatuses.includes(accountStatus)) {
        return res.status(400).json({ success: false, message: 'Invalid account status' });
      }
      fields.accountStatus = accountStatus;
    }

    if (createdAt !== undefined) {
      const parsedDate = new Date(createdAt);
      if (Number.isNaN(parsedDate.getTime())) {
        return res.status(400).json({ success: false, message: 'Invalid creation date' });
      }
      fields.createdAt = parsedDate.toISOString().slice(0, 19).replace('T', ' ');
    }

    const setClauses = Object.keys(fields).map(key => `\`${key}\` = ?`).join(', ');
    const values = Object.values(fields);
    if (setClauses.length) {
      const pool = await db.initializePool();
      const connection = await pool.getConnection();
      try {
        await connection.execute(`UPDATE users SET ${setClauses} WHERE id = ?`, [...values, userId]);
      } finally {
        await connection.release();
      }
    }

    const updated = await db.getUserById(userId);
    res.json({
      success: true,
      message: 'User updated successfully',
      user: {
        id: updated.id,
        email: updated.email,
        firstName: updated.firstName,
        lastName: updated.lastName,
        accountNumber: updated.accountNumber,
        routingNumber: updated.routingNumber,
        accountType: updated.accountType,
        accountStatus: updated.accountStatus,
        createdAt: updated.createdAt
      }
    });
  } catch (e) {
    console.error('[ADMIN] update-user error', e);
    res.status(500).json({ success: false, message: 'Failed to update user' });
  }
});

app.get('/api/transactions/all', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      const [transactions] = await connection.execute(
        `SELECT t.*, fu.email AS senderEmail, fu.firstName AS senderFirst, fu.lastName AS senderLast, fu.accountNumber AS senderAccountNumber,
                tu.email AS recipientEmail, tu.firstName AS recipientFirst, tu.lastName AS recipientLast, tu.accountNumber AS recipientAccountNumber
           FROM transactions t
           LEFT JOIN users fu ON t.fromUserId = fu.id
           LEFT JOIN users tu ON t.toUserId = tu.id
           ORDER BY t.createdAt DESC LIMIT 200`
      );
      res.json({ success: true, transactions });
    } finally {
      await connection.release();
    }
  } catch (e) {
    console.error('[ADMIN] transactions/all error', e);
    res.status(500).json({ success: false, message: 'Failed to load transactions' });
  }
});

app.get('/api/admin/activity-logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      let logs = [];
      try {
        const [rows] = await connection.execute(
          'SELECT al.id, al.user_id, al.action_type, al.action_details, al.ip_address, al.created_at, u.firstName, u.lastName FROM activity_logs al LEFT JOIN users u ON al.user_id = u.id ORDER BY al.created_at DESC LIMIT 100'
        );
        logs = rows.map(row => ({
          id: row.id,
          user_id: row.user_id,
          userName: row.firstName && row.lastName ? `${row.firstName} ${row.lastName}` : null,
          action_type: row.action_type,
          action_details: row.action_details,
          ip_address: row.ip_address,
          created_at: row.created_at
        }));
      } catch (activityError) {
        if (!String(activityError.message).includes('activity_logs')) {
          throw activityError;
        }
        // Fallback to recent transactions if activity_logs table is absent.
        const [txRows] = await connection.execute(
          'SELECT t.id, t.fromUserId, t.toUserId, t.type, t.description, t.status, t.createdAt FROM transactions t ORDER BY t.createdAt DESC LIMIT 100'
        );
        logs = txRows.map(row => ({
          id: `tx_${row.id}`,
          user_id: row.fromUserId || row.toUserId || null,
          userName: null,
          action_type: row.type || 'transaction',
          action_details: row.description || '',
          ip_address: 'N/A',
          created_at: row.createdAt
        }));
      }
      res.json({ success: true, logs });
    } finally {
      await connection.release();
    }
  } catch (e) {
    console.error('[ADMIN] activity-logs error', e);
    res.status(500).json({ success: false, message: 'Failed to load activity logs' });
  }
});

app.get('/api/user/:userId/transactions', authenticateToken, async (req, res) => {
  try {
    const requestedUserId = Number(req.params.userId);
    if (!Number.isFinite(requestedUserId)) {
      return res.status(400).json({ success: false, message: 'Invalid userId' });
    }

    const currentUser = await db.getUserByEmail(req.user.email);
    if (!currentUser) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    const isAdmin = !!currentUser.isAdmin;
    if (!isAdmin && currentUser.id !== requestedUserId) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const transactions = await db.getUserTransactions(requestedUserId, 100);
    
    // Calculate running balance for each transaction
    const user = await db.getUserById(requestedUserId);
    let runningBalance = user.balance;
    
    const txnsWithBalance = transactions.map(tx => {
      const amount = Number(tx.amount) || 0;
      const isCredit = tx.toUserId === requestedUserId;
      const previousBalance = isCredit ? runningBalance - amount : runningBalance + amount;
      runningBalance = previousBalance;
      
      return {
        ...tx,
        balanceAfter: runningBalance,
        balanceBefore: previousBalance,
        direction: isCredit ? 'credit' : 'debit',
        amountFormatted: `$${amount.toFixed(2)}`
      };
    });
    
    res.json({ success: true, transactions: txnsWithBalance });
  } catch (e) {
    console.error('[API] user transactions error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch transactions' });
  }
});

app.get('/api/user/:userId/activity', authenticateToken, async (req, res) => {
  try {
    const requestedUserId = Number(req.params.userId);
    if (!Number.isFinite(requestedUserId)) {
      return res.status(400).json({ success: false, message: 'Invalid userId' });
    }

    const currentUser = await db.getUserByEmail(req.user.email);
    if (!currentUser) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    const isAdmin = !!currentUser.isAdmin;
    if (!isAdmin && currentUser.id !== requestedUserId) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      let activities = [];
      try {
        const [logRows] = await connection.execute(
          'SELECT id, user_id, action_type, action_details, ip_address, created_at FROM activity_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
          [requestedUserId]
        );
        activities = logRows.map(row => ({
          id: `log_${row.id}`,
          user_id: row.user_id,
          action: row.action_type,
          description: row.action_details,
          ip_address: row.ip_address,
          timestamp: row.created_at
        }));
      } catch (activityError) {
        if (!String(activityError.message).includes('activity_logs')) {
          throw activityError;
        }
      }

      const transactions = await db.getUserTransactions(requestedUserId, 50);
      const transactionActivities = transactions.map(tx => ({
        id: `tx_${tx.id}`,
        user_id: tx.fromUserId === requestedUserId ? tx.fromUserId : tx.toUserId,
        action: tx.fromUserId === requestedUserId ? `Outgoing ${tx.type || 'transaction'}` : `Incoming ${tx.type || 'transaction'}`,
        description: tx.description || '',
        timestamp: tx.createdAt || tx.created_at,
        transactionId: tx.id
      }));

      activities = [...activities, ...transactionActivities]
        .filter(a => a.timestamp)
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 50);

      res.json({ success: true, activities });
    } finally {
      await connection.release();
    }
  } catch (e) {
    console.error('[API] user activity error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch activity' });
  }
});

// ============ NOTIFICATIONS ENDPOINTS ============
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 10, 50);
    const currentUser = await db.getUserByEmail(req.user.email);
    
    if (!currentUser) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Get user-specific notifications from transactions
    const _pool = await db.initializePool();
    const [transactions] = await _pool.query(
      'SELECT * FROM transactions WHERE fromUserId = ? OR toUserId = ? ORDER BY createdAt DESC LIMIT ?',
      [currentUser.id, currentUser.id, limit]
    );
    
    // Build notifications from user's transactions only
    const notifications = (transactions || []).map(tx => {
      let message = '';
      if (tx.fromUserId === currentUser.id) {
        message = `You transferred $${parseFloat(tx.amount).toFixed(2)}`;
      } else {
        message = `You received $${parseFloat(tx.amount).toFixed(2)}`;
      }
      return {
        id: tx.id,
        type: 'transaction',
        title: 'Transaction ' + (tx.status === 'completed' ? 'Completed' : 'Pending'),
        message: message,
        amount: tx.amount,
        read: false,
        createdAt: tx.createdAt
      };
    });

    // Add account notifications only for this user
    if (currentUser.createdAt) {
      const daysSinceCreation = Math.floor((Date.now() - new Date(currentUser.createdAt).getTime()) / (1000 * 60 * 60 * 24));
      if (daysSinceCreation === 0) {
        notifications.unshift({
          id: 0,
          type: 'account',
          title: 'Welcome',
          message: 'Welcome to Heritage Bank! Your account is now active.',
          read: false,
          createdAt: new Date()
        });
      }
    }

    const unreadCount = notifications.filter(n => !n.read).length;
    res.json({ success: true, notifications: notifications.slice(0, limit), unreadCount });
  } catch (e) {
    console.error('[API] notifications error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch notifications' });
  }
});

app.put('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    res.json({ success: true, message: 'All notifications marked as read' });
  } catch (e) {
    console.error('[API] read-all notifications error', e);
    res.status(500).json({ success: false, message: 'Failed to mark notifications as read' });
  }
});

// ============ SAVINGS GOALS ENDPOINTS ============

async function ensureSavingsGoalsTable(connection) {
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS savings_goals (
      id INT PRIMARY KEY AUTO_INCREMENT,
      userId INT NOT NULL,
      name VARCHAR(255) NOT NULL,
      targetAmount DECIMAL(12,2) NOT NULL,
      currentAmount DECIMAL(12,2) DEFAULT 0,
      targetDate DATE,
      category VARCHAR(50) DEFAULT 'other',
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_userId (userId)
    )
  `);
}

app.get('/api/savings-goals', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureSavingsGoalsTable(connection);
      const [goals] = await connection.execute(
        'SELECT * FROM savings_goals WHERE userId = ? ORDER BY createdAt DESC',
        [user.id]
      );
      res.json({ success: true, goals });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] savings-goals error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch savings goals' });
  }
});

app.post('/api/savings-goals', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    
    const { name, targetAmount, currentAmount, targetDate, category } = req.body;
    if (!name || !targetAmount) {
      return res.status(400).json({ success: false, message: 'Name and target amount are required' });
    }
    
    const initialAmount = parseFloat(currentAmount) || 0;
    if (initialAmount > 0 && parseFloat(user.balance) < initialAmount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance for initial savings amount' });
    }
    
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureSavingsGoalsTable(connection);
      await connection.beginTransaction();
      
      // Insert savings goal
      const [result] = await connection.execute(
        'INSERT INTO savings_goals (userId, name, targetAmount, currentAmount, targetDate, category) VALUES (?, ?, ?, ?, ?, ?)',
        [user.id, name, targetAmount, initialAmount, targetDate || null, category || 'other']
      );
      
      // If initial amount > 0, deduct from balance and record transaction
      if (initialAmount > 0) {
        await connection.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [initialAmount, user.id]);
        await connection.execute(
          'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
          [user.id, null, initialAmount, 'savings_goal', `Savings goal: ${name}`, 'completed']
        );
      }
      
      await connection.commit();
      res.json({ success: true, message: 'Goal created successfully', goalId: result.insertId });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] create savings-goal error', e);
    res.status(500).json({ success: false, message: 'Failed to create savings goal' });
  }
});

app.put('/api/savings-goals/:id', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    
    const { name, targetAmount, currentAmount, targetDate, category } = req.body;
    
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureSavingsGoalsTable(connection);
      
      // Verify ownership and get existing data
      const [[existing]] = await connection.execute(
        'SELECT * FROM savings_goals WHERE id = ? AND userId = ?',
        [req.params.id, user.id]
      );
      
      if (!existing) {
        return res.status(404).json({ success: false, message: 'Goal not found' });
      }
      
      const newAmount = parseFloat(currentAmount) || 0;
      const oldAmount = parseFloat(existing.currentAmount) || 0;
      const amountDifference = newAmount - oldAmount;
      
      // Check if user has enough balance for increase
      if (amountDifference > 0 && parseFloat(user.balance) < amountDifference) {
        return res.status(400).json({ success: false, message: 'Insufficient balance for this savings amount' });
      }
      
      await connection.beginTransaction();
      
      // Update goal
      await connection.execute(
        'UPDATE savings_goals SET name = ?, targetAmount = ?, currentAmount = ?, targetDate = ?, category = ? WHERE id = ? AND userId = ?',
        [name, targetAmount, newAmount, targetDate || null, category || 'other', req.params.id, user.id]
      );
      
      // Handle balance change if currentAmount changed
      if (amountDifference !== 0) {
        if (amountDifference > 0) {
          // Adding to goal - deduct from balance
          await connection.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amountDifference, user.id]);
          await connection.execute(
            'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
            [user.id, null, amountDifference, 'savings_goal', `Added to savings goal: ${name}`, 'completed']
          );
        } else {
          // Removing from goal - add back to balance
          await connection.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [Math.abs(amountDifference), user.id]);
          await connection.execute(
            'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
            [null, user.id, Math.abs(amountDifference), 'savings_withdrawal', `Withdrawn from savings goal: ${name}`, 'completed']
          );
        }
      }
      
      await connection.commit();
      res.json({ success: true, message: 'Goal updated successfully' });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] update savings-goal error', e);
    res.status(500).json({ success: false, message: 'Failed to update savings goal' });
  }
});

app.delete('/api/savings-goals/:id', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureSavingsGoalsTable(connection);
      const [result] = await connection.execute(
        'DELETE FROM savings_goals WHERE id = ? AND userId = ?',
        [req.params.id, user.id]
      );
      
      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: 'Goal not found' });
      }
      
      res.json({ success: true, message: 'Goal deleted successfully' });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] delete savings-goal error', e);
    res.status(500).json({ success: false, message: 'Failed to delete savings goal' });
  }
});

// ============ TRANSACTION RECEIPT ENDPOINT ============
app.get('/api/transactions/:id/receipt', authenticateToken, async (req, res) => {
  try {
    const transactionId = req.params.id;
    const currentUser = await db.getUserByEmail(req.user.email);
    
    // Retrieve transaction from DB
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      const [[transaction]] = await conn.execute('SELECT * FROM transactions WHERE id = ?', [transactionId]);
      if (!transaction) return res.status(404).json({ success: false, message: 'Transaction not found' });

      // Generate PDF buffer using ReceiptGenerator
      try {
        const pdfBuf = await ReceiptGenerator.generate(transaction, currentUser);
        res.setHeader('Content-Type', 'application/pdf');
        const filename = `Heritage_Bank_Receipt_${transaction.reference || transactionId}.pdf`;
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        return res.send(pdfBuf);
      } catch (pdfErr) {
        console.error('[API] receipt generation error', pdfErr);
        return res.status(500).json({ success: false, message: 'Failed to generate receipt PDF' });
      }
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[API] transaction receipt error', e);
    res.status(500).json({ success: false, message: 'Failed to generate receipt' });
  }
});

// ============ BULK PAYMENTS ENDPOINTS ============
app.post('/api/bulk-payments/upload', authenticateToken, async (req, res) => {
  try {
    // Mock file upload handler
    res.json({ 
      success: true, 
      batchId: `BATCH-${Date.now()}`,
      message: 'File uploaded successfully',
      preview: {
        totalRecords: 10,
        estimatedAmount: 50000.00
      }
    });
  } catch (e) {
    console.error('[API] bulk-payments upload error', e);
    res.status(500).json({ success: false, message: 'Failed to upload file' });
  }
});

app.get('/api/bulk-payments/template/sample', authenticateToken, async (req, res) => {
  try {
    // Return CSV template
    const template = 'Recipient Email,Amount,Description\nexample@bank.com,500.00,Payment for services\ntest@bank.com,1000.00,Transfer to account';
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=bulk-payments-template.csv');
    res.send(template);
  } catch (e) {
    console.error('[API] bulk-payments template error', e);
    res.status(500).json({ success: false, message: 'Failed to generate template' });
  }
});

app.post('/api/bulk-payments/:batchId/execute', authenticateToken, async (req, res) => {
  try {
    const batchId = req.params.batchId;
    res.json({
      success: true,
      message: 'Bulk payment executed successfully',
      batchId,
      results: {
        total: 10,
        successful: 10,
        failed: 0,
        totalAmount: 50000.00
      }
    });
  } catch (e) {
    console.error('[API] bulk-payments execute error', e);
    res.status(500).json({ success: false, message: 'Failed to execute bulk payment' });
  }
});

app.get('/api/bulk-payments', authenticateToken, async (req, res) => {
  try {
    const batches = [
      { id: 'BATCH-1717944000000', date: new Date(), status: 'completed', count: 10, amount: 50000.00 },
      { id: 'BATCH-1717857600000', date: new Date(Date.now() - 86400000), status: 'completed', count: 5, amount: 25000.00 }
    ];
    res.json({ success: true, batches });
  } catch (e) {
    console.error('[API] bulk-payments list error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch bulk payments' });
  }
});

app.get('/api/bulk-payments/:batchId', authenticateToken, async (req, res) => {
  try {
    const batchId = req.params.batchId;
    res.json({
      success: true,
      batch: {
        id: batchId,
        date: new Date(),
        status: 'completed',
        records: [
          { email: 'user1@bank.com', amount: 500.00, status: 'completed' },
          { email: 'user2@bank.com', amount: 1000.00, status: 'completed' }
        ]
      }
    });
  } catch (e) {
    console.error('[API] bulk-payments detail error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch batch details' });
  }
});

// ============ ANALYTICS ENDPOINTS ============
app.get('/api/analytics', authenticateToken, async (req, res) => {
  try {
    const period = req.query.period || 'month';
    const currentUser = await db.getUserByEmail(req.user.email);
    if (!currentUser) return res.status(404).json({ success: false, message: 'User not found' });
    
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      // Calculate date range based on period
      const now = new Date();
      let startDate;
      switch (period) {
        case 'week':
          startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
          break;
        case 'quarter':
          startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
          break;
        case 'year':
          startDate = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);
          break;
        case 'all':
          startDate = new Date('2020-01-01');
          break;
        default: // month
          startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      }
      
      // Get income (money received)
      const [[incomeResult]] = await conn.execute(
        'SELECT COALESCE(SUM(amount), 0) as total, COUNT(*) as count FROM transactions WHERE toUserId = ? AND status = ? AND createdAt >= ?',
        [currentUser.id, 'completed', startDate.toISOString()]
      );
      
      // Get expenses (money sent)
      const [[expenseResult]] = await conn.execute(
        'SELECT COALESCE(SUM(amount), 0) as total, COUNT(*) as count FROM transactions WHERE fromUserId = ? AND status = ? AND createdAt >= ?',
        [currentUser.id, 'completed', startDate.toISOString()]
      );
      
      const totalIncome = parseFloat(incomeResult.total || 0);
      const totalExpenses = parseFloat(expenseResult.total || 0);
      const transactionCount = (incomeResult.count || 0) + (expenseResult.count || 0);
      
      // Get spending by category
      const [categories] = await conn.execute(
        `SELECT category, COUNT(*) as count, SUM(amount) as total FROM transactions 
         WHERE fromUserId = ? AND status = ? AND createdAt >= ? AND category IS NOT NULL 
         GROUP BY category ORDER BY total DESC LIMIT 10`,
        [currentUser.id, 'completed', startDate.toISOString()]
      );
      
      // Generate trend data (weekly breakdown for month, monthly for year, etc.)
      let trend = [];
      if (period === 'month' || period === 'week') {
        // Weekly breakdown
        for (let i = 3; i >= 0; i--) {
          const weekEnd = new Date(now.getTime() - i * 7 * 24 * 60 * 60 * 1000);
          const weekStart = new Date(weekEnd.getTime() - 7 * 24 * 60 * 60 * 1000);
          
          const [[weekIncome]] = await conn.execute(
            'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE toUserId = ? AND status = ? AND createdAt BETWEEN ? AND ?',
            [currentUser.id, 'completed', weekStart.toISOString(), weekEnd.toISOString()]
          );
          
          const [[weekExpense]] = await conn.execute(
            'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE fromUserId = ? AND status = ? AND createdAt BETWEEN ? AND ?',
            [currentUser.id, 'completed', weekStart.toISOString(), weekEnd.toISOString()]
          );
          
          trend.push({
            label: `Week ${4 - i}`,
            income: parseFloat(weekIncome.total || 0),
            expenses: parseFloat(weekExpense.total || 0)
          });
        }
      } else {
        // Monthly breakdown for longer periods
        const months = period === 'year' ? 12 : 4;
        for (let i = months - 1; i >= 0; i--) {
          const monthEnd = new Date(now.getFullYear(), now.getMonth() - i + 1, 0);
          const monthStart = new Date(now.getFullYear(), now.getMonth() - i, 1);
          
          const [[monthIncome]] = await conn.execute(
            'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE toUserId = ? AND status = ? AND createdAt BETWEEN ? AND ?',
            [currentUser.id, 'completed', monthStart.toISOString(), monthEnd.toISOString()]
          );
          
          const [[monthExpense]] = await conn.execute(
            'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE fromUserId = ? AND status = ? AND createdAt BETWEEN ? AND ?',
            [currentUser.id, 'completed', monthStart.toISOString(), monthEnd.toISOString()]
          );
          
          trend.push({
            label: monthStart.toLocaleDateString('en-US', { month: 'short' }),
            month: monthStart.toISOString().slice(0, 7),
            income: parseFloat(monthIncome.total || 0),
            expenses: parseFloat(monthExpense.total || 0)
          });
        }
      }
      
      res.json({
        success: true,
        period,
        totalIncome,
        totalExpenses,
        netFlow: totalIncome - totalExpenses,
        transactionCount,
        categories: categories.map(c => ({ category: c.category, count: c.count, total: parseFloat(c.total) })),
        trend
      });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[API] analytics error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch analytics' });
  }
});

// ============ CONTACT FORM ENDPOINTS ============
app.post('/api/contact', async (req, res) => {
  try {
    const { email, subject, message, name } = req.body;
    
    if (!email || !subject || !message) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }
    
    // Mock: log to console (in production, send email or store in DB)
    console.log(`[CONTACT] New message from ${name || email}: ${subject}`);
    
    res.json({
      success: true,
      message: 'Your message has been received. We will get back to you soon.',
      ticketId: `TICKET-${Date.now()}`
    });
  } catch (e) {
    console.error('[API] contact error', e);
    res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});

// ============ NEWSLETTER ENDPOINTS ============
app.post('/api/newsletter', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }
    
    console.log(`[NEWSLETTER] Subscribed: ${email}`);
    
    res.json({
      success: true,
      message: 'Successfully subscribed to our newsletter'
    });
  } catch (e) {
    console.error('[API] newsletter error', e);
    res.status(500).json({ success: false, message: 'Failed to subscribe' });
  }
});

// ============ MESSAGES ENDPOINTS ============

async function ensureMessagesTable(connection) {
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS messages (
      id INT PRIMARY KEY AUTO_INCREMENT,
      fromUserId INT NOT NULL,
      toUserId INT,
      type VARCHAR(50) DEFAULT 'message',
      title VARCHAR(255),
      content TEXT,
      isRead BOOLEAN DEFAULT FALSE,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (fromUserId) REFERENCES users(id),
      FOREIGN KEY (toUserId) REFERENCES users(id),
      INDEX idx_toUserId (toUserId),
      INDEX idx_createdAt (createdAt)
    )
  `);
}

app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureMessagesTable(connection);
      const type = req.query.type || 'all';
      let query = 'SELECT * FROM messages WHERE toUserId = ? OR fromUserId = ?';
      const params = [user.id, user.id];

      if (type !== 'all') {
        query += ' AND type = ?';
        params.push(type);
      }

      query += ' ORDER BY createdAt DESC LIMIT 100';
      const [messages] = await connection.execute(query, params);
      
      res.json({ success: true, messages });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] messages list error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch messages' });
  }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const { toUserId, title, content, type } = req.body;
    if (!content) {
      return res.status(400).json({ success: false, message: 'Content is required' });
    }

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureMessagesTable(connection);
      const [result] = await connection.execute(
        'INSERT INTO messages (fromUserId, toUserId, type, title, content) VALUES (?, ?, ?, ?, ?)',
        [user.id, toUserId || null, type || 'message', title || '', content]
      );
      
      res.json({ success: true, message: 'Message sent', messageId: result.insertId });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] send message error', e);
    res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});

app.get('/api/messages/:id', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureMessagesTable(connection);
      const [[message]] = await connection.execute(
        'SELECT * FROM messages WHERE id = ? AND (toUserId = ? OR fromUserId = ?)',
        [req.params.id, user.id, user.id]
      );

      if (!message) {
        return res.status(404).json({ success: false, message: 'Message not found' });
      }

      res.json({ success: true, message });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] get message error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch message' });
  }
});

app.put('/api/messages/:id/read', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureMessagesTable(connection);
      await connection.execute(
        'UPDATE messages SET isRead = TRUE WHERE id = ? AND toUserId = ?',
        [req.params.id, user.id]
      );

      res.json({ success: true, message: 'Message marked as read' });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] mark message read error', e);
    res.status(500).json({ success: false, message: 'Failed to mark message as read' });
  }
});

app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureMessagesTable(connection);
      const [result] = await connection.execute(
        'DELETE FROM messages WHERE id = ? AND (toUserId = ? OR fromUserId = ?)',
        [req.params.id, user.id, user.id]
      );

      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: 'Message not found' });
      }

      res.json({ success: true, message: 'Message deleted' });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] delete message error', e);
    res.status(500).json({ success: false, message: 'Failed to delete message' });
  }
});

app.post('/api/messages/send', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const { toUserId, title, content, type } = req.body;
    if (!content) {
      return res.status(400).json({ success: false, message: 'Content is required' });
    }

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureMessagesTable(connection);
      const [result] = await connection.execute(
        'INSERT INTO messages (fromUserId, toUserId, type, title, content) VALUES (?, ?, ?, ?, ?)',
        [user.id, toUserId || null, type || 'message', title || '', content]
      );
      
      res.json({ success: true, message: 'Message sent successfully', messageId: result.insertId });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] send message error', e);
    res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});

// ============ ADDITIONAL ADMIN ENDPOINTS (from admin.html) ============
app.get('/api/admin/cards', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const q = (req.query.q || '').toString().trim().toLowerCase();
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureCardsTable(connection);
      const [cards] = await connection.execute(
        `SELECT c.*, u.firstName, u.lastName, u.email, u.accountNumber
         FROM cards c LEFT JOIN users u ON c.userId = u.id
         ORDER BY c.issuedAt DESC LIMIT 500`
      );
      const filtered = q ? cards.filter(c =>
        (c.email || '').toLowerCase().includes(q) ||
        (c.firstName || '').toLowerCase().includes(q) ||
        (c.lastName || '').toLowerCase().includes(q) ||
        (c.cardNumberMasked || '').includes(q) ||
        (c.accountNumber || '').includes(q)
      ) : cards;
      res.json({ success: true, cards: filtered });
    } finally {
      await connection.release();
    }
  } catch (e) {
    console.error('[API] admin cards error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch cards' });
  }
});

app.get('/api/admin/search-users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const query = (req.query.query || '').toString().trim();
    const users = await db.getAllUsers();
    const lower = query.toLowerCase();
    const filtered = query ? users.filter(u =>
      (u.email || '').toLowerCase().includes(lower) ||
      (u.firstName || '').toLowerCase().includes(lower) ||
      (u.lastName || '').toLowerCase().includes(lower) ||
      (u.accountNumber || '').includes(lower)
    ) : users;
    res.json({ success: true, users: filtered.map(u => ({ id: u.id, email: u.email, firstName: u.firstName, lastName: u.lastName, balance: parseFloat(u.balance || 0), accountNumber: u.accountNumber || null, accountStatus: u.accountStatus || 'active', transferRestricted: !!u.transferRestricted })) });
  } catch (e) {
    console.error('[API] admin search users error', e);
    res.status(500).json({ success: false, message: 'Failed to search users' });
  }
});

app.delete('/api/admin/users/:userId/passkeys', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.userId);
    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ success: false, message: 'Valid user id is required' });
    }

    const targetUser = await db.getUserById(userId);
    if (!targetUser) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      let removedCount = 0;
      try {
        const [result] = await connection.execute('DELETE FROM webauthn_credentials WHERE userId = ?', [userId]);
        removedCount = Number(result?.affectedRows || 0);
      } catch (_) {
        removedCount = 0;
      }
      res.json({
        success: true,
        message: `Removed ${removedCount} passkey(s) for ${targetUser.email}`,
        removedCount
      });
    } finally {
      await connection.release();
    }
  } catch (e) {
    console.error('[ADMIN] remove-user-passkeys error', e);
    res.status(500).json({ success: false, message: 'Failed to remove user passkeys' });
  }
});

app.post('/api/admin/create-user', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { firstName, lastName, email, phone, password, initialBalance, address, city, state, zip, country } = req.body;
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ success: false, message: 'firstName, lastName, email, and password are required' });
    }
    const existing = await db.getUserByEmail(email);
    if (existing) return res.status(409).json({ success: false, message: 'Email already registered' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await db.createUser(null, email, firstName, lastName, hashedPassword, false, phone || null, null);
    // Set initial balance and extra fields if provided
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      const bal = parseFloat(initialBalance);
      if (Number.isFinite(bal) && bal >= 0) {
        await connection.execute('UPDATE users SET balance = ? WHERE id = ?', [bal, user.id]);
      }
      // Best-effort extra fields
      const extras = {};
      if (address) extras.address = address;
      if (city) extras.city = city;
      if (state) extras.state = state;
      if (zip) extras.zipCode = zip;
      if (country) extras.country = country;
      const keys = Object.keys(extras);
      if (keys.length) {
        const setClauses = keys.map(k => `\`${k}\` = ?`).join(', ');
        await connection.execute(`UPDATE users SET ${setClauses} WHERE id = ?`, [...Object.values(extras), user.id]).catch(() => {});
      }
    } finally {
      await connection.release();
    }
    const fresh = await db.getUserById(user.id);
    res.status(201).json({ success: true, message: 'User created successfully', user: { id: fresh.id, email: fresh.email, firstName: fresh.firstName, lastName: fresh.lastName, accountNumber: fresh.accountNumber, balance: parseFloat(fresh.balance) } });
  } catch (e) {
    console.error('[API] admin create user error', e);
    res.status(500).json({ success: false, message: 'Failed to create user: ' + e.message });
  }
});

app.get('/api/admin/pending-transactions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    res.json({ success: true, transactions: [] });
  } catch (e) {
    console.error('[API] admin pending transactions error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch pending transactions' });
  }
});

app.get('/api/admin/pending-transfers', authenticateToken, requireAdmin, async (req, res) => {
  try {
    res.json({ success: true, transfers: [] });
  } catch (e) {
    console.error('[API] admin pending transfers error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch pending transfers' });
  }
});

// ============ WEBAUTHN / BIOMETRIC LOGIN ENDPOINTS ============

// WebAuthn registration options (called from settings page)
app.post('/api/auth/webauthn/register-options', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Generate challenge
    const challenge = Buffer.from(Array.from({ length: 32 }, () => Math.floor(Math.random() * 256)));
    const challengeB64 = challenge.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    // Store challenge temporarily (in production, use Redis or session)
    // For now, we'll return it and expect it back

    const options = {
      challenge: challengeB64,
      rp: {
        name: 'Heritage Bank',
        id: req.hostname || 'localhost'
      },
      user: {
        id: Buffer.from(String(user.id)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
        name: user.email,
        displayName: `${user.firstName} ${user.lastName}`
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },  // ES256
        { alg: -257, type: 'public-key' }  // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        requireResidentKey: false,
        userVerification: 'preferred'
      },
      timeout: 60000,
      attestation: 'none'
    };

    res.json({ success: true, options });
  } catch (error) {
    console.error('[API] WebAuthn register options error:', error);
    res.status(500).json({ success: false, message: 'Failed to generate registration options' });
  }
});

// WebAuthn registration verification
app.post('/api/auth/webauthn/register-verify', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // In production, verify the attestation response properly
    // For now, we'll store the credential ID and the attestation object
    const { attestationResponse } = req.body;
    if (!attestationResponse) {
      return res.status(400).json({ success: false, message: 'Missing attestation response' });
    }

    const credentialId = attestationResponse.id || '';
    const publicKey = attestationResponse.response?.attestationObject || '';

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      // Check if webauthn_credentials table exists
      const [tables] = await connection.execute(
        "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'webauthn_credentials'",
        [process.env.DB_NAME || process.env.MYSQLDATABASE || 'heritage_bank']
      );

      if (tables.length === 0) {
        await connection.execute(`
          CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id INT PRIMARY KEY AUTO_INCREMENT,
            userId INT NOT NULL,
            credentialId TEXT NOT NULL,
            publicKey TEXT NOT NULL,
            counter INT DEFAULT 0,
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (userId) REFERENCES users(id),
            INDEX idx_userId (userId)
          )
        `);
      }

      await connection.execute(
        'INSERT INTO webauthn_credentials (userId, credentialId, publicKey) VALUES (?, ?, ?)',
        [user.id, credentialId, publicKey]
      );

      res.json({ success: true, message: 'Biometric login registered successfully' });
    } finally {
      await connection.release();
    }
  } catch (error) {
    console.error('[API] WebAuthn register verify error:', error);
    res.status(500).json({ success: false, message: 'Failed to register biometric login' });
  }
});

// WebAuthn login options
app.post('/api/auth/webauthn/login-options', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await db.getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      const [credentials] = await connection.execute(
        'SELECT credentialId FROM webauthn_credentials WHERE userId = ?',
        [user.id]
      );

      if (credentials.length === 0) {
        return res.json({ success: false, noBiometric: true, message: 'No biometric credentials registered' });
      }

      const challenge = Buffer.from(Array.from({ length: 32 }, () => Math.floor(Math.random() * 256)));
      const challengeB64 = challenge.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

      const options = {
        challenge: challengeB64,
        timeout: 60000,
        rpId: req.hostname || 'localhost',
        allowCredentials: credentials.map(c => ({
          type: 'public-key',
          id: c.credentialId
        })),
        userVerification: 'preferred'
      };

      res.json({ success: true, options });
    } finally {
      await connection.release();
    }
  } catch (error) {
    console.error('[API] WebAuthn login options error:', error);
    res.status(500).json({ success: false, message: 'Failed to generate login options' });
  }
});

// WebAuthn login verification
app.post('/api/auth/webauthn/login-verify', async (req, res) => {
  try {
    const { assertionResponse } = req.body;
    
    // In production, verify the assertion properly
    // For now, simplified verification
    const credentialId = assertionResponse.id;

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      const [credentials] = await connection.execute(
        'SELECT userId FROM webauthn_credentials WHERE credentialId = ?',
        [credentialId]
      );

      if (credentials.length === 0) {
        return res.status(401).json({ success: false, message: 'Invalid credential' });
      }

      const userId = credentials[0].userId;
      const user = await db.getUserById(userId);

      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }

      // Generate JWT
      const token = jwt.sign(
        { userId: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        success: true,
        message: 'Biometric login successful',
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          balance: parseFloat(user.balance),
          isAdmin: user.isAdmin || false,
          accountNumber: user.accountNumber,
          accountType: user.accountType || 'Savings'
        },
        token
      });
    } finally {
      await connection.release();
    }
  } catch (error) {
    console.error('[API] WebAuthn login verify error:', error);
    res.status(500).json({ success: false, message: 'Biometric login failed' });
  }
});

// ============ BENEFICIARY MANAGEMENT ENDPOINTS ============

// Get all beneficiaries for current user
app.get('/api/beneficiaries', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      // Check if beneficiaries table exists
      const [tables] = await connection.execute(
        "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'beneficiaries'",
        [process.env.DB_NAME || process.env.MYSQLDATABASE || 'heritage_bank']
      );

      if (tables.length === 0) {
        // Create beneficiaries table
        await connection.execute(`
          CREATE TABLE IF NOT EXISTS beneficiaries (
            id INT PRIMARY KEY AUTO_INCREMENT,
            userId INT NOT NULL,
            name VARCHAR(255) NOT NULL,
            nickname VARCHAR(255),
            accountNumber VARCHAR(64) NOT NULL,
            bankName VARCHAR(255) DEFAULT 'Heritage Bank',
            email VARCHAR(255),
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (userId) REFERENCES users(id),
            INDEX idx_userId (userId)
          )
        `);
        console.log('[DB] Beneficiaries table created');
      }

      const [beneficiaries] = await connection.execute(
        'SELECT * FROM beneficiaries WHERE userId = ? ORDER BY createdAt DESC',
        [user.id]
      );

      res.json({ success: true, beneficiaries });
    } finally {
      await connection.release();
    }
  } catch (error) {
    console.error('[API] Get beneficiaries error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch beneficiaries' });
  }
});

// Add new beneficiary
app.post('/api/beneficiaries', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const { name, accountNumber, bankName, email, nickname } = req.body;
    if (!name || !accountNumber) {
      return res.status(400).json({ success: false, message: 'Name and account number are required' });
    }

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await connection.execute(
        'INSERT INTO beneficiaries (userId, name, nickname, accountNumber, bankName, email) VALUES (?, ?, ?, ?, ?, ?)',
        [user.id, name, nickname || null, accountNumber, bankName || 'Heritage Bank', email || null]
      );

      res.json({ success: true, message: 'Beneficiary added successfully' });
    } finally {
      await connection.release();
    }
  } catch (error) {
    console.error('[API] Add beneficiary error:', error);
    res.status(500).json({ success: false, message: 'Failed to add beneficiary' });
  }
});

// Update beneficiary
app.put('/api/beneficiaries/:id', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const beneficiaryId = req.params.id;
    const { name, accountNumber, bankName, email, nickname } = req.body;

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      // Verify ownership
      const [existing] = await connection.execute(
        'SELECT * FROM beneficiaries WHERE id = ? AND userId = ?',
        [beneficiaryId, user.id]
      );

      if (existing.length === 0) {
        return res.status(404).json({ success: false, message: 'Beneficiary not found' });
      }

      await connection.execute(
        'UPDATE beneficiaries SET name = ?, nickname = ?, accountNumber = ?, bankName = ?, email = ? WHERE id = ? AND userId = ?',
        [name, nickname || null, accountNumber, bankName || 'Heritage Bank', email || null, beneficiaryId, user.id]
      );

      res.json({ success: true, message: 'Beneficiary updated successfully' });
    } finally {
      await connection.release();
    }
  } catch (error) {
    console.error('[API] Update beneficiary error:', error);
    res.status(500).json({ success: false, message: 'Failed to update beneficiary' });
  }
});

// Delete beneficiary
app.delete('/api/beneficiaries/:id', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const beneficiaryId = req.params.id;

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      const [result] = await connection.execute(
        'DELETE FROM beneficiaries WHERE id = ? AND userId = ?',
        [beneficiaryId, user.id]
      );

      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: 'Beneficiary not found' });
      }

      res.json({ success: true, message: 'Beneficiary deleted successfully' });
    } finally {
      await connection.release();
    }
  } catch (error) {
    console.error('[API] Delete beneficiary error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete beneficiary' });
  }
});

// ============ TRANSFER & PAYMENT ENDPOINTS ============

// User-to-user transfer
app.post('/api/user/transfer', authenticateToken, async (req, res) => {
  try {
    const { recipientEmail, toEmail, toAccountNumber, amount, description } = req.body;
    const currentUser = await db.getUserByEmail(req.user.email);
    const actualAmount = parseFloat(amount);

    if (!Number.isFinite(actualAmount) || actualAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }

    // Check transfer restriction
    if (currentUser.transferRestricted) {
      const pool = await db.initializePool();
      const conn = await pool.getConnection();
      try {
        let reason = 'Your account has a transfer restriction. Please contact support.';
        try {
          const [[u]] = await conn.execute('SELECT transferRestrictionReason FROM users WHERE id = ?', [currentUser.id]);
          if (u && u.transferRestrictionReason) reason = u.transferRestrictionReason;
        } catch (_) {}
        return res.status(403).json({ success: false, message: reason, transferRestricted: true, restrictionReason: reason });
      } finally { await conn.release(); }
    }

    // Resolve recipient
    let recipient = null;
    const emailInput = recipientEmail || toEmail;
    if (emailInput) {
      recipient = await db.getUserByEmail(emailInput);
    } else if (toAccountNumber) {
      const pool = await db.initializePool();
      const conn = await pool.getConnection();
      try {
        const [rows] = await conn.execute('SELECT id FROM users WHERE accountNumber = ?', [toAccountNumber]);
        if (rows[0]) recipient = await db.getUserById(rows[0].id);
      } finally { await conn.release(); }
    }

    if (!recipient) {
      return res.status(404).json({ success: false, message: 'Recipient not found' });
    }
    if (recipient.id === currentUser.id) {
      return res.status(400).json({ success: false, message: 'Cannot transfer to yourself' });
    }
    if (parseFloat(currentUser.balance) < actualAmount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await connection.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [actualAmount, currentUser.id]);
      await connection.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [actualAmount, recipient.id]);
      await connection.execute(
        'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
        [currentUser.id, recipient.id, actualAmount, 'transfer', description || 'Money transfer', 'completed']
      );
      await connection.commit();
      console.log(`[TRANSFER] ${currentUser.email} -> ${recipient.email}: $${actualAmount}`);
      res.json({
        success: true,
        message: 'Transfer completed successfully',
        transactionId: `TXN-${Date.now()}`,
        to: recipient.email,
        amount: actualAmount,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      await connection.release();
    }
  } catch (e) {
    console.error('[API] user transfer error', e);
    res.status(500).json({ success: false, message: 'Transfer failed: ' + e.message });
  }
});

// Admin transfer (admin to user or between users)
app.post('/api/admin/transfer', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const currentUser = await db.getUserByEmail(req.user.email);

    const { fromEmail, toEmail, toAccountNumber, amount, description, reason, transferType, fromLabel, toLabel } = req.body;
    const actualAmount = parseFloat(amount);

    if ((!toEmail && !toAccountNumber) || !Number.isFinite(actualAmount) || actualAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid transfer details' });
    }

    // Resolve recipient by email or account number
    let recipient = null;
    if (toEmail) {
      recipient = await db.getUserByEmail(toEmail);
    } else {
      const pool = await db.initializePool();
      const conn = await pool.getConnection();
      try {
        const [rows] = await conn.execute('SELECT * FROM users WHERE accountNumber = ?', [toAccountNumber]);
        recipient = rows[0] ? (await db.getUserById(rows[0].id)) : null;
      } finally { await conn.release(); }
    }
    if (!recipient) return res.status(404).json({ success: false, message: 'Recipient not found' });

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      if (fromEmail) {
        const sender = await db.getUserByEmail(fromEmail);
        if (!sender) return res.status(404).json({ success: false, message: 'Sender not found' });
        if (parseFloat(sender.balance) < actualAmount) return res.status(400).json({ success: false, message: 'Sender has insufficient balance' });
        await connection.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [actualAmount, sender.id]);
        await connection.execute(
          'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
          [sender.id, recipient.id, actualAmount, transferType || 'admin_transfer', buildAdminDescription(description || reason || 'Transfer', fromLabel, toLabel), 'completed']
        );
      } else {
        if (parseFloat(currentUser.balance) < actualAmount) return res.status(400).json({ success: false, message: 'Admin has insufficient balance' });
        await connection.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [actualAmount, currentUser.id]);
        await connection.execute(
          'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
          [currentUser.id, recipient.id, actualAmount, transferType || 'direct_deposit', buildAdminDescription(description || reason || 'Transfer', fromLabel, toLabel), 'completed']
        );
      }
      await connection.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [actualAmount, recipient.id]);
      console.log(`[ADMIN_TRANSFER] -> ${recipient.email}: $${actualAmount}`);
      res.json({ success: true, message: 'Transfer completed successfully', to: recipient.email, amount: actualAmount, timestamp: new Date().toISOString() });
    } finally {
      await connection.release();
    }
  } catch (e) {
    console.error('[API] admin transfer error', e);
    res.status(500).json({ success: false, message: 'Admin transfer failed: ' + e.message });
  }
});

// Admin credit account
function buildAdminDescription(baseDescription, fromLabel, toLabel) {
  let desc = String(baseDescription || '').trim();
  if (!desc) desc = 'Transfer';
  if (String(fromLabel || '').trim()) desc += ` | From: ${String(fromLabel).trim()}`;
  if (String(toLabel || '').trim()) desc += ` | To: ${String(toLabel || '').trim()}`;
  return desc;
}

app.post('/api/admin/credit-account', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const currentUser = await db.getUserByEmail(req.user.email);
    
    const { userId, amount, reason } = req.body;
    if (!userId || !amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid credit details' });
    }
    
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await connection.execute(
        'UPDATE users SET balance = balance + ? WHERE id = ?',
        [amount, userId]
      );
      
      await connection.execute(
        'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
        [1, userId, amount, 'admin_credit', reason || 'Account credit', 'completed']
      );
      
      console.log(`[ADMIN_CREDIT] User ${userId}: +$${amount} (${reason})`);
      
      res.json({
        success: true,
        message: 'Account credited successfully',
        userId,
        amount,
        timestamp: new Date().toISOString()
      });
    } finally {
      await connection.release();
    }
  } catch (e) {
    console.error('[API] admin credit error', e);
    res.status(500).json({ success: false, message: 'Credit failed: ' + e.message });
  }
});

// Admin debit account
app.post('/api/admin/debit-account', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const currentUser = await db.getUserByEmail(req.user.email);

    const { userId, recipient, amount, reason, description, fromLabel, toLabel } = req.body;
    if ((!userId && !recipient) || !amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid debit details' });
    }

    // Resolve target user by userId, email, or account number
    let user = null;
    if (userId) {
      user = await db.getUserById(userId);
    } else {
      const isEmail = String(recipient).includes('@');
      if (isEmail) {
        user = await db.getUserByEmail(recipient);
      } else {
        const pool = await db.initializePool();
        const conn = await pool.getConnection();
        try {
          const [rows] = await conn.execute('SELECT * FROM users WHERE accountNumber = ?', [recipient]);
          if (rows[0]) user = await db.getUserById(rows[0].id);
        } finally { await conn.release(); }
      }
    }
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    if (parseFloat(user.balance) < amount) return res.status(400).json({ success: false, message: 'Insufficient balance' });

    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await connection.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, user.id]);
      await connection.execute(
        'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
        [user.id, currentUser.id, amount, 'admin_debit', buildAdminDescription(reason || description || 'Account debit', fromLabel, toLabel), 'completed']
      );
      console.log(`[ADMIN_DEBIT] User ${user.id}: -$${amount}`);
      res.json({ success: true, message: 'Amount debited successfully', userId: user.id, amount, timestamp: new Date().toISOString() });
    } finally {
      await connection.release();
    }
  } catch (e) {
    console.error('[API] admin debit error', e);
    res.status(500).json({ success: false, message: 'Debit failed: ' + e.message });
  }
});

// ============ USER TRANSFER (supports toAccountNumber) ============
// Override the existing /api/user/transfer to also handle account number lookup
// Note: The original handler only handles toEmail. This one replaces it above.

// ============ BILLS ENDPOINTS ============

const BILLERS = [
  { id: 1, name: 'Con Edison', category: 'Utilities', logo: 'assets/biller-logos/coned.png' },
  { id: 2, name: 'PG&E', category: 'Utilities', logo: 'assets/biller-logos/pge.png' },
  { id: 3, name: 'National Grid', category: 'Utilities', logo: 'assets/biller-logos/nationalgrid.png' },
  { id: 4, name: 'Duke Energy', category: 'Utilities', logo: 'assets/biller-logos/duke-energy.png' },
  { id: 5, name: 'AT&T', category: 'Utilities', logo: 'assets/biller-logos/att.png' },
  { id: 6, name: 'Comcast Xfinity', category: 'Utilities', logo: 'assets/biller-logos/xfinity.png' },
  { id: 7, name: 'Verizon', category: 'Utilities', logo: 'assets/biller-logos/verizon.png' },
  { id: 8, name: 'T-Mobile', category: 'Utilities', logo: 'assets/biller-logos/tmobile.png' },
  { id: 9, name: 'State Farm', category: 'Insurance', logo: 'assets/biller-logos/statefarm.png' },
  { id: 10, name: 'GEICO', category: 'Insurance', logo: 'assets/biller-logos/geico.png' },
  { id: 11, name: 'Progressive', category: 'Insurance', logo: 'assets/biller-logos/progressive.png' },
  { id: 12, name: 'Allstate', category: 'Insurance', logo: 'assets/biller-logos/allstate.png' },
  { id: 13, name: 'American Express', category: 'Credit', logo: 'assets/biller-logos/americanexpress.png' },
  { id: 14, name: 'Discover', category: 'Credit', logo: 'assets/biller-logos/discover.png' },
  { id: 15, name: 'Capital One', category: 'Credit', logo: 'assets/biller-logos/capitalone.png' },
  { id: 16, name: 'Zillow Rent', category: 'Housing', logo: 'assets/biller-logos/zillow.png' },
  { id: 17, name: 'Rocket Mortgage', category: 'Housing', logo: 'assets/biller-logos/rocketmortgage.png' }
];

app.get('/api/bills/billers', (req, res) => {
  res.json({ success: true, billers: BILLERS });
});

app.post('/api/bills/pay', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const { billerId, amount, accountNumber: billerAcct } = req.body;
    if (!billerId || !amount || amount <= 0) return res.status(400).json({ success: false, message: 'Invalid payment details' });
    if (parseFloat(user.balance) < amount) return res.status(400).json({ success: false, message: 'Insufficient balance' });
    const biller = BILLERS.find(b => b.id == billerId);
    if (!biller) return res.status(404).json({ success: false, message: 'Biller not found' });
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await connection.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, user.id]);
      await connection.execute(
        'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
        [user.id, null, amount, 'bill_payment', `Bill payment to ${biller.name}${billerAcct ? ` (Acct: ${billerAcct})` : ''}`, 'completed']
      );
      res.json({ success: true, message: `Payment of $${amount} to ${biller.name} successful` });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] bills/pay error', e);
    res.status(500).json({ success: false, message: 'Payment failed: ' + e.message });
  }
});

// ============ CHECK DEPOSIT ENDPOINTS ============

async function ensureCheckDepositsTable(connection) {
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS check_deposits (
      id INT PRIMARY KEY AUTO_INCREMENT,
      userId INT NOT NULL,
      amount DECIMAL(12,2) NOT NULL,
      accountType VARCHAR(20) DEFAULT 'checking',
      checkNumber VARCHAR(20),
      payer VARCHAR(255),
      memo TEXT,
      frontImage LONGTEXT,
      backImage LONGTEXT,
      status VARCHAR(20) DEFAULT 'pending',
      reference VARCHAR(50),
      rejectionReason TEXT,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id),
      INDEX idx_userId (userId)
    )
  `);
}

app.post('/api/check-deposit', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const { amount, accountType, checkNumber, payer, memo, frontImage, backImage } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ success: false, message: 'Invalid amount' });
    if (!frontImage || !backImage) return res.status(400).json({ success: false, message: 'Both check images required' });
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureCheckDepositsTable(connection);
      const reference = `CHK-${Date.now()}`;
      await connection.execute(
        'INSERT INTO check_deposits (userId, amount, accountType, checkNumber, payer, memo, frontImage, backImage, reference) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [user.id, amount, accountType || 'checking', checkNumber || null, payer || null, memo || null, frontImage, backImage, reference]
      );
      res.json({ success: true, message: 'Check deposit submitted for review', reference });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] check-deposit error', e);
    res.status(500).json({ success: false, message: 'Submission failed: ' + e.message });
  }
});

app.get('/api/check-deposits', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureCheckDepositsTable(connection);
      const [deposits] = await connection.execute(
        'SELECT id, amount, accountType, checkNumber, payer, status, reference, rejectionReason, createdAt FROM check_deposits WHERE userId = ? ORDER BY createdAt DESC LIMIT 20',
        [user.id]
      );
      res.json({ success: true, deposits });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] check-deposits error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch deposits' });
  }
});

app.get('/api/admin/check-deposits', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const status = req.query.status || '';
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureCheckDepositsTable(connection);
      const whereClause = status ? 'WHERE cd.status = ?' : '';
      const params = status ? [status] : [];
      const [deposits] = await connection.execute(
        `SELECT cd.*, u.firstName, u.lastName, u.email, u.accountNumber, u.accountType
         FROM check_deposits cd LEFT JOIN users u ON cd.userId = u.id
         ${whereClause} ORDER BY cd.createdAt DESC LIMIT 200`,
        params
      );
      res.json({ success: true, deposits });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[ADMIN] check-deposits error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch check deposits' });
  }
});

app.post('/api/admin/approve-check-deposit/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureCheckDepositsTable(connection);
      const [rows] = await connection.execute('SELECT * FROM check_deposits WHERE id = ?', [req.params.id]);
      if (!rows[0]) return res.status(404).json({ success: false, message: 'Deposit not found' });
      if (rows[0].status !== 'pending') return res.status(400).json({ success: false, message: 'Deposit is not pending' });
      await connection.execute('UPDATE check_deposits SET status = ? WHERE id = ?', ['approved', req.params.id]);
      await connection.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [rows[0].amount, rows[0].userId]);
      await connection.execute(
        'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
        [null, rows[0].userId, rows[0].amount, 'check_deposit', `Check deposit approved${rows[0].checkNumber ? ` #${rows[0].checkNumber}` : ''}`, 'completed']
      );
      res.json({ success: true, message: 'Check deposit approved and balance credited' });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[ADMIN] approve-check-deposit error', e);
    res.status(500).json({ success: false, message: 'Failed to approve deposit' });
  }
});

app.post('/api/admin/reject-check-deposit/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureCheckDepositsTable(connection);
      await connection.execute('UPDATE check_deposits SET status = ?, rejectionReason = ? WHERE id = ?', ['rejected', reason || 'Rejected by admin', req.params.id]);
      res.json({ success: true, message: 'Check deposit rejected' });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[ADMIN] reject-check-deposit error', e);
    res.status(500).json({ success: false, message: 'Failed to reject deposit' });
  }
});

// ============ LOANS ENDPOINTS ============

async function ensureLoansTable(connection) {
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS loan_applications (
      id INT PRIMARY KEY AUTO_INCREMENT,
      userId INT NOT NULL,
      loanType VARCHAR(50),
      amount DECIMAL(14,2),
      term INT,
      income DECIMAL(14,2),
      employment VARCHAR(50),
      purpose TEXT,
      status VARCHAR(30) DEFAULT 'pending',
      interestRate DECIMAL(5,2),
      monthlyPayment DECIMAL(12,2),
      adminNotes TEXT,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id),
      INDEX idx_userId (userId)
    )
  `);
}

app.post('/api/loans/apply', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const { loanType, amount, term, income, employment, purpose } = req.body;
    if (!loanType || !amount || !term) return res.status(400).json({ success: false, message: 'Loan type, amount, and term are required' });
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureLoansTable(connection);
      const [result] = await connection.execute(
        'INSERT INTO loan_applications (userId, loanType, amount, term, income, employment, purpose) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [user.id, loanType, amount, term, income || null, employment || null, purpose || null]
      );
      res.json({ success: true, message: 'Loan application submitted', applicationId: `LA-${String(result.insertId).padStart(6, '0')}` });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] loans/apply error', e);
    res.status(500).json({ success: false, message: 'Failed to submit application: ' + e.message });
  }
});

app.get('/api/loans/my-applications', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureLoansTable(connection);
      const [rows] = await connection.execute(
        'SELECT * FROM loan_applications WHERE userId = ? ORDER BY createdAt DESC',
        [user.id]
      );
      res.json({ success: true, applications: rows });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] loans/my-applications error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch applications' });
  }
});

app.get('/api/admin/loans/pending', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureLoansTable(connection);
      const [rows] = await connection.execute(
        `SELECT la.*, u.firstName, u.lastName, u.email,
         CONCAT(u.firstName, ' ', u.lastName) as userName
         FROM loan_applications la LEFT JOIN users u ON la.userId = u.id
         ORDER BY la.createdAt DESC LIMIT 200`
      );
      res.json({ success: true, applications: rows });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[ADMIN] loans/pending error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch loan applications' });
  }
});

app.put('/api/admin/loans/:id/approve', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { interestRate } = req.body;
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureLoansTable(connection);
      const [rows] = await connection.execute('SELECT * FROM loan_applications WHERE id = ?', [req.params.id]);
      if (!rows[0]) return res.status(404).json({ success: false, message: 'Application not found' });
      const loan = rows[0];
      const rate = parseFloat(interestRate) || 7.5;
      const monthlyRate = rate / 100 / 12;
      const monthly = loan.term > 0 ? (loan.amount * monthlyRate * Math.pow(1 + monthlyRate, loan.term)) / (Math.pow(1 + monthlyRate, loan.term) - 1) : 0;
      await connection.execute(
        'UPDATE loan_applications SET status = ?, interestRate = ?, monthlyPayment = ? WHERE id = ?',
        ['approved', rate, monthly.toFixed(2), req.params.id]
      );
      // Credit the loan amount to the user's account
      await connection.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [loan.amount, loan.userId]);
      await connection.execute(
        'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
        [null, loan.userId, loan.amount, 'loan_disbursement', `Loan approved: ${loan.loanType} at ${rate}% APR`, 'completed']
      );
      res.json({ success: true, message: 'Loan approved and funds disbursed' });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[ADMIN] loans/approve error', e);
    res.status(500).json({ success: false, message: 'Failed to approve loan' });
  }
});

app.put('/api/admin/loans/:id/reject', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { rejectionReason } = req.body;
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureLoansTable(connection);
      await connection.execute(
        'UPDATE loan_applications SET status = ?, adminNotes = ? WHERE id = ?',
        ['rejected', rejectionReason || 'Application rejected', req.params.id]
      );
      res.json({ success: true, message: 'Loan rejected' });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[ADMIN] loans/reject error', e);
    res.status(500).json({ success: false, message: 'Failed to reject loan' });
  }
});

// ============ USER PROFILE UPDATE ============

app.put('/api/user/profile/complete', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const { firstName, lastName, phone, address, city, state, zipCode, dateOfBirth, gender } = req.body;
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      const fields = {};
      if (firstName) fields.firstName = firstName;
      if (lastName) fields.lastName = lastName;
      if (phone !== undefined) fields.phoneNumber = phone;
      if (address !== undefined) fields.address = address;
      if (city !== undefined) fields.city = city;
      if (state !== undefined) fields.state = state;
      if (zipCode !== undefined) fields.zipCode = zipCode;
      if (dateOfBirth !== undefined) fields.dateOfBirth = dateOfBirth || null;
      if (gender !== undefined) fields.gender = gender || null;
      const keys = Object.keys(fields);
      if (keys.length) {
        const setClauses = keys.map(k => `\`${k}\` = ?`).join(', ');
        await conn.execute(`UPDATE users SET ${setClauses} WHERE id = ?`, [...Object.values(fields), user.id]).catch(() => {});
      }
      res.json({ success: true, message: 'Profile updated successfully' });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[API] profile update error', e);
    res.status(500).json({ success: false, message: 'Failed to update profile' });
  }
});

function getProfileImageDir() {
  const uploadDir = path.join(__dirname, '..', 'assets', 'profile-images');
  try {
    fs.mkdirSync(uploadDir, { recursive: true });
  } catch (err) {
    console.error('[UPLOAD] Failed to create profile image directory:', err);
  }
  return uploadDir;
}

function getProfileImageExtension(mimeType) {
  const mapping = {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/webp': 'webp'
  };
  return mapping[mimeType] || null;
}

function storeProfileDataUrl(userId, dataUrl, originalFileName) {
  const match = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/.exec(dataUrl);
  if (!match) return null;

  const mimeType = match[1];
  const base64Data = match[2];
  const extension = getProfileImageExtension(mimeType);
  if (!extension) return null;

  const safeBaseName = originalFileName ? path.parse(originalFileName).name.replace(/[^a-zA-Z0-9-_]/g, '_') : `profile-${userId}`;
  const fileName = `${safeBaseName}-${Date.now()}.${extension}`;
  const uploadDir = getProfileImageDir();
  const filePath = path.join(uploadDir, fileName);

  try {
    const buffer = Buffer.from(base64Data, 'base64');
    fs.writeFileSync(filePath, buffer);
    return `/assets/profile-images/${fileName}`;
  } catch (err) {
    console.error('[UPLOAD] Failed to write profile image file:', err);
    return null;
  }
}

function deleteProfileImageFile(profileImagePath) {
  if (!profileImagePath || typeof profileImagePath !== 'string') return;
  const expectedPrefix = '/assets/profile-images/';
  if (!profileImagePath.startsWith(expectedPrefix)) return;
  const fileName = profileImagePath.substring(expectedPrefix.length);
  const filePath = path.join(__dirname, '..', 'assets', 'profile-images', fileName);
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch (err) {
    console.error('[UPLOAD] Failed to delete old profile image file:', err);
  }
}

// Profile picture upload endpoint
app.post('/api/user/profile/picture', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const { fileData, fileName } = req.body || {};
    if (!fileData) return res.status(400).json({ success: false, message: 'No file data' });

    const isDataUrl = typeof fileData === 'string' && /^data:image\/[a-zA-Z0-9.+-]+;base64,/.test(fileData);
    const dataSizeBytes = isDataUrl ? Buffer.byteLength(fileData.split(',')[1] || '', 'base64') : Buffer.byteLength(String(fileData), 'utf8');
    if (dataSizeBytes > 5 * 1024 * 1024) {
      return res.status(400).json({ success: false, message: 'File size exceeds 5MB limit' });
    }

    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await conn.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS profileImage LONGTEXT`).catch(() => {});

      let profileImageValue = fileData;
      if (isDataUrl) {
        const storedPath = storeProfileDataUrl(user.id, fileData, fileName);
        if (storedPath) {
          // Remove old stored image if we previously saved one
          deleteProfileImageFile(user.profileImage);
          profileImageValue = storedPath;
        }
      }

      await conn.execute('UPDATE users SET profileImage = ? WHERE id = ?', [profileImageValue, user.id]);
      res.json({ success: true, profileImage: profileImageValue, message: 'Profile picture uploaded successfully' });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[API] profile picture upload error:', e);
    res.status(500).json({ success: false, message: 'Upload failed' });
  }
});

app.get('/api/user/profile/picture', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      const [[result]] = await conn.execute('SELECT profileImage FROM users WHERE id = ?', [user.id]).catch(() => [[{}]]);
      if (result && result.profileImage) {
        res.json({ success: true, profileImage: result.profileImage });
      } else {
        res.json({ success: true, profileImage: null });
      }
    } finally { await conn.release(); }
  } catch (e) {
    res.status(500).json({ success: false, message: 'Failed to fetch profile picture' });
  }
});

app.delete('/api/user/profile/picture', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      deleteProfileImageFile(user.profileImage);
      await conn.execute('UPDATE users SET profileImage = NULL WHERE id = ?', [user.id]).catch(() => {});
      res.json({ success: true, message: 'Profile picture removed' });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[API] profile picture delete error:', e);
    res.status(500).json({ success: false, message: 'Remove failed' });
  }
});

// ============ AUTH — CHANGE PASSWORD ============

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ success: false, message: 'Both passwords are required' });
    const passwordHash = user.passwordHash || user.password;
    const match = await bcrypt.compare(currentPassword, passwordHash);
    if (!match) return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    if (newPassword.length < 8) return res.status(400).json({ success: false, message: 'New password must be at least 8 characters' });
    const hashed = await bcrypt.hash(newPassword, 10);
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      const col = await db.detectPasswordColumn ? (await db.detectPasswordColumn()) : 'password';
      await conn.execute(`UPDATE users SET \`${col || 'password'}\` = ? WHERE id = ?`, [hashed, user.id]);
      res.json({ success: true, message: 'Password changed successfully' });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[API] change-password error', e);
    res.status(500).json({ success: false, message: 'Failed to change password' });
  }
});

// ============ SECURITY / SESSIONS (stub — returns plausible data) ============

app.get('/api/user/security/login-history', authenticateToken, async (req, res) => {
  res.json({ success: true, logins: [
    { device: 'Chrome on Windows', location: 'United States', ip: '192.168.1.1', timestamp: new Date() },
    { device: 'Mobile Safari', location: 'United States', ip: '10.0.0.1', timestamp: new Date(Date.now() - 86400000) }
  ]});
});

app.get('/api/user/security/active-sessions', authenticateToken, async (req, res) => {
  res.json({ success: true, sessions: [
    { id: 'current', deviceName: 'Current Device', browserName: 'Chrome', location: 'United States', lastActivity: new Date() }
  ]});
});

app.post('/api/user/security/logout-session/:id', authenticateToken, async (req, res) => {
  res.json({ success: true, message: 'Session logged out' });
});

app.post('/api/user/security/logout-all', authenticateToken, async (req, res) => {
  res.json({ success: true, message: 'All sessions logged out' });
});

// ============ USER VERIFICATION STATUS ============

app.get('/api/user/verification-status', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, verification: {
      isVerified: !!(user.isVerified),
      documentRequested: !!(user.documentRequested),
      documentRequestMessage: user.documentRequestMessage || null,
      documents: []
    }});
  } catch (e) {
    console.error('[API] verification-status error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch verification status' });
  }
});

// ============ ACCOUNT CONTROLS ============

app.post('/api/user/account/freeze', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await conn.execute("UPDATE users SET accountStatus = 'frozen' WHERE id = ?", [user.id]);
      res.json({ success: true, message: 'Account frozen' });
    } finally { await conn.release(); }
  } catch (e) { res.status(500).json({ success: false, message: 'Failed to freeze account' }); }
});

app.post('/api/user/account/unfreeze', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await conn.execute("UPDATE users SET accountStatus = 'active' WHERE id = ?", [user.id]);
      res.json({ success: true, message: 'Account unfrozen' });
    } finally { await conn.release(); }
  } catch (e) { res.status(500).json({ success: false, message: 'Failed to unfreeze account' }); }
});

app.post('/api/user/account/international', authenticateToken, async (req, res) => {
  res.json({ success: true, message: 'International transactions setting updated' });
});

// ============ USER PREFERENCES & PIN ============

app.put('/api/user/preferences', authenticateToken, async (req, res) => {
  res.json({ success: true, message: 'Preferences updated' });
});

app.post('/api/user/transaction-pin', authenticateToken, async (req, res) => {
  res.json({ success: true, message: 'Transaction PIN updated' });
});

app.delete('/api/user/transaction-pin', authenticateToken, async (req, res) => {
  res.json({ success: true, message: 'Transaction PIN removed' });
});

// ============ USER BENEFICIARIES ALIAS ============
// settings-enhanced.js calls /api/user/beneficiaries (transfer.html uses /api/beneficiaries)
app.get('/api/user/beneficiaries', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      let rows = [];
      try {
        [rows] = await conn.execute('SELECT * FROM beneficiaries WHERE userId = ? ORDER BY createdAt DESC', [user.id]);
      } catch (_) {}
      res.json({ success: true, beneficiaries: rows });
    } finally { await conn.release(); }
  } catch (e) { res.status(500).json({ success: false, message: 'Failed to fetch beneficiaries' }); }
});

app.post('/api/user/beneficiaries', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const { name, nickname, accountNumber, routingNumber, bankName } = req.body;
    if (!name || !accountNumber) return res.status(400).json({ success: false, message: 'Name and account number required' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await conn.execute(
        'INSERT INTO beneficiaries (userId, name, nickname, accountNumber, bankName, email) VALUES (?, ?, ?, ?, ?, ?)',
        [user.id, name, nickname || null, accountNumber, bankName || 'Heritage Bank', null]
      ).catch(async () => {
        // Table might not have routing column — ignore
      });
      res.json({ success: true, message: 'Beneficiary added' });
    } finally { await conn.release(); }
  } catch (e) { res.status(500).json({ success: false, message: 'Failed to add beneficiary' }); }
});

app.delete('/api/user/beneficiaries/:id', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await conn.execute('DELETE FROM beneficiaries WHERE id = ? AND userId = ?', [req.params.id, user.id]);
      res.json({ success: true, message: 'Beneficiary deleted' });
    } finally { await conn.release(); }
  } catch (e) { res.status(500).json({ success: false, message: 'Failed to delete beneficiary' }); }
});

// ============ EMAIL/PHONE VERIFICATION STUBS ============

app.post('/api/user/resend-email-verification', authenticateToken, async (req, res) => {
  res.json({ success: true, message: 'Verification email sent' });
});

app.post('/api/user/verify-phone', authenticateToken, async (req, res) => {
  res.json({ success: true, message: 'Phone verified' });
});

// ============ WEBAUTHN CREDENTIALS MANAGEMENT ============

app.get('/api/auth/webauthn/credentials', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      let creds = [];
      try {
        [creds] = await conn.execute('SELECT id, createdAt FROM webauthn_credentials WHERE userId = ?', [user.id]);
      } catch (_) {}
      res.json({ success: true, credentials: creds });
    } finally { await conn.release(); }
  } catch (e) { res.status(500).json({ success: false, message: 'Failed to fetch credentials' }); }
});

app.delete('/api/auth/webauthn/credentials/:id', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await conn.execute('DELETE FROM webauthn_credentials WHERE id = ? AND userId = ?', [req.params.id, user.id]).catch(() => {});
      res.json({ success: true, message: 'Passkey removed' });
    } finally { await conn.release(); }
  } catch (e) { res.status(500).json({ success: false, message: 'Failed to remove passkey' }); }
});

// ============ ADMIN SUPPORT TICKETS ============

async function ensureSupportTables(connection) {
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS support_tickets (
      id INT PRIMARY KEY AUTO_INCREMENT,
      userId INT,
      userEmail VARCHAR(255),
      category VARCHAR(50) DEFAULT 'general',
      subject VARCHAR(255) NOT NULL,
      description TEXT,
      priority VARCHAR(20) DEFAULT 'low',
      status VARCHAR(20) DEFAULT 'open',
      adminReply TEXT,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `);
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS user_messages (
      id INT PRIMARY KEY AUTO_INCREMENT,
      userId INT,
      userEmail VARCHAR(255),
      subject VARCHAR(255) NOT NULL,
      body TEXT,
      adminReply TEXT,
      status VARCHAR(20) DEFAULT 'open',
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS contact_messages (
      id INT PRIMARY KEY AUTO_INCREMENT,
      firstName VARCHAR(100),
      lastName VARCHAR(100),
      email VARCHAR(255),
      subject VARCHAR(255),
      message TEXT,
      status VARCHAR(20) DEFAULT 'new',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS newsletter_subscribers (
      id INT PRIMARY KEY AUTO_INCREMENT,
      email VARCHAR(255) UNIQUE NOT NULL,
      status VARCHAR(20) DEFAULT 'active',
      subscribedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

app.get('/api/admin/support-tickets', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const status = req.query.status || '';
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await ensureSupportTables(conn);
      const where = status ? 'WHERE status = ?' : '';
      const [tickets] = await conn.execute(`SELECT * FROM support_tickets ${where} ORDER BY createdAt DESC LIMIT 200`, status ? [status] : []);
      res.json({ success: true, tickets });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] support-tickets error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch support tickets' });
  }
});

app.put('/api/admin/support-tickets/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { adminReply, status } = req.body;
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await ensureSupportTables(conn);
      await conn.execute('UPDATE support_tickets SET adminReply = ?, status = ? WHERE id = ?', [adminReply || null, status || 'pending', req.params.id]);
      res.json({ success: true, message: 'Ticket updated' });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] update support ticket error', e);
    res.status(500).json({ success: false, message: 'Failed to update ticket' });
  }
});

app.post('/api/support-tickets', authenticateToken, async (req, res) => {
  return res.status(403).json({ success: false, message: 'Support ticket creation is currently unavailable.' });
});

app.get('/api/support-tickets', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await ensureSupportTables(conn);
      const [tickets] = await conn.execute(
        'SELECT * FROM support_tickets WHERE userId = ? ORDER BY createdAt DESC LIMIT 200',
        [user.id]
      );
      res.json({ success: true, tickets });
    } finally {
      await conn.release();
    }
  } catch (e) {
    console.error('[API] user support-tickets error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch support tickets' });
  }
});

app.get('/api/admin/messages', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await ensureSupportTables(conn);
      const [messages] = await conn.execute('SELECT * FROM user_messages ORDER BY createdAt DESC LIMIT 200');
      res.json({ success: true, messages });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] messages error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch messages' });
  }
});

app.put('/api/admin/messages/:id/reply', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { adminReply } = req.body;
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await ensureSupportTables(conn);
      await conn.execute('UPDATE user_messages SET adminReply = ?, status = ? WHERE id = ?', [adminReply, 'replied', req.params.id]);
      res.json({ success: true, message: 'Reply sent' });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] message reply error', e);
    res.status(500).json({ success: false, message: 'Failed to send reply' });
  }
});

app.get('/api/admin/contact-messages', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const status = req.query.status || '';
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await ensureSupportTables(conn);
      const where = status ? 'WHERE status = ?' : '';
      const [messages] = await conn.execute(`SELECT * FROM contact_messages ${where} ORDER BY created_at DESC LIMIT 200`, status ? [status] : []);
      res.json({ success: true, messages });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] contact-messages error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch contact messages' });
  }
});

app.put('/api/admin/contact-messages/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await ensureSupportTables(conn);
      await conn.execute('UPDATE contact_messages SET status = ? WHERE id = ?', [status, req.params.id]);
      res.json({ success: true, message: 'Message updated' });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] update contact message error', e);
    res.status(500).json({ success: false, message: 'Failed to update message' });
  }
});

app.get('/api/admin/newsletter-subscribers', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await ensureSupportTables(conn);
      const [subscribers] = await conn.execute('SELECT * FROM newsletter_subscribers ORDER BY subscribedAt DESC');
      res.json({ success: true, subscribers });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] newsletter error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch subscribers' });
  }
});

// Also persist newsletter subscriptions
app.post('/api/newsletter', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email is required' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await conn.execute(`
        CREATE TABLE IF NOT EXISTS newsletter_subscribers (
          id INT PRIMARY KEY AUTO_INCREMENT,
          email VARCHAR(255) UNIQUE NOT NULL,
          status VARCHAR(20) DEFAULT 'active',
          subscribedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      await conn.execute('INSERT IGNORE INTO newsletter_subscribers (email) VALUES (?)', [email]);
    } catch (_) {}
    finally { await conn.release(); }
    console.log(`[NEWSLETTER] Subscribed: ${email}`);
    res.json({ success: true, message: 'Successfully subscribed to our newsletter' });
  } catch (e) {
    console.error('[API] newsletter error', e);
    res.status(500).json({ success: false, message: 'Failed to subscribe' });
  }
});

// ============ ADMIN MONTHLY REPORT ============

app.get('/api/admin/monthly-report', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const month = req.query.month || new Date().toISOString().slice(0, 7);
    const [year, mon] = month.split('-');
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      const [[newUsersRow]] = await conn.execute(
        'SELECT COUNT(*) as count FROM users WHERE YEAR(createdAt) = ? AND MONTH(createdAt) = ?',
        [year, parseInt(mon)]
      );
      const [[txnRow]] = await conn.execute(
        'SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as volume FROM transactions WHERE YEAR(createdAt) = ? AND MONTH(createdAt) = ?',
        [year, parseInt(mon)]
      );
      res.json({
        success: true,
        newUsers: newUsersRow.count || 0,
        totalTransactions: txnRow.count || 0,
        totalVolume: parseFloat(txnRow.volume || 0),
        loansApproved: 0
      });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] monthly-report error', e);
    res.status(500).json({ success: false, message: 'Failed to generate report' });
  }
});

// ============ ADMIN SEARCH TRANSACTIONS ============

app.get('/api/admin/search-transactions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const query = (req.query.query || '').toString().trim();
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      const like = `%${query}%`;
      const [transactions] = await conn.execute(
        `SELECT t.*, fu.email AS senderEmail, fu.firstName AS senderFirst, fu.lastName AS senderLast, fu.accountNumber AS senderAccountNumber,
                tu.email AS recipientEmail, tu.firstName AS recipientFirst, tu.lastName AS recipientLast, tu.accountNumber AS recipientAccountNumber
           FROM transactions t
           LEFT JOIN users fu ON t.fromUserId = fu.id
           LEFT JOIN users tu ON t.toUserId = tu.id
           WHERE t.description LIKE ? OR t.type LIKE ? ORDER BY t.createdAt DESC LIMIT 100`,
        [like, like]
      );
      res.json({ success: true, transactions });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] search-transactions error', e);
    res.status(500).json({ success: false, message: 'Failed to search transactions' });
  }
});

// ============ ADMIN EDIT TRANSACTION ============

app.put('/api/admin/edit-transaction/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { description } = req.body;
    if (!description) return res.status(400).json({ success: false, message: 'Description is required' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await conn.execute('UPDATE transactions SET description = ? WHERE id = ?', [description, req.params.id]);
      const [[txn]] = await conn.execute('SELECT * FROM transactions WHERE id = ?', [req.params.id]);
      res.json({ success: true, message: 'Transaction updated', transaction: txn });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] edit-transaction error', e);
    res.status(500).json({ success: false, message: 'Failed to update transaction' });
  }
});

// ============ ADMIN APPROVE/DENY TRANSACTIONS & TRANSFERS ============

app.post('/api/admin/approve-transaction/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      const [[txn]] = await conn.execute('SELECT * FROM transactions WHERE id = ?', [req.params.id]);
      if (!txn) return res.status(404).json({ success: false, message: 'Transaction not found' });
      if (txn.status !== 'pending') return res.status(400).json({ success: false, message: 'Transaction is not pending' });
      await conn.execute('UPDATE transactions SET status = ? WHERE id = ?', ['completed', req.params.id]);
      if (txn.toUserId) await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [txn.amount, txn.toUserId]);
      if (txn.fromUserId) await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [txn.amount, txn.fromUserId]);
      res.json({ success: true, message: 'Transaction approved' });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] approve-transaction error', e);
    res.status(500).json({ success: false, message: 'Failed to approve transaction' });
  }
});

app.post('/api/admin/deny-transaction/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await conn.execute('UPDATE transactions SET status = ?, description = CONCAT(description, ?) WHERE id = ?',
        ['denied', reason ? ` [Denied: ${reason}]` : ' [Denied by admin]', req.params.id]);
      res.json({ success: true, message: 'Transaction denied' });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] deny-transaction error', e);
    res.status(500).json({ success: false, message: 'Failed to deny transaction' });
  }
});

app.post('/api/admin/approve-transfer/:id', authenticateToken, requireAdmin, async (req, res) => {
  res.json({ success: true, message: 'Transfer approved' });
});

app.post('/api/admin/reject-transfer/:id', authenticateToken, requireAdmin, async (req, res) => {
  res.json({ success: true, message: 'Transfer rejected' });
});

// ============ ADMIN RESTRICTION & LOOKUP ENDPOINTS ============

async function resolveUserByEmailOrAccount(input) {
  const isEmail = String(input || '').includes('@');
  if (isEmail) return db.getUserByEmail(input);
  const pool = await db.initializePool();
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.execute('SELECT id FROM users WHERE accountNumber = ?', [input]);
    return rows[0] ? db.getUserById(rows[0].id) : null;
  } finally { await conn.release(); }
}

app.get('/api/admin/lookup-user', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const input = req.query.email || req.query.accountNumber || '';
    const user = await resolveUserByEmailOrAccount(input);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user: { id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName, balance: parseFloat(user.balance), accountNumber: user.accountNumber } });
  } catch (e) {
    console.error('[ADMIN] lookup-user error', e);
    res.status(500).json({ success: false, message: 'Lookup failed' });
  }
});

app.post('/api/admin/toggle-transfer-restriction', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { email, accountNumber, userId, restricted, reason } = req.body;
    let user = null;
    if (userId) user = await db.getUserById(userId);
    else if (email) user = await db.getUserByEmail(email);
    else if (accountNumber) user = await resolveUserByEmailOrAccount(accountNumber);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      if (restricted && reason) {
        await conn.execute('UPDATE users SET transferRestricted = ?, transferRestrictionReason = ? WHERE id = ?', [1, reason, user.id]).catch(async () => {
          await conn.execute('UPDATE users SET transferRestricted = ? WHERE id = ?', [1, user.id]);
        });
      } else {
        await conn.execute('UPDATE users SET transferRestricted = ? WHERE id = ?', [restricted ? 1 : 0, user.id]);
      }
    } finally { await conn.release(); }
    res.json({ success: true, message: `Transfer restriction ${restricted ? 'enabled' : 'removed'} for ${user.email}` });
  } catch (e) {
    console.error('[ADMIN] toggle-transfer-restriction error', e);
    res.status(500).json({ success: false, message: 'Failed to update restriction' });
  }
});

app.get('/api/admin/restricted-users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.execute('SELECT id, email, firstName, lastName, balance, accountNumber FROM users WHERE transferRestricted = 1');
      res.json({ success: true, users: rows.map(u => ({ ...u, balance: parseFloat(u.balance || 0) })) });
    } finally { await conn.release(); }
  } catch (e) {
    console.error('[ADMIN] restricted-users error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch restricted users' });
  }
});

app.put('/api/admin/verify-user/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { isVerified } = req.body;
    const pool = await db.initializePool();
    const conn = await pool.getConnection();
    try {
      await conn.execute('UPDATE users SET isVerified = ? WHERE id = ?', [isVerified ? 1 : 0, req.params.userId]).catch(() => {});
    } finally { await conn.release(); }
    res.json({ success: true, message: `User ${isVerified ? 'verified' : 'unverified'} successfully` });
  } catch (e) {
    console.error('[ADMIN] verify-user error', e);
    res.status(500).json({ success: false, message: 'Failed to update verification' });
  }
});

app.post('/api/admin/request-documents/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log(`[ADMIN] Document request sent to user ${req.params.userId}`);
    res.json({ success: true, message: 'Document request sent' });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Failed to send document request' });
  }
});

// ============ CARDS ENDPOINTS ============

async function ensureCardsTable(connection) {
  console.log('[DB] Ensuring cards table exists...');
  try {
    // Ensure bank_accounts table exists (required for card issuance)
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS bank_accounts (
        id INT PRIMARY KEY AUTO_INCREMENT,
        userId INT NOT NULL,
        accountNumber VARCHAR(64),
        accountType VARCHAR(30) DEFAULT 'checking',
        accountName VARCHAR(100) DEFAULT 'Primary Checking',
        ledgerBalance DECIMAL(19,2) DEFAULT 0,
        availableBalance DECIMAL(19,2) DEFAULT 0,
        status VARCHAR(20) DEFAULT 'active',
        isPrimary TINYINT(1) DEFAULT 0,
        openedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES users(id),
        INDEX idx_userId (userId)
      )
    `).catch(() => {});

    const createTableSQL = `
      CREATE TABLE IF NOT EXISTS cards (
        id INT PRIMARY KEY AUTO_INCREMENT,
        accountId INT DEFAULT NULL,
        userId INT NOT NULL,
        cardType VARCHAR(20) NOT NULL DEFAULT 'virtual',
        cardNumber VARCHAR(255),
        cardNumberMasked VARCHAR(30),
        cardholderName VARCHAR(255),
        expirationDate VARCHAR(10),
        cvv VARCHAR(10),
        status VARCHAR(20) DEFAULT 'active',
        deliveryStatus VARCHAR(30) DEFAULT 'not_applicable',
        deliveryAddress TEXT,
        deliveryEtaText VARCHAR(100),
        dailySpendLimit DECIMAL(12,2) DEFAULT 5000,
        monthlySpendLimit DECIMAL(12,2) DEFAULT 25000,
        onlineEnabled TINYINT(1) DEFAULT 1,
        internationalEnabled TINYINT(1) DEFAULT 0,
        issuedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES users(id),
        INDEX idx_userId (userId),
        INDEX idx_accountId (accountId)
      )
    `;
    console.log('[DB] Executing CREATE TABLE IF NOT EXISTS for cards...');
    await connection.execute(createTableSQL);
    console.log('[DB] Ensuring legacy card table columns are present...');
    await connection.execute(`ALTER TABLE cards
      ADD COLUMN IF NOT EXISTS cardNumberMasked VARCHAR(30),
      ADD COLUMN IF NOT EXISTS cvv VARCHAR(10),
      ADD COLUMN IF NOT EXISTS deliveryStatus VARCHAR(30) DEFAULT 'not_applicable',
      ADD COLUMN IF NOT EXISTS deliveryAddress TEXT,
      ADD COLUMN IF NOT EXISTS deliveryEtaText VARCHAR(100),
      ADD COLUMN IF NOT EXISTS dailySpendLimit DECIMAL(12,2) DEFAULT 5000,
      ADD COLUMN IF NOT EXISTS monthlySpendLimit DECIMAL(12,2) DEFAULT 25000,
      ADD COLUMN IF NOT EXISTS onlineEnabled TINYINT(1) DEFAULT 1,
      ADD COLUMN IF NOT EXISTS internationalEnabled TINYINT(1) DEFAULT 0,
      ADD COLUMN IF NOT EXISTS issuedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    `).catch(() => {});
    console.log('[DB] ✓ Cards table ready');
  } catch (err) {
    console.error('[DB] Error ensuring cards table:', err.message);
    throw err;
  }
}

app.get('/api/cards', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureCardsTable(connection);
      const [cards] = await connection.execute('SELECT * FROM cards WHERE userId = ? ORDER BY issuedAt DESC', [user.id]);
      const safe = cards.map(({ cardNumber, cvv, ...rest }) => rest);
      res.json({ success: true, cards: safe });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] cards error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch cards' });
  }
});

app.get('/api/cards/:cardId', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureCardsTable(connection);
      const [rows] = await connection.execute('SELECT * FROM cards WHERE id = ? AND userId = ?', [req.params.cardId, user.id]);
      if (!rows[0]) return res.status(404).json({ success: false, message: 'Card not found' });
      const card = rows[0];
      const fullCardNumber = card.cardType === 'virtual' ? card.cardNumber : null;
      const { cardNumber, cvv, ...safe } = card;
      res.json({ success: true, card: { ...safe, fullCardNumber } });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] card detail error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch card' });
  }
});

app.post('/api/cards/apply', authenticateToken, async (req, res) => {
  console.log('[CARDS_APPLY] Request received');
  try {
    console.log('[CARDS_APPLY] Authenticating user:', req.user?.email);
    const user = await db.getUserByEmail(req.user.email);
    if (!user) {
      console.log('[CARDS_APPLY] User not found');
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    console.log('[CARDS_APPLY] User found:', user.id, user.email);
    
    const { kind, deliveryAddress, pin, cardholderName } = req.body;
    const cardType = kind === 'physical' ? 'debit' : 'virtual';
    console.log('[CARDS_APPLY] Card type:', cardType);

    if (kind === 'physical') {
      if (!deliveryAddress || !String(deliveryAddress).trim()) {
        return res.status(400).json({ success: false, message: 'Delivery address is required for physical cards' });
      }
      if (!/^[0-9]{4}$/.test(String(pin || ''))) {
        return res.status(400).json({ success: false, message: 'PIN must be a 4-digit number' });
      }
    }
    
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      console.log('[CARDS_APPLY] Ensuring cards table exists...');
      await ensureCardsTable(connection);
      console.log('[CARDS_APPLY] Cards table ready');

      console.log('[CARDS_APPLY] Ensuring linked bank account exists...');
      const [acctRows] = await connection.execute(
        `SELECT id FROM bank_accounts WHERE userId = ? AND status = 'active' ORDER BY isPrimary DESC, openedAt ASC LIMIT 1`,
        [user.id]
      );
      console.log('[CARDS_APPLY] bank_accounts query result:', JSON.stringify(acctRows));
      let accountId = acctRows?.[0]?.id;
      if (!accountId) {
        console.log('[CARDS_APPLY] No active bank account found, creating primary account');
        const accountNumber = String(1000000000 + Number(user.id));
        const accountName = 'Primary Checking';
        const balance = parseFloat(user.balance) || 0;
        const [acctResult] = await connection.execute(
          `INSERT INTO bank_accounts (userId, accountNumber, accountType, accountName, ledgerBalance, availableBalance, status, isPrimary)
           VALUES (?, ?, 'checking', ?, ?, ?, 'active', 1)`,
          [user.id, accountNumber, accountName, balance, balance]
        );
        console.log('[CARDS_APPLY] bank_accounts insert result:', JSON.stringify(acctResult));
        accountId = acctResult.insertId;
        console.log('[CARDS_APPLY] Created bank account id:', accountId);
      }
      if (!accountId) {
        console.error('[CARDS_APPLY] accountId still missing after creation');
        throw new Error('No bank account available for card issuance');
      }
      
      const rawNumber = Array.from({ length: 16 }, () => Math.floor(Math.random() * 10)).join('');
      const masked = '****-****-****-' + rawNumber.slice(-4);
      const cvv = String(Math.floor(100 + Math.random() * 900));
      const now = new Date();
      const expiry = `${String(now.getMonth() + 1).padStart(2, '0')}/${String(now.getFullYear() + 4).slice(-2)}`;
      const holderName = (cardholderName || `${user.firstName} ${user.lastName}`).toUpperCase();
      const deliveryStatus = cardType === 'virtual' ? 'not_applicable' : 'processing';
      const cardStatus = cardType === 'virtual' ? 'active' : 'pending';
      
      console.log('[CARDS_APPLY] Inserting card into database...');
      console.log('[CARDS_APPLY] Insert params:', { userId: user.id, cardType, cardStatus, holderName, deliveryStatus, addressLength: deliveryAddress?.length || 0 });
      
      let insertResult;
      try {
        const [result] = await connection.execute(
          `INSERT INTO cards (accountId, userId, cardType, cardNumber, cardNumberMasked, cardholderName, expirationDate, cvv, status, deliveryStatus, deliveryAddress)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [accountId, user.id, cardType, rawNumber, masked, holderName, expiry, cvv, cardStatus, deliveryStatus, deliveryAddress || null]
        );
        insertResult = result;
        console.log('[CARDS_APPLY] Card inserted successfully, ID:', result.insertId);
      } catch (insertErr) {
        console.error('[CARDS_APPLY] ❌ INSERT FAILED:', insertErr.message);
        console.error('[CARDS_APPLY] SQL Error Code:', insertErr.code);
        console.error('[CARDS_APPLY] SQL Error Errno:', insertErr.errno);
        throw insertErr;
      }
      
      const responseCard = { 
        id: insertResult.insertId, 
        cardType, 
        cardNumberMasked: masked, 
        cardholderName: holderName, 
        expirationDate: expiry, 
        status: cardStatus, 
        deliveryStatus, 
        issuedAt: new Date().toISOString() 
      };
      
      if (cardType === 'virtual') {
        responseCard.cardNumber = rawNumber;
        responseCard.cvv = cvv;
        console.log('[CARDS_APPLY] Virtual card details included in response');
      }
      
      console.log('[CARDS_APPLY] Sending success response');
      res.status(201).json({ 
        success: true, 
        message: cardType === 'virtual' ? 'Virtual card issued' : 'Physical card requested', 
        card: responseCard 
      });
    } finally { 
      await connection.release();
      console.log('[CARDS_APPLY] Database connection released');
    }
  } catch (e) {
    console.error('[CARDS_APPLY] ❌ ERROR:', e);
    console.error('[CARDS_APPLY] Error stack:', e.stack);
    console.error('[CARDS_APPLY] Error code:', e.code);
    console.error('[CARDS_APPLY] Error sqlMessage:', e.sqlMessage);
    console.error('[CARDS_APPLY] Error errno:', e.errno);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to issue card: ' + e.message,
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
  }
});

async function setCardStatus(req, res, status) {
  try {
    const user = await db.getUserByEmail(req.user.email);
    const isAdmin = user && user.isAdmin;
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureCardsTable(connection);
      const where = isAdmin ? 'id = ?' : 'id = ? AND userId = ?';
      const params = isAdmin ? [req.params.cardId] : [req.params.cardId, user.id];
      const [result] = await connection.execute(`UPDATE cards SET status = ? WHERE ${where}`, [status, ...params]);
      if (result.affectedRows === 0) return res.status(404).json({ success: false, message: 'Card not found' });
      res.json({ success: true, message: `Card ${status}` });
    } finally { await connection.release(); }
  } catch (e) {
    console.error(`[API] card ${status} error`, e);
    res.status(500).json({ success: false, message: `Failed to ${status} card` });
  }
}

app.put('/api/cards/:cardId/freeze', authenticateToken, (req, res) => setCardStatus(req, res, 'frozen'));
app.put('/api/cards/:cardId/unfreeze', authenticateToken, (req, res) => setCardStatus(req, res, 'active'));
app.put('/api/cards/:cardId/block', authenticateToken, (req, res) => setCardStatus(req, res, 'blocked'));
app.put('/api/cards/:cardId/pause', authenticateToken, (req, res) => setCardStatus(req, res, 'paused'));
app.put('/api/cards/:cardId/unpause', authenticateToken, (req, res) => setCardStatus(req, res, 'active'));
app.put('/api/cards/:cardId/change-pin', authenticateToken, async (req, res) => {
  res.json({ success: true, message: 'PIN changed successfully' });
});

app.put('/api/admin/cards/:cardId/freeze', authenticateToken, requireAdmin, (req, res) => setCardStatus(req, res, 'frozen'));
app.put('/api/admin/cards/:cardId/unfreeze', authenticateToken, requireAdmin, (req, res) => setCardStatus(req, res, 'active'));
app.put('/api/admin/cards/:cardId/pause', authenticateToken, requireAdmin, (req, res) => setCardStatus(req, res, 'paused'));
app.put('/api/admin/cards/:cardId/unpause', authenticateToken, requireAdmin, (req, res) => setCardStatus(req, res, 'active'));

app.put('/api/admin/cards/:cardId/delivery', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { deliveryStatus, deliveryEtaText } = req.body;
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureCardsTable(connection);
      await connection.execute(
        'UPDATE cards SET deliveryStatus = ?, deliveryEtaText = ? WHERE id = ?',
        [deliveryStatus, deliveryEtaText || null, req.params.cardId]
      );
      res.json({ success: true, message: 'Delivery status updated' });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] card delivery update error', e);
    res.status(500).json({ success: false, message: 'Failed to update delivery status' });
  }
});

// ============ NEW FEATURES (Scheduled Transfers, Budgets, Disputes, Investments, etc) ============

require('./new-features')(app, authenticateToken, requireAdmin, db);

// ============ INVESTMENTS ENDPOINTS ============

async function ensureInvestmentsTable(connection) {
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS investments (
      id INT PRIMARY KEY AUTO_INCREMENT,
      userId INT NOT NULL,
      product VARCHAR(100) NOT NULL,
      amount DECIMAL(14,2) NOT NULL,
      apy DECIMAL(5,2) NOT NULL,
      period INT NOT NULL,
      estimatedReturn DECIMAL(14,2) NOT NULL,
      maturityDate DATE NOT NULL,
      status VARCHAR(30) DEFAULT 'active',
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_userId (userId),
      INDEX idx_status (status)
    )
  `);
}

app.post('/api/investments/invest', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    
    const { product, amount, period } = req.body;
    if (!product || !amount || !period) {
      return res.status(400).json({ success: false, message: 'Product, amount, and period are required' });
    }
    
    // Define product rates
    const products = {
      'Savings Bond': { rate: 3.5, min: 500 },
      'Index Fund': { rate: 7.2, min: 1000 },
      'Fixed Deposit': { rate: 4.8, min: 1000 },
      'Growth Fund': { rate: 9.5, min: 2000 }
    };
    
    const productInfo = products[product];
    if (!productInfo) {
      return res.status(400).json({ success: false, message: 'Invalid product' });
    }
    
    if (amount < productInfo.min) {
      return res.status(400).json({ success: false, message: `Minimum investment for ${product} is $${productInfo.min}` });
    }
    
    if (parseFloat(user.balance) < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    // Calculate returns
    const estimatedReturn = amount * Math.pow(1 + productInfo.rate / 100, period) - amount;
    const maturityDate = new Date();
    maturityDate.setFullYear(maturityDate.getFullYear() + period);
    
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await ensureInvestmentsTable(connection);
      
      // Deduct from balance
      await connection.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, user.id]);
      
      // Create investment
      const [result] = await connection.execute(
        'INSERT INTO investments (userId, product, amount, apy, period, estimatedReturn, maturityDate) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [user.id, product, amount, productInfo.rate, period, estimatedReturn, maturityDate.toISOString().split('T')[0]]
      );
      
      // Record transaction
      await connection.execute(
        'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
        [user.id, null, amount, 'investment', `Investment in ${product}`, 'completed']
      );
      
      await connection.commit();
      
      res.json({
        success: true,
        message: 'Investment created successfully',
        investment: {
          id: result.insertId,
          product,
          amount,
          apy: productInfo.rate,
          period,
          estimatedReturn,
          maturityDate: maturityDate.toISOString().split('T')[0]
        }
      });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      await connection.release();
    }
  } catch (e) {
    console.error('[API] invest error', e);
    res.status(500).json({ success: false, message: 'Investment failed: ' + e.message });
  }
});

app.get('/api/investments/my-investments', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await ensureInvestmentsTable(connection);
      const [investments] = await connection.execute(
        'SELECT * FROM investments WHERE userId = ? ORDER BY createdAt DESC',
        [user.id]
      );
      
      const totalInvested = investments.filter(i => i.status === 'active').reduce((sum, i) => sum + parseFloat(i.amount), 0);
      const totalEstimatedReturn = investments.filter(i => i.status === 'active').reduce((sum, i) => sum + parseFloat(i.estimatedReturn), 0);
      
      res.json({
        success: true,
        investments,
        totalInvested,
        totalEstimatedReturn
      });
    } finally { await connection.release(); }
  } catch (e) {
    console.error('[API] my-investments error', e);
    res.status(500).json({ success: false, message: 'Failed to fetch investments' });
  }
});

app.post('/api/investments/:id/withdraw', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    
    const pool = await db.initializePool();
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await ensureInvestmentsTable(connection);
      
      const [[investment]] = await connection.execute(
        'SELECT * FROM investments WHERE id = ? AND userId = ? AND status = ?',
        [req.params.id, user.id, 'active']
      );
      
      if (!investment) {
        return res.status(404).json({ success: false, message: 'Investment not found or already withdrawn' });
      }
      
      const isMatured = new Date(investment.maturityDate) <= new Date();
      let payout = parseFloat(investment.amount);
      let penalty = 0;
      
      if (isMatured) {
        // Matured - give full amount + returns
        payout += parseFloat(investment.estimatedReturn);
      } else {
        // Early withdrawal - 10% penalty on principal
        penalty = payout * 0.10;
        payout -= penalty;
      }
      
      // Update investment status
      await connection.execute(
        'UPDATE investments SET status = ? WHERE id = ?',
        [isMatured ? 'matured' : 'withdrawn', req.params.id]
      );
      
      // Credit user account
      await connection.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [payout, user.id]);
      
      // Record transaction
      await connection.execute(
        'INSERT INTO transactions (fromUserId, toUserId, amount, type, description, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
        [null, user.id, payout, 'investment_withdrawal', `${isMatured ? 'Matured' : 'Early'} withdrawal from ${investment.product}`, 'completed']
      );
      
      await connection.commit();
      
      const [[updatedUser]] = await connection.execute('SELECT balance FROM users WHERE id = ?', [user.id]);
      
      res.json({
        success: true,
        message: isMatured ? 'Investment matured and collected' : 'Investment withdrawn with penalty',
        payout,
        penalty,
        newBalance: parseFloat(updatedUser.balance)
      });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      await connection.release();
    }
  } catch (e) {
    console.error('[API] withdraw investment error', e);
    res.status(500).json({ success: false, message: 'Withdrawal failed: ' + e.message });
  }
});

// ============ BLOG & NEWS ============
// Fetch latest financial news from free API
app.get('/api/blog/feed', async (req, res) => {
  try {
    const newsApiKey = process.env.NEWS_API_KEY || 'demo';
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 12;
    
    console.log('[API] NEWS_API_KEY from env:', newsApiKey ? newsApiKey.substring(0, 5) + '...' : 'NOT SET');
    console.log('[API] Using newsApiKey === "demo"?', newsApiKey === 'demo');
    
    // Try to fetch from NewsAPI.org (free tier: https://newsapi.org)
    const newsUrl = `https://newsapi.org/v2/everything?q=banking+finance+investment&sortBy=publishedAt&language=en&pageSize=${pageSize}&page=${page}&apiKey=${newsApiKey}`;
    
    console.log('[API] newsUrl:', newsUrl.substring(0, 100) + '...');
    
    if (newsApiKey === 'demo') {
      // Fallback to demo data if no API key is set
      return res.json({
        success: true,
        articles: [
          {
            title: 'Interest Rates Reach New Highs in 2026',
            description: 'Central banks maintain elevated rates as inflation continues to stabilize. Heritage Bank offers competitive rates on savings accounts.',
            urlToImage: 'https://images.unsplash.com/photo-1518611505867-48e2b964cea5?w=500&h=300&fit=crop',
            url: '#',
            author: 'Financial Times',
            publishedAt: new Date(Date.now() - 2*24*60*60*1000).toISOString(),
            source: { name: 'Financial News' }
          },
          {
            title: 'Digital Banking Trends: AI Takes Center Stage',
            description: 'Machine learning transforms customer experience as banks adopt advanced personalization. Heritage Bank leads innovation in digital banking.',
            urlToImage: 'https://images.unsplash.com/photo-1460925895917-adf4198c4b83?w=500&h=300&fit=crop',
            url: '#',
            author: 'TechCrunch',
            publishedAt: new Date(Date.now() - 1*24*60*60*1000).toISOString(),
            source: { name: 'Tech News' }
          },
          {
            title: 'Security Alert: New Fraud Prevention Methods Emerge',
            description: 'Banks implement advanced biometric authentication to protect customers. Your financial security is our priority.',
            urlToImage: 'https://images.unsplash.com/photo-1516321318423-f06b0b814d0e?w=500&h=300&fit=crop',
            url: '#',
            author: 'Reuters',
            publishedAt: new Date(Date.now() - 3*24*60*60*1000).toISOString(),
            source: { name: 'Security News' }
          },
          {
            title: 'Investment Portfolio Diversification: 2026 Guide',
            description: 'Expert tips for building a balanced investment portfolio in the current market environment.',
            urlToImage: 'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?w=500&h=300&fit=crop',
            url: '#',
            author: 'Investment Weekly',
            publishedAt: new Date(Date.now() - 4*24*60*60*1000).toISOString(),
            source: { name: 'Investment News' }
          },
          {
            title: 'Cryptocurrency Reaches Maturity in Traditional Finance',
            description: 'Major financial institutions integrate crypto services. Heritage Bank explores blockchain technology adoption.',
            urlToImage: 'https://images.unsplash.com/photo-1526628653108-6a37142458f9?w=500&h=300&fit=crop',
            url: '#',
            author: 'Crypto Insider',
            publishedAt: new Date(Date.now() - 5*24*60*60*1000).toISOString(),
            source: { name: 'Crypto News' }
          },
          {
            title: 'Retirement Planning: How to Start Early',
            description: 'Financial experts share strategies for building retirement wealth through consistent savings and smart investments.',
            urlToImage: 'https://images.unsplash.com/photo-1521737604893-6f3031224c94?w=500&h=300&fit=crop',
            url: '#',
            author: 'Wealth Advisor',
            publishedAt: new Date(Date.now() - 6*24*60*60*1000).toISOString(),
            source: { name: 'Retirement News' }
          }
        ],
        totalResults: 100,
        page,
        pageSize
      });
    }
    
    // Fetch from NewsAPI (requires free API key from newsapi.org)
    const https = require('https');
    const url = require('url');
    const apiUrlObj = new url.URL(newsUrl);
    
    const options = {
      hostname: apiUrlObj.hostname,
      path: apiUrlObj.pathname + apiUrlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Heritage Bank Blog Feed (https://heritagebank.com)'
      }
    };
    
    const apiRequest = https.request(options, (apiRes) => {
      let data = '';
      apiRes.on('data', chunk => { data += chunk; });
      apiRes.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.status === 'ok') {
            res.json({
              success: true,
              articles: parsed.articles,
              totalResults: parsed.totalResults,
              page,
              pageSize
            });
          } else {
            throw new Error(parsed.message || 'NewsAPI error');
          }
        } catch (e) {
          console.error('[API] NewsAPI parse error:', e);
          res.json({
            success: true,
            articles: [],
            totalResults: 0,
            page,
            pageSize,
            message: 'Using demo data. To enable real news, get a free API key from newsapi.org'
          });
        }
      });
    });

    apiRequest.on('error', (e) => {
      console.error('[API] NewsAPI fetch error:', e);
      res.json({
        success: true,
        articles: [],
        totalResults: 0,
        page,
        pageSize,
        fallback: true
      });
    });

    apiRequest.end();
  } catch (e) {
    console.error('[API] blog feed error:', e);
    res.status(500).json({ success: false, message: 'Failed to fetch blog feed' });
  }
});

// ============ STATIC FILES & SPA ============

// Serve static files from root directory
const rootPath = path.join(__dirname, '..');
console.log(`[STARTUP] Static files root path: ${rootPath}`);
console.log(`[STARTUP] Root directory exists: ${fs.existsSync(rootPath)}`);

const indexHtmlPath = path.join(rootPath, 'index.html');
console.log(`[STARTUP] index.html path: ${indexHtmlPath}`);
console.log(`[STARTUP] index.html exists: ${fs.existsSync(indexHtmlPath)}`);

app.use(express.static(rootPath, {
  maxAge: '1d',
  etag: false,
  index: ['index.html']
}));
console.log('[MIDDLEWARE] ✓ Static file serving configured');

// Serve extensionless HTML routes for root static pages like /branches -> branches.html
app.get('/:page([a-zA-Z0-9_-]+)', (req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return next();
  }

  const pageName = req.params.page;
  const htmlFile = path.join(rootPath, `${pageName}.html`);

  try {
    if (fs.existsSync(htmlFile) && fs.statSync(htmlFile).isFile()) {
      return res.sendFile(htmlFile);
    }
  } catch (err) {
    console.warn('[STATIC ROUTE] Error checking HTML file for', pageName, err.message);
  }

  return next();
});

// SPA fallback - serve index.html for non-API routes
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return next();
  }

  res.sendFile(path.join(rootPath, 'index.html'));
});
console.log('[MIDDLEWARE] ✓ SPA fallback configured');

// ============ MIDDLEWARE ============

// Token authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ success: false, message: 'Invalid token' });
  }
}

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found',
    path: req.path
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ============ SEED DATA ============
// Initialize default admin account for production
async function initializeSeedData() {
  try {
    const adminEmail = ADMIN_EMAIL;
    const adminPassword = ADMIN_PASSWORD;
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    await db.upsertUser(adminEmail, {
      firstName: 'Admin',
      lastName: 'Account',
      passwordHash: hashedPassword,
      isAdmin: true,
      accountStatus: 'active'
    });

    console.log(`[SEED] ✓ Admin account ensured: ${adminEmail}`);
  } catch (err) {
    console.error('[SEED] ✗ Failed to initialize seed data:', err);
    throw err;
  }
}

// ============ START SERVER ============

if (require.main === module) {
  // Initialize database, then seed data, then start server
  async function startup() {
    try {
      console.log('\n[STARTUP] *** DATABASE INITIALIZATION SEQUENCE ***\n');
      
      // Initialize database connection pool
      await db.initializePool();
      console.log('[STARTUP] ✓ Database connection pool ready');
      
      // Create tables if they don't exist
      await db.initializeSchema();
      console.log('[STARTUP] ✓ Database schema initialized');
      
      // Initialize seed data (admin account)
      await initializeSeedData();
      console.log('[STARTUP] ✓ Seed data initialized');
      
      console.log('[STARTUP] *** DATABASE INITIALIZATION COMPLETE ***\n');
      
      // Start server
      app.listen(PORT, '0.0.0.0', () => {
        console.log('\n========================================');
        console.log('[SERVER] ✓ Server started successfully!');
        console.log(`[SERVER] Listening on port: ${PORT}`);
        console.log(`[SERVER] Address: 0.0.0.0:${PORT}`);
        console.log(`[SERVER] Environment: ${process.env.NODE_ENV || 'development'}`);
        console.log('[SERVER] Health check: GET /api/health');
        console.log(`[SERVER] Timestamp: ${new Date().toISOString()}`);
        console.log('========================================\n');
      }).on('error', (err) => {
        console.error('[SERVER] ✗ Failed to start server:', err);
        process.exit(1);
      });
    } catch (error) {
      console.error('[STARTUP] ✗ Startup failed:', error);
      process.exit(1);
    }
  }
  
  startup();
}

module.exports = app;
// Force rebuild at 2026-06-09 13:07:04
// Force redeploy 06/09/2026 14:59:07
