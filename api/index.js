/**
 * Vercel Serverless Function - Heritage Bank Backend API
 * 
 * This wraps the Express backend to run on Vercel Functions.
 * Firebase Admin SDK is initialized via FIREBASE_SERVICE_ACCOUNT env var.
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');
const path = require('path');

// Initialize Firebase Admin from Vercel environment variable
let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    // Vercel passes JSON as stringified env var
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    console.log('✓ Firebase credentials loaded from FIREBASE_SERVICE_ACCOUNT env var');
  } catch (err) {
    console.error('✗ Failed to parse FIREBASE_SERVICE_ACCOUNT:', err.message);
    throw new Error('Invalid Firebase credentials: ' + err.message);
  }
} else {
  throw new Error('FIREBASE_SERVICE_ACCOUNT environment variable not set');
}

// Initialize Firebase Admin SDK
try {
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log('✓ Firebase Admin SDK initialized');
  }
} catch (err) {
  console.error('✗ Failed to initialize Firebase:', err.message);
  throw err;
}

const db = admin.firestore();
const auth = admin.auth();

// Create Express app
const app = express();
app.set('etag', false);

// Load environment variables
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// Constants
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'support@heritagebank.com';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const PRODUCTION_ORIGIN = process.env.PRODUCTION_ORIGIN || 'https://heritage-bank.vercel.app';

// Rate limiting
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });

// CORS - Allow Vercel deployment domain + local dev
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : [
      'https://heritage-bank.vercel.app',
      'http://localhost:3000',
      'http://localhost:5173',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173'
    ];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.indexOf(origin) !== -1) return callback(null, true);
    callback(new Error('CORS not allowed'));
  },
  credentials: true
}));

// Middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(apiLimiter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Auth endpoints
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, firstName, lastName, ssn } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    // Create Firebase user
    const userRecord = await auth.createUser({
      email,
      password,
      displayName: `${firstName} ${lastName}`
    });

    // Store user data in Firestore
    await db.collection('users').doc(userRecord.uid).set({
      email,
      firstName,
      lastName,
      ssn: ssn ? Buffer.from(ssn).toString('base64') : null,
      createdAt: new Date(),
      accountStatus: 'active',
      profileComplete: !!ssn
    });

    // Generate JWT
    const token = require('jsonwebtoken').sign({ uid: userRecord.uid }, JWT_SECRET, {
      expiresIn: '7d'
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: { uid: userRecord.uid, email },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(400).json({ message: error.message });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    // Verify with Firebase (in production, use Firebase REST API)
    const user = await auth.getUserByEmail(email);

    // Generate JWT
    const token = require('jsonwebtoken').sign({ uid: user.uid }, JWT_SECRET, {
      expiresIn: '7d'
    });

    res.json({
      message: 'Login successful',
      user: { uid: user.uid, email: user.email },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Default 404
app.use((req, res) => {
  res.status(404).json({ message: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Export for Vercel
module.exports = app;
