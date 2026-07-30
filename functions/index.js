/**
 * Heritage Bank - Firebase Cloud Functions Entry Point
 *
 * This file wraps the existing Express app (backend/server.js) as a
 * Firebase Cloud Function. The database stays on MySQL/TiDB — no migration needed.
 *
 * Environment variables are set via:
 *   firebase functions:secrets:set DB_HOST
 *   firebase functions:secrets:set DB_PASSWORD
 *   ... etc
 * Or via the Firebase Console → Functions → Configuration.
 */

const functions = require('firebase-functions');
const admin = require('firebase-admin');

// Initialize Firebase Admin (needed for the SDK, even if we don't use Firestore)
if (!admin.apps.length) {
  admin.initializeApp();
}

// Load the Express app from the backend folder.
// All routes, middleware, and DB logic stay exactly the same.
const app = require('../backend/server');

// Export the Express app as a single Firebase Cloud Function named "api".
// firebase.json routes /api/** → this function.
exports.api = functions
  .runWith({
    // Increase timeout for financial operations (max 540s on Blaze plan)
    timeoutSeconds: 120,
    // Allocate enough memory for PDF generation and DB connection pool
    memory: '512MB',
  })
  .https.onRequest(app);
