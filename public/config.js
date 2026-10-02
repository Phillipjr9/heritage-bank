// Heritage Bank - API Configuration
//
// ARCHITECTURE: the frontend and the backend are hosted SEPARATELY.
//   • Frontend : Cloudflare Pages  → https://heritage-bank.pages.dev  (static files only)
//   • Backend  : Render web service → runs backend/server.js (Express + MySQL/TiDB)
//
// Cloudflare Pages cannot run the Express API, so these pages must call the
// backend by its ABSOLUTE URL. This file is the single place that URL is
// defined — every page loads config.js and reads window.API_URL.

// ============================================================================
// ►► SET THIS to your Render service URL after deploying (no trailing slash).
//    Find it in the Render dashboard, e.g. https://heritage-bank-api.onrender.com
// ============================================================================
const BACKEND_URL = 'https://heritage-bank-zr16.onrender.com';

window.API_URL = (() => {
    const { hostname, protocol, origin } = window.location;

    // Escape hatch for testing against another backend without a redeploy:
    //   localStorage.setItem('apiUrl', 'https://some-other-backend.onrender.com')
    try {
        const override = localStorage.getItem('apiUrl');
        if (override) return override.replace(/\/$/, '');
    } catch (_) { /* localStorage blocked */ }

    // Local development — `node backend/server.js` listens on 3000 by default.
    if (protocol === 'file:' || hostname === 'localhost' || hostname === '127.0.0.1') {
        return 'http://localhost:3000';
    }

    // Served directly BY the backend (Render serves the repo root too), so the
    // API is same-origin and no cross-origin call is needed.
    if (hostname.endsWith('.onrender.com')) {
        return origin;
    }

    // Static hosting (Cloudflare Pages, Vercel, Firebase) → cross-origin API.
    return BACKEND_URL;
})();

console.log('[Config] API_URL =', window.API_URL);
