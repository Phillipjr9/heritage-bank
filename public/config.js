// Heritage Bank - API Configuration
// Frontend auto-detects whether it's running locally or on Cloudflare Pages

window.API_URL = (() => {
    const { hostname, protocol } = window.location;

    // Local development
    if (protocol === 'file:' || hostname === 'localhost' || hostname === '127.0.0.1') {
        return 'http://localhost:3001';
    }

    // Production - points to Railway backend
    // Update RAILWAY_BACKEND_URL with your actual Railway URL after deploying backend
    const RAILWAY_BACKEND_URL = 'https://heritagebank-production.up.railway.app';
    return RAILWAY_BACKEND_URL;
})();
