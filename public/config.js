// Heritage Bank - API Configuration
// Frontend auto-detects whether it's running locally or on Cloudflare Pages

window.API_URL = (() => {
    const { hostname, protocol } = window.location;

    // Local development
    if (protocol === 'file:' || hostname === 'localhost' || hostname === '127.0.0.1') {
        return 'http://localhost:3001';
    }

    // Production - Railway backend
    return 'https://heritage-bank-production.up.railway.app';
})();
