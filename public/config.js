// Heritage Bank - API Configuration
// Frontend auto-detects local dev vs deployed. In production the API is
// served same-origin by the Render web service, so no host is hard-coded.

window.API_URL = (() => {
    const { hostname, protocol } = window.location;

    // Local development
    if (protocol === 'file:' || hostname === 'localhost' || hostname === '127.0.0.1') {
        return 'http://localhost:3001';
    }

    // Production - same origin (Render serves the API and frontend together)
    return window.location.origin;
})();
