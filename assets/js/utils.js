/**
 * Shared Utility Functions for Heritage Bank Frontend
 * This file contains common functions used across multiple pages
 */

// API URL Configuration
const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
    ? 'http://localhost:3001' 
    : '';

/**
 * Password Strength Checker
 * @param {string} password - The password to check
 * @returns {Object} - Object with score, level, and color
 */
function checkPasswordStrength(password) {
    const strength = {
        score: 0,
        level: 'Very Weak',
        color: '#f44336'
    };
    
    if (!password) return strength;
    
    // Calculate strength score
    if (password.length >= 8) strength.score++;
    if (password.length >= 12) strength.score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength.score++;
    if (/\d/.test(password)) strength.score++;
    if (/[^a-zA-Z\d]/.test(password)) strength.score++;
    
    // Determine level and color based on score
    if (strength.score <= 1) {
        strength.level = 'Very Weak';
        strength.color = '#f44336';
    } else if (strength.score === 2) {
        strength.level = 'Weak';
        strength.color = '#ff9800';
    } else if (strength.score === 3) {
        strength.level = 'Medium';
        strength.color = '#ffc107';
    } else if (strength.score === 4) {
        strength.level = 'Strong';
        strength.color = '#8bc34a';
    } else {
        strength.level = 'Very Strong';
        strength.color = '#4caf50';
    }
    
    return strength;
}

/**
 * Check Authentication
 * Redirects to signin page if no token is found
 * @returns {string|null} - Returns token if found, null otherwise
 */
function checkAuth() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'signin.html';
        return null;
    }
    return token;
}

/**
 * Format Currency
 * @param {number|string} amount - The amount to format
 * @returns {string} - Formatted currency string
 */
function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(amount);
}

/**
 * Format Date
 * @param {string|Date} date - The date to format
 * @returns {string} - Formatted date string
 */
function formatDate(date) {
    return new Date(date).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
}

/**
 * Format Date and Time
 * @param {string|Date} date - The date to format
 * @returns {string} - Formatted date and time string
 */
function formatDateTime(date) {
    return new Date(date).toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/**
 * Mask Account Number
 * Shows only the last 4 digits
 * @param {string} accountNumber - The account number to mask
 * @returns {string} - Masked account number
 */
function maskAccountNumber(accountNumber) {
    if (!accountNumber) return '';
    const last4 = accountNumber.slice(-4);
    return `****${last4}`;
}

/**
 * Show Alert Message
 * @param {string} message - The message to display
 * @param {string} type - The alert type (success, error, warning, info)
 */
function showAlert(message, type = 'info') {
    // Create alert element if it doesn't exist
    let alertBox = document.getElementById('alertBox');
    if (!alertBox) {
        alertBox = document.createElement('div');
        alertBox.id = 'alertBox';
        alertBox.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 4px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            z-index: 10000;
            max-width: 400px;
            animation: slideIn 0.3s ease-out;
        `;
        document.body.appendChild(alertBox);
    }
    
    // Set colors based on type
    const colors = {
        success: { bg: '#4caf50', text: '#fff' },
        error: { bg: '#f44336', text: '#fff' },
        warning: { bg: '#ff9800', text: '#fff' },
        info: { bg: '#2196f3', text: '#fff' }
    };
    
    const color = colors[type] || colors.info;
    alertBox.style.backgroundColor = color.bg;
    alertBox.style.color = color.text;
    alertBox.textContent = message;
    alertBox.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        alertBox.style.display = 'none';
    }, 5000);
}

/**
 * Make Authenticated API Request
 * @param {string} endpoint - The API endpoint
 * @param {Object} options - Fetch options
 * @returns {Promise<Response>} - The fetch response
 */
async function authenticatedFetch(endpoint, options = {}) {
    const token = localStorage.getItem('token');
    
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': token ? `Bearer ${token}` : ''
        }
    };
    
    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...(options.headers || {})
        }
    };
    
    const response = await fetch(`${API_URL}${endpoint}`, mergedOptions);
    
    if (response.status === 401) {
        // Token expired or invalid
        localStorage.removeItem('token');
        window.location.href = 'signin.html';
        throw new Error('Authentication required');
    }
    
    return response;
}

// Export functions for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        API_URL,
        checkPasswordStrength,
        checkAuth,
        formatCurrency,
        formatDate,
        formatDateTime,
        maskAccountNumber,
        showAlert,
        authenticatedFetch
    };
}
