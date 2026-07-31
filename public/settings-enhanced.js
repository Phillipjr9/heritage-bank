/**
 * Enhanced Settings Page JavaScript
 * Handles all banking profile features: account info, documents, beneficiaries,
 * security, 2FA, login history, sessions, data export, and account controls
 */

const API_URL = window.API_URL || (() => {
    const { hostname, protocol } = window.location;
    if (protocol === 'file:' || hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '0.0.0.0') {
        return 'http://localhost:3001';
    }
    return `${window.location.protocol}//${window.location.host}`;
})();

// HTML escape helper to prevent XSS
function escapeHtml(str) {
    if (str == null) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function getProfileImageSrc(profileImage) {
    if (!profileImage) return null;
    if (/^data:/i.test(profileImage) || /^https?:\/\//i.test(profileImage)) return profileImage;
    if (profileImage.startsWith('/')) return `${API_URL}${profileImage}`;
    if (profileImage.startsWith('assets/')) return `${API_URL}/${profileImage}`;
    return `${API_URL}/backend/${profileImage}`;
}

let userId = null;
let loginHistoryCache = [];
let activeSessionsCache = [];

// ============================================================================
// AUTHENTICATION & INITIALIZATION
// ============================================================================

async function checkAuth() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'signin.html';
        return;
    }
    
    try {
        const res = await fetch(`${API_URL}/api/user/profile/complete`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!res.ok) {
            if (res.status === 401) {
                window.location.href = 'signin.html';
                return;
            }
            throw new Error('Failed to load profile');
        }
        
        const data = await res.json();
        
        if (data.success && data.user) {
            userId = data.user.id;
            await populateAllSections(data.user);
        } else {
            window.location.href = 'signin.html';
        }
    } catch (e) {
        console.error('Auth error:', e);
        showAlert('Error loading profile: ' + e.message, 'error');
    }
}

async function populateAllSections(user) {
    // Populate basic profile
    populateProfileForm(user);
    
    // Populate account information
    populateAccountInfo(user);
    
    // Populate transaction limits
    populateTransactionLimits(user);
    
    // Load login history
    await loadLoginHistory();
    
    // Load active sessions
    await loadActiveSessions();
    
    // Load beneficiaries
    await loadBeneficiaries();
    
    // Load document verification status
    await loadDocumentStatus(user);

    // Load recent activity
    await loadActivity();
    
    // Load account controls state
    populateAccountControls(user);
    
    // Load preferences
    await loadPreferences(user);
}

// ============================================================================
// PROFILE FORM - BASIC & ENHANCED
// ============================================================================

function populateProfileForm(user) {
    // Profile picture
    loadProfilePicture(user);
    
    // Basic fields
    document.getElementById('firstName').value = user.firstName || '';
    document.getElementById('lastName').value = user.lastName || '';
    document.getElementById('email').value = user.email || '';
    document.getElementById('phone').value = user.phone || '';
    document.getElementById('address').value = user.address || '';
    document.getElementById('city').value = user.city || '';
    document.getElementById('country').value = user.country || 'United States';
    
    // Enhanced fields (if present)
    if (document.getElementById('dateOfBirth')) {
        document.getElementById('dateOfBirth').value = user.dateOfBirth || '';
    }
    if (document.getElementById('ssn')) {
        document.getElementById('ssn').value = maskSSN(user.ssn) || '';
    }
    if (document.getElementById('state')) {
        document.getElementById('state').value = user.state || '';
    }
    if (document.getElementById('zipCode')) {
        document.getElementById('zipCode').value = user.zipCode || '';
    }
    if (document.getElementById('gender')) {
        document.getElementById('gender').value = user.gender || '';
    }
    
    // Populate verification badges
    updateVerificationBadges(user);
}

function maskSSN(ssn) {
    if (!ssn) return '';
    const clean = ssn.replace(/\D/g, '');
    if (clean.length !== 9) return '';
    return `***-**-${clean.slice(-4)}`;
}

function updateVerificationBadges(user) {
    const emailBadge = document.getElementById('emailVerificationBadge');
    const phoneBadge = document.getElementById('phoneVerificationBadge');
    const verifyEmailBtn = document.getElementById('verifyEmailBtn');
    const verifyPhoneBtn = document.getElementById('verifyPhoneBtn');
    
    if (emailBadge) {
        if (user.emailVerified) {
            emailBadge.innerHTML = '<i class="fas fa-check-circle" style="color: #4caf50;"></i> Verified';
            emailBadge.style.color = '#4caf50';
            if (verifyEmailBtn) verifyEmailBtn.style.display = 'none';
        } else {
            emailBadge.innerHTML = '<i class="fas fa-exclamation-circle" style="color: #ff9800;"></i> Unverified';
            emailBadge.style.color = '#ff9800';
            if (verifyEmailBtn) verifyEmailBtn.style.display = '';
        }
    }
    
    if (phoneBadge) {
        if (user.phoneVerified) {
            phoneBadge.innerHTML = '<i class="fas fa-check-circle" style="color: #4caf50;"></i> Verified';
            phoneBadge.style.color = '#4caf50';
            if (verifyPhoneBtn) verifyPhoneBtn.style.display = 'none';
        } else {
            phoneBadge.innerHTML = '<i class="fas fa-exclamation-circle" style="color: #ff9800;"></i> Unverified';
            phoneBadge.style.color = '#ff9800';
            if (verifyPhoneBtn) verifyPhoneBtn.style.display = '';
        }
    }
}

// ============================================================================
// EMAIL & PHONE VERIFICATION
// ============================================================================

async function sendEmailVerification() {
    const token = localStorage.getItem('token');
    try {
        const res = await fetch(`${API_URL}/api/user/resend-email-verification`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        if (data.success) {
            showAlert(data.message || 'Verification email sent!', 'success');
            await checkAuth();
        } else {
            showAlert(data.message || 'Verification failed', 'error');
        }
    } catch (e) {
        showAlert('Error: ' + e.message, 'error');
    }
}
window.sendEmailVerification = sendEmailVerification;

async function sendPhoneVerification() {
    const token = localStorage.getItem('token');
    try {
        const res = await fetch(`${API_URL}/api/user/verify-phone`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        if (data.success) {
            showAlert(data.message || 'Phone verification sent!', 'success');
            await checkAuth();
        } else {
            showAlert(data.message || 'Verification failed', 'error');
        }
    } catch (e) {
        showAlert('Error: ' + e.message, 'error');
    }
}
window.sendPhoneVerification = sendPhoneVerification;

// ============================================================================
// ACCOUNT INFORMATION DISPLAY
// ============================================================================

function populateAccountInfo(user) {
    const accountNumberEl = document.getElementById('accountNumber');
    const routingNumberEl = document.getElementById('routingNumber');
    const accountTypeEl = document.getElementById('accountType');
    const accountStatusEl = document.getElementById('accountStatus');
    const balanceEl = document.getElementById('currentBalance');
    const memberSinceEl = document.getElementById('memberSince');
    
    if (accountNumberEl) {
        accountNumberEl.textContent = formatAccountNumber(user.accountNumber || '');
    }
    if (routingNumberEl) {
        routingNumberEl.textContent = user.routingNumber || 'N/A';
    }
    if (accountTypeEl) {
        accountTypeEl.textContent = formatAccountType(user.accountType || '');
    }
    if (accountStatusEl) {
        accountStatusEl.innerHTML = getStatusBadge(user.accountStatus || 'active');
    }
    if (balanceEl) {
        balanceEl.textContent = formatCurrency(user.balance || 0);
    }
    if (memberSinceEl && user.createdAt) {
        memberSinceEl.textContent = formatDate(user.createdAt);
    }
}

function formatAccountNumber(num) {
    const str = String(num).padStart(10, '0');
    return str.slice(0, 4) + '-' + str.slice(4);
}

function formatAccountType(type) {
    const types = {
        'checking': 'Checking Account',
        'savings': 'Savings Account',
        'money-market': 'Money Market Account',
        'cd': 'Certificate of Deposit'
    };
    return types[type] || type;
}

function getStatusBadge(status) {
    const badges = {
        'active': '<span class="badge" style="background: #4caf50;">Active</span>',
        'frozen': '<span class="badge" style="background: #ff9800;">Frozen</span>',
        'suspended': '<span class="badge" style="background: #f44336;">Suspended</span>',
        'pending': '<span class="badge" style="background: #2196f3;">Pending</span>'
    };
    return badges[status] || `<span class="badge">${status}</span>`;
}

function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD',
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(amount);
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
}

// ============================================================================
// TRANSACTION LIMITS
// ============================================================================

function populateTransactionLimits(user) {
    const daily = {
        limit: user.dailyTransferLimit || 10000,
        spent: user.dailyTransferSpent || 0
    };
    const weekly = {
        limit: user.weeklyTransferLimit || 50000,
        spent: user.weeklyTransferSpent || 0
    };
    const monthly = {
        limit: user.monthlyTransferLimit || 200000,
        spent: user.monthlyTransferSpent || 0
    };
    
    updateLimitDisplay('daily', daily);
    updateLimitDisplay('weekly', weekly);
    updateLimitDisplay('monthly', monthly);
    
    const singleEl = document.getElementById('singleTransactionLimit');
    if (singleEl) {
        singleEl.textContent = formatCurrency(user.singleTransactionLimit || 25000);
    }
}

function updateLimitDisplay(period, data) {
    const percentUsed = Math.round((data.spent / data.limit) * 100);
    const labelEl = document.getElementById(`${period}Limit`);
    const progressEl = document.getElementById(`${period}Progress`);
    const spentEl = document.getElementById(`${period}Spent`);
    
    if (labelEl) {
        labelEl.textContent = formatCurrency(data.limit);
    }
    if (spentEl) {
        spentEl.textContent = `${formatCurrency(data.spent)} of ${formatCurrency(data.limit)}`;
    }
    if (progressEl) {
        progressEl.style.width = percentUsed + '%';
        const color = percentUsed > 80 ? '#f44336' : percentUsed > 50 ? '#ff9800' : '#4caf50';
        progressEl.style.backgroundColor = color;
    }
}

// ============================================================================
// PROFILE UPDATE
// ============================================================================

// ============================================================================
// PROFILE PICTURE
// ============================================================================

function getDefaultAvatar(gender) {
    if (gender === 'female') return 'assets/avatar-female.jpg';
    return 'assets/avatar-male.jpg';
}

function loadProfilePicture(user) {
    const img = document.getElementById('profilePictureImg');
    const icon = document.getElementById('profilePictureIcon');
    const removeBtn = document.getElementById('removeProfilePicBtn');
    const nameEl = document.getElementById('profilePictureName');

    if (nameEl && user.firstName) {
        nameEl.textContent = `${user.firstName} ${user.lastName || ''}`.trim();
    }

    // Store gender for avatar fallback
    window._userGender = user.gender || null;

    if (user.profileImage) {
        const src = getProfileImageSrc(user.profileImage);
        img.src = src;
        img.style.display = 'block';
        if (icon) icon.style.display = 'none';
        if (removeBtn) removeBtn.style.display = '';
    } else {
        // Show icon until image is uploaded
        img.style.display = 'none';
        if (icon) icon.style.display = 'block';
        if (removeBtn) removeBtn.style.display = 'none';
    }

    // Also update sidebar avatar if present
    updateSidebarAvatar(user.profileImage, user.gender);
}

function updateSidebarAvatar(profileImage, gender) {
    const avatar = document.getElementById('sidebarUserAvatar');
    const avatarIcon = document.getElementById('sidebarUserAvatarIcon');
    const avatarImg = document.getElementById('sidebarUserAvatarImg');
    if (!avatar) return;

    if (profileImage) {
        if (avatarImg) {
            avatarImg.src = getProfileImageSrc(profileImage);
            avatarImg.style.display = 'block';
        }
        if (avatarIcon) avatarIcon.style.display = 'none';
    } else {
        // Show icon until image is uploaded
        if (avatarImg) avatarImg.style.display = 'none';
        if (avatarIcon) avatarIcon.style.display = 'block';
    }
}

function handleProfilePictureSelect(e) {
    const file = e.target.files[0];
    if (!file) return;

    // Validate type
    const validTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!validTypes.includes(file.type)) {
        showAlert('Invalid image format. Please use JPEG, PNG, GIF, or WebP.', 'error');
        return;
    }

    // Validate size (5MB)
    if (file.size > 5 * 1024 * 1024) {
        showAlert('Image too large. Maximum size is 5MB.', 'error');
        return;
    }

    const reader = new FileReader();
    reader.onload = async function(ev) {
        await uploadProfilePicture(ev.target.result, file.name);
    };
    reader.readAsDataURL(file);

    // Reset input so same file can be re-selected
    e.target.value = '';
}

async function uploadProfilePicture(fileData, fileName) {
    const token = localStorage.getItem('token');
    try {
        const res = await fetch(`${API_URL}/api/user/profile/picture`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ fileData, fileName })
        });

        const data = await res.json();
        if (data.success) {
            showAlert('Profile picture updated!', 'success');
            // Update UI
            const img = document.getElementById('profilePictureImg');
            const icon = document.getElementById('profilePictureIcon');
            const removeBtn = document.getElementById('removeProfilePicBtn');
            img.src = getProfileImageSrc(data.profileImage);
            img.style.display = 'block';
            if (icon) icon.style.display = 'none';
            if (removeBtn) removeBtn.style.display = '';
            updateSidebarAvatar(data.profileImage, window._userGender);
        } else {
            showAlert(data.message || 'Upload failed', 'error');
        }
    } catch (e) {
        showAlert('Error uploading picture: ' + e.message, 'error');
    }
}

async function removeProfilePicture() {
    const token = localStorage.getItem('token');
    try {
        const res = await fetch(`${API_URL}/api/user/profile/picture`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await res.json();
        if (data.success) {
            showAlert('Profile picture removed', 'success');
            const img = document.getElementById('profilePictureImg');
            const icon = document.getElementById('profilePictureIcon');
            const removeBtn = document.getElementById('removeProfilePicBtn');
            img.style.display = 'none';
            if (icon) icon.style.display = 'block';
            if (removeBtn) removeBtn.style.display = 'none';
            updateSidebarAvatar(null, window._userGender);
        } else {
            showAlert(data.message || 'Remove failed', 'error');
        }
    } catch (e) {
        showAlert('Error removing picture: ' + e.message, 'error');
    }
}

// Make removeProfilePicture available globally
window.removeProfilePicture = removeProfilePicture;

// ============================================================================
// PROFILE UPDATE
// ============================================================================

async function updateProfile(e) {
    e?.preventDefault();
    const token = localStorage.getItem('token');
    
    const profileData = {
        firstName: document.getElementById('firstName').value,
        lastName: document.getElementById('lastName').value,
        email: document.getElementById('email').value,
        phone: document.getElementById('phone').value,
        address: document.getElementById('address').value,
        city: document.getElementById('city').value,
        state: document.getElementById('state')?.value,
        zipCode: document.getElementById('zipCode')?.value,
        dateOfBirth: document.getElementById('dateOfBirth')?.value,
        country: document.getElementById('country').value,
        gender: document.getElementById('gender')?.value || null
    };
    
    try {
        const res = await fetch(`${API_URL}/api/user/profile/complete`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(profileData)
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('Profile updated successfully!', 'success');
        } else {
            showAlert(data.message || 'Update failed', 'error');
        }
    } catch (e) {
        showAlert('Error updating profile: ' + e.message, 'error');
    }
}

// ============================================================================
// LOGIN HISTORY & SESSIONS
// ============================================================================

async function loadLoginHistory() {
    const token = localStorage.getItem('token');
    const container = document.getElementById('loginHistoryContainer');
    if (!container) return;
    
    try {
        const res = await fetch(`${API_URL}/api/user/security/login-history`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success && data.logins) {
            loginHistoryCache = data.logins;
            displayLoginHistory(data.logins);
        } else {
            container.innerHTML = '<p style="color: #999; text-align: center;">No login history available</p>';
        }
    } catch (e) {
        console.error('Error loading login history:', e);
        container.innerHTML = '<p style="color: #999; text-align: center;">Error loading history</p>';
    }
}

function displayLoginHistory(logins) {
    const container = document.getElementById('loginHistoryContainer');
    if (!container) return;
    
    container.innerHTML = '';
    if (!logins || logins.length === 0) {
        const empty = document.createElement('p');
        empty.style.color = '#999';
        empty.style.textAlign = 'center';
        empty.textContent = 'No login history';
        container.appendChild(empty);
        return;
    }

    logins.slice(0, 10).forEach(login => {
        const card = document.createElement('div');
        card.className = 'history-item';
        card.style.padding = '10px';
        card.style.borderBottom = '1px solid #eee';

        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.justifyContent = 'space-between';
        row.style.alignItems = 'center';

        const left = document.createElement('div');
        const title = document.createElement('strong');
        title.textContent = login.device || 'Unknown Device';
        left.appendChild(title);

        const detail = document.createElement('p');
        detail.style.margin = '5px 0 0 0';
        detail.style.color = '#666';
        detail.style.fontSize = '0.85rem';
        detail.innerHTML = `<i class="fas fa-map-marker-alt"></i> ${escapeHtml(login.location || 'Unknown Location')}<br><i class="fas fa-globe"></i> IP: ${maskIP(login.ip || 'N/A')}`;
        left.appendChild(detail);

        const right = document.createElement('div');
        right.style.textAlign = 'right';
        right.style.color = '#999';
        right.style.fontSize = '0.85rem';
        right.textContent = formatTimeAgo(login.timestamp || login.createdAt || new Date());

        row.appendChild(left);
        row.appendChild(right);
        card.appendChild(row);
        container.appendChild(card);
    });
}

function maskIP(ip) {
    if (!ip) return 'N/A';
    const parts = ip.split('.');
    if (parts.length === 4) {
        return `${parts[0]}.${parts[1]}.***.***.`;
    }
    return ip;
}

function formatTimeAgo(date) {
    const now = new Date();
    const time = new Date(date);
    const seconds = Math.floor((now - time) / 1000);
    
    if (seconds < 60) return 'Just now';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 7) return `${days}d ago`;
    
    return time.toLocaleDateString();
}

async function loadActiveSessions() {
    const token = localStorage.getItem('token');
    const container = document.getElementById('activeSessionsContainer');
    if (!container) return;
    
    try {
        const res = await fetch(`${API_URL}/api/user/security/active-sessions`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success && data.sessions) {
            activeSessionsCache = data.sessions;
            displayActiveSessions(data.sessions);
        } else {
            container.innerHTML = '<p style="color: #999; text-align: center;">No active sessions</p>';
        }
    } catch (e) {
        console.error('Error loading active sessions:', e);
    }
}

function displayActiveSessions(sessions) {
    const container = document.getElementById('activeSessionsContainer');
    if (!container) return;
    
    container.innerHTML = '';
    if (!sessions || sessions.length === 0) {
        const empty = document.createElement('p');
        empty.style.color = '#999';
        empty.style.textAlign = 'center';
        empty.textContent = 'No active sessions';
        container.appendChild(empty);
        return;
    }

    sessions.forEach(session => {
        const card = document.createElement('div');
        card.className = 'session-item';
        card.style.padding = '15px';
        card.style.borderBottom = '1px solid #eee';
        card.style.display = 'flex';
        card.style.justifyContent = 'space-between';
        card.style.alignItems = 'center';

        const left = document.createElement('div');
        const title = document.createElement('strong');
        title.textContent = session.deviceName || 'Device';
        left.appendChild(title);

        const browserInfo = document.createElement('span');
        browserInfo.style.color = '#999';
        browserInfo.style.fontSize = '0.85rem';
        browserInfo.style.display = 'block';
        browserInfo.textContent = session.browserName || 'Browser';
        left.appendChild(browserInfo);

        const location = document.createElement('p');
        location.style.margin = '5px 0 0 0';
        location.style.color = '#666';
        location.style.fontSize = '0.85rem';
        location.innerHTML = `<i class="fas fa-map-marker-alt"></i> ${escapeHtml(session.location || 'Unknown Location')}`;
        left.appendChild(location);

        const lastActive = document.createElement('p');
        lastActive.style.margin = '5px 0 0 0';
        lastActive.style.color = '#999';
        lastActive.style.fontSize = '0.8rem';
        lastActive.textContent = `Last active: ${formatTimeAgo(session.lastActivity || new Date())}`;
        left.appendChild(lastActive);

        const button = document.createElement('button');
        button.className = 'btn btn-secondary btn-sm';
        button.type = 'button';
        button.innerHTML = '<i class="fas fa-sign-out-alt"></i> Logout';
        button.addEventListener('click', () => logoutSession(session.id || session._id));

        card.appendChild(left);
        card.appendChild(button);
        container.appendChild(card);
    });
}

async function logoutSession(sessionId) {
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/user/security/logout-session/${sessionId}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('Session logged out', 'success');
            await loadActiveSessions();
        } else {
            showAlert('Failed to logout session', 'error');
        }
    } catch (e) {
        showAlert('Error: ' + e.message, 'error');
    }
}

async function logoutAllSessions() {
    const confirmed = await showConfirmDialog('This will log you out of all devices. Continue?', 'Log out of all devices', 'Log out', 'Cancel');
    if (!confirmed) return;
    
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/user/security/logout-all`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success) {
            localStorage.removeItem('token');
            window.location.href = 'signin.html';
        }
    } catch (e) {
        showAlert('Error: ' + e.message, 'error');
    }
}

// ============================================================================
// PASSWORD CHANGE & PASSWORD STRENGTH
// ============================================================================

function togglePasswordForm() {
    const form = document.getElementById('passwordForm');
    if (form) {
        form.style.display = form.style.display === 'none' ? 'block' : 'none';
    }
}

async function changePassword(e) {
    e?.preventDefault();
    const currentPass = document.getElementById('currentPassword')?.value;
    const newPass = document.getElementById('newPassword')?.value;
    const confirmPass = document.getElementById('confirmPassword')?.value;
    
    if (!currentPass || !newPass || !confirmPass) {
        showAlert('All password fields are required', 'error');
        return;
    }
    
    if (newPass !== confirmPass) {
        showAlert('New passwords do not match!', 'error');
        return;
    }
    
    const strength = checkPasswordStrength(newPass);
    if (strength.score < 3) {
        showAlert('New password is too weak. Use uppercase, lowercase, numbers, and symbols.', 'error');
        return;
    }
    
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/auth/change-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                currentPassword: currentPass,
                newPassword: newPass
            })
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('Password changed successfully!', 'success');
            togglePasswordForm();
            document.getElementById('currentPassword').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('confirmPassword').value = '';
            updatePasswordStrengthMeter('');
        } else {
            showAlert(data.message || 'Password change failed', 'error');
        }
    } catch (e) {
        showAlert('Error changing password: ' + e.message, 'error');
    }
}

function checkPasswordStrength(password) {
    const strength = {
        score: 0,
        level: 'Very Weak',
        color: '#f44336'
    };
    
    if (!password) return strength;
    
    if (password.length >= 8) strength.score++;
    if (password.length >= 12) strength.score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength.score++;
    if (/\d/.test(password)) strength.score++;
    if (/[^a-zA-Z\d]/.test(password)) strength.score++;
    
    const levels = [
        { level: 'Very Weak', color: '#f44336' },
        { level: 'Weak', color: '#ff9800' },
        { level: 'Fair', color: '#ffc107' },
        { level: 'Strong', color: '#8bc34a' },
        { level: 'Very Strong', color: '#4caf50' }
    ];
    
    const levelIndex = Math.min(strength.score, 4);
    strength.level = levels[levelIndex].level;
    strength.color = levels[levelIndex].color;
    
    return strength;
}

function updatePasswordStrengthMeter(password) {
    const meter = document.getElementById('passwordStrengthMeter');
    const text = document.getElementById('passwordStrengthText');
    
    if (!meter || !text) return;
    
    const strength = checkPasswordStrength(password);
    const percentage = (strength.score / 5) * 100;
    
    meter.style.width = percentage + '%';
    meter.style.backgroundColor = strength.color;
    text.textContent = strength.level;
    text.style.color = strength.color;
}

// ============================================================================
// TWO-FACTOR AUTHENTICATION
// ============================================================================

function toggle2FAForm() {
    const form = document.getElementById('twoFactorSetupForm');
    if (form) {
        form.style.display = form.style.display === 'none' ? 'block' : 'none';
    }
}

function toggle2FACheckbox() {
    const toggle = document.getElementById('twoFactorToggle');
    const setup = document.getElementById('twoFASetup');
    if (toggle && toggle.checked) {
        if (setup) setup.style.display = 'block';
        enable2FA();
    } else {
        if (setup) setup.style.display = 'none';
        disable2FA();
    }
}

function handleUpdate2FAMethod() {
    const method = document.getElementById('twoFAMethod')?.value;
    if (method) {
        showAlert(`2FA method updated to ${method}`, 'success');
    }
}

function requestLimitIncrease() {
    const msg = document.getElementById('limitIncreaseMsg');
    if (msg) {
        msg.style.display = 'block';
        msg.innerHTML = '<i class="fas fa-info-circle"></i> Your request has been submitted. A representative will review your account and contact you within 2-3 business days.';
    } else {
        showAlert('Your limit increase request has been submitted. A representative will contact you within 2-3 business days.', 'success');
    }
}

async function enable2FA(e) {
    e?.preventDefault();
    const method = document.getElementById('twoFAMethod')?.value || 'sms';
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/user/2fa/enable`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ method })
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('Two-Factor Authentication enabled!', 'success');
            toggle2FAForm();
            generateBackupCodes();
        } else {
            showAlert(data.message || 'Failed to enable 2FA', 'error');
        }
    } catch (e) {
        showAlert('Error: ' + e.message, 'error');
    }
}

async function disable2FA() {
    const confirmed = await showConfirmDialog('Disable Two-Factor Authentication? This reduces your account security.', 'Disable Two-Factor Authentication', 'Disable', 'Cancel');
    if (!confirmed) return;
    
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/user/2fa/disable`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('Two-Factor Authentication disabled', 'success');
        }
    } catch (e) {
        showAlert('Error: ' + e.message, 'error');
    }
}

async function generateBackupCodes() {
    const token = localStorage.getItem('token');
    const container = document.getElementById('backupCodesContainer');
    
    if (!container) return;
    
    try {
        const res = await fetch(`${API_URL}/api/user/2fa/backup-codes`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success && data.codes) {
            displayBackupCodes(data.codes);
        }
    } catch (e) {
        console.error('Error generating backup codes:', e);
    }
}

function displayBackupCodes(codes) {
    const container = document.getElementById('backupCodesContainer');
    if (!container) return;
    container.innerHTML = '';

    const card = document.createElement('div');
    card.style.background = '#f9f9f9';
    card.style.padding = '15px';
    card.style.borderRadius = '8px';
    card.style.borderLeft = '4px solid #ff9800';

    const heading = document.createElement('h4');
    heading.innerHTML = '<i class="fas fa-shield-alt"></i> Backup Codes';
    card.appendChild(heading);

    const help = document.createElement('p');
    help.style.color = '#666';
    help.style.fontSize = '0.9rem';
    help.textContent = 'Save these codes in a safe place. Use them if you lose access to your 2FA device.';
    card.appendChild(help);

    const codesWrapper = document.createElement('div');
    codesWrapper.style.background = 'white';
    codesWrapper.style.padding = '10px';
    codesWrapper.style.borderRadius = '4px';
    codesWrapper.style.fontFamily = 'monospace';
    codesWrapper.style.fontSize = '0.85rem';
    codesWrapper.style.lineHeight = '1.8';

    codes.forEach(code => {
        const codeLine = document.createElement('div');
        codeLine.className = 'backup-code';
        codeLine.textContent = code;
        codesWrapper.appendChild(codeLine);
    });
    card.appendChild(codesWrapper);

    const downloadButton = document.createElement('button');
    downloadButton.className = 'btn btn-secondary btn-sm';
    downloadButton.type = 'button';
    downloadButton.style.marginTop = '10px';
    downloadButton.innerHTML = '<i class="fas fa-download"></i> Download';
    downloadButton.addEventListener('click', downloadBackupCodes);
    card.appendChild(downloadButton);

    container.appendChild(card);
}

function downloadBackupCodes() {
    const codes = document.querySelectorAll('#backupCodesContainer .backup-code');
    const text = Array.from(codes).map(el => el.textContent).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'backup-codes.txt';
    a.click();
}

// ============================================================================
// ACCOUNT VERIFICATION & DOCUMENTS
// ============================================================================

async function loadDocumentStatus(user) {
    const token = localStorage.getItem('token');
    const statusEl = document.getElementById('verificationStatus');
    const loadingEl = document.getElementById('verificationLoading');
    const requestSection = document.getElementById('documentRequestSection');
    if (!statusEl) return;
    
    try {
        const res = await fetch(`${API_URL}/api/user/verification-status`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success) {
            const v = data.verification;
            if (loadingEl) loadingEl.style.display = 'none';
            
            if (v.isVerified) {
                statusEl.style.background = '#e8f5e9';
                statusEl.style.border = '2px solid #4caf50';
                statusEl.innerHTML = `
                    <i class="fas fa-check-circle" style="font-size: 2.5rem; color: #4caf50; margin-bottom: 10px;"></i>
                    <h3 style="margin: 0; color: #2e7d32;">Account Verified</h3>
                    <p style="margin: 8px 0 0; color: #555; font-size: 0.9rem;">Your identity has been verified. You have full access to all banking features.</p>
                `;
            } else {
                statusEl.style.background = '#fff8e1';
                statusEl.style.border = '2px solid #ffc107';
                statusEl.innerHTML = `
                    <i class="fas fa-clock" style="font-size: 2.5rem; color: #ffc107; margin-bottom: 10px;"></i>
                    <h3 style="margin: 0; color: #f57f17;">Verification Pending</h3>
                    <p style="margin: 8px 0 0; color: #555; font-size: 0.9rem;">Your account is awaiting verification. You may be asked to submit documents.</p>
                `;
            }

            // Show document request section if admin has requested documents
            if (v.documentRequested && requestSection) {
                requestSection.style.display = 'block';
                const msgEl = document.getElementById('documentRequestMessage');
                if (msgEl) msgEl.textContent = v.documentRequestMessage || 'Please upload the requested identification documents.';
            }

            // Show previously uploaded docs
            if (v.documents && v.documents.length > 0) {
                displayDocuments(v.documents);
            }
        }
    } catch (e) {
        console.error('Error loading verification status:', e);
        if (loadingEl) loadingEl.textContent = 'Unable to load verification status';
    }
}

function displayDocuments(documents) {
    const container = document.getElementById('uploadedDocsList');
    if (!container) return;
    
    container.innerHTML = '';
    if (!documents || documents.length === 0) return;

    const header = document.createElement('h4');
    header.style.marginBottom = '10px';
    header.style.color = '#333';
    header.textContent = 'Uploaded Documents';
    container.appendChild(header);

    documents.forEach(doc => {
        const card = document.createElement('div');
        card.style.padding = '12px';
        card.style.background = '#f9f9f9';
        card.style.borderRadius = '6px';
        card.style.display = 'flex';
        card.style.justifyContent = 'space-between';
        card.style.alignItems = 'center';
        card.style.marginBottom = '10px';

        const left = document.createElement('div');
        const title = document.createElement('strong');
        title.textContent = doc.documentType || 'Document';
        left.appendChild(title);

        const meta = document.createElement('p');
        meta.style.margin = '4px 0 0';
        meta.style.color = '#666';
        meta.style.fontSize = '0.85rem';
        const uploadedDate = new Date(doc.uploadedAt || Date.now()).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
        const status = document.createElement('span');
        status.style.color = doc.verified ? '#4caf50' : '#ff9800';
        status.textContent = doc.verified ? 'Verified' : 'Under Review';
        meta.innerHTML = `Uploaded: ${uploadedDate} • Status: `;
        meta.appendChild(status);
        left.appendChild(meta);

        card.appendChild(left);
        container.appendChild(card);
    });
}

async function uploadDocument(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    if (file.size > 10 * 1024 * 1024) {
        showAlert('File size exceeds 10MB limit', 'error');
        return;
    }
    
    const token = localStorage.getItem('token');
    const formData = new FormData();
    formData.append('document', file);
    
    try {
        const res = await fetch(`${API_URL}/api/user/documents/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` },
            body: formData
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('Document uploaded successfully!', 'success');
            await loadDocumentStatus({});
        } else {
            showAlert(data.message || 'Upload failed', 'error');
        }
    } catch (e) {
        showAlert('Error uploading document: ' + e.message, 'error');
    }
}

// ============================================================================
// BENEFICIARIES MANAGEMENT
// ============================================================================

async function loadBeneficiaries() {
    const token = localStorage.getItem('token');
    const container = document.getElementById('beneficiariesList');
    if (!container) return;
    
    try {
        const res = await fetch(`${API_URL}/api/user/beneficiaries`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success && data.beneficiaries) {
            displayBeneficiaries(data.beneficiaries);
        } else {
            container.innerHTML = '<p style="text-align: center; color: #999;">No beneficiaries added yet</p>';
        }
    } catch (e) {
        console.error('Error loading beneficiaries:', e);
    }
}

function displayBeneficiaries(beneficiaries) {
    const container = document.getElementById('beneficiariesList');
    if (!container) return;
    
    container.innerHTML = '';
    if (!beneficiaries || beneficiaries.length === 0) {
        const empty = document.createElement('p');
        empty.style.textAlign = 'center';
        empty.style.color = '#999';
        empty.textContent = 'No beneficiaries added yet';
        container.appendChild(empty);
        return;
    }

    beneficiaries.forEach(ben => {
        const safeId = escapeHtml(String(ben.id || ben._id));
        const card = document.createElement('div');
        card.className = 'beneficiary-item';
        card.style.padding = '15px';
        card.style.borderBottom = '1px solid #eee';
        card.style.display = 'flex';
        card.style.justifyContent = 'space-between';
        card.style.alignItems = 'center';

        const left = document.createElement('div');
        const nameEl = document.createElement('strong');
        nameEl.textContent = ben.name;
        left.appendChild(nameEl);

        if (ben.nickname) {
            const nicknameEl = document.createElement('span');
            nicknameEl.style.color = '#999';
            nicknameEl.style.fontSize = '0.9rem';
            nicknameEl.textContent = ` (${ben.nickname})`;
            left.appendChild(nicknameEl);
        }

        const details = document.createElement('p');
        details.style.margin = '5px 0 0 0';
        details.style.color = '#666';
        details.style.fontSize = '0.85rem';
        details.innerHTML = `Account: ${maskAccountNumber(ben.accountNumber)}<br>Routing: ${escapeHtml(ben.routingNumber)} | Bank: ${escapeHtml(ben.bankName || 'N/A')}<br>`;

        const status = document.createElement('span');
        status.style.color = ben.verified ? '#4caf50' : '#ff9800';
        status.textContent = ben.verified ? 'Verified' : 'Pending Verification';
        details.appendChild(status);
        left.appendChild(details);

        const right = document.createElement('div');
        const editButton = document.createElement('button');
        editButton.className = 'btn btn-secondary btn-sm';
        editButton.type = 'button';
        editButton.innerHTML = '<i class="fas fa-edit"></i>';
        editButton.addEventListener('click', () => editBeneficiary(safeId));

        const deleteButton = document.createElement('button');
        deleteButton.className = 'btn btn-danger btn-sm';
        deleteButton.type = 'button';
        deleteButton.style.marginLeft = '5px';
        deleteButton.innerHTML = '<i class="fas fa-trash"></i>';
        deleteButton.addEventListener('click', () => deleteBeneficiary(safeId));

        right.appendChild(editButton);
        right.appendChild(deleteButton);

        card.appendChild(left);
        card.appendChild(right);
        container.appendChild(card);
    });
}

function maskAccountNumber(account) {
    if (!account) return 'N/A';
    return '*'.repeat(account.length - 4) + account.slice(-4);
}

async function editBeneficiary(benId) {
    const token = localStorage.getItem('token');
    const userId = localStorage.getItem('userId');

    try {
        const res = await fetch(`${API_URL}/api/user/${userId}/beneficiaries`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        const ben = (data.beneficiaries || []).find(b => (b.id || b._id) == benId);
        if (!ben) return showAlert('Beneficiary not found', 'error');

        const name = await showPromptDialog('Beneficiary Name:', ben.name || '', 'Edit Beneficiary', 'Save', 'Cancel');
        if (name === null) return;

        const nickname = await showPromptDialog('Nickname (optional):', ben.nickname || '', 'Edit Beneficiary', 'Save', 'Cancel');
        if (nickname === null) return;

        const updateRes = await fetch(`${API_URL}/api/user/${userId}/beneficiaries/${benId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ name, nickname })
        });
        const result = await updateRes.json();

        if (result.success) {
            showAlert('Beneficiary updated', 'success');
            await loadBeneficiaries();
        } else {
            showAlert(result.message || 'Update failed', 'error');
        }
    } catch (e) {
        showAlert('Error: ' + e.message, 'error');
    }
}

function showAddBeneficiaryForm() {
    const form = document.getElementById('addBeneficiaryForm');
    if (form) {
        form.style.display = 'block';
    }
}

function hideAddBeneficiaryForm() {
    const form = document.getElementById('addBeneficiaryForm');
    if (form) {
        form.style.display = 'none';
        clearBeneficiaryForm();
    }
}

function clearBeneficiaryForm() {
    document.getElementById('beneficiaryName').value = '';
    document.getElementById('beneficiaryNickname').value = '';
    document.getElementById('beneficiaryAccount').value = '';
    document.getElementById('beneficiaryRouting').value = '';
    document.getElementById('beneficiaryBank').value = '';
}

async function addBeneficiary() {
    const name = document.getElementById('beneficiaryName')?.value;
    const nickname = document.getElementById('beneficiaryNickname')?.value;
    const account = document.getElementById('beneficiaryAccount')?.value;
    const routing = document.getElementById('beneficiaryRouting')?.value;
    const bank = document.getElementById('beneficiaryBank')?.value;
    
    if (!name || !account || !routing) {
        showAlert('Name, account, and routing number are required', 'error');
        return;
    }
    
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/user/beneficiaries`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                name, nickname, accountNumber: account, routingNumber: routing, bankName: bank
            })
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('Beneficiary added successfully!', 'success');
            hideAddBeneficiaryForm();
            await loadBeneficiaries();
        } else {
            showAlert(data.message || 'Failed to add beneficiary', 'error');
        }
    } catch (e) {
        showAlert('Error: ' + e.message, 'error');
    }
}

async function deleteBeneficiary(benId) {
    const confirmed = await showConfirmDialog('Delete this beneficiary?', 'Delete Beneficiary', 'Delete', 'Cancel');
    if (!confirmed) return;
    
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/user/beneficiaries/${benId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('Beneficiary deleted', 'success');
            await loadBeneficiaries();
        }
    } catch (e) {
        showAlert('Error: ' + e.message, 'error');
    }
}

// ============================================================================
// ACCOUNT CONTROLS
// ============================================================================

function populateAccountControls(user) {
    const freezeToggle = document.getElementById('freezeAccountToggle');
    const intlToggle = document.getElementById('internationalToggle');
    
    if (freezeToggle) {
        freezeToggle.checked = user.accountFrozen || false;
    }
    if (intlToggle) {
        intlToggle.checked = user.internationalEnabled !== false;
    }
}

async function toggleAccountFreeze() {
    const toggle = document.getElementById('freezeAccountToggle');
    const token = localStorage.getItem('token');
    const action = toggle.checked ? 'freeze' : 'unfreeze';
    
    try {
        const res = await fetch(`${API_URL}/api/user/account/${action}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert(`Account ${action}d successfully`, 'success');
        } else {
            toggle.checked = !toggle.checked;
            showAlert('Failed to ' + action + ' account', 'error');
        }
    } catch (e) {
        toggle.checked = !toggle.checked;
        showAlert('Error: ' + e.message, 'error');
    }
}

async function toggleInternational() {
    const toggle = document.getElementById('internationalToggle');
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/user/account/international`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ enabled: toggle.checked })
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('International transactions ' + (toggle.checked ? 'enabled' : 'disabled'), 'success');
        } else {
            toggle.checked = !toggle.checked;
            showAlert('Failed to update setting', 'error');
        }
    } catch (e) {
        toggle.checked = !toggle.checked;
        showAlert('Error: ' + e.message, 'error');
    }
}

// ============================================================================
// PRIVACY & DATA MANAGEMENT
// ============================================================================

function loadPreferences(user) {
    // Load notification toggles
    const notificationToggles = document.querySelectorAll('[id^="notification"]');
    notificationToggles.forEach(toggle => {
        const prefKey = toggle.id;
        const pref = user.preferences?.[prefKey] ?? true;
        toggle.checked = pref;
    });
    
    // Load dark mode preference
    const darkModeToggle = document.getElementById('darkModeToggle');
    if (darkModeToggle) {
        const darkMode = localStorage.getItem('darkMode') === 'true';
        darkModeToggle.checked = darkMode;
        if (darkMode) {
            document.body.classList.add('dark-mode');
        }
    }
    
    // Load transaction PIN status
    const pinStatus = document.getElementById('pinStatus');
    if (pinStatus) {
        pinStatus.textContent = user.transactionPin ? 'Enabled' : 'Not Set';
        pinStatus.style.color = user.transactionPin ? '#28a745' : '#dc3545';
    }
}

// Dark Mode Toggle
function toggleDarkMode() {
    const darkModeToggle = document.getElementById('darkModeToggle');
    const isDark = darkModeToggle?.checked;
    
    localStorage.setItem('darkMode', isDark);
    
    if (isDark) {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
    
    // Also save to server
    updatePreference('darkMode', isDark);
}

// Transaction PIN Management
function showPinSetup() {
    const modal = document.getElementById('pinModal');
    if (modal) modal.classList.add('active');
}

function hidePinModal() {
    const modal = document.getElementById('pinModal');
    if (modal) modal.classList.remove('active');
    // Clear inputs
    document.querySelectorAll('#pinModal input').forEach(input => input.value = '');
}

async function saveTransactionPin(e) {
    e.preventDefault();
    
    const currentPin = document.getElementById('currentPin')?.value || '';
    const newPin = document.getElementById('newPin').value;
    const confirmPin = document.getElementById('confirmPin').value;
    
    if (newPin.length !== 4 || !/^\d{4}$/.test(newPin)) {
        showAlert('PIN must be exactly 4 digits', 'error');
        return;
    }
    
    if (newPin !== confirmPin) {
        showAlert('PINs do not match', 'error');
        return;
    }
    
    const token = localStorage.getItem('token');
    try {
        const res = await fetch(`${API_URL}/api/user/transaction-pin`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ currentPin, newPin })
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('Transaction PIN updated successfully', 'success');
            hidePinModal();
            const pinStatus = document.getElementById('pinStatus');
            if (pinStatus) {
                pinStatus.textContent = 'Enabled';
                pinStatus.style.color = '#28a745';
            }
        } else {
            showAlert(data.message || 'Failed to update PIN', 'error');
        }
    } catch (e) {
        showAlert('Error updating PIN', 'error');
    }
}

async function removeTransactionPin() {
    const confirmed = await showConfirmDialog('Are you sure you want to remove your transaction PIN?', 'Remove Transaction PIN', 'Remove', 'Cancel');
    if (!confirmed) return;
    
    const token = localStorage.getItem('token');
    try {
        const res = await fetch(`${API_URL}/api/user/transaction-pin`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('Transaction PIN removed', 'success');
            const pinStatus = document.getElementById('pinStatus');
            if (pinStatus) {
                pinStatus.textContent = 'Not Set';
                pinStatus.style.color = '#dc3545';
            }
        } else {
            showAlert(data.message || 'Failed to remove PIN', 'error');
        }
    } catch (e) {
        showAlert('Error removing PIN', 'error');
    }
}

async function updatePreference(key, value) {
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/user/preferences`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ [key]: value })
        });
        
        const data = await res.json();
        if (!data.success) {
            showAlert('Failed to update preference', 'error');
        }
    } catch (e) {
        console.error('Error updating preference:', e);
    }
}

async function downloadStatement() {
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/user/statements/current`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `statement-${new Date().toISOString().split('T')[0]}.pdf`;
        a.click();
        
        showAlert('Statement downloaded', 'success');
    } catch (e) {
        showAlert('Error downloading statement: ' + e.message, 'error');
    }
}

async function exportData() {
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/user/privacy/export-data`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success && data.data) {
            const json = JSON.stringify(data.data, null, 2);
            const blob = new Blob([json], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `mydata-${new Date().toISOString().split('T')[0]}.json`;
            a.click();
            
            showAlert('Your data has been exported', 'success');
        }
    } catch (e) {
        showAlert('Error exporting data: ' + e.message, 'error');
    }
}

async function requestAccountDeletion() {
    const confirmed = await showConfirmDialog('Request account deletion? You will have 30 days to cancel this request.', 'Request Account Deletion', 'Request', 'Cancel');
    if (!confirmed) return;
    
    const token = localStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_URL}/api/user/privacy/delete-request`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await res.json();
        if (data.success) {
            showAlert('Account deletion request submitted. You have 30 days to cancel.', 'success');
        } else {
            showAlert(data.message || 'Failed to request deletion', 'error');
        }
    } catch (e) {
        showAlert('Error: ' + e.message, 'error');
    }
}

async function confirmCloseAccount() {
    const firstConfirm = await showConfirmDialog('Are you sure you want to close your account? This action cannot be undone.', 'Close Account', 'Continue', 'Cancel');
    if (!firstConfirm) return;

    const code = await showPromptDialog('To confirm account closure, type CLOSE below.', 'CLOSE', 'Confirm Account Closure', 'Confirm', 'Cancel');
    if (code && code.trim().toUpperCase() === 'CLOSE') {
        showAlert('Please contact customer support to close your account.', 'error');
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function showAlert(message, type) {
    const alert = document.getElementById('alertBox');
    if (!alert) return;
    
    alert.textContent = message;
    alert.className = `alert alert-${type}`;
    alert.style.display = 'block';
    setTimeout(() => alert.style.display = 'none', 5000);
}

function logout() {
    const consent = localStorage.getItem('cookieConsent');
    localStorage.clear();
    if (consent) localStorage.setItem('cookieConsent', consent);
    window.location.href = 'signin.html';
}

async function showDialog({ title = 'Confirm action', message = '', type = 'confirm', defaultValue = '', confirmText = 'Confirm', cancelText = 'Cancel' }) {
    return new Promise((resolve) => {
        const overlay = document.getElementById('globalDialog');
        const titleEl = document.getElementById('dialogTitle');
        const messageEl = document.getElementById('dialogMessage');
        const inputContainer = document.getElementById('dialogInputContainer');
        const confirmBtn = document.getElementById('dialogConfirmBtn');
        const cancelBtn = document.getElementById('dialogCancelBtn');

        if (!overlay || !messageEl || !confirmBtn || !cancelBtn || !inputContainer) {
            resolve(type === 'prompt' ? null : false);
            return;
        }

        titleEl.textContent = title;
        messageEl.textContent = message;
        inputContainer.innerHTML = '';
        overlay.classList.add('active');
        overlay.setAttribute('aria-hidden', 'false');

        let input;
        if (type === 'prompt') {
            input = document.createElement('input');
            input.type = 'text';
            input.value = defaultValue;
            input.placeholder = defaultValue || 'Enter value';
            input.className = 'dialog-input';
            inputContainer.appendChild(input);
            setTimeout(() => input.focus(), 0);
        }

        confirmBtn.textContent = confirmText;
        cancelBtn.textContent = cancelText;

        const cleanup = () => {
            overlay.classList.remove('active');
            overlay.setAttribute('aria-hidden', 'true');
            confirmBtn.removeEventListener('click', onConfirm);
            cancelBtn.removeEventListener('click', onCancel);
            overlay.removeEventListener('click', onBackdropClick);
            document.removeEventListener('keydown', onKeyDown);
        };

        const onConfirm = () => {
            cleanup();
            resolve(type === 'prompt' ? input.value : true);
        };

        const onCancel = () => {
            cleanup();
            resolve(type === 'prompt' ? null : false);
        };

        const onBackdropClick = (event) => {
            if (event.target === overlay) onCancel();
        };

        const onKeyDown = (event) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                onCancel();
            }
            if (event.key === 'Enter' && type === 'prompt') {
                event.preventDefault();
                onConfirm();
            }
        };

        confirmBtn.addEventListener('click', onConfirm);
        cancelBtn.addEventListener('click', onCancel);
        overlay.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onKeyDown);
    });
}

function showConfirmDialog(message, title = 'Confirm', confirmText = 'Confirm', cancelText = 'Cancel') {
    return showDialog({ title, message, type: 'confirm', confirmText, cancelText });
}

function showPromptDialog(message, defaultValue = '', title = 'Input Required', confirmText = 'Save', cancelText = 'Cancel') {
    return showDialog({ title, message, type: 'prompt', defaultValue, confirmText, cancelText });
}

// ============================================================================
// EVENT LISTENERS & INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    // Setup password strength meter listener
    const newPassInput = document.getElementById('newPassword');
    if (newPassInput) {
        newPassInput.addEventListener('input', (e) => updatePasswordStrengthMeter(e.target.value));
    }
    
    // Setup preference toggles
    document.querySelectorAll('[id^="notification"]').forEach(toggle => {
        toggle.addEventListener('change', (e) => updatePreference(e.target.id, e.target.checked));
    });
    
    // Setup profile form submission
    const profileForm = document.getElementById('profileForm');
    if (profileForm) {
        profileForm.addEventListener('submit', updateProfile);
    }
    
    // Setup password change form submission
    const passwordForm = document.getElementById('passwordChangeForm');
    if (passwordForm) {
        passwordForm.addEventListener('submit', changePassword);
    }
    
    // Setup 2FA form submission
    const twoFactorForm = document.getElementById('twoFactorSetupForm');
    if (twoFactorForm) {
        twoFactorForm.addEventListener('submit', enable2FA);
    }
    
    const profilePictureInput = document.getElementById('profilePictureInput');
    if (profilePictureInput) {
        profilePictureInput.addEventListener('change', handleProfilePictureSelect);
    }

    // Load biometric credentials after DOM is ready
    loadBiometricCredentials();

    // Check auth and load profile
    checkAuth();
});

// ============================================================================
// RECENT ACTIVITY
// ============================================================================

async function loadActivity() {
    const token = localStorage.getItem('token');
    if (!userId) return;
    
    try {
        const res = await fetch(`${API_URL}/api/user/${userId}/activity?ts=${Date.now()}`, {
            cache: 'no-store',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        
        if (data.success && Array.isArray(data.activities)) {
            displayActivity(data.activities.slice(0, 10));
            return;
        }
        displayActivity([]);
    } catch (e) {
        console.error('Activity load error:', e);
        displayActivity([]);
    }
}

function displayActivity(activities) {
    const container = document.getElementById('activityList');
    if (!container) return;

    container.innerHTML = '';
    if (!activities || activities.length === 0) {
        const item = document.createElement('div');
        item.className = 'activity-item';

        const dot = document.createElement('div');
        dot.className = 'activity-dot';
        item.appendChild(dot);

        const content = document.createElement('div');
        content.className = 'activity-content';

        const message = document.createElement('p');
        message.textContent = 'No recent activity yet';
        content.appendChild(message);

        const hint = document.createElement('span');
        hint.textContent = 'New logins and transactions will appear here';
        content.appendChild(hint);

        item.appendChild(content);
        container.appendChild(item);
        return;
    }

    activities.forEach(activity => {
        const date = new Date(activity.timestamp || activity.createdAt);
        const timeAgo = (!isNaN(date.getTime())) ? getTimeAgo(date) : '-';

        const actionText = activity.action || activity.title || activity.description || 'Activity';
        const descText = (activity.action && activity.description) ? String(activity.description) : '';
        const meta = [descText, timeAgo].filter(Boolean).join(' • ');

        const item = document.createElement('div');
        item.className = 'activity-item';

        const dot = document.createElement('div');
        dot.className = 'activity-dot';
        item.appendChild(dot);

        const content = document.createElement('div');
        content.className = 'activity-content';

        const title = document.createElement('p');
        title.textContent = actionText;
        content.appendChild(title);

        const span = document.createElement('span');
        span.textContent = meta || timeAgo;
        content.appendChild(span);

        item.appendChild(content);
        container.appendChild(item);
    });
}

function getTimeAgo(date) {
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);
    
    if (diff < 60) return 'Just now';
    if (diff < 3600) return Math.floor(diff / 60) + ' minutes ago';
    if (diff < 86400) return Math.floor(diff / 3600) + ' hours ago';
    if (diff < 604800) return Math.floor(diff / 86400) + ' days ago';
    
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        checkPasswordStrength,
        formatCurrency,
        maskSSN,
        maskIP,
        formatDate,
        loadActivity,
        displayActivity,
        getTimeAgo
    };
}

// ============================================================================
// BIOMETRIC / PASSKEY REGISTRATION
// ============================================================================

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function loadBiometricCredentials() {
    const token = localStorage.getItem('token');
    if (!token) return;
    const container = document.getElementById('biometricCredentialsList');
    if (!container) return;

    try {
        const res = await fetch(`${API_URL}/api/auth/webauthn/credentials`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        if (!data.success || !data.credentials.length) {
            container.innerHTML = '<p style="color:#94a3b8;font-size:0.85rem;padding:10px 0 0;">No passkeys registered yet. Add one to enable passwordless sign-in.</p>';
            return;
        }

        container.innerHTML = '';
        data.credentials.forEach((c, i) => {
            const dateStr = new Date(c.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });

            const item = document.createElement('div');
            item.className = 'biometric-cred-item';

            const info = document.createElement('div');
            info.className = 'biometric-cred-info';

            const icon = document.createElement('div');
            icon.className = 'biometric-cred-icon';
            icon.innerHTML = '<i class="fas fa-fingerprint"></i>';
            info.appendChild(icon);

            const details = document.createElement('div');
            const nameEl = document.createElement('div');
            nameEl.className = 'biometric-cred-name';
            nameEl.textContent = `Passkey ${i + 1}`;
            details.appendChild(nameEl);

            const dateEl = document.createElement('div');
            dateEl.className = 'biometric-cred-date';
            dateEl.innerHTML = `<i class="fas fa-calendar-alt"></i> Added ${escapeHtml(dateStr)}`;
            details.appendChild(dateEl);

            info.appendChild(details);
            item.appendChild(info);

            const removeBtn = document.createElement('button');
            removeBtn.className = 'btn btn-danger';
            removeBtn.type = 'button';
            removeBtn.style.padding = '6px 14px';
            removeBtn.style.fontSize = '0.8rem';
            removeBtn.style.borderRadius = '8px';
            removeBtn.innerHTML = '<i class="fas fa-trash"></i> Remove';
            removeBtn.addEventListener('click', () => removeBiometricCredential(c.id));

            item.appendChild(removeBtn);
            container.appendChild(item);
        });
    } catch (e) {
        container.innerHTML = '';
    }
}

async function registerBiometric() {
    if (!window.PublicKeyCredential) {
        showAlert('Your browser does not support biometric/passkey login. Use a modern browser like Chrome, Edge, or Safari.', 'error');
        return;
    }

    const btn = document.getElementById('biometricRegisterBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Registering...'; }

    const token = localStorage.getItem('token');
    if (!token) {
        showAlert('You need to sign in before registering a passkey.', 'error');
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-plus-circle"></i> Add Passkey'; }
        return;
    }

    try {
        // Step 1: Get registration options from server
        const optRes = await fetch(`${API_URL}/api/auth/webauthn/register-options`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        const optData = await optRes.json();
        if (!optRes.ok || !optData.success) {
            throw new Error(optData.message || 'Failed to get registration options from the backend.');
        }

        const options = optData.options;

        // Decode base64url fields for the browser API
        options.challenge = Uint8Array.from(atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
        options.user.id = Uint8Array.from(atob(options.user.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
        if (options.excludeCredentials) {
            options.excludeCredentials = options.excludeCredentials.map(c => ({
                ...c,
                id: Uint8Array.from(atob(c.id.replace(/-/g, '+').replace(/_/g, '/')), c2 => c2.charCodeAt(0))
            }));
        }

        // Step 2: Create credential via browser
        const credential = await navigator.credentials.create({ publicKey: options });
        if (!credential) {
            throw new Error('The browser did not return a passkey credential.');
        }

        // Step 3: Encode response for server
        const attestationResponse = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                transports: credential.response.getTransports ? credential.response.getTransports() : ['internal']
            },
            clientExtensionResults: credential.getClientExtensionResults()
        };

        // Step 4: Verify with server
        const verRes = await fetch(`${API_URL}/api/auth/webauthn/register-verify`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ attestationResponse })
        });
        const verData = await verRes.json();

        if (verData.success) {
            showAlert('Biometric passkey registered successfully!', 'success');
            loadBiometricCredentials();
        } else {
            throw new Error(verData.message || 'Verification failed.');
        }
    } catch (e) {
        const message = String(e?.message || 'Unknown passkey registration error.');
        if (e?.name === 'NotAllowedError' || /cancelled|denied/i.test(message)) {
            showAlert('Biometric registration was cancelled by the browser or device. Try again and approve the prompt.', 'error');
        } else if (/support|PublicKeyCredential|webAuthn|browser/i.test(message)) {
            showAlert('Your browser does not support passkey registration. Use a compatible browser and try again.', 'error');
        } else {
            showAlert('Failed to register passkey: ' + message, 'error');
        }
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-plus-circle"></i> Add Passkey'; }
    }
}

async function removeBiometricCredential(credId) {
    const confirmed = await showConfirmDialog('Remove this passkey? You won\'t be able to use it for biometric login anymore.', 'Remove Passkey', 'Remove', 'Cancel');
    if (!confirmed) return;
    const token = localStorage.getItem('token');
    try {
        const res = await fetch(`${API_URL}/api/auth/webauthn/credentials/${credId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        if (data.success) {
            showAlert('Passkey removed.', 'success');
            loadBiometricCredentials();
        } else {
            showAlert(data.message || 'Failed to remove passkey.', 'error');
        }
    } catch (e) {
        showAlert('Error removing passkey.', 'error');
    }
}

