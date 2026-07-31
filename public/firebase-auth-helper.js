/**
 * Heritage Bank - Firebase Auth Helper
 * Handles Firebase Authentication and syncs with the backend MySQL database.
 * Used by signin.html and signup.html.
 */

// Firebase SDK loaded via CDN before this script runs.
// Config is in firebase-config.js which must be loaded first.

const AUTH_API_URL = (() => {
    const { hostname, protocol } = window.location;
    if (protocol === 'file:' || hostname === 'localhost' || hostname === '127.0.0.1') {
        return 'http://localhost:3001';
    }
    return 'https://heritage-bank-production.up.railway.app';
})();

/**
 * After Firebase Auth succeeds, exchange the Firebase ID token for a
 * backend JWT and store the session in localStorage.
 */
async function syncFirebaseUserWithBackend(firebaseUser, extraProfile = {}) {
    const idToken = await firebaseUser.getIdToken();

    const res = await fetch(`${AUTH_API_URL}/api/auth/firebase-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken, ...extraProfile })
    });

    const data = await res.json();
    if (!data.success) throw new Error(data.message || 'Backend sync failed');

    // Store session exactly like the existing login flow
    localStorage.setItem('token', data.token);
    localStorage.setItem('user', JSON.stringify({
        id: data.user.id,
        firstName: data.user.firstName,
        lastName: data.user.lastName,
        email: data.user.email,
        accountNumber: data.user.accountNumber,
        accountType: data.user.accountType,
        isAdmin: !!data.user.isAdmin
    }));

    return data.user;
}

/**
 * Sign in with email + password via Firebase Auth.
 */
async function firebaseSignIn(email, password) {
    const auth = firebase.auth();
    const cred = await auth.signInWithEmailAndPassword(email, password);
    return syncFirebaseUserWithBackend(cred.user);
}

/**
 * Sign up with email + password via Firebase Auth, then sync to backend.
 */
async function firebaseSignUp(email, password, profile = {}) {
    const auth = firebase.auth();
    const cred = await auth.createUserWithEmailAndPassword(email, password);

    // Set display name in Firebase
    if (profile.firstName || profile.lastName) {
        await cred.user.updateProfile({
            displayName: `${profile.firstName || ''} ${profile.lastName || ''}`.trim()
        });
    }

    return syncFirebaseUserWithBackend(cred.user, profile);
}

/**
 * Sign in with Google popup via Firebase Auth.
 * Falls back to redirect when the browser blocks the popup.
 */
async function firebaseGoogleSignIn() {
    const auth = firebase.auth();
    const provider = new firebase.auth.GoogleAuthProvider();
    provider.addScope('email');
    provider.addScope('profile');

    try {
        const cred = await auth.signInWithPopup(provider);
        return syncFirebaseUserWithBackend(cred.user);
    } catch (e) {
        const msg = e?.message || '';

        if (e && (e.code === 'auth/configuration-not-found' || /configuration-not-found/i.test(msg))) {
            throw new Error('Google sign-in is not configured for this browser origin. Please add heritage-bank.pages.dev to Firebase Authentication authorized domains and ensure Google Sign-In is enabled for this project.');
        }

        if (e && (e.code === 'auth/popup-blocked' || /popup|blocked|cancelled|denied/i.test(msg))) {
            await auth.signInWithRedirect(provider);
            return { redirecting: true };
        }

        throw e;
    }
}

/**
 * Complete the Google redirect flow on the page the browser lands on after auth.
 */
async function handleFirebaseGoogleRedirectResult() {
    const auth = firebase.auth();
    try {
        const result = await auth.getRedirectResult();
        if (!result || !result.user) {
            return null;
        }
        return syncFirebaseUserWithBackend(result.user);
    } catch (e) {
        const msg = e?.message || '';
        if (e && (e.code === 'auth/configuration-not-found' || /configuration-not-found/i.test(msg))) {
            throw new Error('Google sign-in is not configured for this browser origin. Please add heritage-bank.pages.dev to Firebase Authentication authorized domains and ensure Google Sign-In is enabled for this project.');
        }
        throw e;
    }
}

/**
 * Sign out from both Firebase and clear local session.
 */
async function firebaseSignOut() {
    try { await firebase.auth().signOut(); } catch (_) {}
    const consent = localStorage.getItem('cookieConsent');
    localStorage.clear();
    if (consent) localStorage.setItem('cookieConsent', consent);
    window.location.href = 'signin.html';
}

// Expose globally
window.firebaseSignIn = firebaseSignIn;
window.firebaseSignUp = firebaseSignUp;
window.firebaseGoogleSignIn = firebaseGoogleSignIn;
window.handleFirebaseGoogleRedirectResult = handleFirebaseGoogleRedirectResult;
window.firebaseSignOut = firebaseSignOut;
window.syncFirebaseUserWithBackend = syncFirebaseUserWithBackend;
