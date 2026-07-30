// Firebase configuration - Heritage Bank
const firebaseConfig = {
  apiKey: "AIzaSyD5ERFnJ3CmFyVvHHUVX2M7JkF0RrDc7Wg",
  authDomain: "heritagebank-3c12d.firebaseapp.com",
  projectId: "heritagebank-3c12d",
  storageBucket: "heritagebank-3c12d.firebasestorage.app",
  messagingSenderId: "335576779003",
  appId: "1:335576779003:web:a59a99a97316c6212fc85e",
  measurementId: "G-3E2KTM12QX"
};

if (typeof firebase !== 'undefined') {
  if (!firebase.apps.length) firebase.initializeApp(firebaseConfig);
} else {
  window.addEventListener('load', () => {
    if (!firebase.apps.length) firebase.initializeApp(firebaseConfig);
  });
}
