# Quick Test Guide - Authentication System

## 🚀 Ready to Test

Your authentication system has been completely overhauled with banking-standard security and compliance features. Here's how to test everything.

---

## Prerequisites

### Servers Running
- ✅ **Backend**: http://localhost:3001 (Node.js/Express)
- ✅ **Frontend**: http://localhost:8000 (http-server)
- ✅ **Database**: TiDB Cloud (connected)

### Check Server Status
```powershell
# Backend should show:
# 🏦 Heritage Bank running on port 3001
# ✅ Database initialized with all tables

# Frontend should show:
# Starting up http-server
# Available on: http://127.0.0.1:8000
```

---

## Test 1: Enhanced Login Page 🔐

### URL
```
http://localhost:8000/signin.html
```

### Features to Test

#### ✅ Test 1.1 - Basic Login
1. Enter email: `admin@heritage.com`
2. Enter password: `admin123`
3. Click **Sign In**
4. Should redirect to dashboard

#### ✅ Test 1.2 - Login with Account Number
1. Create a new account first (see Test 2)
2. Note your account number (e.g., `1234567890`)
3. On login page, enter account number instead of email
4. Enter password
5. Click **Sign In**
6. Should successfully login

#### ✅ Test 1.3 - Password Visibility Toggle
1. Enter any password
2. Click the **👁 eye icon** next to password field
3. Password should become visible
4. Click again to hide

#### ✅ Test 1.4 - Remember Me
1. Check the **"Remember me"** checkbox
2. Login successfully
3. Close browser
4. Reopen and check if you're still logged in (30-day token)

#### ✅ Test 1.5 - Failed Login Lockout
1. Enter email: `test@example.com`
2. Enter wrong password: `wrongpass`
3. Click **Sign In**
4. Should show: "⚠️ 1 failed attempt(s). 4 remaining before lockout"
5. Repeat 4 more times with wrong password
6. After 5th attempt, should show: "Account locked for 15 minutes"
7. Button should be disabled
8. Countdown timer should appear
9. Wait for timer to expire or clear localStorage to unlock

#### ✅ Test 1.6 - Security Notice
1. Page should display: "🔒 Your session is encrypted and secure"

#### ✅ Test 1.7 - Forgot Password Link
1. Click **"Forgot Password?"** link
2. Should redirect to forgot-password.html

#### ✅ Test 1.8 - Last Login Display
1. Login successfully
2. Logout
3. Login again
4. Should display: "Last login: [timestamp]"

---

## Test 2: Enhanced Signup (4-Step Wizard) 📝

### URL
```
http://localhost:8000/open-account-enhanced.html
```

### Full Happy Path Test

#### Step 1: Personal Information
1. **First Name**: John
2. **Last Name**: Doe
3. **Date of Birth**: 01/15/1990 (must be 18+)
4. **SSN** (optional): 123-45-6789 (auto-formats as you type)
5. Click **Next Step** →

**Validation Tests**:
- Try DOB with age < 18 (should reject)
- Leave first/last name empty (should show error)

#### Step 2: Contact Details
1. **Email**: john.doe@example.com
2. **Phone**: 5551234567 (auto-formats to +1 (555) 123-4567)
3. **Street Address**: 123 Main Street
4. **City**: New York
5. **State**: Select "NY" from dropdown
6. **ZIP Code**: 10001 (must be 5 digits)
7. **Country**: United States (readonly)
8. Click **Next Step** →

**Validation Tests**:
- Enter invalid email format (should reject)
- Enter ZIP code with 4 digits (should reject)
- Leave any required field empty (should reject)

#### Step 3: Account Setup
1. **Account Type**: Click on **"Checking Account"** card (should highlight green)
2. **Initial Deposit**: 500 (minimum $50)
3. **Password**: SecurePass123! (watch strength meter change colors)
4. **Confirm Password**: SecurePass123! (must match)
5. **Referral Code** (optional): REF123
6. Click **Next Step** →

**Validation Tests**:
- Try deposit < $50 (should reject)
- Try weak password (should show warning)
- Enter non-matching passwords (should reject)
- Don't select account type (should reject)

**Password Strength Levels**:
- `pass` → 🔴 Very Weak (20%)
- `password123` → 🟠 Weak (40%)
- `Password123` → 🟡 Fair (60%)
- `Password123!` → 🟢 Strong (80%)
- `SecurePass123!` → 🟢 Very Strong (100%)

#### Step 4: Review & Confirm
1. Review summary should show all your information
2. Check **"I agree to the Terms & Conditions"**
3. Check **"I agree to the Privacy Policy"**
4. Check **"I confirm I am at least 18 years old"**
5. Optionally check **"I want to receive promotional emails"**
6. Click **Create Account**

**Validation Tests**:
- Uncheck any required checkbox (should reject)

#### Success!
- Should show: "Account created successfully! Account Number: XXXXXXXXXX"
- Should auto-login and redirect to dashboard after 2 seconds
- Check your balance = $500 (your initial deposit)

---

## Test 3: Backend API Testing 🔧

### Test 3.1 - Registration Endpoint

**Using Postman/curl**:
```bash
POST http://localhost:3001/api/auth/register
Content-Type: application/json

{
  "firstName": "Jane",
  "lastName": "Smith",
  "email": "jane@example.com",
  "password": "SecurePass456!",
  "phone": "+1 (555) 987-6543",
  "dateOfBirth": "1995-08-20",
  "ssn": "987-65-4321",
  "address": "456 Oak Avenue",
  "city": "Los Angeles",
  "state": "CA",
  "zipCode": "90001",
  "country": "United States",
  "accountType": "savings",
  "initialDeposit": 1000,
  "referralCode": "TEST123",
  "marketingConsent": true
}
```

**Expected Response**:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 2,
    "firstName": "Jane",
    "lastName": "Smith",
    "email": "jane@example.com",
    "accountNumber": "3847562910",
    "balance": 1000,
    "accountType": "savings"
  }
}
```

**Error Tests**:
```bash
# Test 1: Age < 18
{
  "dateOfBirth": "2010-01-01"  # Should return 400: "You must be at least 18 years old"
}

# Test 2: Deposit < $50
{
  "initialDeposit": 25  # Should return 400: "Minimum initial deposit is $50.00"
}

# Test 3: Duplicate email
{
  "email": "admin@heritage.com"  # Should return 400: "Email already registered"
}
```

### Test 3.2 - Login Endpoint

**Using Postman/curl**:
```bash
POST http://localhost:3001/api/auth/login
Content-Type: application/json

{
  "email": "jane@example.com",
  "password": "SecurePass456!",
  "rememberMe": true
}
```

**Expected Response**:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 2,
    "firstName": "Jane",
    "lastName": "Smith",
    "email": "jane@example.com",
    "accountNumber": "3847562910",
    "balance": 1000,
    "isAdmin": false,
    "lastLogin": "2024-01-15T14:30:00.000Z"
  }
}
```

**Login with Account Number**:
```bash
{
  "email": "3847562910",  # Use account number instead!
  "password": "SecurePass456!",
  "rememberMe": false
}
```

---

## Test 4: Database Verification 💾

### Check New User Record
```sql
SELECT * FROM users WHERE email = 'jane@example.com';
```

**Should show all new fields**:
- dateOfBirth: 1995-08-20
- ssn: 987-65-4321
- address: 456 Oak Avenue
- city: Los Angeles
- state: CA
- zipCode: 90001
- accountType: savings
- accountStatus: active
- marketingConsent: 1
- lastLogin: [timestamp]

### Check Initial Deposit Transaction
```sql
SELECT * FROM transactions WHERE userId = 2 ORDER BY createdAt DESC LIMIT 1;
```

**Should show**:
- type: deposit
- amount: 1000.00
- description: Initial account deposit
- status: completed
- reference: DEP-[timestamp]

### Check Login History
```sql
SELECT * FROM login_history WHERE userId = 2 ORDER BY loginAt DESC;
```

**Should show entries for**:
- Successful logins with IP address
- Failed login attempts (if tested)
- User agent information

---

## Test 5: Edge Cases & Error Handling 🧪

### Signup Errors

#### Test 5.1 - Empty Required Fields
1. Leave first name empty
2. Click Next
3. Should show: "Please fill in all required fields"

#### Test 5.2 - Invalid Email Format
1. Enter email: `notanemail`
2. Complete Step 2
3. Should show: "Please enter a valid email address"

#### Test 5.3 - Invalid ZIP Code
1. Enter ZIP: `123` (only 3 digits)
2. Complete Step 2
3. Should show: "Please enter a valid 5-digit ZIP code"

#### Test 5.4 - Underage Registration
1. Enter DOB: 01/01/2010 (14 years old)
2. Click Next from Step 1
3. Should show: "You must be at least 18 years old to open an account"

#### Test 5.5 - Weak Password
1. Enter password: `pass`
2. Check strength meter: should show "Very Weak" in red
3. Try to proceed
4. Should show: "Password is too weak..."

#### Test 5.6 - Password Mismatch
1. Password: `SecurePass123!`
2. Confirm: `SecurePass456!`
3. Try to proceed
4. Should show: "Passwords do not match"

#### Test 5.7 - Minimum Deposit Not Met
1. Enter initial deposit: `25`
2. Try to proceed
3. Should show: "Minimum initial deposit is $50.00"

#### Test 5.8 - No Account Type Selected
1. Don't click any account type card
2. Try to proceed from Step 3
3. Should show: "Please select an account type"

#### Test 5.9 - Terms Not Accepted
1. Complete all steps
2. Leave "Terms & Conditions" unchecked
3. Click Create Account
4. Should show: "You must agree to all required terms and conditions"

### Login Errors

#### Test 5.10 - Invalid Credentials
1. Enter email: `test@test.com`
2. Enter password: `wrongpassword`
3. Should show: "Invalid credentials"
4. Should increment failed attempts counter

#### Test 5.11 - Account Lockout
1. Fail login 5 times
2. Should show: "Too many failed attempts. Account locked for 15 minutes."
3. Button should be disabled
4. Countdown should appear

#### Test 5.12 - Frozen Account (if admin freezes account)
1. Admin freezes user account from admin panel
2. User tries to login
3. Should show: "Account is frozen. Please contact support."

---

## Test 6: Auto-Formatting ✨

### SSN Formatting
1. Type: `123456789`
2. Should auto-format to: `123-45-6789`

### Phone Formatting
1. Type: `5551234567`
2. Should auto-format to: `+1 (555) 123-4567`

---

## Test 7: Responsive Design 📱

### Desktop (1920x1080)
1. Open signup in full screen
2. All 4 account type cards should display in 2x2 grid
3. Form should be centered
4. Progress bar should span full width

### Tablet (768px)
1. Resize browser to tablet width
2. Account type cards should stack
3. Form inputs should remain readable
4. Navigation buttons should be full width

### Mobile (375px)
1. Resize to mobile width
2. All content should be visible without horizontal scroll
3. Inputs should be touch-friendly
4. Progress steps should stack or scroll

---

## Test 8: Browser Compatibility 🌐

Test on:
- ✅ Chrome (recommended)
- ✅ Firefox
- ✅ Safari
- ✅ Edge

### Features to verify:
- Password visibility toggle (eye icon)
- Account type card selection
- Progress bar animation
- Auto-formatting (SSN, phone)
- localStorage lockout
- Form validation messages

---

## Common Issues & Solutions 🔧

### Issue 1: "Account locked" immediately on page load
**Solution**: Clear localStorage
```javascript
// In browser console:
localStorage.clear()
// Refresh page
```

### Issue 2: Auto-formatting not working
**Solution**: Make sure you're typing directly, not copy-pasting

### Issue 3: "Email already registered"
**Solution**: Use a different email or check existing users in database

### Issue 4: Backend not responding
**Solution**: 
```powershell
# Check backend is running
netstat -ano | findstr :3001

# If not running, start it
cd "c:\Users\USER\HERITAGE AY\backend"
node server.js
```

### Issue 5: Database schema not updated
**Solution**: Backend auto-creates tables on startup, but if issues persist:
```sql
-- Drop and recreate users table
DROP TABLE IF EXISTS users;
-- Restart backend server to recreate with new schema
```

---

## Success Criteria ✅

### Login Page
- [ ] Can login with email
- [ ] Can login with account number
- [ ] Password toggle works
- [ ] Remember me extends token to 30 days
- [ ] Failed attempts tracked
- [ ] 5 failed = 15-minute lockout
- [ ] Lockout countdown works
- [ ] Forgot password link works
- [ ] Security notice displayed
- [ ] Loading spinner shows during login

### Signup Page
- [ ] All 4 steps display correctly
- [ ] Progress indicator updates
- [ ] Step 1: Age validation (18+)
- [ ] Step 2: Email & ZIP validation
- [ ] Step 3: Account type cards selectable
- [ ] Step 3: Password strength indicator works
- [ ] Step 3: Minimum deposit enforced
- [ ] Step 4: Review summary accurate
- [ ] Step 4: Terms checkboxes required
- [ ] SSN auto-formats (XXX-XX-XXXX)
- [ ] Phone auto-formats (+1 (XXX) XXX-XXXX)
- [ ] Account created successfully
- [ ] Initial deposit transaction created
- [ ] Auto-login after signup

### Backend
- [ ] Registration accepts all 18 fields
- [ ] Age validation works (reject < 18)
- [ ] Deposit validation works (reject < $50)
- [ ] Duplicate email check works
- [ ] Login with email works
- [ ] Login with account number works
- [ ] login_history table populated
- [ ] lastLogin timestamp updated
- [ ] Remember me = 30d token expiry

---

## Performance Benchmarks ⚡

### Expected Response Times
- Login API: < 500ms
- Registration API: < 1000ms
- Page Load: < 2 seconds
- Step Navigation: Instant
- Auto-formatting: Real-time

---

## Security Checklist 🔒

- [ ] Passwords hashed with bcrypt
- [ ] Tokens signed with JWT
- [ ] Failed attempts logged
- [ ] Account lockout working
- [ ] SQL injection prevented (parameterized queries)
- [ ] XSS prevented (no eval, innerHTML sanitized)
- [ ] CORS configured correctly
- [ ] SSL notice displayed
- [ ] Sensitive data not logged

---

## Next Steps After Testing 🚀

1. **Two-Factor Authentication**
   - Add email OTP verification
   - Add SMS OTP verification

2. **Email Verification**
   - Send verification email on signup
   - Require email confirmation before full access

3. **Document Upload**
   - Add ID upload to signup
   - Integrate with documents table

4. **Admin Features**
   - Add user management (freeze/unfreeze accounts)
   - View login history from admin panel
   - Account type management

---

## Quick Reference Card 📋

### Test Account Credentials
```
Admin Account:
Email: admin@heritage.com
Password: admin123
Account Number: (check database)

Test User (after creating):
Email: [your test email]
Password: [password you set]
Account Number: [shown on success]
```

### Key URLs
```
Frontend:   http://localhost:8000
Backend:    http://localhost:3001
Login:      http://localhost:8000/signin.html
Signup:     http://localhost:8000/open-account-enhanced.html
Dashboard:  http://localhost:8000/dashboard.html
Admin:      http://localhost:8000/admin.html
```

### API Endpoints
```
POST /api/auth/login
POST /api/auth/register
GET  /api/user/profile
GET  /api/health
```

---

## Report Issues 🐛

If you find any bugs during testing, note:
1. What you were doing
2. What you expected
3. What actually happened
4. Browser console errors (F12)
5. Network tab errors (if API-related)

---

**Happy Testing! 🎉**

Everything is ready to go. Start with the Login page (Test 1), then move to Signup (Test 2), and verify database records (Test 4).
