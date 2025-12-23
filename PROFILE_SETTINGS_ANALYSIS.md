# User Profile & Settings - Banking Requirements Analysis

## Current State Assessment

### ✅ What's Already There
1. **Basic Profile Fields**
   - First Name, Last Name
   - Email (readonly)
   - Phone Number
   - Address, City, Country

2. **Security Features**
   - Change Password
   - Two-Factor Authentication toggle (UI only)

3. **Notification Preferences**
   - Email Notifications
   - Transaction Alerts
   - Security Alerts
   - Marketing Communications

4. **Account Actions**
   - Download Statement
   - Activity Log
   - Close Account

---

## ❌ What's Missing (Banking Standards)

### 1. Personal Information (KYC Compliance)

#### Missing Critical Fields:
- ❌ **Date of Birth** - Required for age verification and legal compliance
- ❌ **Social Security Number (SSN)** - Tax reporting and identity verification
- ❌ **State/Province** - Complete address (only City & Country shown)
- ❌ **ZIP/Postal Code** - Complete mailing address
- ❌ **Full Street Address** - Currently only "Address" field
- ❌ **Account Type Display** - Checking/Savings/Business/Premium
- ❌ **Account Number** - User should see their account number
- ❌ **Routing Number** - For wire transfers and ACH
- ❌ **Account Status** - Active/Frozen/Suspended display
- ❌ **Member Since Date** - Account creation date

#### Missing Optional Fields:
- ❌ **Middle Name** - Full legal name
- ❌ **Preferred Name** - Display name
- ❌ **Gender** - Optional demographic data
- ❌ **Occupation** - Risk assessment
- ❌ **Employer** - Income verification
- ❌ **Annual Income Range** - Credit decisions

---

### 2. Contact Preferences

#### Missing:
- ❌ **Preferred Contact Method** - Email/Phone/SMS/Mail
- ❌ **Preferred Language** - English/Spanish/etc.
- ❌ **Time Zone** - For scheduling and alerts
- ❌ **Alternative Phone** - Backup contact
- ❌ **Emergency Contact** - Name & phone
- ❌ **Best Time to Call** - Customer service preference

---

### 3. Security & Privacy

#### Missing Critical Features:
- ❌ **Login History** - Recent login attempts with IP, device, location
- ❌ **Active Sessions** - See all logged-in devices
- ❌ **Logout Other Devices** - Remote session termination
- ❌ **Security Questions** - Password recovery
- ❌ **Trusted Devices** - Device fingerprinting
- ❌ **SMS Alerts Toggle** - Critical transaction notifications
- ❌ **Email Verification Status** - Verified/Unverified badge
- ❌ **Phone Verification Status** - Verified/Unverified badge
- ❌ **PIN Management** - ATM/Debit card PIN
- ❌ **Biometric Settings** - Fingerprint/Face ID (if supported)

#### Missing Password Features:
- ❌ **Password Strength Indicator** - Show current password strength
- ❌ **Password History** - Can't reuse last 5 passwords
- ❌ **Last Password Change Date** - Display when last changed
- ❌ **Password Expiry Warning** - Force change every 90 days

#### Missing 2FA Features:
- ❌ **2FA Method Selection** - SMS/Email/Authenticator App
- ❌ **Backup Codes** - Recovery codes for 2FA
- ❌ **2FA Device Management** - Registered devices list

---

### 4. Transaction & Account Limits

#### Missing:
- ❌ **Daily Transfer Limit** - View and request changes
- ❌ **Weekly Transfer Limit** - View current limit
- ❌ **Monthly Transfer Limit** - View current limit
- ❌ **Single Transaction Limit** - Maximum per transaction
- ❌ **ATM Withdrawal Limit** - Daily ATM limit
- ❌ **International Transaction Toggle** - Enable/disable
- ❌ **Current Limit Usage** - Used/Remaining this period
- ❌ **Request Limit Increase** - Submit increase request
- ❌ **Spending Controls** - Category-based limits

---

### 5. Privacy & Data Management

#### Missing GDPR/Privacy Features:
- ❌ **Data Download** - Export all personal data (GDPR right)
- ❌ **Data Deletion Request** - Right to be forgotten
- ❌ **Marketing Opt-Out History** - Track consent changes
- ❌ **Cookie Preferences** - Manage tracking cookies
- ❌ **Third-Party Sharing** - Opt-out of data sharing
- ❌ **Privacy Policy Version** - Show accepted policy version
- ❌ **Terms Acceptance Date** - When terms were accepted
- ❌ **Data Retention Policy** - How long data is kept

---

### 6. Document Management

#### Missing:
- ❌ **ID Documents** - Upload/view ID, passport, driver's license
- ❌ **Proof of Address** - Upload utility bills, bank statements
- ❌ **Tax Documents** - W-9, 1099, tax forms
- ❌ **Document Verification Status** - Pending/Approved/Rejected
- ❌ **Document Expiry Alerts** - When ID expires
- ❌ **Re-upload Expired Docs** - Easy renewal process

---

### 7. Beneficiaries & Payees

#### Missing:
- ❌ **Manage Beneficiaries** - View/edit saved beneficiaries
- ❌ **Add New Beneficiary** - Quick add from settings
- ❌ **Beneficiary Limits** - Per-beneficiary transfer limits
- ❌ **Beneficiary Verification** - Status of verification
- ❌ **Delete Beneficiary** - Remove saved payees
- ❌ **Favorite Beneficiaries** - Quick access to frequent payees

---

### 8. Account Statements & Reports

#### Missing:
- ❌ **Statement Delivery Preference** - Email/Mail/Online
- ❌ **Statement Frequency** - Monthly/Quarterly/Annual
- ❌ **Statement History** - List of all statements
- ❌ **Tax Documents** - 1099-INT, year-end summaries
- ❌ **Transaction Export** - CSV/Excel download
- ❌ **Custom Date Range Reports** - Generate reports for any period

---

### 9. Linked Accounts & Integration

#### Missing:
- ❌ **Link External Accounts** - Connect other bank accounts
- ❌ **Verify External Accounts** - Micro-deposit verification
- ❌ **Plaid Integration** - Instant account linking
- ❌ **Remove Linked Accounts** - Unlink accounts
- ❌ **Account Aggregation** - View all accounts in one place
- ❌ **Auto-transfer Rules** - Scheduled transfers between accounts

---

### 10. Accessibility & Preferences

#### Missing:
- ❌ **Font Size Preference** - Large/Normal/Small
- ❌ **High Contrast Mode** - For visually impaired
- ❌ **Screen Reader Support** - ARIA labels
- ❌ **Dashboard Layout** - Customize widget order
- ❌ **Default Landing Page** - Where to go after login
- ❌ **Currency Display** - Format preferences
- ❌ **Date Format** - MM/DD/YYYY vs DD/MM/YYYY

---

### 11. Advanced Security Features

#### Missing:
- ❌ **Freeze Account** - Temporary self-freeze
- ❌ **Unfreeze Account** - Self-unfreeze with verification
- ❌ **Transaction Freeze** - Block all outgoing transactions
- ❌ **Card Controls** - Freeze/unfreeze debit card
- ❌ **Geographic Restrictions** - Block transactions from certain countries
- ❌ **Merchant Category Blocks** - Block gambling, etc.
- ❌ **Daily Spending Alerts** - Alert when spending exceeds $X
- ❌ **Low Balance Alerts** - Alert when balance < $X

---

### 12. Account Information Display

#### Missing Read-Only Info:
- ❌ **Account Number** - Formatted with last 4 digits
- ❌ **Routing Number** - For ACH/wire transfers
- ❌ **Account Type** - Checking/Savings/Business/Premium
- ❌ **Account Status** - Active/Frozen/Suspended
- ❌ **Account Open Date** - Member since
- ❌ **Last Activity Date** - Last transaction date
- ❌ **Current Balance** - Quick balance view
- ❌ **Available Balance** - After pending transactions
- ❌ **Customer ID** - Unique customer identifier
- ❌ **Branch/Region** - Associated branch

---

### 13. Communication Preferences

#### Missing:
- ❌ **Email Frequency** - Daily/Weekly/Monthly digest
- ❌ **SMS Alerts** - Enable/disable SMS
- ❌ **Push Notifications** - Mobile app alerts
- ❌ **Phone Call Preferences** - Do Not Call options
- ❌ **Mail Preferences** - Paperless banking opt-in
- ❌ **Transaction Alert Threshold** - Alert for transactions > $X
- ❌ **Newsletter Subscription** - Opt-in/out

---

### 14. Scheduled Actions

#### Missing:
- ❌ **Scheduled Transfers** - View/edit recurring transfers
- ❌ **Scheduled Payments** - View/edit bill payments
- ❌ **Payment Calendar** - Upcoming scheduled payments
- ❌ **Pause Scheduled Payment** - Temporarily suspend
- ❌ **Delete Scheduled Payment** - Cancel recurring payment

---

### 15. Audit Trail & Activity Log

#### Missing:
- ❌ **Profile Change History** - Who changed what and when
- ❌ **Settings Change Log** - Audit trail of settings
- ❌ **Password Change History** - Last 5 password changes
- ❌ **Failed Login Attempts** - Recent failed logins
- ❌ **IP Address Log** - Recent access IPs
- ❌ **Device History** - All devices used to access account
- ❌ **Export Activity Log** - Download full history

---

## Priority Ranking (Implementation Order)

### 🔴 CRITICAL (Must Have for Banking Compliance)
1. **Account Information Display** - Account number, routing, type, status
2. **Complete Address Fields** - State, ZIP code, full street address
3. **Date of Birth** - Age verification and legal requirement
4. **Login History & Active Sessions** - Security requirement
5. **Transaction Limits Management** - Risk management
6. **Email/Phone Verification Status** - KYC compliance
7. **Password Strength & History** - Security best practice

### 🟠 HIGH PRIORITY (Standard Banking Features)
8. **Beneficiary Management** - Common banking feature
9. **Statement Preferences** - Customer expectation
10. **Document Upload** - KYC/AML requirement
11. **2FA Method Selection** - Enhanced security
12. **Freeze/Unfreeze Account** - Fraud prevention
13. **Linked External Accounts** - Customer convenience
14. **Privacy Data Download** - GDPR compliance

### 🟡 MEDIUM PRIORITY (Enhanced Experience)
15. **Emergency Contact** - Good practice
16. **Security Questions** - Password recovery
17. **Scheduled Transfers View** - User convenience
18. **Transaction Export** - Accounting needs
19. **Accessibility Options** - Inclusive design
20. **Communication Preferences** - Reduce spam

### 🟢 LOW PRIORITY (Nice to Have)
21. **Preferred Language** - Multi-language support
22. **Dashboard Customization** - UX enhancement
23. **Spending Controls by Category** - Advanced feature
24. **Geographic Restrictions** - Advanced security
25. **Newsletter Subscription** - Marketing

---

## Recommended Implementation Plan

### Phase 1: Critical Information & Security (Week 1)
- Add missing profile fields (DOB, SSN, State, ZIP)
- Display account details (number, routing, type, status)
- Login history and active sessions
- Email/phone verification badges
- Transaction limits display

### Phase 2: Enhanced Security (Week 2)
- Password strength indicator
- 2FA method selection with backup codes
- Security questions setup
- Freeze/unfreeze account toggle
- Logout other devices

### Phase 3: Document & Beneficiary Management (Week 3)
- Document upload section
- Beneficiary management
- Statement preferences
- Privacy data download

### Phase 4: Advanced Features (Week 4)
- Linked external accounts
- Scheduled transfers management
- Transaction export
- Accessibility preferences
- Communication preferences

---

## Backend API Requirements

### New Endpoints Needed:
```javascript
// Profile Management
PUT  /api/user/profile/complete      // Update all profile fields
GET  /api/user/profile/verification  // Get verification statuses
POST /api/user/profile/verify-email  // Send verification email
POST /api/user/profile/verify-phone  // Send SMS verification

// Security
GET  /api/user/security/login-history        // Recent logins
GET  /api/user/security/active-sessions      // Active sessions
POST /api/user/security/logout-session/:id   // Logout specific session
POST /api/user/security/logout-all           // Logout all devices
GET  /api/user/security/password-strength    // Check password strength
POST /api/user/security/security-questions   // Save security questions

// 2FA
POST /api/user/2fa/enable               // Enable 2FA
POST /api/user/2fa/disable              // Disable 2FA
GET  /api/user/2fa/backup-codes         // Get backup codes
POST /api/user/2fa/verify               // Verify 2FA code

// Limits
GET  /api/user/limits                   // Get all limits
PUT  /api/user/limits/request-increase  // Request limit increase
GET  /api/user/limits/usage             // Current usage

// Documents
POST /api/user/documents/upload         // Upload document
GET  /api/user/documents                // List documents
DELETE /api/user/documents/:id          // Delete document

// Beneficiaries
GET  /api/user/beneficiaries            // List beneficiaries
POST /api/user/beneficiaries            // Add beneficiary
PUT  /api/user/beneficiaries/:id        // Update beneficiary
DELETE /api/user/beneficiaries/:id      // Remove beneficiary

// Privacy
GET  /api/user/privacy/export-data      // Export all data (GDPR)
POST /api/user/privacy/delete-request   // Request deletion

// Account Controls
POST /api/user/account/freeze           // Freeze account
POST /api/user/account/unfreeze         // Unfreeze account
POST /api/user/account/close-request    // Request closure
```

---

## Database Schema Updates

### Users Table - Add Columns:
```sql
ALTER TABLE users ADD COLUMN:
- dateOfBirth DATE                          -- Already added
- ssn VARCHAR(11)                           -- Already added
- state VARCHAR(50)                         -- Already added
- zipCode VARCHAR(10)                       -- Already added
- middleName VARCHAR(100)
- preferredName VARCHAR(100)
- occupation VARCHAR(100)
- employer VARCHAR(255)
- annualIncome VARCHAR(50)                  -- Range: <25k, 25-50k, etc.
- emergencyContactName VARCHAR(200)
- emergencyContactPhone VARCHAR(20)
- preferredContactMethod ENUM('email', 'phone', 'sms', 'mail')
- preferredLanguage VARCHAR(10) DEFAULT 'en'
- timeZone VARCHAR(50)
- emailVerified BOOLEAN DEFAULT false
- phoneVerified BOOLEAN DEFAULT false
- emailVerifiedAt TIMESTAMP NULL
- phoneVerifiedAt TIMESTAMP NULL
- lastPasswordChange TIMESTAMP NULL
- passwordExpiryDate TIMESTAMP NULL
- accountFrozenByUser BOOLEAN DEFAULT false
- internationalTransactionsEnabled BOOLEAN DEFAULT true
```

### New Tables Needed:

#### 1. login_history (Already exists - verify)
```sql
CREATE TABLE login_history (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT,
    ipAddress VARCHAR(45),
    userAgent TEXT,
    device VARCHAR(255),
    location VARCHAR(255),
    status ENUM('success', 'failed'),
    failureReason VARCHAR(255),
    sessionId VARCHAR(255),
    loginAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id)
);
```

#### 2. active_sessions
```sql
CREATE TABLE active_sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT,
    sessionToken VARCHAR(500),
    ipAddress VARCHAR(45),
    userAgent TEXT,
    device VARCHAR(255),
    location VARCHAR(255),
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lastActivity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expiresAt TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id)
);
```

#### 3. security_questions
```sql
CREATE TABLE security_questions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT,
    question VARCHAR(500),
    answerHash VARCHAR(255),
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id)
);
```

#### 4. two_factor_auth
```sql
CREATE TABLE two_factor_auth (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT UNIQUE,
    method ENUM('sms', 'email', 'authenticator'),
    secret VARCHAR(255),
    backupCodes TEXT,                    -- JSON array
    enabled BOOLEAN DEFAULT false,
    enabledAt TIMESTAMP NULL,
    lastUsedAt TIMESTAMP NULL,
    FOREIGN KEY (userId) REFERENCES users(id)
);
```

#### 5. user_documents (Already exists - verify)
```sql
CREATE TABLE user_documents (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT,
    documentType ENUM('id', 'passport', 'drivers_license', 'utility_bill', 'tax_form', 'other'),
    fileName VARCHAR(255),
    filePath VARCHAR(500),
    fileSize INT,
    uploadedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verificationStatus ENUM('pending', 'approved', 'rejected'),
    verifiedBy INT NULL,
    verifiedAt TIMESTAMP NULL,
    expiryDate DATE NULL,
    FOREIGN KEY (userId) REFERENCES users(id)
);
```

#### 6. linked_accounts
```sql
CREATE TABLE linked_accounts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT,
    bankName VARCHAR(255),
    accountNumber VARCHAR(50),          -- Encrypted
    routingNumber VARCHAR(20),
    accountType VARCHAR(50),
    nickname VARCHAR(100),
    verificationStatus ENUM('pending', 'verified', 'failed'),
    linkedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lastUsedAt TIMESTAMP NULL,
    FOREIGN KEY (userId) REFERENCES users(id)
);
```

#### 7. user_preferences
```sql
CREATE TABLE user_preferences (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT UNIQUE,
    emailNotifications BOOLEAN DEFAULT true,
    smsNotifications BOOLEAN DEFAULT false,
    pushNotifications BOOLEAN DEFAULT true,
    transactionAlerts BOOLEAN DEFAULT true,
    securityAlerts BOOLEAN DEFAULT true,
    marketingEmails BOOLEAN DEFAULT false,
    statementDelivery ENUM('email', 'mail', 'online') DEFAULT 'email',
    statementFrequency ENUM('monthly', 'quarterly', 'annual') DEFAULT 'monthly',
    transactionAlertThreshold DECIMAL(15,2) DEFAULT 500.00,
    lowBalanceThreshold DECIMAL(15,2) DEFAULT 100.00,
    theme VARCHAR(20) DEFAULT 'light',
    language VARCHAR(10) DEFAULT 'en',
    FOREIGN KEY (userId) REFERENCES users(id)
);
```

#### 8. profile_change_log
```sql
CREATE TABLE profile_change_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT,
    fieldChanged VARCHAR(100),
    oldValue TEXT,
    newValue TEXT,
    changedBy INT,                      -- Could be admin
    changedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ipAddress VARCHAR(45),
    FOREIGN KEY (userId) REFERENCES users(id)
);
```

---

## Summary Statistics

### Current Settings Page:
- **Sections**: 4 (Profile, Security, Notifications, Account Actions)
- **Editable Fields**: 7 (firstName, lastName, phone, address, city, country, password)
- **Security Features**: 2 (Password change, 2FA toggle - UI only)
- **Missing Critical Fields**: 15+
- **Missing Features**: 50+

### Recommended Enhanced Settings:
- **Sections**: 12-15 sections
- **Editable Fields**: 30+ fields
- **Security Features**: 15+ features
- **New Database Tables**: 6-8 tables
- **New API Endpoints**: 25+ endpoints

### Compliance Gap:
- **KYC Compliance**: 40% complete (missing DOB, SSN visibility, verification status)
- **GDPR Compliance**: 20% complete (missing data export, deletion request)
- **Security Best Practices**: 30% complete (missing login history, session management)
- **Banking Standards**: 35% complete (missing limits, beneficiaries, documents)

---

## Next Steps

1. **Review this analysis** with stakeholders
2. **Prioritize features** based on regulatory requirements
3. **Design wireframes** for new sections
4. **Create database migration** scripts
5. **Implement Phase 1** critical features
6. **Test thoroughly** before production

This analysis provides a roadmap to transform the basic settings page into a comprehensive, banking-compliant user profile management system.
