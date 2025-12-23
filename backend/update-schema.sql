-- Heritage Bank Core Banking System Schema
-- Author: GitHub Copilot (GPT-4.1)
-- Date: 2025-12-22

-- 1. ROLES & ACCESS CONTROL
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(32) UNIQUE NOT NULL, -- Super Admin, Admin, Customer
    description TEXT
);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    role_id INTEGER NOT NULL REFERENCES roles(id),
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(32),
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending, active, locked, etc.
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP, -- soft delete
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    mfa_enabled BOOLEAN DEFAULT FALSE
);

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(128) NOT NULL,
    details TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. CUSTOMER PROFILE & ONBOARDING
CREATE TABLE customer_profiles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),
    full_name VARCHAR(128) NOT NULL,
    date_of_birth DATE NOT NULL,
    address_street VARCHAR(128) NOT NULL,
    address_city VARCHAR(64) NOT NULL,
    address_state CHAR(2) NOT NULL,
    address_zip VARCHAR(10) NOT NULL,
    ssn_last4 CHAR(4) NOT NULL,
    gov_id_type VARCHAR(32) NOT NULL,
    gov_id_number VARCHAR(32) NOT NULL,
    terms_accepted BOOLEAN NOT NULL,
    privacy_accepted BOOLEAN NOT NULL,
    signup_status VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending, approved, rejected, active
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. ACCOUNTS
CREATE TABLE accounts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    account_number VARCHAR(12) UNIQUE NOT NULL,
    type VARCHAR(16) NOT NULL, -- checking, savings
    status VARCHAR(16) NOT NULL DEFAULT 'active', -- active, frozen, closed
    ledger_balance NUMERIC(16,2) NOT NULL DEFAULT 0.00,
    available_balance NUMERIC(16,2) NOT NULL DEFAULT 0.00,
    overdraft_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP,
    flags VARCHAR(64), -- under review, restricted, etc.
    deleted_at TIMESTAMP
);

-- 4. VIRTUAL CARDS
CREATE TABLE cards (
    id SERIAL PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    card_number CHAR(16) UNIQUE NOT NULL,
    expiry_date CHAR(5) NOT NULL, -- MM/YY
    cvv CHAR(3) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active', -- active, frozen, closed
    spending_limit NUMERIC(16,2),
    online_enabled BOOLEAN DEFAULT TRUE,
    international_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- 5. TRANSACTIONS
CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    type VARCHAR(16) NOT NULL, -- deposit, withdrawal, transfer, fee, interest
    amount NUMERIC(16,2) NOT NULL,
    reference_id VARCHAR(32) UNIQUE NOT NULL,
    description TEXT,
    status VARCHAR(16) NOT NULL DEFAULT 'posted', -- posted, pending, reversed
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    available_at TIMESTAMP,
    related_account_id INTEGER REFERENCES accounts(id), -- for transfers
    card_id INTEGER REFERENCES cards(id), -- for card transactions
    admin_id INTEGER REFERENCES users(id), -- for admin adjustments
    immutable BOOLEAN DEFAULT TRUE
);

-- 6. TRANSFER LOGS
CREATE TABLE transfer_logs (
    id SERIAL PRIMARY KEY,
    sender_account_id INTEGER NOT NULL REFERENCES accounts(id),
    receiver_account_id INTEGER NOT NULL REFERENCES accounts(id),
    amount NUMERIC(16,2) NOT NULL,
    reference_id VARCHAR(32) UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 7. STATEMENTS
CREATE TABLE statements (
    id SERIAL PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    file_url TEXT -- link to PDF or HTML statement
);

-- 8. NOTIFICATIONS
CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    type VARCHAR(32) NOT NULL, -- login, transfer, low_balance, etc.
    message TEXT NOT NULL,
    read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 9. SUPPORT TICKETS
CREATE TABLE support_tickets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    subject VARCHAR(128) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'open', -- open, closed, pending
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP
);

-- 10. FAQ & HELP
CREATE TABLE faqs (
    id SERIAL PRIMARY KEY,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 11. FEATURE TOGGLES
CREATE TABLE feature_toggles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(64) UNIQUE NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 12. MAINTENANCE MODE
CREATE TABLE maintenance_mode (
    id SERIAL PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- ==================== BENEFICIARIES TABLE ====================
CREATE TABLE IF NOT EXISTS beneficiaries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    accountNumber VARCHAR(50) NOT NULL,
    bankName VARCHAR(255) DEFAULT 'Heritage Bank',
    email VARCHAR(255),
    nickname VARCHAR(100),
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_beneficiary (userId)
);

-- ==================== TRANSACTION LIMITS TABLE ====================
CREATE TABLE IF NOT EXISTS transaction_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    dailyLimit DECIMAL(15,2) DEFAULT 10000.00,
    weeklyLimit DECIMAL(15,2) DEFAULT 50000.00,
    monthlyLimit DECIMAL(15,2) DEFAULT 200000.00,
    singleTransactionLimit DECIMAL(15,2) DEFAULT 5000.00,
    dailySpent DECIMAL(15,2) DEFAULT 0.00,
    weeklySpent DECIMAL(15,2) DEFAULT 0.00,
    monthlySpent DECIMAL(15,2) DEFAULT 0.00,
    lastResetDate DATE,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_limit (userId)
);

-- ==================== SCHEDULED PAYMENTS TABLE ====================
CREATE TABLE IF NOT EXISTS scheduled_payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    type ENUM('transfer', 'bill') NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    frequency ENUM('once', 'daily', 'weekly', 'monthly') NOT NULL,
    nextRunDate DATE NOT NULL,
    endDate DATE,
    toAccountNumber VARCHAR(50),
    toEmail VARCHAR(255),
    billerId INT,
    description VARCHAR(500),
    status ENUM('active', 'paused', 'completed', 'cancelled') DEFAULT 'active',
    lastRunDate DATE,
    runCount INT DEFAULT 0,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_scheduled (userId),
    INDEX idx_next_run (nextRunDate, status)
);

-- ==================== DOCUMENTS TABLE (KYC) ====================
CREATE TABLE IF NOT EXISTS documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    documentType ENUM('id_card', 'passport', 'drivers_license', 'utility_bill', 'bank_statement', 'other') NOT NULL,
    fileName VARCHAR(255) NOT NULL,
    filePath VARCHAR(500) NOT NULL,
    fileSize INT,
    mimeType VARCHAR(100),
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    reviewedBy INT,
    reviewedAt TIMESTAMP NULL,
    rejectionReason TEXT,
    uploadedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (reviewedBy) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_documents (userId),
    INDEX idx_status (status)
);

-- ==================== LOGIN HISTORY TABLE ====================
CREATE TABLE IF NOT EXISTS login_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    ipAddress VARCHAR(45),
    userAgent TEXT,
    device VARCHAR(255),
    location VARCHAR(255),
    city VARCHAR(100),
    country VARCHAR(100),
    loginStatus ENUM('success', 'failed') NOT NULL,
    failureReason VARCHAR(255),
    isSuspicious BOOLEAN DEFAULT false,
    loginAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_login (userId),
    INDEX idx_login_time (loginAt),
    INDEX idx_suspicious (isSuspicious)
);

-- ==================== CARDS UPDATE ====================
ALTER TABLE cards ADD COLUMN IF NOT EXISTS status ENUM('active', 'frozen', 'blocked', 'expired') DEFAULT 'active';
ALTER TABLE cards ADD COLUMN IF NOT EXISTS pin VARCHAR(255);
ALTER TABLE cards ADD COLUMN IF NOT EXISTS lastUsed TIMESTAMP NULL;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS frozenAt TIMESTAMP NULL;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS blockedAt TIMESTAMP NULL;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS blockReason VARCHAR(500);

-- ==================== COMPLIANCE & AUDIT ENHANCEMENTS ====================

-- 13. ENHANCED AUDIT LOGS (Full Audit Trail with IP, Old/New Values)
CREATE TABLE IF NOT EXISTS compliance_audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT,                                           -- User who performed the action (NULL for system)
    targetUserId INT,                                     -- User affected by the action
    entityType ENUM('user', 'account', 'transaction', 'card', 'document', 'system', 'admin', 'compliance') NOT NULL,
    entityId INT,                                         -- ID of the affected entity
    action VARCHAR(128) NOT NULL,                         -- Action performed (e.g., 'balance_adjustment', 'account_freeze')
    oldValue TEXT,                                        -- Previous value (JSON for complex data)
    newValue TEXT,                                        -- New value (JSON for complex data)
    reason TEXT,                                          -- Reason for the action
    ipAddress VARCHAR(45),                                -- IP address of the actor
    userAgent TEXT,                                       -- Browser/device info
    sessionId VARCHAR(128),                               -- Session identifier
    requestId VARCHAR(64),                                -- Unique request ID for tracing
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (targetUserId) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_entity (entityType, entityId),
    INDEX idx_user_audit (userId),
    INDEX idx_target_user (targetUserId),
    INDEX idx_action (action),
    INDEX idx_created (createdAt)
);

-- 14. COMPLIANCE FLAGS (AML, Fraud, Regulatory Holds)
CREATE TABLE IF NOT EXISTS compliance_flags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    accountId INT,                                        -- Optional: specific account
    flagType ENUM(
        'aml_review',                                     -- Anti-Money Laundering review
        'fraud_alert',                                    -- Suspected fraud
        'kyc_incomplete',                                 -- KYC documents pending
        'kyc_expired',                                    -- KYC documents expired
        'ofac_match',                                     -- OFAC sanctions list potential match
        'unusual_activity',                               -- Unusual transaction patterns
        'high_risk',                                      -- High-risk customer designation
        'regulatory_hold',                                -- Regulatory/legal hold
        'pep',                                            -- Politically Exposed Person
        'restricted',                                     -- Account restricted
        'under_review'                                    -- General review
    ) NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    description TEXT,
    triggeredBy ENUM('system', 'admin', 'compliance_officer') DEFAULT 'system',
    triggeredById INT,                                    -- ID of admin/user who flagged
    status ENUM('active', 'resolved', 'escalated', 'dismissed') DEFAULT 'active',
    resolvedBy INT,
    resolvedAt TIMESTAMP NULL,
    resolutionNotes TEXT,
    expiresAt TIMESTAMP NULL,                             -- Auto-expiry for some flags
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (accountId) REFERENCES accounts(id) ON DELETE SET NULL,
    FOREIGN KEY (triggeredById) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (resolvedBy) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_flags (userId),
    INDEX idx_account_flags (accountId),
    INDEX idx_flag_type (flagType),
    INDEX idx_flag_status (status),
    INDEX idx_severity (severity)
);

-- 15. ADMIN ACTION LOGS (Separate from user audit for admin oversight)
CREATE TABLE IF NOT EXISTS admin_action_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    adminId INT NOT NULL,                                 -- Admin who performed action
    targetUserId INT,                                     -- Customer affected
    targetAccountId INT,                                  -- Account affected
    actionType ENUM(
        'user_create',
        'user_approve',
        'user_reject',
        'user_suspend',
        'user_activate',
        'user_delete',
        'account_freeze',
        'account_unfreeze',
        'account_close',
        'balance_adjust',
        'card_freeze',
        'card_unfreeze',
        'card_block',
        'transaction_reverse',
        'document_approve',
        'document_reject',
        'flag_add',
        'flag_resolve',
        'limit_change',
        'impersonate_start',
        'impersonate_end',
        'report_generate',
        'system_config_change'
    ) NOT NULL,
    previousState TEXT,                                   -- JSON of previous state
    newState TEXT,                                        -- JSON of new state
    reason TEXT NOT NULL,                                 -- Required reason for all admin actions
    amount DECIMAL(15,2),                                 -- For balance adjustments
    ipAddress VARCHAR(45),
    userAgent TEXT,
    approvedBy INT,                                       -- For dual-control actions
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (adminId) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (targetUserId) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (approvedBy) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_admin (adminId),
    INDEX idx_target_user (targetUserId),
    INDEX idx_action_type (actionType),
    INDEX idx_created (createdAt)
);

-- 16. ACCOUNT DELETION REQUESTS (GDPR/CCPA - Right to be Forgotten)
CREATE TABLE IF NOT EXISTS account_deletion_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    requestedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    scheduledDeletionDate DATE NOT NULL,                  -- 30-day grace period
    reason TEXT,
    status ENUM('pending', 'cancelled', 'processing', 'completed') DEFAULT 'pending',
    cancelledAt TIMESTAMP NULL,
    cancelledReason TEXT,
    processedAt TIMESTAMP NULL,
    processedBy INT,                                      -- Admin who processed
    dataExportProvided BOOLEAN DEFAULT FALSE,
    finalBalance DECIMAL(15,2),                           -- Balance at time of request
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (processedBy) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user (userId),
    INDEX idx_status (status),
    INDEX idx_scheduled (scheduledDeletionDate)
);

-- 17. REGULATORY REPORTS (CTR, SAR, Daily/Monthly Reports)
CREATE TABLE IF NOT EXISTS regulatory_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    reportType ENUM(
        'ctr',                                            -- Currency Transaction Report ($10k+)
        'sar',                                            -- Suspicious Activity Report
        'daily_summary',                                  -- Daily transaction summary
        'monthly_summary',                                -- Monthly account summary
        'quarterly_compliance',                           -- Quarterly compliance report
        'annual_report',                                  -- Annual report
        'audit_report',                                   -- Audit trail export
        'ofac_screening',                                 -- OFAC screening results
        'kyc_status'                                      -- KYC completion report
    ) NOT NULL,
    periodStart DATE,
    periodEnd DATE,
    generatedBy INT,                                      -- Admin who generated
    generatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('pending', 'generated', 'submitted', 'acknowledged') DEFAULT 'pending',
    submittedAt TIMESTAMP NULL,
    submittedTo VARCHAR(128),                             -- Regulatory body
    referenceNumber VARCHAR(64),                          -- External reference
    filePath VARCHAR(500),                                -- Path to generated report file
    summary TEXT,                                         -- JSON summary of report contents
    recordCount INT,                                      -- Number of records in report
    totalAmount DECIMAL(20,2),                            -- Total amount if applicable
    FOREIGN KEY (generatedBy) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_report_type (reportType),
    INDEX idx_period (periodStart, periodEnd),
    INDEX idx_status (status)
);

-- 18. INTEREST ACCRUAL LOGS (Savings Account Interest)
CREATE TABLE IF NOT EXISTS interest_accruals (
    id INT AUTO_INCREMENT PRIMARY KEY,
    accountId INT NOT NULL,
    periodStart DATE NOT NULL,
    periodEnd DATE NOT NULL,
    openingBalance DECIMAL(15,2) NOT NULL,
    averageDailyBalance DECIMAL(15,2) NOT NULL,
    interestRate DECIMAL(8,6) NOT NULL,                   -- APY as decimal (e.g., 0.0425 for 4.25%)
    interestEarned DECIMAL(15,4) NOT NULL,
    compoundingMethod ENUM('daily', 'monthly', 'quarterly') DEFAULT 'daily',
    status ENUM('accrued', 'posted', 'adjusted') DEFAULT 'accrued',
    postedAt TIMESTAMP NULL,
    transactionId INT,                                    -- Link to transaction when posted
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (accountId) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (transactionId) REFERENCES transactions(id) ON DELETE SET NULL,
    INDEX idx_account (accountId),
    INDEX idx_period (periodStart, periodEnd),
    INDEX idx_status (status)
);

-- 19. FEE ENGINE (Account Fees Tracking)
CREATE TABLE IF NOT EXISTS account_fees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    accountId INT NOT NULL,
    feeType ENUM(
        'monthly_maintenance',
        'overdraft',
        'nsf',                                            -- Non-Sufficient Funds
        'wire_transfer',
        'international_transfer',
        'atm_fee',
        'paper_statement',
        'card_replacement',
        'stop_payment',
        'account_closure',
        'dormant_account',
        'excess_withdrawal'                               -- Savings Reg D violation
    ) NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    description TEXT,
    status ENUM('pending', 'charged', 'waived', 'reversed') DEFAULT 'pending',
    chargedAt TIMESTAMP NULL,
    waivedBy INT,                                         -- Admin who waived
    waivedAt TIMESTAMP NULL,
    waiveReason TEXT,
    transactionId INT,                                    -- Link to transaction
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (accountId) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (waivedBy) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (transactionId) REFERENCES transactions(id) ON DELETE SET NULL,
    INDEX idx_account (accountId),
    INDEX idx_fee_type (feeType),
    INDEX idx_status (status)
);

-- 20. FEE SCHEDULE (Configurable Fee Amounts)
CREATE TABLE IF NOT EXISTS fee_schedule (
    id INT AUTO_INCREMENT PRIMARY KEY,
    feeType VARCHAR(64) NOT NULL,
    accountType ENUM('checking', 'savings', 'business', 'premium', 'all') DEFAULT 'all',
    amount DECIMAL(15,2) NOT NULL,
    description TEXT,
    isActive BOOLEAN DEFAULT TRUE,
    effectiveFrom DATE NOT NULL,
    effectiveTo DATE,                                     -- NULL = no end date
    conditions TEXT,                                      -- JSON conditions for when fee applies
    createdBy INT,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (createdBy) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE KEY unique_fee_type_account (feeType, accountType, effectiveFrom),
    INDEX idx_fee_type (feeType),
    INDEX idx_active (isActive)
);

-- 21. SCHEDULED COMPLIANCE JOBS (Batch Processing)
CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    jobType ENUM(
        'interest_calculation',
        'fee_assessment',
        'dormant_account_check',
        'kyc_expiry_check',
        'suspicious_activity_scan',
        'daily_report',
        'monthly_statement',
        'balance_snapshot',
        'deletion_processing',
        'ofac_screening'
    ) NOT NULL,
    frequency ENUM('hourly', 'daily', 'weekly', 'monthly', 'quarterly', 'annually') NOT NULL,
    lastRunAt TIMESTAMP NULL,
    nextRunAt TIMESTAMP NOT NULL,
    status ENUM('idle', 'running', 'completed', 'failed') DEFAULT 'idle',
    lastResult TEXT,                                      -- JSON result of last run
    recordsProcessed INT DEFAULT 0,
    errorMessage TEXT,
    isActive BOOLEAN DEFAULT TRUE,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_job_type (jobType),
    INDEX idx_next_run (nextRunAt),
    INDEX idx_status (status)
);

-- 22. TRANSACTION HOLDS (Pending/Memo Posts)
CREATE TABLE IF NOT EXISTS transaction_holds (
    id INT AUTO_INCREMENT PRIMARY KEY,
    accountId INT NOT NULL,
    cardId INT,                                           -- If card transaction
    amount DECIMAL(15,2) NOT NULL,
    merchantName VARCHAR(255),
    merchantCategory VARCHAR(64),
    holdType ENUM('authorization', 'pending_deposit', 'check_hold', 'admin_hold') NOT NULL,
    expiresAt TIMESTAMP NOT NULL,                         -- When hold auto-releases
    status ENUM('active', 'released', 'posted', 'expired') DEFAULT 'active',
    releasedAt TIMESTAMP NULL,
    postedTransactionId INT,                              -- Link to final transaction
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (accountId) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (cardId) REFERENCES cards(id) ON DELETE SET NULL,
    FOREIGN KEY (postedTransactionId) REFERENCES transactions(id) ON DELETE SET NULL,
    INDEX idx_account (accountId),
    INDEX idx_status (status),
    INDEX idx_expires (expiresAt)
);

-- 23. DAILY BALANCE SNAPSHOTS (For Reporting & Interest Calc)
CREATE TABLE IF NOT EXISTS balance_snapshots (
    id INT AUTO_INCREMENT PRIMARY KEY,
    accountId INT NOT NULL,
    snapshotDate DATE NOT NULL,
    ledgerBalance DECIMAL(15,2) NOT NULL,
    availableBalance DECIMAL(15,2) NOT NULL,
    holdAmount DECIMAL(15,2) DEFAULT 0.00,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (accountId) REFERENCES accounts(id) ON DELETE CASCADE,
    UNIQUE KEY unique_account_date (accountId, snapshotDate),
    INDEX idx_date (snapshotDate)
);

-- 24. DATA EXPORT LOGS (GDPR Compliance)
CREATE TABLE IF NOT EXISTS data_export_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    exportType ENUM('full_profile', 'transactions', 'statements', 'all_data') NOT NULL,
    requestedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    generatedAt TIMESTAMP NULL,
    expiresAt TIMESTAMP,                                  -- Download link expiry
    downloadCount INT DEFAULT 0,
    filePath VARCHAR(500),
    fileSize INT,
    status ENUM('pending', 'generating', 'ready', 'downloaded', 'expired') DEFAULT 'pending',
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user (userId),
    INDEX idx_status (status)
);

-- 25. SYSTEM CONFIGURATION (Feature Toggles & Settings)
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    configKey VARCHAR(128) UNIQUE NOT NULL,
    configValue TEXT NOT NULL,
    configType ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
    description TEXT,
    isPublic BOOLEAN DEFAULT FALSE,                       -- Can be read by non-admins
    updatedBy INT,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (updatedBy) REFERENCES users(id) ON DELETE SET NULL
);

-- ==================== INSERT DEFAULT CONFIGURATIONS ====================

-- Insert default roles
INSERT IGNORE INTO roles (name, description) VALUES 
    ('super_admin', 'Full system access with all permissions'),
    ('admin', 'Administrative access for user and account management'),
    ('customer', 'Standard customer access');

-- Insert default fee schedule
INSERT IGNORE INTO fee_schedule (feeType, accountType, amount, description, effectiveFrom) VALUES
    ('monthly_maintenance', 'checking', 12.00, 'Monthly account maintenance fee', CURDATE()),
    ('monthly_maintenance', 'savings', 5.00, 'Monthly savings account fee', CURDATE()),
    ('monthly_maintenance', 'premium', 0.00, 'Premium accounts have no monthly fee', CURDATE()),
    ('overdraft', 'all', 35.00, 'Overdraft fee per occurrence', CURDATE()),
    ('nsf', 'all', 35.00, 'Non-sufficient funds fee', CURDATE()),
    ('wire_transfer', 'all', 25.00, 'Domestic wire transfer fee', CURDATE()),
    ('international_transfer', 'all', 45.00, 'International wire transfer fee', CURDATE()),
    ('paper_statement', 'all', 3.00, 'Paper statement fee per month', CURDATE()),
    ('card_replacement', 'all', 10.00, 'Debit card replacement fee', CURDATE()),
    ('stop_payment', 'all', 30.00, 'Stop payment request fee', CURDATE()),
    ('excess_withdrawal', 'savings', 10.00, 'Excess withdrawal fee (Reg D)', CURDATE());

-- Insert default system config
INSERT IGNORE INTO system_config (configKey, configValue, configType, description, isPublic) VALUES
    ('maintenance_mode', 'false', 'boolean', 'Enable/disable maintenance mode', TRUE),
    ('maintenance_message', 'We are currently performing scheduled maintenance. Please try again later.', 'string', 'Maintenance mode message', TRUE),
    ('min_initial_deposit', '50', 'number', 'Minimum initial deposit amount', TRUE),
    ('max_daily_transfer', '10000', 'number', 'Maximum daily transfer limit', FALSE),
    ('savings_apy', '0.0425', 'number', 'Current savings account APY', TRUE),
    ('checking_overdraft_limit', '500', 'number', 'Maximum overdraft amount for checking', FALSE),
    ('kyc_document_expiry_days', '365', 'number', 'Days until KYC documents expire', FALSE),
    ('dormant_account_days', '365', 'number', 'Days of inactivity before account marked dormant', FALSE),
    ('deletion_grace_period_days', '30', 'number', 'Days before account deletion is processed', FALSE),
    ('ctr_threshold', '10000', 'number', 'Currency Transaction Report threshold', FALSE),
    ('session_timeout_minutes', '30', 'number', 'User session timeout in minutes', FALSE),
    ('max_login_attempts', '5', 'number', 'Max failed login attempts before lockout', FALSE),
    ('lockout_duration_minutes', '15', 'number', 'Account lockout duration', FALSE);

-- Insert default scheduled jobs
INSERT IGNORE INTO scheduled_jobs (jobType, frequency, nextRunAt) VALUES
    ('interest_calculation', 'daily', DATE_ADD(CURDATE(), INTERVAL 1 DAY)),
    ('fee_assessment', 'monthly', LAST_DAY(CURDATE()) + INTERVAL 1 DAY),
    ('dormant_account_check', 'monthly', LAST_DAY(CURDATE()) + INTERVAL 1 DAY),
    ('kyc_expiry_check', 'daily', DATE_ADD(CURDATE(), INTERVAL 1 DAY)),
    ('suspicious_activity_scan', 'daily', DATE_ADD(CURDATE(), INTERVAL 1 DAY)),
    ('daily_report', 'daily', DATE_ADD(CURDATE(), INTERVAL 1 DAY)),
    ('monthly_statement', 'monthly', LAST_DAY(CURDATE()) + INTERVAL 1 DAY),
    ('balance_snapshot', 'daily', DATE_ADD(CURDATE(), INTERVAL 1 DAY)),
    ('deletion_processing', 'daily', DATE_ADD(CURDATE(), INTERVAL 1 DAY));
