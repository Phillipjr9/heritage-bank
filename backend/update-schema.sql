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
