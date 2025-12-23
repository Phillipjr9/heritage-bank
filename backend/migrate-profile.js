/**
 * Database Migration Script for Banking Profile Features
 * Creates all necessary tables for enhanced user profile functionality
 * Run this before deploying the updated application
 */

const mysql = require('mysql2/promise');
require('dotenv').config();

async function runMigrations() {
    let connection;
    try {
        // Connect to database
        connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            port: process.env.DB_PORT || 4000,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            ssl: { rejectUnauthorized: false }
        });

        console.log('✅ Connected to database');

        // 1. Active Sessions Table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS active_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId INT NOT NULL,
                sessionToken VARCHAR(500) UNIQUE,
                deviceName VARCHAR(255),
                browserName VARCHAR(255),
                location VARCHAR(255),
                ipAddress VARCHAR(45),
                lastActivity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                expiresAt TIMESTAMP,
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_sessions (userId),
                INDEX idx_expires (expiresAt)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        `);
        console.log('✅ Created active_sessions table');

        // 2. User Preferences Table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS user_preferences (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId INT NOT NULL UNIQUE,
                notificationsEmail BOOLEAN DEFAULT true,
                notificationsSms BOOLEAN DEFAULT true,
                notificationsPush BOOLEAN DEFAULT false,
                notificationsInApp BOOLEAN DEFAULT true,
                marketingEmails BOOLEAN DEFAULT false,
                loginAlertsEnabled BOOLEAN DEFAULT true,
                transactionAlertsEnabled BOOLEAN DEFAULT true,
                largeTransactionAlert DECIMAL(15,2) DEFAULT 5000,
                language VARCHAR(10) DEFAULT 'en',
                timezone VARCHAR(50) DEFAULT 'America/New_York',
                internationalEnabled BOOLEAN DEFAULT true,
                preferenceKey VARCHAR(255),
                preferenceValue JSON,
                updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_prefs (userId)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        `);
        console.log('✅ Created user_preferences table');

        // 3. Security Questions Table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS security_questions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId INT NOT NULL,
                questionId INT,
                answerHash VARCHAR(255),
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_questions (userId)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        `);
        console.log('✅ Created security_questions table');

        // 4. User Documents Table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS user_documents (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId INT NOT NULL,
                documentType VARCHAR(100),
                fileName VARCHAR(255),
                filePath VARCHAR(500),
                fileSize INT,
                verificationStatus ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                rejectionReason TEXT,
                expiryDate DATE,
                reviewedBy INT,
                reviewedAt TIMESTAMP NULL,
                uploadedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (reviewedBy) REFERENCES users(id),
                INDEX idx_user_documents (userId),
                INDEX idx_status (verificationStatus),
                INDEX idx_uploaded (uploadedAt)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        `);
        console.log('✅ Created user_documents table');

        // 5. Profile Change Log Table (Audit Trail)
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS profile_change_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId INT NOT NULL,
                fieldChanged VARCHAR(255),
                oldValue TEXT,
                newValue TEXT,
                changeReason VARCHAR(255),
                ipAddress VARCHAR(45),
                changedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_changes (userId),
                INDEX idx_changed_at (changedAt)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        `);
        console.log('✅ Created profile_change_log table');

        // 6. Linked Accounts Table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS linked_accounts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId INT NOT NULL,
                linkedAccountNumber VARCHAR(50),
                linkedRoutingNumber VARCHAR(20),
                linkedBankName VARCHAR(255),
                accountHolderName VARCHAR(255),
                verificationStatus ENUM('pending', 'verified', 'failed') DEFAULT 'pending',
                verificationCode VARCHAR(10),
                verificationAttempts INT DEFAULT 0,
                linkedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verifiedAt TIMESTAMP NULL,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_linked (userId),
                INDEX idx_status (verificationStatus)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        `);
        console.log('✅ Created linked_accounts table');

        // 7. Enhance Users Table with New Columns (if not already present)
        try {
            await connection.execute('ALTER TABLE users ADD COLUMN emailVerified BOOLEAN DEFAULT false');
            console.log('✅ Added emailVerified column');
        } catch (e) {
            if (e.code !== 'ER_DUP_FIELDNAME') throw e;
            console.log('ℹ️  emailVerified column already exists');
        }

        try {
            await connection.execute('ALTER TABLE users ADD COLUMN phoneVerified BOOLEAN DEFAULT false');
            console.log('✅ Added phoneVerified column');
        } catch (e) {
            if (e.code !== 'ER_DUP_FIELDNAME') throw e;
            console.log('ℹ️  phoneVerified column already exists');
        }

        try {
            await connection.execute('ALTER TABLE users ADD COLUMN twoFactorEnabled BOOLEAN DEFAULT false');
            console.log('✅ Added twoFactorEnabled column');
        } catch (e) {
            if (e.code !== 'ER_DUP_FIELDNAME') throw e;
            console.log('ℹ️  twoFactorEnabled column already exists');
        }

        try {
            await connection.execute('ALTER TABLE users ADD COLUMN twoFactorMethod VARCHAR(20)');
            console.log('✅ Added twoFactorMethod column');
        } catch (e) {
            if (e.code !== 'ER_DUP_FIELDNAME') throw e;
            console.log('ℹ️  twoFactorMethod column already exists');
        }

        try {
            await connection.execute('ALTER TABLE users ADD COLUMN deletionRequestedAt TIMESTAMP NULL');
            console.log('✅ Added deletionRequestedAt column');
        } catch (e) {
            if (e.code !== 'ER_DUP_FIELDNAME') throw e;
            console.log('ℹ️  deletionRequestedAt column already exists');
        }

        try {
            await connection.execute('ALTER TABLE users ADD COLUMN scheduledDeletionDate TIMESTAMP NULL');
            console.log('✅ Added scheduledDeletionDate column');
        } catch (e) {
            if (e.code !== 'ER_DUP_FIELDNAME') throw e;
            console.log('ℹ️  scheduledDeletionDate column already exists');
        }

        // 8. Enhance Beneficiaries Table
        try {
            await connection.execute('ALTER TABLE beneficiaries ADD COLUMN routingNumber VARCHAR(20)');
            console.log('✅ Added routingNumber to beneficiaries');
        } catch (e) {
            if (e.code !== 'ER_DUP_FIELDNAME') throw e;
            console.log('ℹ️  routingNumber already exists in beneficiaries');
        }

        try {
            await connection.execute('ALTER TABLE beneficiaries ADD COLUMN verified BOOLEAN DEFAULT false');
            console.log('✅ Added verified to beneficiaries');
        } catch (e) {
            if (e.code !== 'ER_DUP_FIELDNAME') throw e;
            console.log('ℹ️  verified already exists in beneficiaries');
        }

        // 9. Create Transaction Limits Table (if not exists)
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS transaction_limits (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId INT NOT NULL UNIQUE,
                dailyLimit DECIMAL(15,2) DEFAULT 10000,
                weeklyLimit DECIMAL(15,2) DEFAULT 50000,
                monthlyLimit DECIMAL(15,2) DEFAULT 200000,
                singleTransactionLimit DECIMAL(15,2) DEFAULT 25000,
                dailySpent DECIMAL(15,2) DEFAULT 0,
                weeklySpent DECIMAL(15,2) DEFAULT 0,
                monthlySpent DECIMAL(15,2) DEFAULT 0,
                updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_limits (userId)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        `);
        console.log('✅ Created transaction_limits table');

        console.log('\n✅ All migrations completed successfully!');
        console.log('\n📋 Created/Enhanced tables:');
        console.log('  1. active_sessions - Track user sessions across devices');
        console.log('  2. user_preferences - Store user notification and UI preferences');
        console.log('  3. security_questions - Store security questions for account recovery');
        console.log('  4. user_documents - Track KYC documents and verification status');
        console.log('  5. profile_change_log - Audit trail of profile changes');
        console.log('  6. linked_accounts - External account linking');
        console.log('  7. Enhanced users table - Added 6 new columns for enhanced features');
        console.log('  8. Enhanced beneficiaries table - Added routing number and verification');
        console.log('  9. transaction_limits - Track daily/weekly/monthly transaction limits');

        return true;
    } catch (error) {
        console.error('❌ Migration error:', error.message);
        return false;
    } finally {
        if (connection) {
            await connection.end();
        }
    }
}

// Run migrations
runMigrations().then(success => {
    process.exit(success ? 0 : 1);
});
