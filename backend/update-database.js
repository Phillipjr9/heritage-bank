const mysql = require('mysql2/promise');
require('dotenv').config();

async function updateSchema() {
    try {
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            port: process.env.DB_PORT || 4000,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            ssl: { rejectUnauthorized: false }
        });

        console.log('✅ Connected to database');

        // Create beneficiaries table
        await connection.execute(`
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
            )
        `);
        console.log('✅ Beneficiaries table created');

        // Create transaction_limits table
        await connection.execute(`
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
            )
        `);
        console.log('✅ Transaction limits table created');

        // Create scheduled_payments table
        await connection.execute(`
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
            )
        `);
        console.log('✅ Scheduled payments table created');

        // Create documents table
        await connection.execute(`
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
            )
        `);
        console.log('✅ Documents table created');

        // Create login_history table
        await connection.execute(`
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
            )
        `);
        console.log('✅ Login history table created');

        // Check if cards table exists, if so update it
        try {
            await connection.execute(`
                ALTER TABLE cards 
                ADD COLUMN IF NOT EXISTS status ENUM('active', 'frozen', 'blocked', 'expired') DEFAULT 'active'
            `);
            await connection.execute(`
                ALTER TABLE cards 
                ADD COLUMN IF NOT EXISTS pin VARCHAR(255)
            `);
            await connection.execute(`
                ALTER TABLE cards 
                ADD COLUMN IF NOT EXISTS lastUsed TIMESTAMP NULL
            `);
            await connection.execute(`
                ALTER TABLE cards 
                ADD COLUMN IF NOT EXISTS frozenAt TIMESTAMP NULL
            `);
            await connection.execute(`
                ALTER TABLE cards 
                ADD COLUMN IF NOT EXISTS blockedAt TIMESTAMP NULL
            `);
            await connection.execute(`
                ALTER TABLE cards 
                ADD COLUMN IF NOT EXISTS blockReason VARCHAR(500)
            `);
            console.log('✅ Cards table updated with new columns');
        } catch (error) {
            console.log('ℹ️  Cards table might not exist yet or columns already added');
        }

        await connection.end();
        console.log('\n✅ All schema updates completed successfully!');

    } catch (error) {
        console.error('❌ Error updating schema:');
        console.error('Message:', error.message);
        console.error('Code:', error.code);
        console.error('Full error:', error);
        process.exit(1);
    }
}

updateSchema();
