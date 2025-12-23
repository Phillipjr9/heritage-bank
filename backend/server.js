const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const path = require('path');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static frontend files from parent directory (for unified deployment)
app.use(express.static(path.join(__dirname, '..')));

// Database Connection Pool - Uses Environment Variables
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 4000,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: { rejectUnauthorized: false }
});

// JWT Secret - Must be set in environment
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('❌ JWT_SECRET environment variable is required');
    process.exit(1);
}

// Banking Details
const ROUTING_NUMBER = process.env.ROUTING_NUMBER || '091238946';
const BANK_NAME = 'Heritage Bank';

// Generate random account number
function generateAccountNumber() {
    return (Math.floor(Math.random() * 9000000000) + 1000000000).toString();
}

// Initialize database
async function initializeDatabase() {
    try {
        const connection = await pool.getConnection();
        
        // Users table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                firstName VARCHAR(100),
                lastName VARCHAR(100),
                email VARCHAR(255) UNIQUE,
                password VARCHAR(255),
                phone VARCHAR(20),
                dateOfBirth DATE,
                ssn VARCHAR(11),
                address VARCHAR(255),
                city VARCHAR(100),
                state VARCHAR(50),
                zipCode VARCHAR(10),
                country VARCHAR(100) DEFAULT 'United States',
                accountNumber VARCHAR(20) UNIQUE,
                routingNumber VARCHAR(20),
                balance DECIMAL(15,2) DEFAULT 50000,
                accountType ENUM('checking', 'savings', 'business', 'premium') DEFAULT 'checking',
                accountStatus ENUM('active', 'frozen', 'suspended', 'closed') DEFAULT 'active',
                isAdmin BOOLEAN DEFAULT false,
                marketingConsent BOOLEAN DEFAULT false,
                lastLogin TIMESTAMP NULL,
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Beneficiaries table
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

        // Transaction limits table
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

        // Scheduled payments table
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

        // Documents table
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
                INDEX idx_user_documents (userId),
                INDEX idx_status (status)
            )
        `);

        // Login history table
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

        // Check if admin exists
        const [adminCheck] = await connection.execute(
            'SELECT * FROM users WHERE email = ?',
            [process.env.ADMIN_EMAIL || 'admin@heritagebank.com']
        );

        if (adminCheck.length === 0 && process.env.ADMIN_PASSWORD) {
            const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
            await connection.execute(
                `INSERT INTO users (firstName, lastName, email, password, phone, accountNumber, routingNumber, balance, isAdmin) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                ['Admin', 'User', process.env.ADMIN_EMAIL || 'admin@heritagebank.com', hashedPassword, '1-800-BANK', generateAccountNumber(), ROUTING_NUMBER, 100000000, true]
            );
            console.log('✅ Admin account created');
        }

        connection.release();
        console.log('✅ Database initialized with all tables');
    } catch (error) {
        console.error('❌ Database error:', error.message);
    }
}

initializeDatabase();

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', database: 'Ready', timestamp: new Date().toISOString() });
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, rememberMe } = req.body;
        
        // Allow login with email or account number
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE email = ? OR accountNumber = ?', 
            [email, email]
        );
        
        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const user = users[0];
        
        // Check if account is frozen or suspended
        if (user.accountStatus === 'frozen' || user.accountStatus === 'suspended') {
            return res.status(403).json({ 
                success: false, 
                message: `Account is ${user.accountStatus}. Please contact support.` 
            });
        }
        
        if (user.accountStatus === 'closed') {
            return res.status(403).json({ 
                success: false, 
                message: 'Account is closed. Please contact support.' 
            });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            // Log failed login attempt
            await pool.execute(
                `INSERT INTO login_history (userId, ipAddress, userAgent, status) 
                 VALUES (?, ?, ?, ?)`,
                [user.id, req.ip, req.get('user-agent'), 'failed']
            );
            
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        // Log successful login
        await pool.execute(
            `INSERT INTO login_history (userId, ipAddress, userAgent, status) 
             VALUES (?, ?, ?, ?)`,
            [user.id, req.ip, req.get('user-agent'), 'success']
        );
        
        // Update last login timestamp
        await pool.execute(
            `UPDATE users SET lastLogin = NOW() WHERE id = ?`,
            [user.id]
        );
        
        const tokenExpiry = rememberMe ? '30d' : '24h';
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: tokenExpiry });

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                accountNumber: user.accountNumber,
                balance: parseFloat(user.balance),
                isAdmin: user.isAdmin,
                lastLogin: user.lastLogin
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { 
            firstName, 
            lastName, 
            email, 
            password, 
            phone, 
            dateOfBirth, 
            ssn, 
            address, 
            city, 
            state, 
            zipCode, 
            country, 
            accountType, 
            initialDeposit, 
            referralCode, 
            marketingConsent 
        } = req.body;
        
        // Validate required fields
        if (!firstName || !lastName || !email || !password || !phone) {
            return res.status(400).json({ success: false, message: 'All required fields must be filled' });
        }
        
        // Validate age
        if (dateOfBirth) {
            const age = Math.floor((new Date() - new Date(dateOfBirth)) / (365.25 * 24 * 60 * 60 * 1000));
            if (age < 18) {
                return res.status(400).json({ success: false, message: 'You must be at least 18 years old' });
            }
        }
        
        // Validate initial deposit
        const deposit = parseFloat(initialDeposit) || 0;
        if (deposit < 50) {
            return res.status(400).json({ success: false, message: 'Minimum initial deposit is $50.00' });
        }
        
        // Check if email already exists
        const [existingUsers] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ success: false, message: 'Email already registered' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const accountNumber = generateAccountNumber();

        await pool.execute(
            `INSERT INTO users (
                firstName, lastName, email, password, phone, 
                dateOfBirth, ssn, address, city, state, zipCode, country,
                accountNumber, routingNumber, balance, accountType, 
                marketingConsent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                firstName, lastName, email, hashedPassword, phone,
                dateOfBirth || null, ssn || null, address || null, city || null, 
                state || null, zipCode || null, country || 'United States',
                accountNumber, ROUTING_NUMBER, deposit, accountType || 'checking',
                marketingConsent || false
            ]
        );

        const [newUser] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = newUser[0];
        
        // Create initial deposit transaction
        if (deposit > 0) {
            await pool.execute(
                `INSERT INTO transactions (userId, type, amount, description, status, reference) 
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [user.id, 'deposit', deposit, 'Initial account deposit', 'completed', `DEP-${Date.now()}`]
            );
        }
        
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

        res.status(201).json({
            success: true,
            token,
            user: {
                id: user.id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                accountNumber: user.accountNumber,
                balance: deposit,
                accountType: user.accountType
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Get user profile
app.get('/api/user/profile', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);
        
        if (users.length === 0) return res.status(404).json({ success: false, message: 'User not found' });

        const user = users[0];
        res.json({
            success: true,
            user: {
                id: user.id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                phone: user.phone,
                accountNumber: user.accountNumber,
                routingNumber: user.routingNumber,
                balance: parseFloat(user.balance),
                isAdmin: user.isAdmin
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Admin: Get all users with balances
app.get('/api/admin/users-with-balances', async (req, res) => {
    try {
        const [users] = await pool.execute('SELECT id, firstName, lastName, email, accountNumber, balance, isAdmin FROM users');
        res.json({ success: true, users });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Admin: Fund user account
app.post('/api/admin/fund-user', async (req, res) => {
    try {
        const { toEmail, toAccountNumber, amount, description } = req.body;
        
        let user;
        if (toEmail) {
            const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [toEmail]);
            user = users[0];
        } else if (toAccountNumber) {
            const [users] = await pool.execute('SELECT * FROM users WHERE accountNumber = ?', [toAccountNumber]);
            user = users[0];
        }

        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        const newBalance = parseFloat(user.balance) + parseFloat(amount);
        await pool.execute('UPDATE users SET balance = ? WHERE id = ?', [newBalance, user.id]);

        res.json({
            success: true,
            message: `$${amount} added to ${user.firstName} ${user.lastName}`,
            newBalance
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Admin: Create user
app.post('/api/admin/create-user', async (req, res) => {
    try {
        const { firstName, lastName, email, password, phone, initialBalance } = req.body;
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const accountNumber = generateAccountNumber();
        const balance = initialBalance || 50000;

        await pool.execute(
            `INSERT INTO users (firstName, lastName, email, password, phone, accountNumber, routingNumber, balance) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [firstName, lastName, email, hashedPassword, phone, accountNumber, ROUTING_NUMBER, balance]
        );

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            accountNumber
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Transfer funds
app.post('/api/user/transfer', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const { toEmail, toAccountNumber, amount, description } = req.body;
        
        const [senders] = await pool.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);
        const sender = senders[0];
        
        if (parseFloat(sender.balance) < parseFloat(amount)) {
            return res.status(400).json({ success: false, message: 'Insufficient funds' });
        }

        let recipient;
        if (toEmail) {
            const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [toEmail]);
            recipient = users[0];
        } else if (toAccountNumber) {
            const [users] = await pool.execute('SELECT * FROM users WHERE accountNumber = ?', [toAccountNumber]);
            recipient = users[0];
        }

        if (!recipient) return res.status(404).json({ success: false, message: 'Recipient not found' });

        await pool.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, sender.id]);
        await pool.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, recipient.id]);

        res.json({
            success: true,
            message: `$${amount} sent to ${recipient.firstName} ${recipient.lastName}`
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Bill Payment - Billers list
const BILLERS = [
    { id: 1, name: 'Electric Company', category: 'utilities', minAmount: 10, maxAmount: 5000 },
    { id: 2, name: 'Water Services', category: 'utilities', minAmount: 10, maxAmount: 1000 },
    { id: 3, name: 'Gas Company', category: 'utilities', minAmount: 10, maxAmount: 2000 },
    { id: 4, name: 'Internet Provider', category: 'internet', minAmount: 20, maxAmount: 500 },
    { id: 5, name: 'Mobile Phone', category: 'phone', minAmount: 10, maxAmount: 1000 },
    { id: 6, name: 'Cable TV', category: 'entertainment', minAmount: 20, maxAmount: 500 },
    { id: 7, name: 'Insurance Premium', category: 'insurance', minAmount: 50, maxAmount: 10000 },
    { id: 8, name: 'Credit Card', category: 'finance', minAmount: 25, maxAmount: 50000 }
];

app.get('/api/bills/billers', (req, res) => {
    res.json({ success: true, billers: BILLERS });
});

app.post('/api/bills/pay', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const { billerId, accountNumber, amount } = req.body;
        
        const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);
        const user = users[0];
        
        if (parseFloat(user.balance) < parseFloat(amount)) {
            return res.status(400).json({ success: false, message: 'Insufficient funds' });
        }

        await pool.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, user.id]);

        res.json({
            success: true,
            message: `Bill payment of $${amount} processed successfully`
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== ACCOUNT STATEMENTS ====================
app.get('/api/statements/download', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { format = 'pdf', startDate, endDate } = req.query;

        const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);
        const user = users[0];

        let query = `
            SELECT t.*, u.firstName, u.lastName, u.email 
            FROM transactions t
            LEFT JOIN users u ON t.toUserId = u.id
            WHERE t.userId = ?
        `;
        const params = [decoded.id];

        if (startDate) {
            query += ' AND t.createdAt >= ?';
            params.push(startDate);
        }
        if (endDate) {
            query += ' AND t.createdAt <= ?';
            params.push(endDate);
        }

        query += ' ORDER BY t.createdAt DESC';
        const [transactions] = await pool.execute(query, params);

        if (format === 'csv') {
            const csvPath = path.join(__dirname, `statement_${decoded.id}_${Date.now()}.csv`);
            const csvWriter = createCsvWriter({
                path: csvPath,
                header: [
                    { id: 'date', title: 'Date' },
                    { id: 'type', title: 'Type' },
                    { id: 'description', title: 'Description' },
                    { id: 'amount', title: 'Amount' },
                    { id: 'balance', title: 'Balance' }
                ]
            });

            const records = transactions.map(t => ({
                date: new Date(t.createdAt).toLocaleDateString(),
                type: t.type,
                description: t.description || t.type,
                amount: `$${parseFloat(t.amount).toFixed(2)}`,
                balance: `$${parseFloat(t.balanceAfter || user.balance).toFixed(2)}`
            }));

            await csvWriter.writeRecords(records);
            res.download(csvPath, `statement_${user.accountNumber}.csv`, () => {
                fs.unlinkSync(csvPath);
            });
        } else {
            // PDF Format
            const doc = new PDFDocument({ margin: 50 });
            const pdfPath = path.join(__dirname, `statement_${decoded.id}_${Date.now()}.pdf`);
            const stream = fs.createWriteStream(pdfPath);

            doc.pipe(stream);

            // Header
            doc.fontSize(24).text('HERITAGE BANK', { align: 'center' });
            doc.fontSize(10).text('Account Statement', { align: 'center' });
            doc.moveDown();

            // Account Info
            doc.fontSize(12).text(`Account Holder: ${user.firstName} ${user.lastName}`);
            doc.text(`Account Number: ${user.accountNumber}`);
            doc.text(`Routing Number: ${user.routingNumber || ROUTING_NUMBER}`);
            doc.text(`Statement Date: ${new Date().toLocaleDateString()}`);
            doc.text(`Current Balance: $${parseFloat(user.balance).toFixed(2)}`);
            doc.moveDown();

            // Transactions Table
            doc.fontSize(14).text('Transaction History', { underline: true });
            doc.moveDown();

            if (transactions.length === 0) {
                doc.fontSize(10).text('No transactions found for this period.');
            } else {
                doc.fontSize(9);
                const startY = doc.y;
                transactions.forEach((t, index) => {
                    const y = startY + (index * 20);
                    if (y > 700) {
                        doc.addPage();
                        doc.y = 50;
                    }
                    doc.text(new Date(t.createdAt).toLocaleDateString(), 50, y, { width: 80 });
                    doc.text(t.type, 140, y, { width: 100 });
                    doc.text(t.description || 'N/A', 250, y, { width: 150 });
                    doc.text(`$${parseFloat(t.amount).toFixed(2)}`, 410, y, { width: 100, align: 'right' });
                });
            }

            doc.end();

            stream.on('finish', () => {
                res.download(pdfPath, `statement_${user.accountNumber}.pdf`, () => {
                    fs.unlinkSync(pdfPath);
                });
            });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== TRANSACTION RECEIPTS ====================
app.get('/api/transactions/:id/receipt', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;

        const [transactions] = await pool.execute(
            'SELECT t.*, u.firstName, u.lastName FROM transactions t LEFT JOIN users u ON t.toUserId = u.id WHERE t.id = ? AND t.userId = ?',
            [id, decoded.id]
        );

        if (transactions.length === 0) {
            return res.status(404).json({ success: false, message: 'Transaction not found' });
        }

        const transaction = transactions[0];
        const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);
        const user = users[0];

        const doc = new PDFDocument({ size: 'A4', margin: 50 });
        const pdfPath = path.join(__dirname, `receipt_${id}_${Date.now()}.pdf`);
        const stream = fs.createWriteStream(pdfPath);

        doc.pipe(stream);

        // Header with bank branding
        doc.fontSize(28).fillColor('#2C5F7F').text('HERITAGE BANK', { align: 'center' });
        doc.fontSize(12).fillColor('black').text('Transaction Receipt', { align: 'center' });
        doc.moveDown(2);

        // Receipt details box
        doc.rect(50, doc.y, 500, 250).stroke();
        const boxStartY = doc.y + 20;

        doc.fontSize(10).fillColor('gray').text('TRANSACTION DETAILS', 70, boxStartY);
        doc.moveDown(1.5);

        const detailsY = doc.y;
        doc.fontSize(11).fillColor('black');
        doc.text('Receipt Number:', 70, detailsY);
        doc.text(`RCP-${String(id).padStart(8, '0')}`, 250, detailsY);
        
        doc.text('Date:', 70, detailsY + 20);
        doc.text(new Date(transaction.createdAt).toLocaleString(), 250, detailsY + 20);
        
        doc.text('Transaction Type:', 70, detailsY + 40);
        doc.text(transaction.type, 250, detailsY + 40);
        
        doc.text('Amount:', 70, detailsY + 60);
        doc.fontSize(16).fillColor('#28a745').text(`$${parseFloat(transaction.amount).toFixed(2)}`, 250, detailsY + 60);
        
        doc.fontSize(11).fillColor('black');
        doc.text('From:', 70, detailsY + 85);
        doc.text(`${user.firstName} ${user.lastName}`, 250, detailsY + 85);
        doc.text(`Account: ${user.accountNumber}`, 250, detailsY + 100);

        if (transaction.toUserId) {
            doc.text('To:', 70, detailsY + 120);
            doc.text(`${transaction.firstName || 'N/A'} ${transaction.lastName || ''}`, 250, detailsY + 120);
        }

        doc.text('Description:', 70, detailsY + 140);
        doc.text(transaction.description || 'N/A', 250, detailsY + 140, { width: 250 });

        doc.text('Status:', 70, detailsY + 180);
        doc.fillColor('#28a745').text('COMPLETED', 250, detailsY + 180);

        // Footer
        doc.fontSize(8).fillColor('gray');
        doc.text('Heritage Bank • 1-800-HERITAGE • www.heritagebank.com', 50, 750, { align: 'center' });
        doc.text('This is a computer-generated receipt and does not require a signature.', 50, 765, { align: 'center' });

        doc.end();

        stream.on('finish', () => {
            res.download(pdfPath, `receipt_${transaction.id}.pdf`, () => {
                fs.unlinkSync(pdfPath);
            });
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== BENEFICIARY MANAGEMENT ====================
app.get('/api/beneficiaries', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        const [beneficiaries] = await pool.execute(
            'SELECT * FROM beneficiaries WHERE userId = ? ORDER BY createdAt DESC',
            [decoded.id]
        );

        res.json({ success: true, beneficiaries });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/beneficiaries', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { name, accountNumber, bankName, email, nickname } = req.body;

        const [result] = await pool.execute(
            'INSERT INTO beneficiaries (userId, name, accountNumber, bankName, email, nickname) VALUES (?, ?, ?, ?, ?, ?)',
            [decoded.id, name, accountNumber, bankName || 'Heritage Bank', email, nickname]
        );

        res.json({ success: true, message: 'Beneficiary added successfully', beneficiaryId: result.insertId });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/beneficiaries/:id', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;
        const { name, accountNumber, bankName, email, nickname } = req.body;

        await pool.execute(
            'UPDATE beneficiaries SET name = ?, accountNumber = ?, bankName = ?, email = ?, nickname = ? WHERE id = ? AND userId = ?',
            [name, accountNumber, bankName, email, nickname, id, decoded.id]
        );

        res.json({ success: true, message: 'Beneficiary updated successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/beneficiaries/:id', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;

        await pool.execute('DELETE FROM beneficiaries WHERE id = ? AND userId = ?', [id, decoded.id]);

        res.json({ success: true, message: 'Beneficiary deleted successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== TRANSACTION SEARCH & FILTERS ====================
app.get('/api/transactions/search', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { startDate, endDate, type, minAmount, maxAmount, search } = req.query;

        let query = `
            SELECT t.*, u.firstName, u.lastName, u.email 
            FROM transactions t
            LEFT JOIN users u ON t.toUserId = u.id
            WHERE t.userId = ?
        `;
        const params = [decoded.id];

        if (startDate) {
            query += ' AND t.createdAt >= ?';
            params.push(startDate);
        }
        if (endDate) {
            query += ' AND t.createdAt <= ?';
            params.push(endDate);
        }
        if (type) {
            query += ' AND t.type = ?';
            params.push(type);
        }
        if (minAmount) {
            query += ' AND t.amount >= ?';
            params.push(minAmount);
        }
        if (maxAmount) {
            query += ' AND t.amount <= ?';
            params.push(maxAmount);
        }
        if (search) {
            query += ' AND (t.description LIKE ? OR u.firstName LIKE ? OR u.lastName LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm);
        }

        query += ' ORDER BY t.createdAt DESC LIMIT 500';
        const [transactions] = await pool.execute(query, params);

        res.json({ success: true, transactions });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== TRANSACTION LIMITS ====================
app.get('/api/limits', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        let [limits] = await pool.execute('SELECT * FROM transaction_limits WHERE userId = ?', [decoded.id]);
        
        if (limits.length === 0) {
            // Create default limits
            await pool.execute(
                'INSERT INTO transaction_limits (userId, dailyLimit, weeklyLimit, monthlyLimit, singleTransactionLimit) VALUES (?, ?, ?, ?, ?)',
                [decoded.id, 10000, 50000, 200000, 5000]
            );
            [limits] = await pool.execute('SELECT * FROM transaction_limits WHERE userId = ?', [decoded.id]);
        }

        res.json({ success: true, limits: limits[0] });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/limits', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { dailyLimit, weeklyLimit, monthlyLimit, singleTransactionLimit } = req.body;

        await pool.execute(
            'UPDATE transaction_limits SET dailyLimit = ?, weeklyLimit = ?, monthlyLimit = ?, singleTransactionLimit = ? WHERE userId = ?',
            [dailyLimit, weeklyLimit, monthlyLimit, singleTransactionLimit, decoded.id]
        );

        res.json({ success: true, message: 'Limits updated successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== CARD MANAGEMENT ====================
app.put('/api/cards/:id/freeze', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;

        await pool.execute(
            'UPDATE cards SET status = ?, frozenAt = CURRENT_TIMESTAMP WHERE id = ? AND userId = ?',
            ['frozen', id, decoded.id]
        );

        res.json({ success: true, message: 'Card frozen successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/cards/:id/unfreeze', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;

        await pool.execute(
            'UPDATE cards SET status = ?, frozenAt = NULL WHERE id = ? AND userId = ?',
            ['active', id, decoded.id]
        );

        res.json({ success: true, message: 'Card unfrozen successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/cards/:id/block', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;
        const { reason } = req.body;

        await pool.execute(
            'UPDATE cards SET status = ?, blockedAt = CURRENT_TIMESTAMP, blockReason = ? WHERE id = ? AND userId = ?',
            ['blocked', reason || 'User requested', id, decoded.id]
        );

        res.json({ success: true, message: 'Card blocked successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/cards/:id/change-pin', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;
        const { currentPin, newPin } = req.body;

        const [cards] = await pool.execute('SELECT * FROM cards WHERE id = ? AND userId = ?', [id, decoded.id]);
        
        if (cards.length === 0) {
            return res.status(404).json({ success: false, message: 'Card not found' });
        }

        const card = cards[0];
        if (card.pin && !(await bcrypt.compare(currentPin, card.pin))) {
            return res.status(400).json({ success: false, message: 'Current PIN is incorrect' });
        }

        const hashedPin = await bcrypt.hash(newPin, 10);
        await pool.execute('UPDATE cards SET pin = ? WHERE id = ?', [hashedPin, id]);

        res.json({ success: true, message: 'PIN changed successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== SCHEDULED PAYMENTS ====================
app.get('/api/scheduled-payments', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        const [payments] = await pool.execute(
            'SELECT * FROM scheduled_payments WHERE userId = ? ORDER BY nextRunDate ASC',
            [decoded.id]
        );

        res.json({ success: true, payments });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/scheduled-payments', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { type, amount, frequency, nextRunDate, endDate, toAccountNumber, toEmail, billerId, description } = req.body;

        const [result] = await pool.execute(
            'INSERT INTO scheduled_payments (userId, type, amount, frequency, nextRunDate, endDate, toAccountNumber, toEmail, billerId, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [decoded.id, type, amount, frequency, nextRunDate, endDate, toAccountNumber, toEmail, billerId, description]
        );

        res.json({ success: true, message: 'Payment scheduled successfully', paymentId: result.insertId });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/scheduled-payments/:id/pause', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;

        await pool.execute(
            'UPDATE scheduled_payments SET status = ? WHERE id = ? AND userId = ?',
            ['paused', id, decoded.id]
        );

        res.json({ success: true, message: 'Payment paused successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/scheduled-payments/:id/resume', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;

        await pool.execute(
            'UPDATE scheduled_payments SET status = ? WHERE id = ? AND userId = ?',
            ['active', id, decoded.id]
        );

        res.json({ success: true, message: 'Payment resumed successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/scheduled-payments/:id', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;

        await pool.execute(
            'UPDATE scheduled_payments SET status = ? WHERE id = ? AND userId = ?',
            ['cancelled', id, decoded.id]
        );

        res.json({ success: true, message: 'Payment cancelled successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== KYC DOCUMENT UPLOAD ====================
app.post('/api/documents/upload', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { documentType, fileName, fileData } = req.body;

        // In production, you'd save to S3/cloud storage. Here we'll save locally for demo
        const uploadsDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadsDir)) {
            fs.mkdirSync(uploadsDir);
        }

        const filePath = path.join(uploadsDir, `${decoded.id}_${Date.now()}_${fileName}`);
        const buffer = Buffer.from(fileData, 'base64');
        fs.writeFileSync(filePath, buffer);

        const [result] = await pool.execute(
            'INSERT INTO documents (userId, documentType, fileName, filePath, fileSize, status) VALUES (?, ?, ?, ?, ?, ?)',
            [decoded.id, documentType, fileName, filePath, buffer.length, 'pending']
        );

        res.json({ success: true, message: 'Document uploaded successfully', documentId: result.insertId });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/documents', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        const [documents] = await pool.execute(
            'SELECT id, documentType, fileName, status, uploadedAt, rejectionReason FROM documents WHERE userId = ? ORDER BY uploadedAt DESC',
            [decoded.id]
        );

        res.json({ success: true, documents });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Admin: Review documents
app.get('/api/admin/documents/pending', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        const [users] = await pool.execute('SELECT isAdmin FROM users WHERE id = ?', [decoded.id]);
        if (!users[0]?.isAdmin) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        const [documents] = await pool.execute(
            `SELECT d.*, u.firstName, u.lastName, u.email 
             FROM documents d 
             JOIN users u ON d.userId = u.id 
             WHERE d.status = 'pending' 
             ORDER BY d.uploadedAt ASC`
        );

        res.json({ success: true, documents });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/admin/documents/:id/approve', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        const [users] = await pool.execute('SELECT isAdmin FROM users WHERE id = ?', [decoded.id]);
        if (!users[0]?.isAdmin) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        const { id } = req.params;
        await pool.execute(
            'UPDATE documents SET status = ?, reviewedBy = ?, reviewedAt = CURRENT_TIMESTAMP WHERE id = ?',
            ['approved', decoded.id, id]
        );

        res.json({ success: true, message: 'Document approved successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/admin/documents/:id/reject', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        const [users] = await pool.execute('SELECT isAdmin FROM users WHERE id = ?', [decoded.id]);
        if (!users[0]?.isAdmin) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        const { id } = req.params;
        const { reason } = req.body;

        await pool.execute(
            'UPDATE documents SET status = ?, reviewedBy = ?, reviewedAt = CURRENT_TIMESTAMP, rejectionReason = ? WHERE id = ?',
            ['rejected', decoded.id, reason, id]
        );

        res.json({ success: true, message: 'Document rejected successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== LOGIN HISTORY ====================
app.get('/api/login-history', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        const [history] = await pool.execute(
            'SELECT * FROM login_history WHERE userId = ? ORDER BY loginAt DESC LIMIT 50',
            [decoded.id]
        );

        res.json({ success: true, history });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== ADMIN ENDPOINTS ====================
// Get all transactions (admin only)
app.get('/api/transactions/all', async (req, res) => {
    try {
        const [transactions] = await pool.execute(`
            SELECT t.*, u1.firstName as senderFirst, u1.lastName as senderLast,
                   u2.firstName as recipientFirst, u2.lastName as recipientLast
            FROM transactions t
            LEFT JOIN users u1 ON t.fromAccount = u1.accountNumber
            LEFT JOIN users u2 ON t.toAccount = u2.accountNumber
            ORDER BY t.created_at DESC
            LIMIT 100
        `);
        
        res.json({ success: true, transactions });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Get activity logs (admin only)
app.get('/api/admin/activity-logs', async (req, res) => {
    try {
        const [logs] = await pool.execute(`
            SELECT a.*, u.firstName, u.lastName, u.email as userName
            FROM activity_logs a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.created_at DESC
            LIMIT 100
        `);
        
        res.json({ success: true, logs });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Forgot password endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        
        if (users.length === 0) {
            return res.json({ success: true, message: 'If email exists, reset link sent' });
        }

        // Generate reset token (in production, send via email)
        const resetToken = Math.random().toString(36).substring(2, 15);
        const resetExpiry = new Date(Date.now() + 3600000); // 1 hour
        
        await pool.execute(
            'UPDATE users SET resetToken = ?, resetTokenExpiry = ? WHERE email = ?',
            [resetToken, resetExpiry, email]
        );

        res.json({ 
            success: true, 
            message: 'Password reset instructions sent to email',
            // For demo purposes only - remove in production
            resetToken: resetToken
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Reset password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, resetToken, newPassword } = req.body;
        
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE email = ? AND resetToken = ? AND resetTokenExpiry > NOW()',
            [email, resetToken]
        );
        
        if (users.length === 0) {
            return res.status(400).json({ success: false, message: 'Invalid or expired reset token' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        await pool.execute(
            'UPDATE users SET password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE email = ?',
            [hashedPassword, email]
        );

        res.json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== ADMIN ACCOUNT MANAGEMENT ====================

// Get dashboard statistics
app.get('/api/admin/dashboard-stats', async (req, res) => {
    try {
        // Total users
        const [userCount] = await pool.execute('SELECT COUNT(*) as count FROM users WHERE accountStatus != "deleted"');
        
        // Total deposits (sum of all balances)
        const [totalBalance] = await pool.execute('SELECT SUM(balance) as total FROM users WHERE accountStatus != "deleted"');
        
        // Today's transactions
        const [todayTxns] = await pool.execute(`
            SELECT COUNT(*) as count 
            FROM transactions 
            WHERE DATE(created_at) = CURDATE()
        `);
        
        // Pending loans
        const [pendingLoans] = await pool.execute(`
            SELECT COUNT(*) as count 
            FROM loan_applications 
            WHERE status = 'pending'
        `);
        
        // Total transactions this month
        const [monthlyTxns] = await pool.execute(`
            SELECT COUNT(*) as count, SUM(amount) as volume
            FROM transactions 
            WHERE MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())
        `);
        
        // Active users (logged in last 30 days)
        const [activeUsers] = await pool.execute(`
            SELECT COUNT(DISTINCT userId) as count 
            FROM login_history 
            WHERE loginStatus = 'success' AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        `);
        
        // Failed login attempts today
        const [failedLogins] = await pool.execute(`
            SELECT COUNT(*) as count 
            FROM login_history 
            WHERE loginStatus = 'failed' AND DATE(created_at) = CURDATE()
        `);

        res.json({ 
            success: true, 
            stats: {
                totalUsers: userCount[0].count,
                totalBalance: totalBalance[0].total || 0,
                todayTransactions: todayTxns[0].count,
                pendingLoans: pendingLoans[0].count,
                monthlyTransactions: monthlyTxns[0].count,
                monthlyVolume: monthlyTxns[0].volume || 0,
                activeUsers: activeUsers[0].count,
                failedLoginsToday: failedLogins[0].count
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Update account status (freeze/unfreeze/deactivate)
app.put('/api/admin/account-status/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { status, reason } = req.body;
        
        if (!['active', 'frozen', 'suspended', 'closed'].includes(status)) {
            return res.status(400).json({ success: false, message: 'Invalid status' });
        }

        const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        await pool.execute(
            'UPDATE users SET accountStatus = ? WHERE id = ?',
            [status, userId]
        );

        // Log the action
        await pool.execute(
            'INSERT INTO activity_logs (user_id, action_type, action_details, ip_address) VALUES (?, ?, ?, ?)',
            [userId, 'ACCOUNT_STATUS_CHANGE', `Status changed to ${status}: ${reason || 'No reason provided'}`, req.ip]
        );

        res.json({ success: true, message: `Account ${status} successfully` });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Search users
app.get('/api/admin/search-users', async (req, res) => {
    try {
        const { query } = req.query;
        
        if (!query || query.length < 2) {
            return res.status(400).json({ success: false, message: 'Search query too short' });
        }

        const searchPattern = `%${query}%`;
        const [users] = await pool.execute(`
            SELECT id, firstName, lastName, email, accountNumber, balance, accountStatus, created_at
            FROM users 
            WHERE (firstName LIKE ? OR lastName LIKE ? OR email LIKE ? OR accountNumber LIKE ?)
            AND accountStatus != 'deleted'
            LIMIT 50
        `, [searchPattern, searchPattern, searchPattern, searchPattern]);

        res.json({ success: true, users });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Search transactions
app.get('/api/admin/search-transactions', async (req, res) => {
    try {
        const { accountNumber, startDate, endDate, minAmount, maxAmount, type } = req.query;
        
        let query = `
            SELECT t.*, 
                   sender.firstName as senderFirst, sender.lastName as senderLast,
                   recipient.firstName as recipientFirst, recipient.lastName as recipientLast
            FROM transactions t
            LEFT JOIN users sender ON t.senderId = sender.id
            LEFT JOIN users recipient ON t.recipientId = recipient.id
            WHERE 1=1
        `;
        const params = [];

        if (accountNumber) {
            query += ` AND (sender.accountNumber = ? OR recipient.accountNumber = ?)`;
            params.push(accountNumber, accountNumber);
        }
        
        if (startDate) {
            query += ` AND DATE(t.created_at) >= ?`;
            params.push(startDate);
        }
        
        if (endDate) {
            query += ` AND DATE(t.created_at) <= ?`;
            params.push(endDate);
        }
        
        if (minAmount) {
            query += ` AND t.amount >= ?`;
            params.push(parseFloat(minAmount));
        }
        
        if (maxAmount) {
            query += ` AND t.amount <= ?`;
            params.push(parseFloat(maxAmount));
        }
        
        if (type) {
            query += ` AND t.type = ?`;
            params.push(type);
        }

        query += ` ORDER BY t.created_at DESC LIMIT 100`;

        const [transactions] = await pool.execute(query, params);
        res.json({ success: true, transactions });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Reverse transaction
app.post('/api/admin/reverse-transaction/:transactionId', async (req, res) => {
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();

        const { transactionId } = req.params;
        const { reason } = req.body;

        // Get original transaction
        const [transactions] = await connection.execute(
            'SELECT * FROM transactions WHERE id = ?',
            [transactionId]
        );

        if (transactions.length === 0) {
            await connection.rollback();
            return res.status(404).json({ success: false, message: 'Transaction not found' });
        }

        const transaction = transactions[0];

        if (transaction.status === 'reversed') {
            await connection.rollback();
            return res.status(400).json({ success: false, message: 'Transaction already reversed' });
        }

        // Reverse the balances
        if (transaction.senderId) {
            await connection.execute(
                'UPDATE users SET balance = balance + ? WHERE id = ?',
                [transaction.amount, transaction.senderId]
            );
        }

        if (transaction.recipientId) {
            await connection.execute(
                'UPDATE users SET balance = balance - ? WHERE id = ?',
                [transaction.amount, transaction.recipientId]
            );
        }

        // Mark as reversed
        await connection.execute(
            'UPDATE transactions SET status = ?, description = CONCAT(description, " [REVERSED: ", ?, "]") WHERE id = ?',
            ['reversed', reason || 'Admin reversal', transactionId]
        );

        // Create reversal transaction record
        await connection.execute(`
            INSERT INTO transactions (senderId, recipientId, amount, type, description, status, reference)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
            transaction.recipientId,
            transaction.senderId,
            transaction.amount,
            'reversal',
            `Reversal of transaction ${transaction.reference}: ${reason}`,
            'completed',
            `REV-${transaction.reference}`
        ]);

        // Log the action
        await connection.execute(
            'INSERT INTO activity_logs (user_id, action_type, action_details, ip_address) VALUES (?, ?, ?, ?)',
            [transaction.senderId, 'TRANSACTION_REVERSED', `Transaction ${transaction.reference} reversed: ${reason}`, req.ip]
        );

        await connection.commit();
        res.json({ success: true, message: 'Transaction reversed successfully' });
    } catch (error) {
        await connection.rollback();
        res.status(500).json({ success: false, message: error.message });
    } finally {
        connection.release();
    }
});

// Force password reset for user
app.post('/api/admin/force-password-reset/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { temporaryPassword } = req.body;

        const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const hashedPassword = await bcrypt.hash(temporaryPassword, 10);
        
        await pool.execute(
            'UPDATE users SET password = ?, forcePasswordChange = 1 WHERE id = ?',
            [hashedPassword, userId]
        );

        // Log the action
        await pool.execute(
            'INSERT INTO activity_logs (user_id, action_type, action_details, ip_address) VALUES (?, ?, ?, ?)',
            [userId, 'PASSWORD_RESET', 'Admin forced password reset', req.ip]
        );

        res.json({ 
            success: true, 
            message: 'Password reset successfully',
            temporaryPassword // Only for demo - send via secure channel in production
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Export users to CSV
app.get('/api/admin/export-users', async (req, res) => {
    try {
        const [users] = await pool.execute(`
            SELECT id, firstName, lastName, email, accountNumber, balance, accountStatus, 
                   phoneNumber, address, city, state, zipCode, created_at
            FROM users 
            WHERE accountStatus != 'deleted'
            ORDER BY created_at DESC
        `);

        // Create CSV
        const headers = 'ID,First Name,Last Name,Email,Account Number,Balance,Status,Phone,Address,City,State,ZIP,Created\n';
        const rows = users.map(u => 
            `${u.id},"${u.firstName}","${u.lastName}","${u.email}",${u.accountNumber},${u.balance},"${u.accountStatus}","${u.phoneNumber || ''}","${u.address || ''}","${u.city || ''}","${u.state || ''}","${u.zipCode || ''}","${u.created_at}"`
        ).join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=users_export.csv');
        res.send(headers + rows);
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Export transactions to CSV
app.get('/api/admin/export-transactions', async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        
        let query = `
            SELECT t.*, 
                   sender.accountNumber as senderAccount, sender.firstName as senderFirst, sender.lastName as senderLast,
                   recipient.accountNumber as recipientAccount, recipient.firstName as recipientFirst, recipient.lastName as recipientLast
            FROM transactions t
            LEFT JOIN users sender ON t.senderId = sender.id
            LEFT JOIN users recipient ON t.recipientId = recipient.id
            WHERE 1=1
        `;
        const params = [];

        if (startDate) {
            query += ` AND DATE(t.created_at) >= ?`;
            params.push(startDate);
        }
        
        if (endDate) {
            query += ` AND DATE(t.created_at) <= ?`;
            params.push(endDate);
        }

        query += ` ORDER BY t.created_at DESC LIMIT 10000`;

        const [transactions] = await pool.execute(query, params);

        // Create CSV
        const headers = 'ID,Reference,Type,Amount,Sender Account,Sender Name,Recipient Account,Recipient Name,Description,Status,Date\n';
        const rows = transactions.map(t => 
            `${t.id},"${t.reference}","${t.type}",${t.amount},"${t.senderAccount || ''}","${t.senderFirst || ''} ${t.senderLast || ''}","${t.recipientAccount || ''}","${t.recipientFirst || ''} ${t.recipientLast || ''}","${t.description}","${t.status}","${t.created_at}"`
        ).join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=transactions_export.csv');
        res.send(headers + rows);
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Get monthly report
app.get('/api/admin/monthly-report', async (req, res) => {
    try {
        const { year, month } = req.query;
        
        const yearVal = year || new Date().getFullYear();
        const monthVal = month || (new Date().getMonth() + 1);

        // Transaction summary
        const [txnSummary] = await pool.execute(`
            SELECT 
                COUNT(*) as totalTransactions,
                SUM(CASE WHEN type = 'transfer' THEN 1 ELSE 0 END) as transfers,
                SUM(CASE WHEN type = 'bill_payment' THEN 1 ELSE 0 END) as billPayments,
                SUM(CASE WHEN type = 'deposit' THEN 1 ELSE 0 END) as deposits,
                SUM(amount) as totalVolume,
                AVG(amount) as avgTransaction
            FROM transactions
            WHERE YEAR(created_at) = ? AND MONTH(created_at) = ?
        `, [yearVal, monthVal]);

        // New users
        const [newUsers] = await pool.execute(`
            SELECT COUNT(*) as count
            FROM users
            WHERE YEAR(created_at) = ? AND MONTH(created_at) = ?
        `, [yearVal, monthVal]);

        // Loans summary
        const [loansSummary] = await pool.execute(`
            SELECT 
                COUNT(*) as totalApplications,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                SUM(CASE WHEN status = 'approved' THEN loanAmount ELSE 0 END) as totalApproved
            FROM loan_applications
            WHERE YEAR(created_at) = ? AND MONTH(created_at) = ?
        `, [yearVal, monthVal]);

        res.json({ 
            success: true,
            report: {
                period: `${yearVal}-${String(monthVal).padStart(2, '0')}`,
                transactions: txnSummary[0],
                newUsers: newUsers[0].count,
                loans: loansSummary[0]
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Update transaction limits
app.put('/api/admin/transaction-limits/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { dailyLimit, singleTransactionLimit } = req.body;

        const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Check if limits record exists
        const [existing] = await pool.execute(
            'SELECT * FROM transaction_limits WHERE userId = ?',
            [userId]
        );

        if (existing.length > 0) {
            await pool.execute(
                'UPDATE transaction_limits SET dailyLimit = ?, singleTransactionLimit = ? WHERE userId = ?',
                [dailyLimit, singleTransactionLimit, userId]
            );
        } else {
            await pool.execute(
                'INSERT INTO transaction_limits (userId, dailyLimit, singleTransactionLimit) VALUES (?, ?, ?)',
                [userId, dailyLimit, singleTransactionLimit]
            );
        }

        // Log the action
        await pool.execute(
            'INSERT INTO activity_logs (user_id, action_type, action_details, ip_address) VALUES (?, ?, ?, ?)',
            [userId, 'LIMITS_UPDATE', `Daily: ${dailyLimit}, Single: ${singleTransactionLimit}`, req.ip]
        );

        res.json({ success: true, message: 'Transaction limits updated successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Helper function to log login attempts
async function logLoginAttempt(userId, ipAddress, userAgent, status, failureReason = null) {
    try {
        await pool.execute(
            'INSERT INTO login_history (userId, ipAddress, userAgent, loginStatus, failureReason) VALUES (?, ?, ?, ?, ?)',
            [userId, ipAddress, userAgent, status, failureReason]
        );
    } catch (error) {
        console.error('Error logging login attempt:', error);
    }
}

// ==================== USER PROFILE (COMPLETE) ====================

// Get complete user profile with all banking details
app.get('/api/user/profile/complete', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);
        
        if (users.length === 0) return res.status(404).json({ success: false, message: 'User not found' });

        const user = users[0];
        res.json({
            success: true,
            user: {
                id: user.id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                phone: user.phone,
                dateOfBirth: user.dateOfBirth,
                ssn: user.ssn,
                address: user.address,
                city: user.city,
                state: user.state,
                zipCode: user.zipCode,
                country: user.country,
                accountNumber: user.accountNumber,
                routingNumber: user.routingNumber,
                accountType: user.accountType,
                accountStatus: user.accountStatus,
                balance: parseFloat(user.balance),
                createdAt: user.createdAt,
                lastLogin: user.lastLogin,
                emailVerified: user.emailVerified || false,
                phoneVerified: user.phoneVerified || false,
                marketingConsent: user.marketingConsent || false,
                // Transaction limits
                dailyTransferLimit: 10000,
                weeklyTransferLimit: 50000,
                monthlyTransferLimit: 200000,
                singleTransactionLimit: 25000,
                dailyTransferSpent: 0,
                weeklyTransferSpent: 0,
                monthlyTransferSpent: 0,
                // Account controls
                accountFrozen: user.accountStatus === 'frozen',
                internationalEnabled: true,
                preferences: {}
            }
        });
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }
        res.status(500).json({ success: false, message: error.message });
    }
});

// Update complete user profile
app.put('/api/user/profile/complete', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const { 
            firstName, lastName, phone, address, city, state, zipCode, 
            dateOfBirth, country 
        } = req.body;

        await pool.execute(`
            UPDATE users SET 
                firstName = COALESCE(?, firstName),
                lastName = COALESCE(?, lastName),
                phone = COALESCE(?, phone),
                address = COALESCE(?, address),
                city = COALESCE(?, city),
                state = COALESCE(?, state),
                zipCode = COALESCE(?, zipCode),
                dateOfBirth = COALESCE(?, dateOfBirth),
                country = COALESCE(?, country)
            WHERE id = ?
        `, [firstName, lastName, phone, address, city, state, zipCode, dateOfBirth, country, decoded.id]);

        res.json({ success: true, message: 'Profile updated successfully' });
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== LOGIN HISTORY & SESSIONS ====================

// Get login history
app.get('/api/user/security/login-history', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const [logins] = await pool.execute(
            'SELECT * FROM login_history WHERE userId = ? ORDER BY createdAt DESC LIMIT 20',
            [decoded.id]
        );

        res.json({ success: true, logins });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Get active sessions
app.get('/api/user/security/active-sessions', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Return mock sessions for now - in production, track actual sessions
        const sessions = [
            {
                id: 'session_current',
                deviceName: 'Current Device',
                browserName: 'Chrome',
                location: 'Current Location',
                lastActivity: new Date()
            }
        ];

        res.json({ success: true, sessions });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Logout specific session
app.post('/api/user/security/logout-session/:sessionId', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        jwt.verify(token, JWT_SECRET);
        
        // In production, invalidate the session
        res.json({ success: true, message: 'Session logged out' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Logout all sessions
app.post('/api/user/security/logout-all', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        jwt.verify(token, JWT_SECRET);
        
        // In production, invalidate all user sessions
        res.json({ success: true, message: 'All sessions logged out' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== DOCUMENTS ====================

// Upload document
app.post('/api/user/documents/upload', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const { fileName, fileData, documentType } = req.body;

        // In production, upload to S3. For demo, we'll just track in DB
        const [result] = await pool.execute(
            'INSERT INTO user_documents (userId, documentType, fileName, verificationStatus, uploadedAt) VALUES (?, ?, ?, ?, NOW())',
            [decoded.id, documentType || 'ID', fileName || 'document', 'pending']
        );

        res.json({ success: true, message: 'Document uploaded', documentId: result.insertId });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Get user documents
app.get('/api/user/documents', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const [documents] = await pool.execute(
            'SELECT id, documentType, fileName, verificationStatus as verified, uploadedAt FROM user_documents WHERE userId = ? ORDER BY uploadedAt DESC',
            [decoded.id]
        );

        res.json({ success: true, documents });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Delete document
app.delete('/api/user/documents/:id', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;

        await pool.execute(
            'DELETE FROM user_documents WHERE id = ? AND userId = ?',
            [id, decoded.id]
        );

        res.json({ success: true, message: 'Document deleted' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== BENEFICIARIES (User API) ====================

// Get user beneficiaries
app.get('/api/user/beneficiaries', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const [beneficiaries] = await pool.execute(
            'SELECT * FROM beneficiaries WHERE userId = ? ORDER BY createdAt DESC',
            [decoded.id]
        );

        res.json({ success: true, beneficiaries });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Add beneficiary
app.post('/api/user/beneficiaries', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const { name, nickname, accountNumber, routingNumber, bankName } = req.body;

        if (!name || !accountNumber) {
            return res.status(400).json({ success: false, message: 'Name and account number required' });
        }

        const [result] = await pool.execute(
            'INSERT INTO beneficiaries (userId, name, nickname, accountNumber, routingNumber, bankName, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
            [decoded.id, name, nickname, accountNumber, routingNumber, bankName || 'Heritage Bank']
        );

        res.json({ success: true, message: 'Beneficiary added', beneficiaryId: result.insertId });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Update beneficiary
app.put('/api/user/beneficiaries/:id', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;
        const { name, nickname, accountNumber, routingNumber, bankName } = req.body;

        await pool.execute(
            'UPDATE beneficiaries SET name = ?, nickname = ?, accountNumber = ?, routingNumber = ?, bankName = ? WHERE id = ? AND userId = ?',
            [name, nickname, accountNumber, routingNumber, bankName, id, decoded.id]
        );

        res.json({ success: true, message: 'Beneficiary updated' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Delete beneficiary
app.delete('/api/user/beneficiaries/:id', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const { id } = req.params;

        await pool.execute(
            'DELETE FROM beneficiaries WHERE id = ? AND userId = ?',
            [id, decoded.id]
        );

        res.json({ success: true, message: 'Beneficiary deleted' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== TWO-FACTOR AUTHENTICATION ====================

// Enable 2FA
app.post('/api/user/2fa/enable', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const { method } = req.body;

        // Generate backup codes
        const codes = Array.from({ length: 8 }, () => 
            Math.random().toString(36).substring(2, 8).toUpperCase()
        );

        await pool.execute(
            'UPDATE users SET twoFactorEnabled = 1, twoFactorMethod = ? WHERE id = ?',
            [method || 'sms', decoded.id]
        );

        res.json({ success: true, message: '2FA enabled', codes });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Disable 2FA
app.post('/api/user/2fa/disable', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);

        await pool.execute(
            'UPDATE users SET twoFactorEnabled = 0, twoFactorMethod = NULL WHERE id = ?',
            [decoded.id]
        );

        res.json({ success: true, message: '2FA disabled' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Generate backup codes
app.post('/api/user/2fa/backup-codes', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);

        // Generate backup codes
        const codes = Array.from({ length: 8 }, () => 
            Math.random().toString(36).substring(2, 8).toUpperCase()
        );

        res.json({ success: true, codes });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== ACCOUNT CONTROLS ====================

// Freeze account
app.post('/api/user/account/freeze', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);

        await pool.execute(
            'UPDATE users SET accountStatus = ? WHERE id = ?',
            ['frozen', decoded.id]
        );

        res.json({ success: true, message: 'Account frozen' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Unfreeze account
app.post('/api/user/account/unfreeze', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);

        await pool.execute(
            'UPDATE users SET accountStatus = ? WHERE id = ?',
            ['active', decoded.id]
        );

        res.json({ success: true, message: 'Account unfrozen' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Toggle international transactions
app.post('/api/user/account/international', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const { enabled } = req.body;

        // Store in preferences table (will create if needed)
        await pool.execute(
            'INSERT INTO user_preferences (userId, internationalEnabled) VALUES (?, ?) ON DUPLICATE KEY UPDATE internationalEnabled = ?',
            [decoded.id, enabled ? 1 : 0, enabled ? 1 : 0]
        );

        res.json({ success: true, message: 'International transactions ' + (enabled ? 'enabled' : 'disabled') });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== PREFERENCES ====================

// Update preferences
app.put('/api/user/preferences', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        
        // For each preference key, update or insert
        for (const [key, value] of Object.entries(req.body)) {
            await pool.execute(
                'INSERT INTO user_preferences (userId, preferenceKey, preferenceValue) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE preferenceValue = ?',
                [decoded.id, key, JSON.stringify(value), JSON.stringify(value)]
            );
        }

        res.json({ success: true, message: 'Preferences updated' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== PRIVACY & DATA ====================

// Export user data (GDPR)
app.get('/api/user/privacy/export-data', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);

        // Get all user data
        const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);
        const [transactions] = await pool.execute('SELECT * FROM transactions WHERE userId = ? ORDER BY createdAt DESC', [decoded.id]);
        const [beneficiaries] = await pool.execute('SELECT * FROM beneficiaries WHERE userId = ?', [decoded.id]);
        const [documents] = await pool.execute('SELECT * FROM user_documents WHERE userId = ?', [decoded.id]);
        const [logins] = await pool.execute('SELECT * FROM login_history WHERE userId = ? LIMIT 100', [decoded.id]);

        const data = {
            exported: new Date(),
            user: users[0],
            transactions,
            beneficiaries,
            documents,
            recentLogins: logins
        };

        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Request account deletion (GDPR)
app.post('/api/user/privacy/delete-request', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);

        // Mark for deletion in 30 days
        const deletionDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        await pool.execute(
            'UPDATE users SET deletionRequestedAt = NOW(), scheduledDeletionDate = ? WHERE id = ?',
            [deletionDate, decoded.id]
        );

        res.json({ success: true, message: 'Account deletion requested. Scheduled for ' + deletionDate.toDateString() });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Download statement
app.get('/api/user/statements/current', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);
        const user = users[0];

        // Get transactions for current month
        const [transactions] = await pool.execute(`
            SELECT * FROM transactions 
            WHERE userId = ? AND MONTH(createdAt) = MONTH(NOW()) AND YEAR(createdAt) = YEAR(NOW())
            ORDER BY createdAt DESC
        `, [decoded.id]);

        // Create PDF
        const doc = new PDFDocument({ margin: 50 });
        const pdfPath = path.join(__dirname, `statement_${decoded.id}_${Date.now()}.pdf`);
        const stream = fs.createWriteStream(pdfPath);

        doc.pipe(stream);

        doc.fontSize(24).text('HERITAGE BANK', { align: 'center' });
        doc.fontSize(12).text('Account Statement', { align: 'center' });
        doc.moveDown();

        doc.fontSize(11);
        doc.text(`Account Holder: ${user.firstName} ${user.lastName}`);
        doc.text(`Account Number: ${user.accountNumber}`);
        doc.text(`Routing Number: ${user.routingNumber || ROUTING_NUMBER}`);
        doc.text(`Current Balance: $${parseFloat(user.balance).toFixed(2)}`);
        doc.text(`Statement Date: ${new Date().toLocaleDateString()}`);
        doc.moveDown();

        doc.fontSize(10).text('Recent Transactions:', { underline: true });
        doc.moveDown(0.5);

        if (transactions.length === 0) {
            doc.text('No transactions this month.');
        } else {
            transactions.forEach((t, i) => {
                doc.text(`${new Date(t.createdAt).toLocaleDateString()} - ${t.type}: $${parseFloat(t.amount).toFixed(2)} - ${t.description || 'N/A'}`);
            });
        }

        doc.end();

        stream.on('finish', () => {
            res.download(pdfPath, `statement_${user.accountNumber}.pdf`, () => {
                fs.unlinkSync(pdfPath);
            });
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Serve index.html for root and any unmatched routes (SPA support)
app.get('*', (req, res) => {
    if (!req.path.startsWith('/api')) {
        res.sendFile(path.join(__dirname, '..', 'index.html'));
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`🏦 Heritage Bank running on port ${PORT}`);
    console.log(`📱 Frontend: http://localhost:${PORT}`);
    console.log(`🔌 API: http://localhost:${PORT}/api`);
});
