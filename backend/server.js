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
                accountNumber VARCHAR(20) UNIQUE,
                routingNumber VARCHAR(20),
                balance DECIMAL(15,2) DEFAULT 50000,
                isAdmin BOOLEAN DEFAULT false,
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
        const { email, password } = req.body;
        
        const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

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
                isAdmin: user.isAdmin
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password, phone } = req.body;
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const accountNumber = generateAccountNumber();

        await pool.execute(
            `INSERT INTO users (firstName, lastName, email, password, phone, accountNumber, routingNumber, balance) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [firstName, lastName, email, hashedPassword, phone, accountNumber, ROUTING_NUMBER, 50000]
        );

        const [newUser] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = newUser[0];
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
                balance: 50000
            }
        });
    } catch (error) {
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
