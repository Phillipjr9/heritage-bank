const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const path = require('path');
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
        console.log('✅ Database initialized');
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
