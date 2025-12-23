const mysql = require('mysql2/promise');
require('dotenv').config();

async function addLastLoginColumn() {
    try {
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            port: process.env.DB_PORT || 4000,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            ssl: { rejectUnauthorized: false }
        });

        console.log('🔄 Checking users table structure...');

        // Check if lastLogin column exists
        const [columns] = await connection.execute(`
            SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'lastLogin'
        `);

        if (columns.length === 0) {
            console.log('⚠️  lastLogin column not found. Adding it...');
            await connection.execute(`
                ALTER TABLE users ADD COLUMN lastLogin TIMESTAMP NULL
            `);
            console.log('✅ lastLogin column added successfully');
        } else {
            console.log('✅ lastLogin column already exists');
        }

        await connection.end();
    } catch (error) {
        console.error('❌ Error:', error.message);
        process.exit(1);
    }
}

addLastLoginColumn();
