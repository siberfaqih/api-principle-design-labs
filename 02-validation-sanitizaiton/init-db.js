const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

// Create database file in the current directory
const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
        return;
    }
    console.log(`Connected to the SQLite database at ${dbPath}`);
});

// Create tables and seed data
db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            nik TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            balance DECIMAL(15,2) DEFAULT 0.00,
            profile_bio TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error('Error creating users table:', err.message);
        } else {
            console.log('Users table created successfully.');
        }
    });

    // Transactions table
    db.run(`
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_account TEXT NOT NULL,
            to_account TEXT NOT NULL,
            amount DECIMAL(15,2) NOT NULL,
            description TEXT,
            transaction_type TEXT NOT NULL,
            status TEXT DEFAULT 'completed',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_account) REFERENCES users(account_number),
            FOREIGN KEY (to_account) REFERENCES users(account_number)
        )
    `, (err) => {
        if (err) {
            console.error('Error creating transactions table:', err.message);
        } else {
            console.log('Transactions table created successfully.');
        }
    });

    // Seed sample users
    const sampleUsers = [
        {
            email: 'john.doe@email.com',
            nik: '3201234567890123',
            full_name: 'John Doe',
            account_number: 'ACC001234567890',
            balance: 1000000.00,
            profile_bio: 'Software Engineer from Jakarta'
        },
        {
            email: 'jane.smith@email.com',
            nik: '3301234567890124',
            full_name: 'Jane Smith',
            account_number: 'ACC001234567891',
            balance: 750000.00,
            profile_bio: 'Marketing Manager from Bandung'
        },
        {
            email: 'bob.wilson@email.com',
            nik: '3401234567890125',
            full_name: 'Bob Wilson',
            account_number: 'ACC001234567892',
            balance: 500000.00,
            profile_bio: 'Business Analyst from Surabaya'
        },
        {
            email: 'alice.brown@email.com',
            nik: '3501234567890126',
            full_name: 'Alice Brown',
            account_number: 'ACC001234567893',
            balance: 250000.00,
            profile_bio: 'Graphic Designer from Yogyakarta'
        }
    ];

    const insertUser = db.prepare(`
        INSERT INTO users (email, nik, full_name, account_number, balance, profile_bio)
        VALUES (?, ?, ?, ?, ?, ?)
    `);

    sampleUsers.forEach((user) => {
        insertUser.run([
            user.email,
            user.nik,
            user.full_name,
            user.account_number,
            user.balance,
            user.profile_bio
        ], (err) => {
            if (err) {
                console.error('Error inserting user:', err.message);
            } else {
                console.log(`User ${user.full_name} inserted successfully.`);
            }
        });
    });

    insertUser.finalize();

    // Seed sample transactions
    const sampleTransactions = [
        {
            from_account: 'ACC001234567890',
            to_account: 'ACC001234567891',
            amount: 100000.00,
            description: 'Monthly salary transfer',
            transaction_type: 'transfer'
        },
        {
            from_account: 'ACC001234567891',
            to_account: 'ACC001234567892',
            amount: 50000.00,
            description: 'Freelance payment',
            transaction_type: 'transfer'
        },
        {
            from_account: 'ACC001234567892',
            to_account: 'ACC001234567893',
            amount: 25000.00,
            description: 'Dinner bill split',
            transaction_type: 'transfer'
        }
    ];

    const insertTransaction = db.prepare(`
        INSERT INTO transactions (from_account, to_account, amount, description, transaction_type)
        VALUES (?, ?, ?, ?, ?)
    `);

    sampleTransactions.forEach((transaction) => {
        insertTransaction.run([
            transaction.from_account,
            transaction.to_account,
            transaction.amount,
            transaction.description,
            transaction.transaction_type
        ], (err) => {
            if (err) {
                console.error('Error inserting transaction:', err.message);
            } else {
                console.log(`Transaction from ${transaction.from_account} to ${transaction.to_account} inserted successfully.`);
            }
        });
    });

    insertTransaction.finalize();
});

// Close database connection
db.close((err) => {
    if (err) {
        console.error('Error closing database:', err.message);
    } else {
        console.log('Database initialization completed successfully.');
        console.log('Database file created at:', dbPath);
        console.log('\nSample accounts created:');
        console.log('- john.doe@email.com (ACC001234567890) - Balance: Rp 1,000,000');
        console.log('- jane.smith@email.com (ACC001234567891) - Balance: Rp 750,000');
        console.log('- bob.wilson@email.com (ACC001234567892) - Balance: Rp 500,000');
        console.log('- alice.brown@email.com (ACC001234567893) - Balance: Rp 250,000');
        console.log('\nRun "npm run vuln-server" or "npm run secure-server" to start the application.');
    }
});