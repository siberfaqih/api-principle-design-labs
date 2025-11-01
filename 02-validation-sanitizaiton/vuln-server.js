const express = require('express');
const { Pool } = require('pg');

const app = express();
const PORT = 3000;

// Middleware - DELIBERATELY MINIMAL (no security headers, no rate limiting)
app.use(express.json({ limit: '50mb' })); // Dangerously high limit
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Connect to external Postgres database (still vulnerable usage below)
const pool = new Pool({
    host: process.env.DB_HOST || 'postgres',
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 5432,
    user: process.env.DB_USER || 'appuser',
    password: process.env.DB_PASSWORD || 'apppassword',
    database: process.env.DB_NAME || 'bankdb'
});

// VULNERABLE ENDPOINT 1: User Registration with SQL Injection
app.post('/api/register', (req, res) => {
    const { email, nik, full_name, account_number, initial_balance, profile_bio } = req.body;
    
    // NO INPUT VALIDATION OR SANITIZATION
    // VULNERABLE: Direct string interpolation in SQL query
    const query = `INSERT INTO users (email, nik, full_name, account_number, balance, profile_bio) 
                   VALUES ('${email}', '${nik}', '${full_name}', '${account_number}', ${initial_balance || 0}, '${profile_bio}')`;
    
    console.log('Executing query:', query); // Dangerous: logging sensitive queries
    
    // Split query by semicolons and execute each statement separately
    const statements = query.split(';').filter(stmt => stmt.trim());
    
    let completedStatements = 0;
    let hasError = false;
    
    statements.forEach((statement) => {
        if (statement.trim()) {
            pool.query(statement.trim(), (err) => {
                if (err && !hasError) {
                    hasError = true;
                    // VULNERABLE: Exposing internal error details
                    return res.status(500).json({ 
                        error: 'Database error', 
                        details: err.message,
                        query: query // NEVER expose queries in production!
                    });
                }
                
                completedStatements++;
                if (completedStatements === statements.length && !hasError) {
                    res.status(201).json({ 
                        message: 'User registered successfully', 
                        executedQuery: query // VULNERABLE: exposing query structure
                    });
                }
            });
        }
    });
});

// VULNERABLE ENDPOINT 2: User Search with SQL Injection
app.get('/api/users/search', (req, res) => {
    const { email, nik } = req.query;

    const emailTrim = typeof email === 'string' ? email.trim() : '';
    const nikTrim = typeof nik === 'string' ? nik.trim() : '';

    // Reject empty search to prevent dumping all users
    if (!emailTrim && !nikTrim) {
        return res.status(400).json({
            error: 'Search requires at least one parameter (email or nik)'
        });
    }

    // VULNERABLE: Direct string interpolation allows SQL injection
    let query = 'SELECT * FROM users WHERE 1=1';

    if (emailTrim) {
        query += ` AND email = '${emailTrim}'`;
    }

    if (nikTrim) {
        query += ` AND nik = '${nikTrim}'`;
    }

    console.log('Search query:', query);

    pool.query(query, (err, result) => {
        if (err) {
            return res.status(500).json({ 
                error: 'Search failed', 
                details: err.message,
                query: query
            });
        }
        const rows = result ? result.rows : [];
        res.json({ 
            users: rows,
            totalFound: rows.length,
            executedQuery: query
        });
    });
});

// VULNERABLE ENDPOINT 3: Profile Display with Stored XSS
app.get('/api/profile/:accountNumber', (req, res) => {
    const { accountNumber } = req.params;
    
    // VULNERABLE: SQL injection in parameter
    const query = `SELECT * FROM users WHERE account_number = '${accountNumber}'`;
    
    pool.query(query, (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        const user = result && result.rows && result.rows[0];
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // VULNERABLE: Rendering HTML without sanitization (Stored XSS)
        const profileHtml = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>User Profile</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    .profile { border: 1px solid #ccc; padding: 20px; border-radius: 5px; }
                    .balance { color: green; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class="profile">
                    <h2>Profile: ${user.full_name}</h2>
                    <p><strong>Email:</strong> ${user.email}</p>
                    <p><strong>NIK:</strong> ${user.nik}</p>
                    <p><strong>Account:</strong> ${user.account_number}</p>
                    <p class="balance"><strong>Balance:</strong> Rp ${Number(user.balance).toLocaleString()}</p>
                    <div>
                        <h3>Bio:</h3>
                        <div>${user.profile_bio}</div>
                    </div>
                </div>
            </body>
            </html>
        `;
        
        res.setHeader('Content-Type', 'text/html');
        res.send(profileHtml);
    });
});

// VULNERABLE ENDPOINT 4: Money Transfer with Business Logic Flaws
app.post('/api/transfer', (req, res) => {
    const { from_account, to_account, amount, description } = req.body;
    
    // NO INPUT VALIDATION
    // VULNERABLE: No balance checking, no transaction atomicity
    
    // First, get sender's current balance (VULNERABLE: Race condition possible)
    const balanceQuery = `SELECT balance FROM users WHERE account_number = '${from_account}'`;
    
    pool.query(balanceQuery, (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        const sender = result && result.rows && result.rows[0];
        if (!sender) {
            return res.status(404).json({ error: 'Sender account not found' });
        }
        
        // VULNERABLE: Trusting client-supplied amount without validation
        // VULNERABLE: No check for negative amounts or overdraft protection
        const newBalance = Number(sender.balance) - Number(amount);
        
        // Update sender balance (VULNERABLE: No transaction, race condition possible)
        const updateSenderQuery = `UPDATE users SET balance = ${newBalance} WHERE account_number = '${from_account}'`;
        
        pool.query(updateSenderQuery, (err) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to update sender balance' });
            }
            
            // Update receiver balance (VULNERABLE: No transaction, partial failure possible)
            const updateReceiverQuery = `UPDATE users SET balance = balance + ${amount} WHERE account_number = '${to_account}'`;
            
            pool.query(updateReceiverQuery, (err) => {
                if (err) {
                    // VULNERABLE: Sender balance already updated, but receiver update failed
                    // This creates inconsistent state!
                    return res.status(500).json({ 
                        error: 'Failed to update receiver balance - INCONSISTENT STATE!',
                        warning: 'Sender balance was already deducted'
                    });
                }
                
                // Record transaction (VULNERABLE: May fail after money transfer)
                const transactionQuery = `INSERT INTO transactions (from_account, to_account, amount, description, transaction_type) 
                                         VALUES ('${from_account}', '${to_account}', ${amount}, '${description}', 'transfer')`;
                
                pool.query(transactionQuery, (err) => {
                    if (err) {
                        // VULNERABLE: Money transferred but transaction not recorded
                        console.error('Transaction recording failed:', err.message);
                    }
                    
                    res.json({ 
                        message: 'Transfer completed',
                        from: from_account,
                        to: to_account,
                        amount: amount,
                        newSenderBalance: newBalance,
                        warning: newBalance < 0 ? 'Account is now overdrawn!' : null
                    });
                });
            });
        });
    });
});

// VULNERABLE ENDPOINT 5: Update Profile Bio (Stored XSS vulnerability)
app.put('/api/profile/:accountNumber/bio', (req, res) => {
    const { accountNumber } = req.params;
    const { profile_bio } = req.body;
    
    // VULNERABLE: Still no input sanitization (allows stored XSS), but use parameters to avoid SQL syntax errors
    const query = 'UPDATE users SET profile_bio = $1 WHERE account_number = $2';
    
    pool.query(query, [profile_bio, accountNumber], (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        if (!result || result.rowCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ 
            message: 'Profile bio updated successfully',
            updatedBio: profile_bio // VULNERABLE: Reflecting unescaped input
        });
    });
});

// VULNERABLE ENDPOINT 6: Get All Users (Information Disclosure)
app.get('/api/users', (req, res) => {
    // VULNERABLE: No authentication, exposing all user data
    const query = 'SELECT * FROM users';
    
    pool.query(query, (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        const users = result ? result.rows : [];
        // VULNERABLE: Exposing sensitive information like NIK, balance
        res.json({ 
            users: users,
            total: users.length,
            warning: 'This endpoint exposes sensitive user data!'
        });
    });
});

// VULNERABLE ENDPOINT 7: Delete User (No Authorization)
app.delete('/api/users/:accountNumber', (req, res) => {
    const { accountNumber } = req.params;
    
    // VULNERABLE: No authentication or authorization checks
    const query = `DELETE FROM users WHERE account_number = '${accountNumber}'`;
    
    pool.query(query, (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        if (!result || result.rowCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ 
            message: 'User deleted successfully',
            deletedAccount: accountNumber,
            warning: 'No authorization required for deletion!'
        });
    });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'vulnerable',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        warning: 'This server contains deliberate vulnerabilities!'
    });
});

// Error handling middleware (VULNERABLE: Exposing stack traces)
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        details: err.message,
        stack: err.stack, // VULNERABLE: Exposing stack trace
        timestamp: new Date().toISOString()
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚨 VULNERABLE SERVER running on http://localhost:${PORT}`);
    console.log('⚠️  WARNING: This server contains deliberate security vulnerabilities!');
    console.log('⚠️  DO NOT use this code in production!');
    console.log('');
    console.log('Available endpoints:');
    console.log('  GET  /api/health - Health check');
    console.log('  POST /api/register - Register new user (SQL injection vulnerable)');
    console.log('  GET  /api/users/search - Search users (SQL injection vulnerable)');
    console.log('  GET  /api/profile/:accountNumber - View profile (XSS vulnerable)');
    console.log('  POST /api/transfer - Transfer money (Logic flaws)');
    console.log('  PUT  /api/profile/:accountNumber/bio - Update bio (XSS vulnerable)');
    console.log('  GET  /api/users - List all users (Information disclosure)');
    console.log('  DELETE /api/users/:accountNumber - Delete user (No authorization)');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down vulnerable server...');
    pool.end()
        .then(() => {
            console.log('Database connection closed.');
            process.exit(0);
        })
        .catch((err) => {
            console.error('Error closing database:', err.message);
            process.exit(1);
        });
});