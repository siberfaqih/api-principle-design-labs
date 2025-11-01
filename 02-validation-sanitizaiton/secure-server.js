const express = require('express');
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html');

const app = express();
const PORT = 3001;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

// Rate limiting
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    }
});

const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limit each IP to 10 requests per windowMs for sensitive operations
    message: {
        error: 'Too many sensitive requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    }
});

app.use(generalLimiter);

// Body parsing with size limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Database: using PostgreSQL pool and wrapper defined below

// Custom validation functions
const validateIndonesianNIK = (nik) => {
    // Indonesian NIK should be exactly 16 digits
    const nikRegex = /^\d{16}$/;
    return nikRegex.test(nik);
};

const validateAccountNumber = (accountNumber) => {
    // Account number format: ACC followed by 12 digits
    const accountRegex = /^ACC\d{12}$/;
    return accountRegex.test(accountNumber);
};

const validateTransferAmount = (amount) => {
    const numAmount = parseFloat(amount);
    return !isNaN(numAmount) && numAmount > 0 && numAmount <= 10000000; // Max 10M IDR per transfer
};

// Error handling middleware for validation
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            error: 'Validation failed',
            details: errors.array().map(err => ({
                field: err.path,
                message: err.msg,
                value: err.value
            }))
        });
    }
    next();
};

// Sanitization helper
const sanitizeInput = (input) => {
    if (typeof input !== 'string') return input;
    return sanitizeHtml(input, {
        allowedTags: [],
        allowedAttributes: {},
        disallowedTagsMode: 'discard'
    });
};

// Replace SQLite connection with Postgres Pool
const pool = new Pool({
    host: process.env.DB_HOST || 'postgres',
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 5432,
    user: process.env.DB_USER || 'appuser',
    password: process.env.DB_PASSWORD || 'apppassword',
    database: process.env.DB_NAME || 'bankdb'
});

const convertPlaceholders = (text) => {
    let i = 0;
    return text.replace(/\?/g, () => {
        i += 1;
        return `$${i}`;
    });
};

const db = {
    all: (text, params, cb) => {
        pool.query(convertPlaceholders(text), params)
            .then(res => cb(null, res.rows))
            .catch(err => cb(err));
    },
    get: (text, params, cb) => {
        pool.query(convertPlaceholders(text), params)
            .then(res => cb(null, res.rows[0] || null))
            .catch(err => cb(err));
    },
    run: (text, params, cb) => {
        if (typeof params === 'function') {
            cb = params;
            params = [];
        }
        pool.query(convertPlaceholders(text), params)
            .then(res => {
                const ctx = {
                    changes: res.rowCount,
                    lastID: res.rows && res.rows[0] && res.rows[0].id ? res.rows[0].id : undefined
                };
                if (cb) cb.call(ctx, null);
            })
            .catch(err => { if (cb) cb(err); });
    }
};

// SECURE ENDPOINT 1: User Registration with Validation
app.post('/api/register', 
    strictLimiter,
    [
        body('email')
            .isEmail()
            .normalizeEmail()
            .withMessage('Valid email is required'),
        body('nik')
            .custom(validateIndonesianNIK)
            .withMessage('NIK must be exactly 16 digits'),
        body('full_name')
            .isLength({ min: 2, max: 100 })
            .matches(/^[a-zA-Z\s]+$/)
            .withMessage('Full name must be 2-100 characters and contain only letters and spaces'),
        body('account_number')
            .custom(validateAccountNumber)
            .withMessage('Account number must follow format ACC############'),
        body('initial_balance')
            .optional()
            .isFloat({ min: 0, max: 100000000 })
            .withMessage('Initial balance must be between 0 and 100,000,000'),
        body('profile_bio')
            .optional()
            .isLength({ max: 500 })
            .withMessage('Profile bio must not exceed 500 characters')
    ],
    handleValidationErrors,
    (req, res) => {
        const { email, nik, full_name, account_number, initial_balance, profile_bio } = req.body;
        
        // Sanitize inputs
        const sanitizedData = {
            email: email.toLowerCase().trim(),
            nik: nik.trim(),
            full_name: sanitizeInput(full_name.trim()),
            account_number: account_number.trim(),
            initial_balance: initial_balance || 0,
            profile_bio: sanitizeInput(profile_bio || '')
        };
        
        // SECURE: Using prepared statements to prevent SQL injection
        const query = `INSERT INTO users (email, nik, full_name, account_number, balance, profile_bio) 
                       VALUES (?, ?, ?, ?, ?, ?) RETURNING id`;
        
        db.run(query, [
            sanitizedData.email,
            sanitizedData.nik,
            sanitizedData.full_name,
            sanitizedData.account_number,
            sanitizedData.initial_balance,
            sanitizedData.profile_bio
        ], function(err) {
            if (err) {
                // SECURE: Generic error message, no internal details exposed
                if (String(err.message).includes('duplicate key')) {
                    return res.status(409).json({ 
                        error: 'User with this email, NIK, or account number already exists'
                    });
                }
                return res.status(500).json({ 
                    error: 'Registration failed. Please try again.'
                });
            }
            
            res.status(201).json({ 
                message: 'User registered successfully', 
                userId: this.lastID,
                accountNumber: sanitizedData.account_number
            });
        });
    }
);

// SECURE ENDPOINT 2: User Search with Validation
app.get('/api/users/search',
    [
        query('email')
            .optional({ checkFalsy: false })
            .isEmail()
            .normalizeEmail()
            .withMessage('Valid email format required'),
        query('nik')
            .optional({ checkFalsy: false })
            .custom(validateIndonesianNIK)
            .withMessage('NIK must be exactly 16 digits')
    ],
    handleValidationErrors,
    (req, res) => {
        const { email, nik } = req.query;

        const trimmedEmail = typeof email === 'string' ? email.trim() : '';
        const trimmedNik = typeof nik === 'string' ? nik.trim() : '';

        // Require at least one non-empty search parameter
        if (!trimmedEmail && !trimmedNik) {
            return res.status(400).json({ 
                error: 'At least one search parameter (email or nik) is required'
            });
        }
        
        let query = 'SELECT id, email, full_name, account_number, created_at FROM users WHERE 1=1';
        const params = [];
        
        if (trimmedEmail) {
            query += ' AND email = ?';
            params.push(trimmedEmail.toLowerCase());
        }
        
        if (trimmedNik) {
            query += ' AND nik = ?';
            params.push(trimmedNik);
        }
        
        // SECURE: Using prepared statements
        db.all(query, params, (err, rows) => {
            if (err) {
                return res.status(500).json({ 
                    error: 'Search failed. Please try again.'
                });
            }
            
            // SECURE: Only returning non-sensitive information
            res.json({ 
                users: rows,
                totalFound: rows.length
            });
        });
    }
);

// SECURE ENDPOINT 3: Profile Display with XSS Protection
app.get('/api/profile/:accountNumber',
    [
        param('accountNumber')
            .custom(validateAccountNumber)
            .withMessage('Invalid account number format')
    ],
    handleValidationErrors,
    (req, res) => {
        const { accountNumber } = req.params;
        
        // SECURE: Using prepared statements
        const query = 'SELECT * FROM users WHERE account_number = ?';
        
        db.get(query, [accountNumber], (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Profile retrieval failed' });
            }
            
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            // SECURE: Sanitizing all output to prevent XSS
            const sanitizedUser = {
                full_name: sanitizeHtml(user.full_name),
                email: sanitizeHtml(user.email),
                nik: sanitizeHtml(user.nik),
                account_number: sanitizeHtml(user.account_number),
                balance: user.balance,
                profile_bio: sanitizeHtml(user.profile_bio || '')
            };
            
            const profileHtml = `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>User Profile - Secure</title>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <style>
                        body { 
                            font-family: Arial, sans-serif; 
                            margin: 40px; 
                            background-color: #f5f5f5;
                        }
                        .profile { 
                            background: white;
                            border: 1px solid #ddd; 
                            padding: 30px; 
                            border-radius: 8px;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                            max-width: 600px;
                        }
                        .balance { color: #28a745; font-weight: bold; font-size: 1.2em; }
                        .security-notice {
                            background: #d4edda;
                            border: 1px solid #c3e6cb;
                            color: #155724;
                            padding: 10px;
                            border-radius: 4px;
                            margin-bottom: 20px;
                        }
                        .field { margin-bottom: 15px; }
                        .label { font-weight: bold; color: #333; }
                    </style>
                </head>
                <body>
                    <div class="security-notice">
                        🔒 This profile is displayed securely with XSS protection enabled.
                    </div>
                    <div class="profile">
                        <h2>Profile: ${sanitizedUser.full_name}</h2>
                        <div class="field">
                            <span class="label">Email:</span> ${sanitizedUser.email}
                        </div>
                        <div class="field">
                            <span class="label">NIK:</span> ${sanitizedUser.nik}
                        </div>
                        <div class="field">
                            <span class="label">Account:</span> ${sanitizedUser.account_number}
                        </div>
                        <div class="field">
                            <span class="label balance">Balance:</span> 
                            <span class="balance">Rp ${user.balance.toLocaleString('id-ID')}</span>
                        </div>
                        <div class="field">
                            <span class="label">Bio:</span>
                            <div style="margin-top: 5px; padding: 10px; background: #f8f9fa; border-radius: 4px;">
                                ${sanitizedUser.profile_bio || 'No bio provided'}
                            </div>
                        </div>
                    </div>
                </body>
                </html>
            `;
            
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.send(profileHtml);
        });
    }
);

// SECURE ENDPOINT 4: Money Transfer with Atomic Transactions
app.post('/api/transfer',
    strictLimiter,
    [
        body('from_account')
            .custom(validateAccountNumber)
            .withMessage('Invalid sender account number format'),
        body('to_account')
            .custom(validateAccountNumber)
            .withMessage('Invalid recipient account number format'),
        body('amount')
            .custom(validateTransferAmount)
            .withMessage('Amount must be between 0.01 and 10,000,000'),
        body('description')
            .optional()
            .isLength({ max: 200 })
            .withMessage('Description must not exceed 200 characters')
    ],
    handleValidationErrors,
    (req, res) => {
        const { from_account, to_account, amount, description } = req.body;
        
        // Sanitize inputs
        const sanitizedData = {
            from_account: from_account.trim(),
            to_account: to_account.trim(),
            amount: parseFloat(amount),
            description: sanitizeInput(description || '')
        };
        
        // Prevent self-transfer
        if (sanitizedData.from_account === sanitizedData.to_account) {
            return res.status(400).json({ error: 'Cannot transfer to the same account' });
        }
        
        (async () => {
            const client = await pool.connect();
            try {
                await client.query('BEGIN');

                const { rows: senderRows } = await client.query(
                    'SELECT balance FROM users WHERE account_number = $1',
                    [sanitizedData.from_account]
                );
                const sender = senderRows[0];
                if (!sender) {
                    await client.query('ROLLBACK');
                    client.release();
                    return res.status(404).json({ error: 'Sender account not found' });
                }
                if (sender.balance < sanitizedData.amount) {
                    await client.query('ROLLBACK');
                    client.release();
                    return res.status(400).json({ 
                        error: 'Insufficient balance',
                        currentBalance: sender.balance,
                        requestedAmount: sanitizedData.amount
                    });
                }

                const { rows: recipientRows } = await client.query(
                    'SELECT id FROM users WHERE account_number = $1',
                    [sanitizedData.to_account]
                );
                if (!recipientRows[0]) {
                    await client.query('ROLLBACK');
                    client.release();
                    return res.status(404).json({ error: 'Recipient account not found' });
                }

                await client.query(
                    'UPDATE users SET balance = balance - $1 WHERE account_number = $2',
                    [sanitizedData.amount, sanitizedData.from_account]
                );
                await client.query(
                    'UPDATE users SET balance = balance + $1 WHERE account_number = $2',
                    [sanitizedData.amount, sanitizedData.to_account]
                );

                const { rows: txRows } = await client.query(
                    'INSERT INTO transactions (from_account, to_account, amount, description, transaction_type) VALUES ($1, $2, $3, $4, $5) RETURNING id',
                    [sanitizedData.from_account, sanitizedData.to_account, sanitizedData.amount, sanitizedData.description, 'transfer']
                );
                const transactionId = txRows[0].id;

                await client.query('COMMIT');
                client.release();
                return res.json({ 
                    message: 'Transfer completed successfully',
                    transactionId,
                    from: sanitizedData.from_account,
                    to: sanitizedData.to_account,
                    amount: sanitizedData.amount,
                    newSenderBalance: sender.balance - sanitizedData.amount
                });
            } catch (err) {
                try { await client.query('ROLLBACK'); } catch (_) {}
                client.release();
                return res.status(500).json({ error: 'Transfer failed. Please try again.' });
            }
        })();
    }
);

// SECURE ENDPOINT 5: Update Profile Bio with Sanitization
app.put('/api/profile/:accountNumber/bio',
    [
        param('accountNumber')
            .custom(validateAccountNumber)
            .withMessage('Invalid account number format'),
        body('profile_bio')
            .isLength({ max: 500 })
            .withMessage('Profile bio must not exceed 500 characters')
    ],
    handleValidationErrors,
    (req, res) => {
        const { accountNumber } = req.params;
        const { profile_bio } = req.body;
        
        // SECURE: Sanitize input to prevent XSS
        const sanitizedBio = sanitizeInput(profile_bio);
        
        // SECURE: Using prepared statements
        const query = 'UPDATE users SET profile_bio = ? WHERE account_number = ?';
        
        db.run(query, [sanitizedBio, accountNumber], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Profile update failed. Please try again.' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            res.json({ 
                message: 'Profile bio updated successfully',
                sanitizedBio: sanitizedBio
            });
        });
    }
);

// SECURE ENDPOINT 6: Get User List (Limited Information)
app.get('/api/users', (req, res) => {
    // SECURE: Only return non-sensitive information
    const query = 'SELECT id, full_name, account_number, created_at FROM users ORDER BY created_at DESC';
    
    db.all(query, (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to retrieve users' });
        }
        
        res.json({ 
            users: users,
            total: users.length,
            note: 'Only non-sensitive information is displayed'
        });
    });
});

// SECURE: No delete endpoint - users should be deactivated, not deleted

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// SECURE: Generic error handling without exposing internal details
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err.message);
    res.status(500).json({
        error: 'Internal server error. Please try again later.',
        timestamp: new Date().toISOString()
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        path: req.path,
        method: req.method
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🔒 SECURE SERVER running on http://localhost:${PORT}`);
    console.log('✅ Security features enabled:');
    console.log('   - Input validation and sanitization');
    console.log('   - SQL injection protection (prepared statements)');
    console.log('   - XSS protection (output sanitization)');
    console.log('   - Rate limiting');
    console.log('   - Security headers (Helmet)');
    console.log('   - Atomic database transactions');
    console.log('   - Request size limits');
    console.log('');
    console.log('Available endpoints:');
    console.log('  GET  /api/health - Health check');
    console.log('  POST /api/register - Register new user (validated & sanitized)');
    console.log('  GET  /api/users/search - Search users (validated)');
    console.log('  GET  /api/profile/:accountNumber - View profile (XSS protected)');
    console.log('  POST /api/transfer - Transfer money (atomic transactions)');
    console.log('  PUT  /api/profile/:accountNumber/bio - Update bio (sanitized)');
    console.log('  GET  /api/users - List users (limited info only)');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down secure server...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err.message);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});