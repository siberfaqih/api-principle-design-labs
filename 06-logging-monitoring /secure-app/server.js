require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');

// Import custom modules
const { 
  logger, 
  logAuthentication, 
  logAuthorization, 
  logDataAccess, 
  logAudit,
  logSuspiciousActivity,
  sanitizeLogData 
} = require('./logger');

const {
  requestId,
  requestLogger,
  securityHeaders,
  createRateLimit,
  logInputValidation,
  errorLogger,
  securityMonitoring,
  notFoundHandler,
  finalErrorHandler,
} = require('./middleware');

const app = express();
const PORT = process.env.PORT || 3000;

// Database configuration with proper error handling
const dbConfig = {
  host: process.env.DB_HOST || 'db',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'rootpassword',
  database: process.env.DB_NAME || 'secure_api_lab',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

let db;

// Initialize database connection with logging
const initDatabase = async () => {
  try {
    db = mysql.createPool(dbConfig);
    
    // Test connection
    const connection = await db.getConnection();
    await connection.ping();
    connection.release();
    
    logger.info('Database connected successfully', {
      host: dbConfig.host,
      database: dbConfig.database,
    });
  } catch (error) {
    logger.error('Database connection failed', {
      error: error.message,
      config: { host: dbConfig.host, database: dbConfig.database },
    });
    process.exit(1);
  }
};

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// Security middleware setup
app.use(requestId);
app.use(securityHeaders);
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
app.use(requestLogger);
app.use(securityMonitoring);
app.use(logInputValidation);

// Rate limiting
const generalLimiter = createRateLimit(15 * 60 * 1000, 100, 'Too many requests from this IP');
const authLimiter = createRateLimit(15 * 60 * 1000, 5, 'Too many authentication attempts');

app.use('/api', generalLimiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

// Enhanced authentication middleware with logging
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    logAuthentication('missing_token', null, req.ip, req.get('User-Agent'), false, {
      requestId: req.id,
      endpoint: req.originalUrl,
    });
    
    return res.status(401).json({ 
      error: 'Access token required',
      requestId: req.id,
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user still exists and is active
    const [users] = await db.execute(
      'SELECT id, username, role, account_locked FROM users WHERE id = ?',
      [decoded.id]
    );

    if (users.length === 0) {
      logAuthentication('user_not_found', decoded.id, req.ip, req.get('User-Agent'), false, {
        requestId: req.id,
        tokenUserId: decoded.id,
      });
      
      return res.status(403).json({ 
        error: 'Invalid token - user not found',
        requestId: req.id,
      });
    }

    const user = users[0];
    
    if (user.account_locked) {
      logAuthentication('account_locked', user.id, req.ip, req.get('User-Agent'), false, {
        requestId: req.id,
        username: user.username,
      });
      
      return res.status(403).json({ 
        error: 'Account is locked',
        requestId: req.id,
      });
    }

    req.user = decoded;
    
    logAuthentication('token_valid', user.id, req.ip, req.get('User-Agent'), true, {
      requestId: req.id,
      username: user.username,
      endpoint: req.originalUrl,
    });
    
    next();
  } catch (error) {
    logAuthentication('invalid_token', null, req.ip, req.get('User-Agent'), false, {
      requestId: req.id,
      error: error.message,
      endpoint: req.originalUrl,
    });
    
    return res.status(403).json({ 
      error: 'Invalid token',
      requestId: req.id,
    });
  }
};

// Input validation rules
const loginValidation = [
  body('username').isLength({ min: 3, max: 50 }).trim().escape(),
  body('password').isLength({ min: 6, max: 100 }),
];

const registerValidation = [
  body('username').isLength({ min: 3, max: 50 }).trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8, max: 100 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
  body('role').optional().isIn(['user', 'admin']),
];

const profileUpdateValidation = [
  body('email').optional().isEmail().normalizeEmail(),
  body('password').optional().isLength({ min: 8, max: 100 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
];

// Helper function to log to audit table
const logToAuditTable = async (userId, action, resource, req, responseStatus, details = {}) => {
  try {
    await db.execute(
      `INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent, 
       request_method, request_path, response_status, severity, details) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId,
        action,
        resource,
        req.ip,
        req.get('User-Agent'),
        req.method,
        req.originalUrl,
        responseStatus,
        responseStatus >= 400 ? 'HIGH' : 'LOW',
        JSON.stringify({ requestId: req.id, ...details }),
      ]
    );
  } catch (error) {
    logger.error('Failed to log to audit table', {
      error: error.message,
      userId,
      action,
      resource,
    });
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    requestId: req.id,
  });
});

// Login endpoint with comprehensive logging
app.post('/api/login', loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logAuthentication('validation_failed', null, req.ip, req.get('User-Agent'), false, {
      requestId: req.id,
      errors: errors.array(),
    });
    
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: errors.array(),
      requestId: req.id,
    });
  }

  const { username, password } = req.body;
  
  try {
    // Get user with failed login attempts
    const [users] = await db.execute(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (users.length === 0) {
      logAuthentication('user_not_found', null, req.ip, req.get('User-Agent'), false, {
        requestId: req.id,
        username,
      });
      
      await logToAuditTable(null, 'LOGIN_FAILED', 'auth', req, 401, { reason: 'user_not_found', username });
      
      return res.status(401).json({ 
        error: 'Invalid credentials',
        requestId: req.id,
      });
    }

    const user = users[0];
    
    // Check if account is locked
    if (user.account_locked && user.locked_until && new Date() < new Date(user.locked_until)) {
      logAuthentication('account_locked', user.id, req.ip, req.get('User-Agent'), false, {
        requestId: req.id,
        username: user.username,
        lockedUntil: user.locked_until,
      });
      
      await logToAuditTable(user.id, 'LOGIN_BLOCKED', 'auth', req, 423, { reason: 'account_locked' });
      
      return res.status(423).json({ 
        error: 'Account is temporarily locked',
        requestId: req.id,
      });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      // Increment failed login attempts
      const newFailedAttempts = user.failed_login_attempts + 1;
      const shouldLock = newFailedAttempts >= 5;
      
      await db.execute(
        `UPDATE users SET failed_login_attempts = ?, 
         account_locked = ?, locked_until = ? WHERE id = ?`,
        [
          newFailedAttempts,
          shouldLock,
          shouldLock ? new Date(Date.now() + 30 * 60 * 1000) : null, // Lock for 30 minutes
          user.id,
        ]
      );

      logAuthentication('password_mismatch', user.id, req.ip, req.get('User-Agent'), false, {
        requestId: req.id,
        username: user.username,
        failedAttempts: newFailedAttempts,
        accountLocked: shouldLock,
      });
      
      await logToAuditTable(user.id, 'LOGIN_FAILED', 'auth', req, 401, { 
        reason: 'invalid_password', 
        attempts: newFailedAttempts,
        locked: shouldLock,
      });
      
      return res.status(401).json({ 
        error: 'Invalid credentials',
        requestId: req.id,
      });
    }

    // Successful login - reset failed attempts and update last login
    await db.execute(
      `UPDATE users SET failed_login_attempts = 0, account_locked = FALSE, 
       locked_until = NULL, last_login = NOW() WHERE id = ?`,
      [user.id]
    );

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Create session record
    const sessionId = uuidv4();
    await db.execute(
      `INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at) 
       VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR))`,
      [sessionId, user.id, req.ip, req.get('User-Agent')]
    );

    logAuthentication('login_success', user.id, req.ip, req.get('User-Agent'), true, {
      requestId: req.id,
      username: user.username,
      sessionId,
    });
    
    await logToAuditTable(user.id, 'LOGIN_SUCCESS', 'auth', req, 200, { sessionId });
    
    res.json({ 
      message: 'Login successful', 
      token,
      user: { 
        id: user.id, 
        username: user.username, 
        role: user.role,
      },
      requestId: req.id,
    });
  } catch (error) {
    logger.error('Login error', {
      error: error.message,
      stack: error.stack,
      requestId: req.id,
      username,
    });
    
    res.status(500).json({ 
      error: 'Internal server error',
      requestId: req.id,
    });
  }
});

// Register endpoint with validation and logging
app.post('/api/register', registerValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Registration validation failed', {
      requestId: req.id,
      errors: errors.array(),
      ip: req.ip,
    });
    
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: errors.array(),
      requestId: req.id,
    });
  }

  const { username, email, password, role = 'user' } = req.body;
  
  try {
    // Check if user exists
    const [existingUsers] = await db.execute(
      'SELECT id FROM users WHERE username = ? OR email = ?',
      [username, email]
    );

    if (existingUsers.length > 0) {
      logAudit('registration_failed', null, 'users', {
        requestId: req.id,
        reason: 'user_exists',
        username,
        email,
        ip: req.ip,
      });
      
      await logToAuditTable(null, 'REGISTRATION_FAILED', 'users', req, 400, { 
        reason: 'user_exists', 
        username, 
        email,
      });
      
      return res.status(400).json({ 
        error: 'User already exists',
        requestId: req.id,
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Insert new user
    const [result] = await db.execute(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, role]
    );

    const userId = result.insertId;

    logAudit('user_created', userId, 'users', {
      requestId: req.id,
      username,
      email,
      role,
      ip: req.ip,
    });
    
    await logToAuditTable(userId, 'USER_CREATED', 'users', req, 201, { 
      username, 
      email, 
      role,
    });

    logger.info('User registered successfully', {
      requestId: req.id,
      userId,
      username,
      email,
      role,
    });
    
    res.status(201).json({ 
      message: 'User created successfully',
      requestId: req.id,
    });
  } catch (error) {
    logger.error('Registration error', {
      error: error.message,
      stack: error.stack,
      requestId: req.id,
      username,
      email,
    });
    
    res.status(500).json({ 
      error: 'Internal server error',
      requestId: req.id,
    });
  }
});

// Get all users (admin only) with proper authorization logging
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    // Authorization check
    if (req.user.role !== 'admin') {
      logAuthorization(req.user.id, 'users', 'read_all', false, {
        requestId: req.id,
        userRole: req.user.role,
        requiredRole: 'admin',
      });
      
      await logToAuditTable(req.user.id, 'UNAUTHORIZED_ACCESS', 'users', req, 403, { 
        action: 'read_all_users',
        userRole: req.user.role,
      });
      
      return res.status(403).json({ 
        error: 'Admin access required',
        requestId: req.id,
      });
    }

    logAuthorization(req.user.id, 'users', 'read_all', true, {
      requestId: req.id,
      userRole: req.user.role,
    });

    // Get users without passwords
    const [users] = await db.execute(
      'SELECT id, username, email, role, created_at, last_login FROM users ORDER BY created_at DESC'
    );

    logDataAccess(req.user.id, 'users', 'read_all', users.length, {
      requestId: req.id,
    });
    
    await logToAuditTable(req.user.id, 'DATA_ACCESS', 'users', req, 200, { 
      action: 'read_all_users',
      recordCount: users.length,
    });

    res.json({
      users,
      count: users.length,
      requestId: req.id,
    });
  } catch (error) {
    logger.error('Get users error', {
      error: error.message,
      stack: error.stack,
      requestId: req.id,
      userId: req.user.id,
    });
    
    res.status(500).json({ 
      error: 'Internal server error',
      requestId: req.id,
    });
  }
});

// Get user profile with access logging
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const [users] = await db.execute(
      'SELECT id, username, email, role, created_at, last_login FROM users WHERE id = ?',
      [req.user.id]
    );

    if (users.length === 0) {
      logger.warn('Profile not found', {
        requestId: req.id,
        userId: req.user.id,
      });
      
      return res.status(404).json({ 
        error: 'User not found',
        requestId: req.id,
      });
    }

    logDataAccess(req.user.id, 'profile', 'read', 1, {
      requestId: req.id,
    });
    
    await logToAuditTable(req.user.id, 'PROFILE_ACCESS', 'profile', req, 200);

    res.json({
      user: users[0],
      requestId: req.id,
    });
  } catch (error) {
    logger.error('Get profile error', {
      error: error.message,
      stack: error.stack,
      requestId: req.id,
      userId: req.user.id,
    });
    
    res.status(500).json({ 
      error: 'Internal server error',
      requestId: req.id,
    });
  }
});

// Update profile with validation and logging
app.put('/api/profile', authenticateToken, profileUpdateValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Profile update validation failed', {
      requestId: req.id,
      userId: req.user.id,
      errors: errors.array(),
    });
    
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: errors.array(),
      requestId: req.id,
    });
  }

  const { email, password } = req.body;
  
  if (!email && !password) {
    return res.status(400).json({ 
      error: 'No updates provided',
      requestId: req.id,
    });
  }

  try {
    const updates = [];
    const values = [];
    const changedFields = [];

    if (email) {
      updates.push('email = ?');
      values.push(email);
      changedFields.push('email');
    }
    
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 12);
      updates.push('password = ?');
      values.push(hashedPassword);
      changedFields.push('password');
    }
    
    values.push(req.user.id);
    
    await db.execute(
      `UPDATE users SET ${updates.join(', ')}, updated_at = NOW() WHERE id = ?`,
      values
    );

    logAudit('profile_updated', req.user.id, 'profile', {
      requestId: req.id,
      changedFields,
    });
    
    await logToAuditTable(req.user.id, 'PROFILE_UPDATE', 'profile', req, 200, { 
      changedFields,
    });

    logger.info('Profile updated successfully', {
      requestId: req.id,
      userId: req.user.id,
      changedFields,
    });

    res.json({ 
      message: 'Profile updated successfully',
      requestId: req.id,
    });
  } catch (error) {
    logger.error('Profile update error', {
      error: error.message,
      stack: error.stack,
      requestId: req.id,
      userId: req.user.id,
    });
    
    res.status(500).json({ 
      error: 'Internal server error',
      requestId: req.id,
    });
  }
});

// Delete user (admin only) with comprehensive logging
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  const targetUserId = parseInt(req.params.id);
  
  try {
    // Authorization check
    if (req.user.role !== 'admin') {
      logAuthorization(req.user.id, 'users', 'delete', false, {
        requestId: req.id,
        targetUserId,
        userRole: req.user.role,
      });
      
      await logToAuditTable(req.user.id, 'UNAUTHORIZED_DELETE', 'users', req, 403, { 
        targetUserId,
        userRole: req.user.role,
      });
      
      return res.status(403).json({ 
        error: 'Admin access required',
        requestId: req.id,
      });
    }

    // Prevent self-deletion
    if (req.user.id === targetUserId) {
      logger.warn('Admin attempted self-deletion', {
        requestId: req.id,
        userId: req.user.id,
        targetUserId,
      });
      
      return res.status(400).json({ 
        error: 'Cannot delete your own account',
        requestId: req.id,
      });
    }

    logAuthorization(req.user.id, 'users', 'delete', true, {
      requestId: req.id,
      targetUserId,
    });

    // Get target user info before deletion
    const [targetUsers] = await db.execute(
      'SELECT username, email, role FROM users WHERE id = ?',
      [targetUserId]
    );

    if (targetUsers.length === 0) {
      logger.warn('Delete attempt on non-existent user', {
        requestId: req.id,
        userId: req.user.id,
        targetUserId,
      });
      
      return res.status(404).json({ 
        error: 'User not found',
        requestId: req.id,
      });
    }

    const targetUser = targetUsers[0];

    // Delete user
    const [result] = await db.execute('DELETE FROM users WHERE id = ?', [targetUserId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        error: 'User not found',
        requestId: req.id,
      });
    }

    logAudit('user_deleted', req.user.id, 'users', {
      requestId: req.id,
      targetUserId,
      targetUsername: targetUser.username,
      targetEmail: targetUser.email,
      targetRole: targetUser.role,
    });
    
    await logToAuditTable(req.user.id, 'USER_DELETED', 'users', req, 200, { 
      targetUserId,
      targetUsername: targetUser.username,
      targetRole: targetUser.role,
    });

    logger.info('User deleted successfully', {
      requestId: req.id,
      adminId: req.user.id,
      deletedUserId: targetUserId,
      deletedUsername: targetUser.username,
    });

    res.json({ 
      message: 'User deleted successfully',
      requestId: req.id,
    });
  } catch (error) {
    logger.error('Delete user error', {
      error: error.message,
      stack: error.stack,
      requestId: req.id,
      userId: req.user.id,
      targetUserId,
    });
    
    res.status(500).json({ 
      error: 'Internal server error',
      requestId: req.id,
    });
  }
});

// Error handling middleware
app.use(errorLogger);
app.use(notFoundHandler);
app.use(finalErrorHandler);

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  
  if (db) {
    await db.end();
    logger.info('Database connection closed');
  }
  
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully');
  
  if (db) {
    await db.end();
    logger.info('Database connection closed');
  }
  
  process.exit(0);
});

// Start server
const startServer = async () => {
  try {
    await initDatabase();
    
    app.listen(PORT, () => {
      logger.info('Secure server started', {
        port: PORT,
        environment: process.env.NODE_ENV || 'development',
        nodeVersion: process.version,
      });
    });
  } catch (error) {
    logger.error('Failed to start server', {
      error: error.message,
      stack: error.stack,
    });
    process.exit(1);
  }
};

startServer();

module.exports = app;