const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// VULNERABILITY 1: No proper logging configuration
// VULNERABILITY 2: Sensitive data in console logs
// VULNERABILITY 3: No request/response logging
// VULNERABILITY 4: No error logging
// VULNERABILITY 5: No security event logging

// Basic middleware
app.use(cors());
app.use(express.json());

// VULNERABILITY 6: Database credentials hardcoded
const db = mysql.createConnection({
  host: 'db',
  user: 'root',
  password: 'rootpassword',
  database: 'secure_api_lab'
});

// VULNERABILITY 7: No connection error handling or logging
db.connect();

// VULNERABILITY 8: JWT secret hardcoded and logged
const JWT_SECRET = 'super-secret-key';
console.log('JWT Secret:', JWT_SECRET); // VULNERABILITY: Logging sensitive data

// VULNERABILITY 9: No authentication middleware logging
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      // VULNERABILITY 10: No failed authentication logging
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// VULNERABILITY 11: No input validation logging
// VULNERABILITY 12: SQL Injection vulnerability with no logging
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // VULNERABILITY 13: Logging sensitive data (password)
  console.log('Login attempt:', { username, password });
  
  // VULNERABILITY 14: SQL Injection - no parameterized queries
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  
  db.query(query, (err, results) => {
    if (err) {
      // VULNERABILITY 15: Exposing database errors to client
      console.log('Database error:', err);
      return res.status(500).json({ error: err.message });
    }

    if (results.length === 0) {
      // VULNERABILITY 16: No failed login attempt logging
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = results[0];
    
    // VULNERABILITY 17: No password comparison logging
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      // VULNERABILITY 18: Logging JWT tokens
      console.log('Generated token:', token);
      
      res.json({ 
        message: 'Login successful', 
        token,
        user: { id: user.id, username: user.username, role: user.role }
      });
    });
  });
});

// VULNERABILITY 19: No registration attempt logging
app.post('/api/register', (req, res) => {
  const { username, email, password, role } = req.body;
  
  // VULNERABILITY 20: Logging all user data including password
  console.log('Registration data:', { username, email, password, role });

  // Check if user exists
  const checkQuery = `SELECT * FROM users WHERE username = '${username}' OR email = '${email}'`;
  
  db.query(checkQuery, (err, results) => {
    if (err) {
      console.log('Database error:', err);
      return res.status(500).json({ error: err.message });
    }

    if (results.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.log('Hashing error:', err);
        return res.status(500).json({ error: 'Error creating user' });
      }

      // VULNERABILITY 21: SQL Injection in INSERT
      const insertQuery = `INSERT INTO users (username, email, password, role) VALUES ('${username}', '${email}', '${hashedPassword}', '${role || 'user'}')`;
      
      db.query(insertQuery, (err, result) => {
        if (err) {
          console.log('Insert error:', err);
          return res.status(500).json({ error: err.message });
        }

        // VULNERABILITY 22: No successful registration logging
        res.status(201).json({ message: 'User created successfully' });
      });
    });
  });
});

// VULNERABILITY 23: No access control logging
app.get('/api/users', authenticateToken, (req, res) => {
  // VULNERABILITY 24: No authorization check logging
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  // VULNERABILITY 25: Exposing all user data including passwords
  const query = 'SELECT * FROM users';
  
  db.query(query, (err, results) => {
    if (err) {
      console.log('Database error:', err);
      return res.status(500).json({ error: err.message });
    }

    // VULNERABILITY 26: No data access logging
    console.log('Admin accessed user data:', results);
    res.json(results);
  });
});

// VULNERABILITY 27: No user profile access logging
app.get('/api/profile', authenticateToken, (req, res) => {
  const userId = req.user.id;
  
  const query = `SELECT id, username, email, role, created_at FROM users WHERE id = ${userId}`;
  
  db.query(query, (err, results) => {
    if (err) {
      console.log('Database error:', err);
      return res.status(500).json({ error: err.message });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(results[0]);
  });
});

// VULNERABILITY 28: No user update logging
app.put('/api/profile', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { email, password } = req.body;
  
  // VULNERABILITY 29: Logging sensitive update data
  console.log('Profile update:', { userId, email, password });

  let updateQuery = 'UPDATE users SET ';
  const updates = [];
  
  if (email) {
    updates.push(`email = '${email}'`);
  }
  
  if (password) {
    const hashedPassword = bcrypt.hashSync(password, 10);
    updates.push(`password = '${hashedPassword}'`);
  }
  
  if (updates.length === 0) {
    return res.status(400).json({ error: 'No updates provided' });
  }
  
  updateQuery += updates.join(', ') + ` WHERE id = ${userId}`;
  
  db.query(updateQuery, (err, result) => {
    if (err) {
      console.log('Update error:', err);
      return res.status(500).json({ error: err.message });
    }

    res.json({ message: 'Profile updated successfully' });
  });
});

// VULNERABILITY 30: No admin action logging
app.delete('/api/users/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const userId = req.params.id;
  
  // VULNERABILITY 31: No deletion attempt logging
  const query = `DELETE FROM users WHERE id = ${userId}`;
  
  db.query(query, (err, result) => {
    if (err) {
      console.log('Delete error:', err);
      return res.status(500).json({ error: err.message });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // VULNERABILITY 32: No successful deletion logging
    res.json({ message: 'User deleted successfully' });
  });
});

// VULNERABILITY 33: No error handling middleware
// VULNERABILITY 34: No 404 logging
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, () => {
  // VULNERABILITY 35: Logging server configuration
  console.log(`Vulnerable server running on port ${PORT}`);
  console.log('Database config:', { host: 'db', user: 'root', password: 'rootpassword' });
});

module.exports = app;