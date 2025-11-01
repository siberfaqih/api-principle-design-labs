-- Create database
CREATE DATABASE IF NOT EXISTS secure_api_lab;
USE secure_api_lab;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    failed_login_attempts INT DEFAULT 0,
    account_locked BOOLEAN DEFAULT FALSE,
    locked_until TIMESTAMP NULL
);

-- Create audit_logs table for security monitoring
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NULL,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    request_method VARCHAR(10) NULL,
    request_path VARCHAR(255) NULL,
    request_body TEXT NULL,
    response_status INT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'LOW',
    details JSON NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create sessions table for session management
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert dummy users
INSERT INTO users (username, email, password, role) VALUES
-- Password: admin123
('admin', 'admin@example.com', '$2a$10$8K1p/a0dCZKOuisin.sOyO6H8EvKlvArWeLUiYiYwpMtscQh/eGsS', 'admin'),
-- Password: user123
('john_doe', 'john@example.com', '$2a$10$8K1p/a0dCZKOuisin.sOyO6H8EvKlvArWeLUiYiYwpMtscQh/eGsS', 'user'),
-- Password: user123
('jane_smith', 'jane@example.com', '$2a$10$8K1p/a0dCZKOuisin.sOyO6H8EvKlvArWeLUiYiYwpMtscQh/eGsS', 'user'),
-- Password: test123
('test_user', 'test@example.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user'),
-- Password: demo123
('demo_user', 'demo@example.com', '$2a$10$5v4n8.OKvKqH.8anpEWe4eLvAcYn2/1l8gCzYOOB8UfOAIUHdvvgm', 'user');

-- Insert some sample audit logs
INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent, request_method, request_path, response_status, severity, details) VALUES
(1, 'LOGIN_SUCCESS', 'auth', '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'POST', '/api/login', 200, 'LOW', '{"login_time": "2024-01-15 10:30:00"}'),
(2, 'LOGIN_FAILED', 'auth', '192.168.1.101', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36', 'POST', '/api/login', 401, 'MEDIUM', '{"reason": "invalid_password", "attempts": 3}'),
(1, 'USER_ACCESS', 'users', '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'GET', '/api/users', 200, 'LOW', '{"accessed_count": 5}'),
(3, 'PROFILE_UPDATE', 'profile', '192.168.1.102', 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15', 'PUT', '/api/profile', 200, 'LOW', '{"updated_fields": ["email"]}'),
(NULL, 'UNAUTHORIZED_ACCESS', 'users', '10.0.0.50', 'curl/7.68.0', 'GET', '/api/users', 403, 'HIGH', '{"reason": "no_token", "suspicious": true}');

-- Insert some active sessions
INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at) VALUES
('sess_admin_001', 1, '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', DATE_ADD(NOW(), INTERVAL 24 HOUR)),
('sess_user_001', 2, '192.168.1.101', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36', DATE_ADD(NOW(), INTERVAL 24 HOUR)),
('sess_user_002', 3, '192.168.1.102', 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15', DATE_ADD(NOW(), INTERVAL 24 HOUR));

-- Create indexes for better performance
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_severity ON audit_logs(severity);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- Create a view for security monitoring
CREATE VIEW security_events AS
SELECT 
    al.id,
    al.user_id,
    u.username,
    al.action,
    al.resource,
    al.ip_address,
    al.request_method,
    al.request_path,
    al.response_status,
    al.severity,
    al.timestamp,
    al.details
FROM audit_logs al
LEFT JOIN users u ON al.user_id = u.id
WHERE al.severity IN ('HIGH', 'CRITICAL') 
   OR al.action IN ('LOGIN_FAILED', 'UNAUTHORIZED_ACCESS', 'SUSPICIOUS_ACTIVITY')
ORDER BY al.timestamp DESC;