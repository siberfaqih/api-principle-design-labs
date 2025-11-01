const winston = require('winston');
const path = require('path');

// Define log levels and colors
const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

const logColors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

winston.addColors(logColors);

// Create custom format for structured logging
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

// Create console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.align(),
  winston.format.printf(
    (info) => `${info.timestamp} ${info.level}: ${info.message}`
  )
);

// Create transports
const transports = [
  // Console transport for development
  new winston.transports.Console({
    format: consoleFormat,
    level: process.env.NODE_ENV === 'production' ? 'warn' : 'debug',
  }),
  
  // File transport for all logs
  new winston.transports.File({
    filename: path.join(__dirname, '../logs/app.log'),
    format: logFormat,
    level: 'info',
    maxsize: 5242880, // 5MB
    maxFiles: 5,
  }),
  
  // File transport for error logs
  new winston.transports.File({
    filename: path.join(__dirname, '../logs/error.log'),
    format: logFormat,
    level: 'error',
    maxsize: 5242880, // 5MB
    maxFiles: 5,
  }),
  
  // File transport for security events
  new winston.transports.File({
    filename: path.join(__dirname, '../logs/security.log'),
    format: logFormat,
    level: 'warn',
    maxsize: 5242880, // 5MB
    maxFiles: 10,
  }),
];

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  levels: logLevels,
  format: logFormat,
  transports,
  exitOnError: false,
});

// Create specialized loggers for different purposes
const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.label({ label: 'SECURITY' })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(__dirname, '../logs/security.log'),
      maxsize: 5242880,
      maxFiles: 10,
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

const auditLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.label({ label: 'AUDIT' })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(__dirname, '../logs/audit.log'),
      maxsize: 5242880,
      maxFiles: 15,
    }),
  ],
});

// Helper functions for structured logging
const logSecurity = (level, message, metadata = {}) => {
  securityLogger.log(level, message, {
    ...metadata,
    timestamp: new Date().toISOString(),
    type: 'security_event',
  });
};

const logAudit = (action, userId, resource, metadata = {}) => {
  auditLogger.info('Audit Event', {
    action,
    userId,
    resource,
    timestamp: new Date().toISOString(),
    ...metadata,
  });
};

const logAuthentication = (event, userId, ip, userAgent, success = true, metadata = {}) => {
  const level = success ? 'info' : 'warn';
  const message = success ? 'Authentication successful' : 'Authentication failed';
  
  logSecurity(level, message, {
    event,
    userId,
    ip,
    userAgent,
    success,
    ...metadata,
  });
};

const logAuthorization = (userId, resource, action, allowed = true, metadata = {}) => {
  const level = allowed ? 'info' : 'warn';
  const message = allowed ? 'Authorization granted' : 'Authorization denied';
  
  logSecurity(level, message, {
    userId,
    resource,
    action,
    allowed,
    ...metadata,
  });
};

const logDataAccess = (userId, resource, operation, recordCount = 0, metadata = {}) => {
  logAudit('data_access', userId, resource, {
    operation,
    recordCount,
    ...metadata,
  });
};

const logSuspiciousActivity = (description, ip, userAgent, metadata = {}) => {
  logSecurity('error', 'Suspicious activity detected', {
    description,
    ip,
    userAgent,
    severity: 'HIGH',
    ...metadata,
  });
};

// Sanitize sensitive data from logs
const sanitizeLogData = (data) => {
  const sensitiveFields = ['password', 'token', 'authorization', 'cookie', 'secret'];
  const sanitized = { ...data };
  
  const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) return obj;
    
    const result = Array.isArray(obj) ? [] : {};
    
    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      
      if (sensitiveFields.some(field => lowerKey.includes(field))) {
        result[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        result[key] = sanitizeObject(value);
      } else {
        result[key] = value;
      }
    }
    
    return result;
  };
  
  return sanitizeObject(sanitized);
};

module.exports = {
  logger,
  securityLogger,
  auditLogger,
  logSecurity,
  logAudit,
  logAuthentication,
  logAuthorization,
  logDataAccess,
  logSuspiciousActivity,
  sanitizeLogData,
};