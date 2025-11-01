const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');
const { 
  logger, 
  logSecurity, 
  logSuspiciousActivity, 
  sanitizeLogData 
} = require('./logger');

// Request ID middleware for tracing
const requestId = (req, res, next) => {
  req.id = uuidv4();
  res.setHeader('X-Request-ID', req.id);
  next();
};

// Enhanced request logging middleware
const requestLogger = morgan((tokens, req, res) => {
  const logData = {
    requestId: req.id,
    method: tokens.method(req, res),
    url: tokens.url(req, res),
    status: tokens.status(req, res),
    contentLength: tokens.res(req, res, 'content-length'),
    responseTime: tokens['response-time'](req, res),
    userAgent: tokens['user-agent'](req, res),
    ip: req.ip || req.connection.remoteAddress,
    userId: req.user ? req.user.id : null,
    timestamp: new Date().toISOString(),
  };

  // Log different levels based on status code
  if (res.statusCode >= 400) {
    if (res.statusCode >= 500) {
      logger.error('HTTP Request Error', logData);
    } else {
      logger.warn('HTTP Request Warning', logData);
    }
  } else {
    logger.http('HTTP Request', logData);
  }

  return null; // Don't output to console via morgan
});

// Security headers middleware
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
});

// Rate limiting with logging
const createRateLimit = (windowMs = 15 * 60 * 1000, max = 100, message = 'Too many requests') => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      const logData = {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.originalUrl,
        method: req.method,
        userId: req.user ? req.user.id : null,
        requestId: req.id,
      };

      logSuspiciousActivity('Rate limit exceeded', req.ip, req.get('User-Agent'), logData);
      
      res.status(429).json({ 
        error: message,
        retryAfter: Math.round(windowMs / 1000),
        requestId: req.id,
      });
    },
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.path === '/health' || req.path === '/api/health';
    },
  });
};

// Input validation logging middleware
const logInputValidation = (req, res, next) => {
  const sensitiveRoutes = ['/api/login', '/api/register', '/api/profile'];
  
  if (sensitiveRoutes.includes(req.path)) {
    const sanitizedBody = sanitizeLogData(req.body);
    
    logger.info('Input validation request', {
      requestId: req.id,
      path: req.path,
      method: req.method,
      body: sanitizedBody,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user ? req.user.id : null,
    });
  }
  
  next();
};

// Error logging middleware
const errorLogger = (err, req, res, next) => {
  const errorData = {
    requestId: req.id,
    error: {
      message: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
      name: err.name,
    },
    request: {
      method: req.method,
      url: req.originalUrl,
      headers: sanitizeLogData(req.headers),
      body: sanitizeLogData(req.body),
      params: req.params,
      query: req.query,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    },
    user: req.user ? { id: req.user.id, username: req.user.username } : null,
    timestamp: new Date().toISOString(),
  };

  // Log based on error type
  if (err.status >= 500 || !err.status) {
    logger.error('Server Error', errorData);
  } else if (err.status >= 400) {
    logger.warn('Client Error', errorData);
  }

  // Check for suspicious patterns
  if (err.message.includes('SQL') || err.message.includes('injection')) {
    logSuspiciousActivity('Potential SQL injection attempt', req.ip, req.get('User-Agent'), {
      error: err.message,
      requestId: req.id,
      url: req.originalUrl,
    });
  }

  next(err);
};

// Security event middleware for suspicious activities
const securityMonitoring = (req, res, next) => {
  const suspiciousPatterns = [
    /(\bor\b|\band\b).*=.*=/i, // SQL injection patterns
    /<script|javascript:|vbscript:/i, // XSS patterns
    /\.\.\//g, // Path traversal
    /\bselect\b.*\bfrom\b/i, // SQL SELECT statements
    /\bunion\b.*\bselect\b/i, // SQL UNION attacks
  ];

  const checkSuspicious = (value) => {
    if (typeof value === 'string') {
      return suspiciousPatterns.some(pattern => pattern.test(value));
    }
    return false;
  };

  // Check URL parameters
  const urlParams = new URLSearchParams(req.url.split('?')[1] || '');
  for (const [key, value] of urlParams) {
    if (checkSuspicious(value)) {
      logSuspiciousActivity('Suspicious URL parameter detected', req.ip, req.get('User-Agent'), {
        parameter: key,
        value: value,
        url: req.originalUrl,
        requestId: req.id,
      });
    }
  }

  // Check request body
  if (req.body && typeof req.body === 'object') {
    for (const [key, value] of Object.entries(req.body)) {
      if (checkSuspicious(value)) {
        logSuspiciousActivity('Suspicious request body detected', req.ip, req.get('User-Agent'), {
          field: key,
          url: req.originalUrl,
          requestId: req.id,
        });
      }
    }
  }

  next();
};

// 404 handler with logging
const notFoundHandler = (req, res) => {
  const logData = {
    requestId: req.id,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user ? req.user.id : null,
  };

  logger.warn('404 Not Found', logData);

  res.status(404).json({
    error: 'Endpoint not found',
    requestId: req.id,
    timestamp: new Date().toISOString(),
  });
};

// Final error handler
const finalErrorHandler = (err, req, res, next) => {
  const status = err.status || 500;
  const message = status === 500 ? 'Internal Server Error' : err.message;

  res.status(status).json({
    error: message,
    requestId: req.id,
    timestamp: new Date().toISOString(),
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
};

module.exports = {
  requestId,
  requestLogger,
  securityHeaders,
  createRateLimit,
  logInputValidation,
  errorLogger,
  securityMonitoring,
  notFoundHandler,
  finalErrorHandler,
};