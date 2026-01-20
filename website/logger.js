import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class Logger {
  constructor() {
    this.logDir = path.join(__dirname, 'logs');
    this.ensureLogDir();
  }

  ensureLogDir() {
    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }
  }

  formatMessage(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    const sanitizedMeta = this.sanitizeData(meta);
    return JSON.stringify({
      timestamp,
      level,
      message,
      ...sanitizedMeta
    });
  }

  sanitizeData(data) {
    if (!data || typeof data !== 'object') return data;
    
    const sanitized = { ...data };
    const sensitiveKeys = ['password', 'pwd', 'connectionString', 'secret', 'token', 'session', 'cookie'];
    
    for (const key in sanitized) {
      if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof sanitized[key] === 'object') {
        sanitized[key] = this.sanitizeData(sanitized[key]);
      }
    }
    
    return sanitized;
  }

  writeLog(level, message, meta = {}) {
    const logMessage = this.formatMessage(level, message, meta);
    const logFile = path.join(this.logDir, `app-${new Date().toISOString().split('T')[0]}.log`);
    
    fs.appendFileSync(logFile, logMessage + '\n');
    
    // Also log to console with appropriate method
    const consoleMethod = level === 'error' ? 'error' : level === 'warn' ? 'warn' : 'log';
    console[consoleMethod](`[${level.toUpperCase()}] ${message}`, meta ? this.sanitizeData(meta) : '');
  }

  info(message, meta) {
    this.writeLog('info', message, meta);
  }

  warn(message, meta) {
    this.writeLog('warn', message, meta);
  }

  error(message, meta) {
    this.writeLog('error', message, meta);
  }

  debug(message, meta) {
    this.writeLog('debug', message, meta);
  }

  mongoError(operation, error, meta = {}) {
    const mongoErrorInfo = {
      operation,
      errorCode: error.code || error.codeName || 'UNKNOWN',
      errorName: error.name || 'MongoError',
      message: error.message,
      ...meta
    };

    // Add specific MongoDB error details if available
    if (error.code) mongoErrorInfo.mongoCode = error.code;
    if (error.codeName) mongoErrorInfo.mongoCodeName = error.codeName;
    if (error.errmsg) mongoErrorInfo.mongoMessage = error.errmsg;
    if (error.connectionGeneration) mongoErrorInfo.connectionGeneration = error.connectionGeneration;
    if (error.topology) mongoErrorInfo.topologyDescription = error.topology.description;

    this.writeLog('error', `MongoDB ${operation} failed`, mongoErrorInfo);
  }
}

export default new Logger();