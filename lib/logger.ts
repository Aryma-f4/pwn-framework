/**
 * Logger utility - Centralized logging with different levels
 * Supports development and production environments
 */

export enum LogLevel {
  DEBUG = 'DEBUG',
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
}

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  data?: unknown;
  stack?: string;
}

class Logger {
  private isDevelopment: boolean;
  private logs: LogEntry[] = [];
  private maxLogs: number = 100;

  constructor() {
    this.isDevelopment = process.env.NODE_ENV === 'development';
  }

  /**
   * Format log message with timestamp and level
   */
  private formatMessage(level: LogLevel, message: string): string {
    const timestamp = new Date().toISOString();
    return `[${timestamp}] [${level}] ${message}`;
  }

  /**
   * Store log entry
   */
  private storeLog(level: LogLevel, message: string, data?: unknown, stack?: string): void {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      data,
      stack,
    };

    this.logs.push(entry);

    // Keep only recent logs
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }
  }

  /**
   * Send logs to external service (e.g., Sentry, LogRocket)
   */
  private async sendToExternalService(entry: LogEntry): Promise<void> {
    if (this.isDevelopment) return;

    try {
      // Example: Send to external logging service
      // await fetch('/api/logs', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(entry),
      // });
    } catch (error) {
      console.error('Failed to send log to external service:', error);
    }
  }

  /**
   * Debug level logging
   */
  debug(message: string, data?: unknown): void {
    const formatted = this.formatMessage(LogLevel.DEBUG, message);
    console.debug(formatted, data);
    this.storeLog(LogLevel.DEBUG, message, data);
  }

  /**
   * Info level logging
   */
  info(message: string, data?: unknown): void {
    const formatted = this.formatMessage(LogLevel.INFO, message);
    console.info(formatted, data);
    this.storeLog(LogLevel.INFO, message, data);
  }

  /**
   * Warning level logging
   */
  warn(message: string, data?: unknown): void {
    const formatted = this.formatMessage(LogLevel.WARN, message);
    console.warn(formatted, data);
    this.storeLog(LogLevel.WARN, message, data);
  }

  /**
   * Error level logging
   */
  error(message: string, error?: Error | unknown, data?: unknown): void {
    const stack = error instanceof Error ? error.stack : undefined;
    const formatted = this.formatMessage(LogLevel.ERROR, message);
    console.error(formatted, error, data);
    this.storeLog(LogLevel.ERROR, message, data, stack);

    // Send to external service in production
    if (!this.isDevelopment) {
      this.sendToExternalService({
        timestamp: new Date().toISOString(),
        level: LogLevel.ERROR,
        message,
        data,
        stack,
      });
    }
  }

  /**
   * Get all stored logs
   */
  getLogs(): LogEntry[] {
    return [...this.logs];
  }

  /**
   * Get logs filtered by level
   */
  getLogsByLevel(level: LogLevel): LogEntry[] {
    return this.logs.filter(log => log.level === level);
  }

  /**
   * Clear all logs
   */
  clearLogs(): void {
    this.logs = [];
  }

  /**
   * Export logs as JSON
   */
  exportLogs(): string {
    return JSON.stringify(this.logs, null, 2);
  }

  /**
   * Export logs as CSV
   */
  exportLogsAsCSV(): string {
    const headers = ['Timestamp', 'Level', 'Message', 'Data', 'Stack'];
    const rows = this.logs.map(log => [
      log.timestamp,
      log.level,
      log.message,
      JSON.stringify(log.data),
      log.stack || '',
    ]);

    const csv = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')),
    ].join('\n');

    return csv;
  }
}

// Export singleton instance
export const logger = new Logger();

// Export type
export type { LogEntry };
