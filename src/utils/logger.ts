/**
 * Logger centralizado usando Winston
 * Proporciona logs estructurados con diferentes niveles
 */

import winston from 'winston';
import { config } from '../config';

/**
 * Formato personalizado para los logs
 */
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

/**
 * Formato para consola con colores
 */
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(meta).length > 0) {
      msg += ` ${JSON.stringify(meta)}`;
    }
    return msg;
  })
);

/**
 * Transportes del logger
 */
const transports: winston.transport[] = [
  // Consola con colores
  new winston.transports.Console({
    format: consoleFormat,
  }),
];

// En producción, agregar logs a archivos
if (config.nodeEnv === 'production') {
  transports.push(
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      format: logFormat,
    }),
    new winston.transports.File({
      filename: 'logs/combined.log',
      format: logFormat,
    })
  );
}

/**
 * Instancia del logger
 */
export const logger = winston.createLogger({
  level: config.log.level,
  format: logFormat,
  transports,
});

/**
 * Stream para Morgan
 */
export const morganStream = {
  write: (message: string) => {
    logger.info(message.trim());
  },
};

