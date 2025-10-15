/**
 * Middleware de manejo de errores
 * Captura y formatea todos los errores de la aplicación
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { sendError } from '../utils/response';

/**
 * Clase de error personalizada para la aplicación
 */
export class AppError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(message: string, statusCode: number = 500, isOperational: boolean = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Middleware para manejar errores 404 (rutas no encontradas)
 */
export const notFoundHandler = (req: Request, _res: Response, next: NextFunction): void => {
  const error = new AppError(`Ruta no encontrada: ${req.originalUrl}`, 404);
  next(error);
};

/**
 * Middleware global de manejo de errores
 * Debe ser el último middleware de la aplicación
 */
export const errorHandler = (
  err: Error | AppError,
  req: Request,
  res: Response,
  _next: NextFunction
): void => {
  // Determinar el código de estado
  const statusCode = err instanceof AppError ? err.statusCode : 500;

  // Log del error
  if (statusCode >= 500) {
    logger.error('Error del servidor', {
      error: err.message,
      stack: err.stack,
      url: req.originalUrl,
      method: req.method,
    });
  } else {
    logger.warn('Error del cliente', {
      error: err.message,
      url: req.originalUrl,
      method: req.method,
    });
  }

  // Enviar respuesta de error
  sendError(
    res,
    err.message || 'Error interno del servidor',
    process.env.NODE_ENV === 'development' ? err.stack : undefined,
    statusCode
  );
};

/**
 * Wrapper para funciones asíncronas en routes/controllers
 * Evita tener que usar try-catch en cada función
 */
export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

