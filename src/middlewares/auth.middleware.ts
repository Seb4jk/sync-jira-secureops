/**
 * Middleware de autenticación JWT
 * Valida el token JWT en las peticiones protegidas
 */

import { Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { AuthRequest, JwtPayload } from '../types';
import { sendError } from '../utils/response';
import { logger } from '../utils/logger';

/**
 * Middleware para validar el token JWT
 * Extrae el token del header Authorization y lo valida
 */
export const authenticateToken = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  try {
    // Obtener el token del header Authorization
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      sendError(res, 'Token de autenticación no proporcionado', 'No token provided', 401);
      return;
    }

    // Verificar y decodificar el token
    jwt.verify(token, config.jwt.secret, (err, decoded) => {
      if (err) {
        logger.warn('Token JWT inválido o expirado', { error: err.message });
        sendError(res, 'Token inválido o expirado', err.message, 403);
        return;
      }

      // Agregar los datos del usuario al request
      req.user = decoded as JwtPayload & { iat: number; exp: number };
      logger.debug('Usuario autenticado', { userId: req.user.id, email: req.user.email });
      next();
    });
  } catch (error) {
    logger.error('Error en la autenticación', { error });
    sendError(res, 'Error en la autenticación', (error as Error).message, 500);
  }
};

/**
 * Middleware opcional - permite pasar sin token pero lo valida si existe
 */
export const optionalAuth = (
  req: AuthRequest,
  _res: Response,
  next: NextFunction
): void => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      next();
      return;
    }

    jwt.verify(token, config.jwt.secret, (err, decoded) => {
      if (!err) {
        req.user = decoded as JwtPayload & { iat: number; exp: number };
      }
      next();
    });
  } catch (error) {
    next();
  }
};

