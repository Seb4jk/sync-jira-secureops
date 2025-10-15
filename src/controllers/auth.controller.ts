/**
 * Controlador de autenticación
 * Maneja las peticiones relacionadas con login y autenticación
 */

import { Request, Response } from 'express';
import { AuthService } from '../services/auth.service';
import { LoginCredentials } from '../types';
import { sendSuccess, sendError } from '../utils/response';
import { logger } from '../utils/logger';
import { AuthRequest } from '../types';

/**
 * Controlador de autenticación
 */
export class AuthController {
  /**
   * Login de usuario
   * POST /auth/login
   */
  static async login(req: Request, res: Response): Promise<void> {
    try {
      const credentials: LoginCredentials = req.body;

      const loginResponse = await AuthService.login(credentials);

      sendSuccess(res, 'Login exitoso', loginResponse, 200);
    } catch (error) {
      logger.error('Error en login', { error });
      throw error;
    }
  }

  /**
   * Valida el token actual del usuario
   * GET /auth/validate
   */
  static async validateToken(req: AuthRequest, res: Response): Promise<void> {
    try {
      // Si llegó aquí, el token ya fue validado por el middleware
      sendSuccess(res, 'Token válido', {
        valid: true,
        user: req.user,
      });
    } catch (error) {
      logger.error('Error al validar token', { error });
      throw error;
    }
  }

  /**
   * Refresca el token del usuario
   * POST /auth/refresh
   */
  static async refreshToken(req: AuthRequest, res: Response): Promise<void> {
    try {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];

      if (!token) {
        sendError(res, 'Token no proporcionado', 'No token provided', 401);
        return;
      }

      const newToken = await AuthService.refreshToken(token);

      sendSuccess(res, 'Token refrescado', {
        token: newToken,
        expiresIn: '24h',
      });
    } catch (error) {
      logger.error('Error al refrescar token', { error });
      throw error;
    }
  }

  /**
   * Obtiene información del usuario actual
   * GET /auth/me
   */
  static async getCurrentUser(req: AuthRequest, res: Response): Promise<void> {
    try {
      sendSuccess(res, 'Usuario autenticado', {
        user: req.user,
      });
    } catch (error) {
      logger.error('Error al obtener usuario actual', { error });
      throw error;
    }
  }
}

