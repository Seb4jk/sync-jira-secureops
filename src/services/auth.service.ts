/**
 * Servicio de autenticación
 * Maneja la lógica de login y generación de tokens JWT
 */

import jwt from 'jsonwebtoken';
import { config } from '../config';
import { JwtPayload, LoginCredentials, LoginResponse } from '../types';
import { AppError } from '../middlewares/error.middleware';
import { logger } from '../utils/logger';

/**
 * Usuario simulado para el sistema (en producción, esto vendría de una base de datos)
 */
const DEMO_USER = {
  id: '1',
  email: 'admin@example.com',
  password: 'admin123', // En producción, usar bcrypt para hashear contraseñas
};

/**
 * Servicio de autenticación
 */
export class AuthService {
  /**
   * Realiza el login y genera un token JWT
   */
  static async login(credentials: LoginCredentials): Promise<LoginResponse> {
    try {
      logger.info('Intento de login', { email: credentials.email });

      // Validar credenciales (en producción, consultar base de datos y validar hash)
      if (
        credentials.email !== DEMO_USER.email ||
        credentials.password !== DEMO_USER.password
      ) {
        throw new AppError('Credenciales inválidas', 401);
      }

      // Generar token JWT
      const payload: JwtPayload = {
        id: DEMO_USER.id,
        email: DEMO_USER.email,
      };

      const token = jwt.sign(payload, config.jwt.secret, {
        expiresIn: config.jwt.expiresIn,
      });

      logger.info('Login exitoso', { userId: DEMO_USER.id, email: DEMO_USER.email });

      return {
        token,
        expiresIn: config.jwt.expiresIn,
        user: {
          id: DEMO_USER.id,
          email: DEMO_USER.email,
        },
      };
    } catch (error) {
      logger.error('Error en el login', { error });
      throw error;
    }
  }

  /**
   * Valida un token JWT
   */
  static async validateToken(token: string): Promise<JwtPayload> {
    try {
      const decoded = jwt.verify(token, config.jwt.secret) as JwtPayload;
      return decoded;
    } catch (error) {
      throw new AppError('Token inválido o expirado', 403);
    }
  }

  /**
   * Refresca un token JWT (genera uno nuevo)
   */
  static async refreshToken(oldToken: string): Promise<string> {
    try {
      const decoded = await this.validateToken(oldToken);

      const payload: JwtPayload = {
        id: decoded.id,
        email: decoded.email,
      };

      const newToken = jwt.sign(payload, config.jwt.secret, {
        expiresIn: config.jwt.expiresIn,
      });

      logger.info('Token refrescado', { userId: decoded.id });

      return newToken;
    } catch (error) {
      logger.error('Error al refrescar token', { error });
      throw error;
    }
  }
}

