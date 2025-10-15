/**
 * Rutas de autenticación
 * Define los endpoints para login y gestión de tokens
 */

import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { asyncHandler } from '../middlewares/error.middleware';
import { authenticateToken } from '../middlewares/auth.middleware';
import { validateLoginCredentials } from '../middlewares/validation.middleware';

const router = Router();

/**
 * POST /auth/login
 * Inicia sesión y obtiene un token JWT
 * Body: { email: string, password: string }
 */
router.post(
  '/login',
  validateLoginCredentials,
  asyncHandler(AuthController.login)
);

/**
 * GET /auth/validate
 * Valida el token actual
 * Requiere autenticación
 */
router.get(
  '/validate',
  authenticateToken,
  asyncHandler(AuthController.validateToken)
);

/**
 * POST /auth/refresh
 * Refresca el token JWT
 * Requiere autenticación
 */
router.post(
  '/refresh',
  authenticateToken,
  asyncHandler(AuthController.refreshToken)
);

/**
 * GET /auth/me
 * Obtiene información del usuario autenticado
 * Requiere autenticación
 */
router.get(
  '/me',
  authenticateToken,
  asyncHandler(AuthController.getCurrentUser)
);

export default router;

