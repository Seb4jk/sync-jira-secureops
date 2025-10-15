/**
 * Rutas de salud del API
 * Define los endpoints para health checks
 */

import { Router } from 'express';
import { HealthController } from '../controllers/health.controller';
import { asyncHandler } from '../middlewares/error.middleware';

const router = Router();

/**
 * GET /health
 * Verifica el estado general del API
 */
router.get('/', asyncHandler(HealthController.getHealth));

/**
 * GET /health/ready
 * Verifica si el servicio está listo para recibir tráfico
 */
router.get('/ready', asyncHandler(HealthController.getReadiness));

/**
 * GET /health/live
 * Verifica si el servicio está vivo
 */
router.get('/live', asyncHandler(HealthController.getLiveness));

export default router;

