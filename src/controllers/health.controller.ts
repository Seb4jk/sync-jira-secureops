/**
 * Controlador de salud del API
 * Proporciona información sobre el estado del servicio
 */

import { Request, Response } from 'express';
import { config } from '../config';
import { sendSuccess } from '../utils/response';
import { logger } from '../utils/logger';

/**
 * Controlador de Health
 */
export class HealthController {
  /**
   * Endpoint para verificar el estado del API
   * GET /health
   */
  static async getHealth(_req: Request, res: Response): Promise<void> {
    try {
      const healthData = {
        status: 'ok',
        message: 'API funcionando correctamente',
        version: config.apiVersion,
        environment: config.nodeEnv,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: {
          total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB',
          used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
        },
      };

      logger.debug('Health check realizado');
      sendSuccess(res, 'API saludable', healthData);
    } catch (error) {
      logger.error('Error en health check', { error });
      throw error;
    }
  }

  /**
   * Endpoint para verificar la disponibilidad (readiness)
   * GET /health/ready
   */
  static async getReadiness(_req: Request, res: Response): Promise<void> {
    try {
      // Aquí se podrían verificar conexiones a bases de datos, APIs externas, etc.
      const isReady = true;

      const readinessData = {
        ready: isReady,
        services: {
          wazuh: 'connected', // Simulated
          jira: 'connected', // Simulated
        },
      };

      sendSuccess(res, 'Servicio listo', readinessData);
    } catch (error) {
      logger.error('Error en readiness check', { error });
      throw error;
    }
  }

  /**
   * Endpoint para verificar si está vivo (liveness)
   * GET /health/live
   */
  static async getLiveness(_req: Request, res: Response): Promise<void> {
    sendSuccess(res, 'Servicio activo', { alive: true });
  }
}

