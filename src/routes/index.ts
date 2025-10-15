/**
 * Archivo principal de rutas
 * Centraliza todas las rutas de la aplicación
 */

import { Router } from 'express';
import healthRoutes from './health.routes';
import authRoutes from './auth.routes';
import vulnerabilitiesRoutes from './vulnerabilities.routes';

const router = Router();

/**
 * Registrar todas las rutas
 */
router.use('/health', healthRoutes);
router.use('/auth', authRoutes);
router.use('/vulnerabilities', vulnerabilitiesRoutes);

/**
 * Ruta raíz - información básica del API
 */
router.get('/', (_req, res) => {
  res.json({
    message: 'API de Sincronización Wazuh-Jira',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      auth: '/auth',
      vulnerabilities: '/vulnerabilities',
    },
    documentation: 'Ver README.md para más información',
  });
});

export default router;

