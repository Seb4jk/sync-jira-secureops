/**
 * Rutas de vulnerabilidades
 * Define los endpoints para gestión de CVEs y sincronización con Jira
 */

import { Router } from 'express';
import { VulnerabilitiesController } from '../controllers/vulnerabilities.controller';
import { asyncHandler } from '../middlewares/error.middleware';
import { authenticateToken } from '../middlewares/auth.middleware';

const router = Router();

// Crear instancia del controlador
const vulnerabilitiesController = new VulnerabilitiesController();

/**
 * POST /vulnerabilities/sync
 * Sincroniza CVEs de Wazuh con tareas de Jira
 * Requiere autenticación
 */
router.post(
  '/sync',
  authenticateToken,
  asyncHandler(vulnerabilitiesController.syncVulnerabilities.bind(vulnerabilitiesController))
);

/**
 * GET /vulnerabilities/cves
 * Obtiene la lista de CVEs desde Wazuh
 * Requiere autenticación
 */
router.get(
  '/cves',
  authenticateToken,
  asyncHandler(vulnerabilitiesController.getCVEs.bind(vulnerabilitiesController))
);

/**
 * GET /vulnerabilities/cves/:cveId
 * Obtiene detalles de un CVE específico
 * Requiere autenticación
 */
router.get(
  '/cves/:cveId',
  authenticateToken,
  asyncHandler(vulnerabilitiesController.getCVEDetails.bind(vulnerabilitiesController))
);

/**
 * POST /vulnerabilities/generate-playbook
 * Genera un playbook de acción usando OpenAI
 * Requiere autenticación
 */
router.post(
  '/generate-playbook',
  authenticateToken,
  asyncHandler(vulnerabilitiesController.generatePlaybook.bind(vulnerabilitiesController))
);

export default router;

