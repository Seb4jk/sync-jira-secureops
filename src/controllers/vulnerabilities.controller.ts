/**
 * Controlador de vulnerabilidades
 * Maneja la sincronización de CVEs entre Wazuh y Jira
 */

import { Request, Response } from 'express';
import { WazuhService } from '../services/wazuh.service';
import { JiraService } from '../services/jira.service';
import { SyncSummary, CVE } from '../types';
import { sendSuccess } from '../utils/response';
import { logger } from '../utils/logger';

/**
 * Controlador de vulnerabilidades
 */
export class VulnerabilitiesController {
  private wazuhService: WazuhService;
  private jiraService: JiraService;

  constructor() {
    this.wazuhService = new WazuhService();
    this.jiraService = new JiraService();
  }

  /**
   * Obtiene datos mock para pruebas (separado de la lógica principal)
   */
  private getMockCVEs(): CVE[] {
    return [
      {
        id: "CVE-TEST-001",
        cve: "CVE-TEST-001",
        title: "Test Vulnerability 1",
        severity: "Critical",
        cvss: 9.8,
        description: "Test vulnerability for validation - Critical severity",
        published: "2024-01-01T00:00:00Z",
        modified: "2024-01-01T00:00:00Z",
        affectedServers: [
          {
            id: "020",
            name: "server636336.test.com",
            hostname: "server636336.test.com",
            ip: "192.168.1.399",
            os: "Debian 10",
            package: "test-package-server636336",
            version: "3.0.0"
          }
        ]
      },
      {
        id: "CVE-TEST-002",
        cve: "CVE-TEST-002",
        title: "Test Vulnerability 2",
        severity: "High",
        cvss: 7.5,
        description: "Test vulnerability for validation - High severity",
        published: "2024-01-02T00:00:00Z",
        modified: "2024-01-02T00:00:00Z",
        affectedServers: [
          {
            id: "004",
            name: "server4.test.com",
            hostname: "server4.test.com",
            ip: "192.168.1.4",
            os: "Ubuntu 22.04",
            package: "test-package-4",
            version: "4.0.0"
          }
        ]
      }
    ];
  }

  /**
   * Sincroniza las vulnerabilidades de Wazuh con Jira (versión inteligente)
   * POST /vulnerabilities/sync
   */
  async syncVulnerabilities(_req: Request, res: Response): Promise<void> {
    const startTime = Date.now();

    try {
      logger.info('Iniciando sincronización inteligente de vulnerabilidades');

      // Obtener CVEs desde Wazuh
      const wazuhCVEs = await this.wazuhService.getCVEs();
      logger.info(`CVEs obtenidos de Wazuh: ${wazuhCVEs.length}`);

      // Inyectar datos mock si está habilitado
      let cves: CVE[] = [...wazuhCVEs];
      
      console.log(`🔍 DEBUG: USE_MOCK_DATA = "${process.env.USE_MOCK_DATA}"`);
      console.log(`🔍 DEBUG: Comparación === 'true': ${process.env.USE_MOCK_DATA === 'true'}`);
      
      if (process.env.USE_MOCK_DATA === 'true') {
        logger.info('Modo mock habilitado, inyectando datos de prueba');
        const mockCVEs = this.getMockCVEs();
        cves = [...wazuhCVEs, ...mockCVEs];
        logger.info(`CVEs totales (Wazuh + Mock): ${cves.length}`);
        console.log('📋 MODO MOCK ACTIVADO - Datos adicionales inyectados');
      } else {
        console.log('📋 MODO MOCK DESACTIVADO - Solo datos de Wazuh');
      }

      // Inicializar resumen
      const summary: SyncSummary = {
        cvesProcessed: 0,
        tasksCreated: 0,
        subtasksCreated: 0,
        errors: 0,
        duration: 0,
        details: [],
      };

      // Procesar cada CVE con sincronización inteligente
      for (const cve of cves) {
        try {
          logger.info(`Procesando CVE con sincronización inteligente: ${cve.cve}`);
          console.log(`\n=== PROCESANDO CVE EN JIRA ===`);
          console.log(`CVE: ${cve.cve}`);
          console.log(`Servidores afectados: ${cve.affectedServers.length}`);
          console.log(`Datos de servidores:`, JSON.stringify(cve.affectedServers, null, 2));
          console.log(`===============================`);

          // Usar sincronización inteligente
          const jiraTask = await this.jiraService.syncTaskWithSubtasks(cve);

          summary.cvesProcessed++;
          
          // Determinar si fue creada o actualizada
          const existingTask = await this.jiraService.findTaskByCVE(cve.cve);
          if (existingTask && existingTask.key === jiraTask.key) {
            // Fue actualizada
            summary.details.push({
              cve: cve.cve,
              taskKey: jiraTask.key,
              subtasksCount: jiraTask.subtasks?.length || 0,
              status: 'success',
            });
          } else {
            // Fue creada
            summary.tasksCreated++;
            summary.details.push({
              cve: cve.cve,
              taskKey: jiraTask.key,
              subtasksCount: jiraTask.subtasks?.length || 0,
              status: 'success',
            });
          }

          summary.subtasksCreated += jiraTask.subtasks?.length || 0;

          logger.info(`CVE procesado exitosamente: ${cve.cve}`, {
            taskKey: jiraTask.key,
            subtasks: jiraTask.subtasks?.length || 0,
          });
        } catch (error) {
          summary.errors++;
          summary.details.push({
            cve: cve.cve,
            taskKey: '',
            subtasksCount: 0,
            status: 'failed',
            error: (error as Error).message,
          });

          logger.error(`Error al procesar CVE: ${cve.cve}`, { error });
        }
      }

      // Finalizar CVEs que ya no existen
      try {
        logger.info('Verificando CVEs eliminados para finalizar');
        await this.jiraService.finalizeDeletedCVEs(cves);
        logger.info('CVEs eliminados procesados');
      } catch (error) {
        logger.error('Error al finalizar CVEs eliminados', { error });
        summary.errors++;
      }

      // Finalizar subtareas huérfanas (que ya no tienen servidores correspondientes)
      try {
        logger.info('Verificando subtareas huérfanas para finalizar');
        await this.jiraService.finalizeOrphanSubtasks(cves);
        logger.info('Subtareas huérfanas procesadas');
      } catch (error) {
        logger.error('Error al finalizar subtareas huérfanas', { error });
        summary.errors++;
      }

      // Calcular duración
      summary.duration = Date.now() - startTime;

      logger.info('Sincronización inteligente completada', {
        cvesProcessed: summary.cvesProcessed,
        tasksCreated: summary.tasksCreated,
        subtasksCreated: summary.subtasksCreated,
        errors: summary.errors,
        duration: summary.duration + 'ms',
      });

      sendSuccess(
        res,
        'Sincronización inteligente completada exitosamente',
        summary,
        200
      );
    } catch (error) {
      logger.error('Error en la sincronización inteligente', { error });
      throw error;
    }
  }

  /**
   * Obtiene la lista de CVEs desde Wazuh
   * GET /vulnerabilities/cves
   */
  async getCVEs(_req: Request, res: Response): Promise<void> {
    try {
      logger.info('Obteniendo lista de CVEs');

      const cves = await this.wazuhService.getCVEs();

      sendSuccess(res, 'CVEs obtenidos exitosamente', {
        count: cves.length,
        cves,
      });
    } catch (error) {
      logger.error('Error al obtener CVEs', { error });
      throw error;
    }
  }

  /**
   * Obtiene detalles de un CVE específico
   * GET /vulnerabilities/cves/:cveId
   */
  async getCVEDetails(req: Request, res: Response): Promise<void> {
    try {
      const { cveId } = req.params;
      logger.info('Obteniendo detalles del CVE', { cveId });

      const cve = await this.wazuhService.getCVEDetails(cveId);

      if (!cve) {
        sendSuccess(res, 'CVE no encontrado', null, 404);
        return;
      }

      sendSuccess(res, 'Detalles del CVE obtenidos', cve);
    } catch (error) {
      logger.error('Error al obtener detalles del CVE', { error });
      throw error;
    }
  }

}

