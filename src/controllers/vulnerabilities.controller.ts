/**
 * Controlador de vulnerabilidades
 * Maneja la sincronización de CVEs entre Wazuh y Jira
 */

import { Request, Response } from 'express';
import { WazuhService } from '../services/wazuh.service';
import { JiraService } from '../services/jira.service';
import { SyncSummary } from '../types';
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
   * Sincroniza las vulnerabilidades de Wazuh con Jira
   * POST /vulnerabilities/sync
   */
  async syncVulnerabilities(_req: Request, res: Response): Promise<void> {
    const startTime = Date.now();

    try {
      logger.info('Iniciando sincronización de vulnerabilidades');

      // Obtener CVEs desde Wazuh
      const cves = await this.wazuhService.getCVEs();
      logger.info(`CVEs obtenidos de Wazuh: ${cves.length}`);

      // Inicializar resumen
      const summary: SyncSummary = {
        cvesProcessed: 0,
        tasksCreated: 0,
        subtasksCreated: 0,
        errors: 0,
        duration: 0,
        details: [],
      };

      // Procesar cada CVE
      for (const cve of cves) {
        try {
          logger.info(`Procesando CVE: ${cve.cve}`);

          // Crear tarea en Jira con sus subtareas
          const jiraTask = await this.jiraService.createTaskWithSubtasks(cve);

          summary.cvesProcessed++;
          summary.tasksCreated++;
          summary.subtasksCreated += jiraTask.subtasks?.length || 0;

          summary.details.push({
            cve: cve.cve,
            taskKey: jiraTask.key,
            subtasksCount: jiraTask.subtasks?.length || 0,
            status: 'success',
          });

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

      // Calcular duración
      summary.duration = Date.now() - startTime;

      logger.info('Sincronización completada', {
        cvesProcessed: summary.cvesProcessed,
        tasksCreated: summary.tasksCreated,
        subtasksCreated: summary.subtasksCreated,
        errors: summary.errors,
        duration: summary.duration + 'ms',
      });

      sendSuccess(
        res,
        'Sincronización completada exitosamente',
        summary,
        200
      );
    } catch (error) {
      logger.error('Error en la sincronización', { error });
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

