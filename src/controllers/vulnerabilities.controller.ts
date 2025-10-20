/**
 * Controlador de vulnerabilidades
 * Maneja la sincronización de CVEs entre Wazuh y Jira
 */

import { Request, Response } from 'express';
import { WazuhService } from '../services/wazuh.service';
import { JiraService } from '../services/jira.service';
import { OpenAIService } from '../services/openai.service';
import { SyncSummary, CVE } from '../types';
import { sendSuccess } from '../utils/response';
import { logger } from '../utils/logger';
import fs from 'fs';
import path from 'path';
import { readCVEsFile, chunkCVEs, getLatestCVEsFile } from '../utils/fileProcessor';

/**
 * Controlador de vulnerabilidades
 */
export class VulnerabilitiesController {
  private wazuhService: WazuhService;
  private jiraService: JiraService;
  private openaiService: OpenAIService;

  constructor() {
    this.wazuhService = new WazuhService();
    this.jiraService = new JiraService();
    this.openaiService = new OpenAIService();
  }

  /**
   * Guarda los datos de CVEs como archivo JSON en el proyecto
   */
  private async saveCVEsToFile(cves: CVE[]): Promise<string> {
    try {
      // Crear directorio downloads si no existe
      const downloadsDir = path.join(process.cwd(), 'downloads');
      if (!fs.existsSync(downloadsDir)) {
        fs.mkdirSync(downloadsDir, { recursive: true });
      }

      // Generar nombre único con timestamp
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `cves-${timestamp}.json`;
      const filePath = path.join(downloadsDir, filename);

      // Preparar datos para guardar
      const dataToSave = {
        timestamp: new Date().toISOString(),
        count: cves.length,
        cves: cves
      };

      // Escribir archivo
      fs.writeFileSync(filePath, JSON.stringify(dataToSave, null, 2), 'utf8');

      logger.info('Archivo de CVEs guardado exitosamente', {
        filename,
        path: filePath,
        count: cves.length
      });

      return filePath;
    } catch (error) {
      logger.error('Error al guardar archivo de CVEs', { error });
      throw new Error(`Error al guardar archivo: ${error instanceof Error ? error.message : 'Error desconocido'}`);
    }
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
   * GET /vulnerabilities/cves?download=true
   */
  async getCVEs(req: Request, res: Response): Promise<void> {
    try {
      const download = req.query.download === 'true';
      logger.info('Obteniendo lista de CVEs', { download });

      const cves = await this.wazuhService.getCVEs();

      // Si se solicita descarga, guardar como archivo JSON
      if (download) {
        const filePath = await this.saveCVEsToFile(cves);
        const filename = path.basename(filePath);
        
        sendSuccess(res, 'CVEs obtenidos y guardados exitosamente', {
          count: cves.length,
          filename,
          filePath,
          message: `Archivo guardado en: ${filePath}`
        });
      } else {
        // Respuesta normal sin descarga
        sendSuccess(res, 'CVEs obtenidos exitosamente', {
          count: cves.length,
          cves,
        });
      }
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

  /**
   * Genera un playbook de acción usando OpenAI
   * POST /vulnerabilities/generate-playbook
   */
  async generatePlaybook(req: Request, res: Response): Promise<void> {
    const startTime = Date.now();

    try {
      logger.info('Iniciando generación de playbook con OpenAI');

      // Validar configuración de OpenAI
      if (!this.openaiService.validateConfiguration()) {
        sendSuccess(res, 'OpenAI no está configurado correctamente', null, 400);
        return;
      }

      // Obtener archivo de CVEs (usar el más reciente por defecto)
      const { filePath } = req.body;
      const targetFile = filePath || getLatestCVEsFile();

      if (!targetFile) {
        sendSuccess(res, 'No se encontró archivo de CVEs. Ejecuta primero GET /vulnerabilities/cves?download=true', null, 404);
        return;
      }

      logger.info('Procesando archivo de CVEs', { filePath: targetFile });

      // Leer archivo de CVEs
      const fileData = readCVEsFile(targetFile);
      const cves = fileData.cves;

      if (cves.length === 0) {
        sendSuccess(res, 'No hay CVEs para procesar', null, 400);
        return;
      }

      // Dividir en chunks
      const chunkingResult = chunkCVEs(cves);
      logger.info('CVEs divididos en chunks', {
        totalCVEs: chunkingResult.totalCVEs,
        totalChunks: chunkingResult.totalChunks
      });

      // Procesar cada chunk con OpenAI
      const chunkResults: string[] = [];
      
      for (let i = 0; i < chunkingResult.chunks.length; i++) {
        const chunk = chunkingResult.chunks[i];
        logger.info(`Procesando chunk ${i + 1}/${chunkingResult.totalChunks}`);
        
        const chunkResult = await this.openaiService.processCVEChunk(
          chunk, 
          i, 
          chunkingResult.totalChunks
        );
        
        chunkResults.push(chunkResult);
        
        // Pausa más larga entre requests para evitar rate limiting
        if (i < chunkingResult.chunks.length - 1) {
          await new Promise(resolve => setTimeout(resolve, 3000)); // 3 segundos de pausa
        }
      }

      // Generar playbook final unificado
      logger.info('Iniciando generación del playbook final unificado');
      const playbook = await this.openaiService.generateFinalPlaybook(chunkResults);

      // Calcular duración
      const duration = Date.now() - startTime;

      logger.info('Playbook generado exitosamente', {
        duration: `${duration}ms`,
        totalCVEs: chunkingResult.totalCVEs,
        totalChunks: chunkingResult.totalChunks,
        threatAnalysisCount: playbook.Threat_Landscape_Analysis.length,
        remediationPhases: Object.keys(playbook.Strategic_Remediation_Plan).length
      });

      sendSuccess(res, 'Playbook generado exitosamente', {
        playbook,
        metadata: {
          sourceFile: targetFile,
          totalCVEs: chunkingResult.totalCVEs,
          totalChunks: chunkingResult.totalChunks,
          duration: `${duration}ms`,
          generatedAt: new Date().toISOString()
        }
      });

    } catch (error) {
      logger.error('Error al generar playbook', { error });
      throw error;
    }
  }

}

