/**
 * Servicio de integración con Jira
 * Maneja la creación de tareas y subtareas en Jira
 */

import axios, { AxiosInstance } from 'axios';
import { config } from '../config';
import { CVE, JiraTask, JiraSubtask, AffectedServer } from '../types';
import { AppError } from '../middlewares/error.middleware';
import { logger } from '../utils/logger';

/**
 * Servicio de Jira
 */
export class JiraService {
  private _axiosInstance: AxiosInstance;

  constructor() {
    // Configurar instancia de axios para Jira
    this._axiosInstance = axios.create({
      baseURL: `${config.jira.apiUrl}/rest/api/3`,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        // Autenticación básica manual
        'Authorization': `Basic ${Buffer.from(`${config.jira.apiEmail}:${config.jira.apiToken}`).toString('base64')}`,
      },
    });
  }

  /**
   * Mapea la severidad del CVE a la prioridad de Jira
   */
  private mapSeverityToPriority(severity: string): string {
    const priorityMap: Record<string, string> = {
      Critical: 'Highest',
      High: 'High',
      Medium: 'Medium',
      Low: 'Low',
    };
    return priorityMap[severity] || 'Medium';
  }

  /**
   * Verifica la configuración de Jira (método temporal para debugging)
   */
  async checkConfiguration(): Promise<any> {
    return {
      apiUrl: config.jira.apiUrl,
      projectKey: config.jira.projectKey,
      apiEmail: config.jira.apiEmail,
      hasToken: !!config.jira.apiToken,
      tokenLength: config.jira.apiToken?.length || 0
    };
  }

  /**
   * Obtiene los tipos de issue disponibles en el proyecto
   */
  async getIssueTypes(): Promise<any> {
    try {
      const response = await this._axiosInstance.get(`/project/${config.jira.projectKey}`);
      return response.data.issueTypes;
    } catch (error) {
      logger.error('Error al obtener tipos de issue', { error });
      throw new AppError('Error al obtener tipos de issue', 500);
    }
  }

  /**
   * Crea una tarea en Jira para un CVE
   */
  async createTask(cve: CVE): Promise<JiraTask> {
    try {
      logger.info('Creando tarea en Jira', { cve: cve.cve });

      const taskData = {
        fields: {
          project: { key: config.jira.projectKey },
          summary: cve.cve,
          issuetype: { name: 'Tarea' },
          priority: { name: this.mapSeverityToPriority(cve.severity) },
          description: this.formatDescription(cve),
        },
      };

      logger.info('Datos de la tarea a enviar a Jira', { 
        cve: cve.cve, 
        taskData,
        config: {
          apiUrl: config.jira.apiUrl,
          projectKey: config.jira.projectKey,
          apiEmail: config.jira.apiEmail
        }
      });

      // Crear tarea real en Jira
      const response = await this._axiosInstance.post('/issue', taskData);

      // DEBUG: Log de la respuesta de Jira
      console.log('=== RESPUESTA DE JIRA ===');
      console.log(JSON.stringify(response.data, null, 2));
      console.log('========================');

      // Tarea real de Jira
      const jiraTask: JiraTask = {
        id: response.data.id,
        key: response.data.key,
        summary: response.data.fields?.summary || 'N/A',
        description: response.data.fields?.description || 'N/A',
        issueType: response.data.fields?.issuetype?.name || 'N/A',
        priority: response.data.fields?.priority?.name || 'N/A',
        status: response.data.fields?.status?.name || 'N/A',
        created: response.data.fields?.created || 'N/A',
        subtasks: [],
      };

      logger.info('Tarea creada exitosamente en Jira', { taskKey: jiraTask.key, cve: cve.cve });

      return jiraTask;
    } catch (error) {
      // DEBUG: Log detallado del error
      console.log('=== ERROR AL CREAR TAREA ===');
      console.log('Error:', error);
      if (error instanceof Error && 'response' in error) {
        console.log('Response status:', (error as any).response?.status);
        console.log('Response data:', (error as any).response?.data);
      }
      console.log('============================');

      logger.error('Error al crear tarea en Jira', { 
        cve: cve.cve, 
        error: error instanceof Error ? error.message : 'Error desconocido',
        status: error instanceof Error && 'response' in error ? (error as any).response?.status : 'N/A',
        statusText: error instanceof Error && 'response' in error ? (error as any).response?.statusText : 'N/A',
        data: error instanceof Error && 'response' in error ? (error as any).response?.data : 'N/A'
      });
      throw new AppError(`Error al crear tarea en Jira para ${cve.cve}`, 500);
    }
  }

  /**
   * Crea una subtarea en Jira para un servidor afectado
   */
  async createSubtask(
    parentTask: JiraTask,
    server: AffectedServer
  ): Promise<JiraSubtask> {
    try {
      logger.info('Creando subtarea en Jira', {
        parentKey: parentTask.key,
        parentId: parentTask.id,
        server: server.name,
        hostname: server.hostname,
      });

      const subtaskData = {
        fields: {
          project: { key: config.jira.projectKey },
          parent: { key: parentTask.key },
          summary: `Remediar ${server.name} - ${server.package}`,
          issuetype: { name: 'Subtarea' },
          description: this._formatServerDescription(server),
        },
      };

      logger.info('Datos de la subtarea a enviar a Jira', { 
        parentKey: parentTask.key,
        subtaskData 
      });

      // Crear subtarea real en Jira
      const response = await this._axiosInstance.post('/issue', subtaskData);

      // DEBUG: Log de la respuesta de Jira para subtarea
      console.log('=== RESPUESTA DE JIRA SUBTAREA ===');
      console.log(JSON.stringify(response.data, null, 2));
      console.log('===================================');

      // Subtarea real de Jira
      const jiraSubtask: JiraSubtask = {
        id: response.data.id,
        key: response.data.key,
        summary: response.data.fields?.summary || 'N/A',
        parentKey: parentTask.key,
        status: response.data.fields?.status?.name || 'N/A',
      };

      logger.info('Subtarea creada exitosamente en Jira', { subtaskKey: jiraSubtask.key });

      return jiraSubtask;
    } catch (error) {
      // DEBUG: Log detallado del error de subtarea
      console.log('=== ERROR AL CREAR SUBTAREA ===');
      console.log('Error:', error);
      if (error instanceof Error && 'response' in error) {
        console.log('Response status:', (error as any).response?.status);
        console.log('Response data:', (error as any).response?.data);
      }
      console.log('================================');

      logger.error('Error al crear subtarea en Jira', {
        parentKey: parentTask.key,
        server: server.name,
        error: error instanceof Error ? error.message : 'Error desconocido',
        status: error instanceof Error && 'response' in error ? (error as any).response?.status : 'N/A',
        statusText: error instanceof Error && 'response' in error ? (error as any).response?.statusText : 'N/A',
        data: error instanceof Error && 'response' in error ? (error as any).response?.data : 'N/A'
      });
      throw new AppError(`Error al crear subtarea para ${server.name}`, 500);
    }
  }

  /**
   * Crea una tarea con todas sus subtareas
   */
  async createTaskWithSubtasks(cve: CVE): Promise<JiraTask> {
    try {

      // Crear la tarea principal
      const task = await this.createTask(cve);

      // Crear subtareas para cada servidor afectado
      const subtasks: JiraSubtask[] = [];
      for (const server of cve.affectedServers) {
        console.log(`\n--- Procesando servidor: ${server.name} (${server.hostname}) ---`);
        const subtask = await this.createSubtask(task, server);
        subtasks.push(subtask);
      }

      task.subtasks = subtasks;

      logger.info('Tarea con subtareas creada exitosamente', {
        taskKey: task.key,
        subtasksCount: subtasks.length,
      });

      return task;
    } catch (error) {
      logger.error('Error al crear tarea con subtareas', { cve: cve.cve, error });
      throw error;
    }
  }

  /**
   * Formatea la descripción del CVE para Jira en formato Atlassian Document Format (ADF)
   */
  private formatDescription(cve: CVE): any {
    return {
      type: 'doc',
      version: 1,
      content: [
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'CVE: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: cve.cve }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'Severidad: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: cve.severity }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'CVSS: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: cve.cvss.toString() }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'Descripción:', marks: [{ type: 'strong' }] }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: cve.description }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'Servidores Afectados: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: cve.affectedServers.length.toString() }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'Publicado: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: cve.published || 'N/A' }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'Modificado: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: cve.modified || 'N/A' }
          ]
        }
      ]
    };
  }

  /**
   * Formatea la descripción del servidor para la subtarea en formato Atlassian Document Format (ADF)
   */
  private _formatServerDescription(server: AffectedServer): any {
    return {
      type: 'doc',
      version: 1,
      content: [
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'Servidor: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: server.name }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'Hostname: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: server.hostname }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'IP: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: server.ip }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'SO: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: server.os }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'Paquete: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: server.package || 'N/A' }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'Versión: ', marks: [{ type: 'strong' }] },
            { type: 'text', text: server.version || 'N/A' }
          ]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'Actualizar o parchear el paquete afectado en este servidor.' }
          ]
        }
      ]
    };
  }

  /**
   * Obtiene el estado de una tarea
   */
  async getTaskStatus(taskKey: string): Promise<string> {
    try {
      // Simulación (en producción, hacer llamada real)
      // const response = await this._axiosInstance.get(`/issue/${taskKey}`);
      // return response.data.fields.status.name;

      return 'To Do';
    } catch (error) {
      logger.error('Error al obtener estado de tarea', { taskKey, error });
      throw new AppError(`Error al obtener estado de tarea ${taskKey}`, 500);
    }
  }
}

