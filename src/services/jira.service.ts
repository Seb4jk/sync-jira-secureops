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
   * Sincronización inteligente: actualiza tareas existentes o crea nuevas
   */
  async syncTaskWithSubtasks(cve: CVE): Promise<JiraTask> {
    try {
      logger.info('Iniciando sincronización inteligente', { cve: cve.cve });

      // Buscar si ya existe una tarea para este CVE
      const existingTask = await this.findTaskByCVE(cve.cve);

      if (existingTask) {
        logger.info('Tarea existente encontrada, procesando', { taskKey: existingTask.key, status: existingTask.status });
        
        // Verificar si la tarea está finalizada y necesita reactivación
        if (existingTask.status === 'Finalizada') {
          logger.info('Tarea finalizada detectada, reactivando', { taskKey: existingTask.key });
          await this.reactivateTask(existingTask.key, cve);
        } else {
          // Actualizar la tarea existente si no está finalizada
          await this.updateTask(existingTask.key, cve);
        }
        
        // Obtener subtareas existentes
        const existingSubtasks = await this.getSubtasks(existingTask.key);
        
        // Crear mapa de servidores actuales para comparación
        const currentServers = new Map();
        cve.affectedServers.forEach(server => {
          const key = `${server.name}-${server.package}`;
          currentServers.set(key, server);
        });

        // Crear mapa de subtareas existentes
        const existingSubtasksMap = new Map();
        existingSubtasks.forEach(subtask => {
          // Extraer servidor y paquete del título de la subtarea
          const match = subtask.summary.match(/Remediar (.+) - (.+)/);
          if (match) {
            const key = `${match[1]}-${match[2]}`;
            existingSubtasksMap.set(key, subtask);
          }
        });

        // Crear nuevas subtareas para servidores que no existen
        const newSubtasks: JiraSubtask[] = [];
        for (const [key, server] of currentServers) {
          if (!existingSubtasksMap.has(key)) {
            logger.info('Creando nueva subtarea para servidor', { server: server.name, package: server.package });
            const subtask = await this.createSubtask(existingTask, server);
            newSubtasks.push(subtask);
          }
        }

        // Manejar subtareas existentes
        for (const [key, subtask] of existingSubtasksMap) {
          if (!currentServers.has(key)) {
            // Finalizar subtarea que ya no tiene servidor correspondiente
            logger.info('Finalizando subtarea sin servidor correspondiente', { 
              subtaskKey: subtask.key, 
              subtaskSummary: subtask.summary,
              serverKey: key 
            });
            console.log(`🔴 FINALIZANDO SUBTAREA: ${subtask.key} - ${subtask.summary}`);
            try {
              await this.changeTaskStatus(subtask.key, 'Finalizada');
              await this.addComment(subtask.key, 'Issues remediado');
              console.log(`✅ SUBTAREA FINALIZADA: ${subtask.key}`);
            } catch (error) {
              console.log(`❌ ERROR AL FINALIZAR SUBTAREA: ${subtask.key}`, error);
              logger.error('Error al finalizar subtarea', { subtaskKey: subtask.key, error });
            }
          } else {
            // Reactivar subtarea si está finalizada pero el servidor sigue afectado
            if (subtask.status === 'Finalizada') {
              logger.info('Reactivando subtarea finalizada', { subtaskKey: subtask.key });
              try {
                await this.changeTaskStatus(subtask.key, 'To Do');
                await this.addComment(subtask.key, 'Subtarea reactivada');
                console.log(`✅ SUBTAREA REACTIVADA: ${subtask.key}`);
              } catch (error) {
                console.log(`❌ ERROR AL REACTIVAR SUBTAREA: ${subtask.key}`, error);
                logger.error('Error al reactivar subtarea', { subtaskKey: subtask.key, error });
              }
            }
          }
        }

        // Actualizar la referencia de la tarea
        const updatedTask = await this.findTaskByCVE(cve.cve);
        if (updatedTask) {
          updatedTask.subtasks = [...existingSubtasks, ...newSubtasks];
          return updatedTask;
        }
        
        return existingTask;
      } else {
        logger.info('No existe tarea, creando nueva', { cve: cve.cve });
        return await this.createTaskWithSubtasks(cve);
      }
    } catch (error) {
      logger.error('Error en sincronización inteligente', { cve: cve.cve, error });
      throw error;
    }
  }

  /**
   * Finaliza subtareas huérfanas que ya no tienen servidores correspondientes
   */
  async finalizeOrphanSubtasks(currentCVEs: CVE[]): Promise<void> {
    try {
      logger.info('Verificando subtareas huérfanas');

      // Crear mapa de todos los servidores actuales
      const currentServers = new Map();
      currentCVEs.forEach(cve => {
        cve.affectedServers.forEach(server => {
          const key = `${server.name}-${server.package}`;
          currentServers.set(key, { cve: cve.cve, server });
        });
      });

      // Obtener todas las tareas del proyecto
      const allTasks = await this.getAllTasks();

      // Verificar cada tarea existente
      for (const task of allTasks) {
        // Extraer CVE del título de la tarea
        const cveMatch = task.summary.match(/^(CVE-\d{4}-\d+|CVE-TEST-\d+)$/);
        if (cveMatch) {
          const cveId = cveMatch[1];
          
          // Solo procesar tareas que están en la lista actual de CVEs
          const currentCVE = currentCVEs.find(cve => cve.cve === cveId);
          if (currentCVE) {
            logger.info('Verificando subtareas huérfanas para CVE activo', { taskKey: task.key, cve: cveId });
            
            // Obtener subtareas de esta tarea
            const subtasks = await this.getSubtasks(task.key);
            
            // Verificar cada subtarea
            for (const subtask of subtasks) {
              // Extraer servidor y paquete del título de la subtarea
              const match = subtask.summary.match(/Remediar (.+) - (.+)/);
              if (match) {
                const serverKey = `${match[1]}-${match[2]}`;
                
                // Si la subtarea no tiene servidor correspondiente en la lista actual
                if (!currentServers.has(serverKey)) {
                  logger.info('Subtarea huérfana encontrada, finalizando', { 
                    subtaskKey: subtask.key, 
                    subtaskSummary: subtask.summary,
                    serverKey 
                  });
                  console.log(`🔴 FINALIZANDO SUBTAREA HUÉRFANA: ${subtask.key} - ${subtask.summary}`);
                  
                  try {
                    await this.changeTaskStatus(subtask.key, 'Finalizada');
                    await this.addComment(subtask.key, 'Issues remediado');
                    console.log(`✅ SUBTAREA HUÉRFANA FINALIZADA: ${subtask.key}`);
                  } catch (error) {
                    console.log(`❌ ERROR AL FINALIZAR SUBTAREA HUÉRFANA: ${subtask.key}`, error);
                    logger.error('Error al finalizar subtarea huérfana', { subtaskKey: subtask.key, error });
                  }
                }
              }
            }
          }
        }
      }
    } catch (error) {
      logger.error('Error al finalizar subtareas huérfanas', { error });
      throw error;
    }
  }

  /**
   * Finaliza tareas de CVEs que ya no existen
   */
  async finalizeDeletedCVEs(currentCVEs: CVE[]): Promise<void> {
    try {
      logger.info('Verificando CVEs eliminados');

      // Obtener todas las tareas del proyecto
      const allTasks = await this.getAllTasks();
      
      // Crear mapa de CVEs actuales
      const currentCVEsMap = new Map();
      currentCVEs.forEach(cve => {
        currentCVEsMap.set(cve.cve, cve);
      });

      console.log(`🔍 DEBUG: CVEs actuales: ${Array.from(currentCVEsMap.keys()).join(', ')}`);
      console.log(`🔍 DEBUG: Total tareas encontradas: ${allTasks.length}`);
      console.log(`🔍 DEBUG: Buscando CVEs con patrón: CVE-\\d{4}-\\d+ y CVE-TEST-\\d+`);

      // Verificar cada tarea existente
      for (const task of allTasks) {
        // Extraer CVE del título de la tarea
        const cveMatch = task.summary.match(/^(CVE-\d{4}-\d+|CVE-TEST-\d+)$/);
        if (cveMatch) {
          const cveId = cveMatch[1];
          console.log(`🔍 DEBUG: Verificando tarea ${task.key} con CVE ${cveId}`);
          
          if (!currentCVEsMap.has(cveId)) {
            logger.info('CVE eliminado encontrado, finalizando tarea', { taskKey: task.key, cve: cveId });
            console.log(`🔴 CVE ELIMINADO DETECTADO: ${cveId} → ${task.key}`);
            
            // Finalizar todas las subtareas primero
            const subtasks = await this.getSubtasks(task.key);
            for (const subtask of subtasks) {
              await this.changeTaskStatus(subtask.key, 'Finalizada');
              await this.addComment(subtask.key, 'Issues remediado');
            }
            
            // Finalizar la tarea principal
            await this.changeTaskStatus(task.key, 'Finalizada');
            await this.addComment(task.key, 'Issues remediado');
          } else {
            console.log(`ℹ️ CVE ACTIVO: ${cveId} → ${task.key} - No se finaliza`);
          }
        } else {
          console.log(`⚠️ TAREA SIN CVE VÁLIDO: ${task.key} - Summary: "${task.summary}"`);
        }
      }
    } catch (error) {
      logger.error('Error al finalizar CVEs eliminados', { error });
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
   * Busca tareas existentes por CVE
   */
  async findTaskByCVE(cve: string): Promise<JiraTask | null> {
    try {
      logger.info('Buscando tarea existente por CVE', { cve });
      
      const response = await this._axiosInstance.post('/search/jql', {
        jql: `project = ${config.jira.projectKey} AND summary ~ "${cve}" AND issuetype = "Tarea"`,
        maxResults: 1,
        fields: ['id', 'key', 'summary', 'description', 'status', 'priority', 'issuetype', 'created']
      });

      if (response.data.issues.length > 0) {
        const issue = response.data.issues[0];
        const task: JiraTask = {
          id: issue.id,
          key: issue.key,
          summary: issue.fields.summary,
          description: issue.fields.description,
          issueType: issue.fields.issuetype.name,
          priority: issue.fields.priority.name,
          status: issue.fields.status.name,
          created: issue.fields.created,
          subtasks: []
        };

        logger.info('Tarea existente encontrada', { taskKey: task.key, cve });
        return task;
      }

      logger.info('No se encontró tarea existente', { cve });
      return null;
    } catch (error) {
      logger.error('Error al buscar tarea por CVE', { cve, error });
      throw new AppError(`Error al buscar tarea por CVE ${cve}`, 500);
    }
  }

  /**
   * Obtiene todas las tareas del proyecto
   */
  async getAllTasks(): Promise<JiraTask[]> {
    try {
      logger.info('Obteniendo todas las tareas del proyecto');
      
      const response = await this._axiosInstance.post('/search/jql', {
        jql: `project = ${config.jira.projectKey} AND issuetype = "Tarea"`,
        maxResults: 1000,
        fields: ['id', 'key', 'summary', 'description', 'status', 'priority', 'issuetype', 'created']
      });

      const tasks: JiraTask[] = response.data.issues.map((issue: any) => ({
        id: issue.id,
        key: issue.key,
        summary: issue.fields.summary,
        description: issue.fields.description,
        issueType: issue.fields.issuetype.name,
        priority: issue.fields.priority.name,
        status: issue.fields.status.name,
        created: issue.fields.created,
        subtasks: []
      }));

      logger.info('Tareas obtenidas', { count: tasks.length });
      return tasks;
    } catch (error) {
      logger.error('Error al obtener todas las tareas', { error });
      throw new AppError('Error al obtener todas las tareas', 500);
    }
  }

  /**
   * Obtiene las subtareas de una tarea principal
   */
  async getSubtasks(parentTaskKey: string): Promise<JiraSubtask[]> {
    try {
      logger.info('Obteniendo subtareas', { parentTaskKey });
      
      const response = await this._axiosInstance.post('/search/jql', {
        jql: `parent = ${parentTaskKey}`,
        maxResults: 100,
        fields: ['id', 'key', 'summary', 'status', 'parent']
      });

      const subtasks: JiraSubtask[] = response.data.issues.map((issue: any) => ({
        id: issue.id,
        key: issue.key,
        summary: issue.fields.summary,
        parentKey: parentTaskKey,
        status: issue.fields.status.name
      }));

      logger.info('Subtareas obtenidas', { parentTaskKey, count: subtasks.length });
      return subtasks;
    } catch (error) {
      logger.error('Error al obtener subtareas', { parentTaskKey, error });
      throw new AppError(`Error al obtener subtareas de ${parentTaskKey}`, 500);
    }
  }

  /**
   * Actualiza una tarea existente
   */
  async updateTask(taskKey: string, cve: CVE): Promise<JiraTask> {
    try {
      logger.info('Actualizando tarea existente', { taskKey, cve: cve.cve });

      const updateData = {
        fields: {
          priority: { name: this.mapSeverityToPriority(cve.severity) },
          description: this.formatDescription(cve),
        }
      };

      const response = await this._axiosInstance.put(`/issue/${taskKey}`, updateData);

      const updatedTask: JiraTask = {
        id: response.data.id,
        key: response.data.key,
        summary: response.data.fields?.summary || 'N/A',
        description: response.data.fields?.description || 'N/A',
        issueType: response.data.fields?.issuetype?.name || 'N/A',
        priority: response.data.fields?.priority?.name || 'N/A',
        status: response.data.fields?.status?.name || 'N/A',
        created: response.data.fields?.created || 'N/A',
        subtasks: []
      };

      logger.info('Tarea actualizada exitosamente', { taskKey: updatedTask.key });
      return updatedTask;
    } catch (error) {
      logger.error('Error al actualizar tarea', { taskKey, error });
      throw new AppError(`Error al actualizar tarea ${taskKey}`, 500);
    }
  }

  /**
   * Reactiva una tarea finalizada
   */
  async reactivateTask(taskKey: string, cve: CVE): Promise<void> {
    try {
      logger.info('Reactivando tarea finalizada', { taskKey, cve: cve.cve });
      console.log(`🔄 REACTIVANDO TAREA: ${taskKey}`);

      // Obtener transiciones disponibles
      const transitionsResponse = await this._axiosInstance.get(`/issue/${taskKey}/transitions`);
      console.log(`📋 TRANSICIONES DISPONIBLES para ${taskKey}:`, transitionsResponse.data.transitions.map((t: any) => t.name));
      
      // Buscar transición para reactivar (To Do, Reopen, Reactivar)
      const reactivateTransition = transitionsResponse.data.transitions.find(
        (transition: any) => 
          transition.name === 'To Do' || 
          transition.name === 'Reopen' || 
          transition.name === 'Reactivar' ||
          transition.to.name === 'To Do'
      );

      if (reactivateTransition) {
        console.log(`✅ TRANSICIÓN DE REACTIVACIÓN ENCONTRADA: ${reactivateTransition.name} (ID: ${reactivateTransition.id})`);

        // Ejecutar la transición para reactivar
        await this._axiosInstance.post(`/issue/${taskKey}/transitions`, {
          transition: { id: reactivateTransition.id }
        });

        // Actualizar la tarea con nueva información
        await this.updateTask(taskKey, cve);

        // Agregar comentario de reactivación
        await this.addComment(taskKey, 'CVE reactivado');

        logger.info('Tarea reactivada exitosamente', { taskKey });
        console.log(`✅ TAREA REACTIVADA: ${taskKey}`);
      } else {
        logger.warn('No se encontró transición de reactivación', { taskKey });
        console.log(`❌ NO SE ENCONTRÓ TRANSICIÓN DE REACTIVACIÓN para ${taskKey}`);
        console.log(`📋 Transiciones disponibles:`, transitionsResponse.data.transitions.map((t: any) => `${t.name} (→ ${t.to.name})`));
      }
    } catch (error) {
      logger.error('Error al reactivar tarea', { taskKey, error });
      console.log(`❌ ERROR AL REACTIVAR TAREA: ${taskKey}`, error);
      throw new AppError(`Error al reactivar tarea ${taskKey}`, 500);
    }
  }

  /**
   * Agrega un comentario a una tarea o subtarea
   */
  async addComment(taskKey: string, commentType: string): Promise<void> {
    try {
      const currentDateTime = new Date().toLocaleString('es-ES', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZone: 'America/Santiago'
      });

      let commentText = '';
      if (commentType === 'Issues remediado') {
        commentText = `Issues remediado: ${currentDateTime}`;
      } else if (commentType === 'CVE reactivado') {
        commentText = `CVE reactivado: ${currentDateTime}`;
      } else if (commentType === 'Subtarea reactivada') {
        commentText = `Subtarea reactivada: ${currentDateTime}`;
      } else {
        commentText = `${commentType}: ${currentDateTime}`;
      }

      await this._axiosInstance.post(`/issue/${taskKey}/comment`, {
        body: {
          type: 'doc',
          version: 1,
          content: [
            {
              type: 'paragraph',
              content: [
                {
                  type: 'text',
                  text: commentText,
                  marks: [{ type: 'strong' }]
                }
              ]
            }
          ]
        }
      });

      logger.info('Comentario agregado exitosamente', { taskKey, commentType });
    } catch (error) {
      logger.error('Error al agregar comentario', { taskKey, commentType, error });
      throw new AppError(`Error al agregar comentario a ${taskKey}`, 500);
    }
  }

  /**
   * Cambia el estado de una tarea o subtarea
   */
  async changeTaskStatus(taskKey: string, statusName: string): Promise<void> {
    try {
      logger.info('Cambiando estado de tarea', { taskKey, statusName });
      console.log(`🔄 CAMBIANDO ESTADO: ${taskKey} → ${statusName}`);

      // Primero obtener las transiciones disponibles
      const transitionsResponse = await this._axiosInstance.get(`/issue/${taskKey}/transitions`);
      console.log(`📋 TRANSICIONES DISPONIBLES para ${taskKey}:`, transitionsResponse.data.transitions.map((t: any) => t.name));
      
      // Buscar la transición que lleve al estado deseado
      const targetTransition = transitionsResponse.data.transitions.find(
        (transition: any) => transition.name === statusName || transition.to.name === statusName
      );

      if (!targetTransition) {
        logger.warn('No se encontró transición para el estado', { taskKey, statusName });
        console.log(`❌ NO SE ENCONTRÓ TRANSICIÓN: ${taskKey} → ${statusName}`);
        console.log(`📋 Transiciones disponibles:`, transitionsResponse.data.transitions.map((t: any) => `${t.name} (→ ${t.to.name})`));
        return;
      }

      console.log(`✅ TRANSICIÓN ENCONTRADA: ${targetTransition.name} (ID: ${targetTransition.id})`);

      // Ejecutar la transición
      await this._axiosInstance.post(`/issue/${taskKey}/transitions`, {
        transition: { id: targetTransition.id }
      });

      logger.info('Estado cambiado exitosamente', { taskKey, statusName });
      console.log(`✅ ESTADO CAMBIADO: ${taskKey} → ${statusName}`);
    } catch (error) {
      logger.error('Error al cambiar estado de tarea', { taskKey, statusName, error });
      console.log(`❌ ERROR AL CAMBIAR ESTADO: ${taskKey} → ${statusName}`, error);
      throw new AppError(`Error al cambiar estado de tarea ${taskKey}`, 500);
    }
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

