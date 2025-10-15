/**
 * Tipos e interfaces principales de la aplicación
 */

import { Request } from 'express';

/**
 * Extensión del Request de Express para incluir datos del usuario autenticado
 */
export interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    iat: number;
    exp: number;
  };
}

/**
 * Estructura de respuesta estándar para la API
 */
export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  timestamp?: string;
}

/**
 * Payload del JWT
 */
export interface JwtPayload {
  id: string;
  email: string;
}

/**
 * CVE encontrado en Wazuh
 */
export interface CVE {
  id: string;
  cve: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  cvss: number;
  description: string;
  affectedServers: AffectedServer[];
  published?: string;
  modified?: string;
}

/**
 * Servidor afectado por un CVE
 */
export interface AffectedServer {
  id: string;
  name: string;
  hostname: string;
  ip: string;
  os: string;
  package?: string;
  version?: string;
}

/**
 * Tarea creada en Jira
 */
export interface JiraTask {
  id: string;
  key: string;
  summary: string;
  description: string;
  issueType: string;
  priority: string;
  status: string;
  created: string;
  subtasks?: JiraSubtask[];
}

/**
 * Subtarea de Jira para un servidor afectado
 */
export interface JiraSubtask {
  id: string;
  key: string;
  summary: string;
  parentKey: string;
  status: string;
}

/**
 * Resumen del proceso de sincronización
 */
export interface SyncSummary {
  cvesProcessed: number;
  tasksCreated: number;
  subtasksCreated: number;
  errors: number;
  duration: number;
  details: {
    cve: string;
    taskKey: string;
    subtasksCount: number;
    status: 'success' | 'failed';
    error?: string;
  }[];
}

/**
 * Credenciales de login
 */
export interface LoginCredentials {
  email: string;
  password: string;
}

/**
 * Respuesta del login
 */
export interface LoginResponse {
  token: string;
  expiresIn: string;
  user: {
    id: string;
    email: string;
  };
}

