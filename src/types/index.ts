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

/**
 * Playbook de acción generado por OpenAI
 */
export interface PlaybookResponse {
  Executive_Summary: ExecutiveSummary;
  Threat_Landscape_Analysis: ThreatAnalysis[];
  Strategic_Remediation_Plan: RemediationPlan;
  Operational_Considerations: OperationalConsiderations;
  Risk_Mitigation: RiskMitigation;
}

/**
 * Resumen ejecutivo del playbook
 */
export interface ExecutiveSummary {
  Critical_Threats: string;
  Business_Impact: string;
  Remediation_Timeline: string;
}

/**
 * Análisis de amenazas específicas
 */
export interface ThreatAnalysis {
  CVE: string;
  Threat_Category: string;
  Attack_Vector: string;
  Business_Criticality: string;
  Exploit_Probability: string;
  Remediation_Complexity: string;
  Downtime_Required: string;
  Risk_Assessment: string;
}

/**
 * Plan estratégico de remediación
 */
export interface RemediationPlan {
  Phase_1_Immediate: RemediationPhase;
  Phase_2_Short_Term: RemediationPhase;
  Phase_3_Long_Term: RemediationPhase;
}

/**
 * Fase de remediación
 */
export interface RemediationPhase {
  Timeline: string;
  Actions: string[];
  Resources_Required?: string[];
  Success_Criteria?: string[];
  Dependencies?: string[];
  Rollback_Plan?: string[];
  Process_Improvements?: string[];
  Monitoring_Strategy?: string[];
}

/**
 * Consideraciones operacionales
 */
export interface OperationalConsiderations {
  Change_Management: string;
  Communication_Plan: string;
  Testing_Strategy: string;
  Documentation_Requirements: string;
}

/**
 * Mitigación de riesgos
 */
export interface RiskMitigation {
  Compensating_Controls: string[];
  Monitoring_Enhancements: string[];
  Incident_Response: string[];
  Business_Continuity: string[];
}

