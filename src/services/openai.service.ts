/**
 * Servicio de integración con OpenAI
 * Procesa CVEs y genera playbooks de acción
 */

import OpenAI from 'openai';
import { config } from '../config';
import { CVE, PlaybookResponse } from '../types';
import { logger } from '../utils/logger';

/**
 * Servicio de OpenAI
 */
export class OpenAIService {
  private openai: OpenAI;

  constructor() {
    if (!config.openai.apiKey) {
      throw new Error('OPENAI_API_KEY no está configurado en las variables de entorno');
    }

    this.openai = new OpenAI({
      apiKey: config.openai.apiKey,
    });
  }

  /**
   * Procesa un chunk de CVEs y extrae información relevante
   */
  async processCVEChunk(cves: CVE[], chunkIndex: number, totalChunks: number): Promise<string> {
    try {
      logger.info(`Procesando chunk ${chunkIndex + 1}/${totalChunks} con ${cves.length} CVEs`);

      const prompt = this.buildChunkPrompt(cves, chunkIndex, totalChunks);

      const response = await this.openai.chat.completions.create({
        model: config.openai.model,
        messages: [
          {
            role: 'system',
            content: 'Eres un experto en ciberseguridad especializado en análisis de vulnerabilidades y creación de playbooks de remediación.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        max_tokens: Math.min(config.openai.maxTokens, 2000), // Reducir tokens para evitar rate limiting
        temperature: 0.3,
      });

      const result = response.choices[0]?.message?.content || '';
      logger.info(`Chunk ${chunkIndex + 1} procesado exitosamente`);
      
      return result;
    } catch (error) {
      logger.error(`Error al procesar chunk ${chunkIndex + 1}`, { error });
      
      // Manejar rate limiting específicamente
      if (error && typeof error === 'object' && 'status' in error && error.status === 429) {
        const rateLimitError = error as any;
        logger.warn('Rate limit alcanzado, generando chunk de fallback', {
          chunkIndex: chunkIndex + 1,
          rateLimitInfo: rateLimitError.error?.message
        });
        return this.generateChunkFallback(cves, chunkIndex, totalChunks);
      }
      
      throw new Error(`Error al procesar chunk ${chunkIndex + 1}: ${error instanceof Error ? error.message : 'Error desconocido'}`);
    }
  }

  /**
   * Genera el playbook final unificando todos los chunks procesados
   */
  async generateFinalPlaybook(chunkResults: string[]): Promise<PlaybookResponse> {
    try {
      logger.info('Generando playbook final unificado');

      const prompt = this.buildFinalPrompt(chunkResults);

      const response = await this.openai.chat.completions.create({
        model: config.openai.model,
        messages: [
          {
            role: 'system',
            content: 'Eres un experto en ciberseguridad especializado en análisis de vulnerabilidades y creación de playbooks de remediación. Responde ÚNICAMENTE en formato JSON válido.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        max_tokens: Math.min(config.openai.maxTokens, 3000), // Limitar tokens para evitar respuestas cortadas
        temperature: 0.2,
      });

      const result = response.choices[0]?.message?.content || '';
      
      // Intentar parsear el JSON
      try {
        // Limpiar la respuesta para extraer solo el JSON
        const cleanedResult = this.extractJSONFromResponse(result);
        const playbook = JSON.parse(cleanedResult) as PlaybookResponse;
        logger.info('Playbook final generado exitosamente');
        return playbook;
      } catch (parseError) {
        logger.error('Error al parsear respuesta JSON del playbook', { 
          parseError, 
          originalResult: result,
          cleanedResult: this.extractJSONFromResponse(result)
        });
        
        // Generar playbook de fallback
        logger.warn('Generando playbook de fallback debido a error de parsing');
        return this.generateFallbackPlaybook(chunkResults);
      }
    } catch (error) {
      logger.error('Error al generar playbook final', { error });
      throw new Error(`Error al generar playbook final: ${error instanceof Error ? error.message : 'Error desconocido'}`);
    }
  }

  /**
   * Construye el prompt para procesar un chunk de CVEs
   */
  private buildChunkPrompt(cves: CVE[], chunkIndex: number, totalChunks: number): string {
    // Crear un análisis detallado de cada CVE
    const cvesAnalysis = cves.map(cve => {
      const affectedPackages = [...new Set(cve.affectedServers.map(s => s.package).filter(Boolean))];
      const affectedServers = cve.affectedServers.length;
      const serverTypes = [...new Set(cve.affectedServers.map(s => s.os).filter(Boolean))];
      
      return {
        cve: cve.cve,
        severity: cve.severity,
        cvss: cve.cvss,
        title: cve.title,
        description: cve.description.substring(0, 300),
        affectedPackages: affectedPackages,
        affectedServersCount: affectedServers,
        serverTypes: serverTypes,
        published: cve.published,
        modified: cve.modified
      };
    });
    
    return `
Analiza estos CVEs críticos y de alta severidad (chunk ${chunkIndex + 1}/${totalChunks}):

${JSON.stringify(cvesAnalysis, null, 2)}

Para cada CVE, proporciona un análisis estratégico que incluya:

1. **IMPACTO REAL**: ¿Qué sistemas críticos están en riesgo? ¿Cuál es el impacto operacional?
2. **EXPLOTABILIDAD**: ¿Qué tan fácil es explotar esta vulnerabilidad? ¿Hay exploits públicos?
3. **DEPENDENCIAS**: ¿Qué servicios o aplicaciones dependen de estos paquetes vulnerables?
4. **VENTANA DE TIEMPO**: ¿Cuánto tiempo tenemos antes de que sea explotada?
5. **COMPLEJIDAD DE REMEDIACIÓN**: ¿Qué tan complejo es aplicar el parche? ¿Requiere downtime?
6. **RIESGO DE REGRESIÓN**: ¿Qué tan probable es que el parche cause problemas?

Responde con análisis narrativo y estratégico, no solo listas genéricas.
`;
  }

  /**
   * Genera un chunk de fallback cuando hay rate limiting
   */
  private generateChunkFallback(cves: CVE[], chunkIndex: number, totalChunks: number): string {
    logger.info(`Generando chunk de fallback ${chunkIndex + 1}/${totalChunks}`);
    
    const criticalCVEs = cves.filter(cve => cve.severity === 'Critical');
    const highCVEs = cves.filter(cve => cve.severity === 'High');
    
    return `
CHUNK ${chunkIndex + 1}/${totalChunks} - FALLBACK GENERADO

CVEs Críticos encontrados: ${criticalCVEs.length}
CVEs de Alta prioridad: ${highCVEs.length}
Total CVEs en chunk: ${cves.length}

CVEs Críticos:
${criticalCVEs.map(cve => `- ${cve.cve}: ${cve.title} (CVSS: ${cve.cvss})`).join('\n')}

CVEs de Alta prioridad:
${highCVEs.map(cve => `- ${cve.cve}: ${cve.title} (CVSS: ${cve.cvss})`).join('\n')}

Acciones recomendadas:
- Priorizar parches para CVEs críticos inmediatamente
- Aplicar actualizaciones de seguridad para paquetes afectados
- Verificar sistemas afectados y aplicar remediaciones
- Documentar todas las acciones tomadas

NOTA: Este chunk fue procesado con fallback debido a rate limiting de OpenAI.
`;
  }

  /**
   * Construye el prompt final para unificar todos los chunks
   */
  private buildFinalPrompt(chunkResults: string[]): string {
    const combinedResults = chunkResults.join('\n\n--- CHUNK SEPARATOR ---\n\n');
    
    return `
Basándote en el análisis estratégico de CVEs, genera un PLAYBOOK DE REMEDIACIÓN ESTRATÉGICO para el equipo de infraestructura y ciberseguridad.

Análisis previo:
${combinedResults}

Genera un JSON con esta estructura estratégica:

{
  "Executive_Summary": {
    "Critical_Threats": "Resumen narrativo de las amenazas más críticas y su impacto en la organización",
    "Business_Impact": "Análisis del impacto en operaciones críticas y servicios",
    "Remediation_Timeline": "Cronograma estratégico de remediación con justificación"
  },
  "Threat_Landscape_Analysis": [
    {
      "CVE": "CVE-2021-3773",
      "Threat_Category": "Network Infrastructure",
      "Attack_Vector": "Remote exploitation",
      "Business_Criticality": "High - Affects core network services",
      "Exploit_Probability": "Medium - Requires network access",
      "Remediation_Complexity": "Low - Standard package update",
      "Downtime_Required": "Minimal - Service restart only",
      "Risk_Assessment": "Narrative assessment of real-world risk"
    }
  ],
  "Strategic_Remediation_Plan": {
    "Phase_1_Immediate": {
      "Timeline": "0-24 hours",
      "Actions": ["Specific critical actions with business justification"],
      "Resources_Required": ["Specific teams and tools needed"],
      "Success_Criteria": ["Measurable outcomes"]
    },
    "Phase_2_Short_Term": {
      "Timeline": "1-7 days", 
      "Actions": ["Strategic actions with risk mitigation"],
      "Dependencies": ["What must be completed first"],
      "Rollback_Plan": ["How to revert if issues occur"]
    },
    "Phase_3_Long_Term": {
      "Timeline": "1-4 weeks",
      "Actions": ["Comprehensive security improvements"],
      "Process_Improvements": ["How to prevent similar issues"],
      "Monitoring_Strategy": ["Ongoing security monitoring approach"]
    }
  },
  "Operational_Considerations": {
    "Change_Management": "Specific change management requirements and approvals needed",
    "Communication_Plan": "Who needs to be notified and when",
    "Testing_Strategy": "How to validate fixes without breaking production",
    "Documentation_Requirements": "What needs to be documented for compliance"
  },
  "Risk_Mitigation": {
    "Compensating_Controls": ["Temporary security measures while patching"],
    "Monitoring_Enhancements": ["Additional monitoring during remediation"],
    "Incident_Response": ["What to do if exploitation is detected"],
    "Business_Continuity": ["How to maintain operations during patching"]
  }
}

IMPORTANTE: 
- Enfoque estratégico y narrativo, no genérico
- Análisis de impacto real en la organización
- Planes específicos con justificación de negocio
- Consideraciones operacionales prácticas
`;
  }

  /**
   * Valida que la API key esté configurada
   */
  validateConfiguration(): boolean {
    return !!config.openai.apiKey;
  }

  /**
   * Extrae JSON de la respuesta de OpenAI, removiendo texto adicional
   */
  private extractJSONFromResponse(response: string): string {
    try {
      // Buscar el primer { y el último } para extraer el JSON
      const firstBrace = response.indexOf('{');
      const lastBrace = response.lastIndexOf('}');
      
      if (firstBrace === -1 || lastBrace === -1 || firstBrace >= lastBrace) {
        throw new Error('No se encontró JSON válido en la respuesta');
      }
      
      const jsonString = response.substring(firstBrace, lastBrace + 1);
      
      // Intentar parsear el JSON
      try {
        JSON.parse(jsonString);
        return jsonString;
      } catch (parseError) {
        // Si el JSON está incompleto, intentar completarlo básicamente
        logger.warn('JSON incompleto detectado, intentando completar', { 
          jsonLength: jsonString.length,
          lastChars: jsonString.slice(-50)
        });
        
        // Buscar si falta cerrar arrays u objetos
        let openBraces = 0;
        let openBrackets = 0;
        let fixedJson = jsonString;
        
        for (let i = 0; i < jsonString.length; i++) {
          const char = jsonString[i];
          if (char === '{') openBraces++;
          if (char === '}') openBraces--;
          if (char === '[') openBrackets++;
          if (char === ']') openBrackets--;
        }
        
        // Cerrar arrays y objetos faltantes
        while (openBrackets > 0) {
          fixedJson += ']';
          openBrackets--;
        }
        while (openBraces > 0) {
          fixedJson += '}';
          openBraces--;
        }
        
        // Intentar parsear el JSON corregido
        try {
          JSON.parse(fixedJson);
          logger.info('JSON corregido exitosamente');
          return fixedJson;
        } catch (finalError) {
          throw new Error('No se pudo corregir el JSON incompleto');
        }
      }
    } catch (error) {
      logger.error('Error al extraer JSON de la respuesta', { 
        error, 
        response: response.substring(0, 500) + '...',
        responseLength: response.length
      });
      throw new Error('No se pudo extraer JSON válido de la respuesta');
    }
  }

  /**
   * Genera un playbook de fallback cuando OpenAI falla
   */
  private generateFallbackPlaybook(_chunkResults: string[]): PlaybookResponse {
    logger.info('Generando playbook de fallback');
    
    return {
      Executive_Summary: {
        Critical_Threats: "Análisis automático detectó múltiples vulnerabilidades críticas y de alta severidad que requieren atención inmediata. El procesamiento con OpenAI falló, pero se requiere acción rápida basada en los datos disponibles.",
        Business_Impact: "Las vulnerabilidades detectadas pueden afectar servicios críticos de red, sistemas operativos y aplicaciones. Se requiere evaluación manual inmediata para determinar el impacto específico en operaciones.",
        Remediation_Timeline: "Fase 1 (0-24h): Evaluación manual urgente. Fase 2 (1-7 días): Implementación de parches críticos. Fase 3 (1-4 semanas): Remediation completa y mejoras de proceso."
      },
      Threat_Landscape_Analysis: [
        {
          CVE: "CVE-FALLBACK-001",
          Threat_Category: "System Vulnerabilities",
          Attack_Vector: "Multiple vectors detected",
          Business_Criticality: "High - Requires immediate assessment",
          Exploit_Probability: "Unknown - Manual analysis required",
          Remediation_Complexity: "Variable - Depends on specific CVEs",
          Downtime_Required: "To be determined per CVE",
          Risk_Assessment: "Manual risk assessment required due to OpenAI processing failure. Immediate security team review recommended."
        }
      ],
      Strategic_Remediation_Plan: {
        Phase_1_Immediate: {
          Timeline: "0-24 hours",
          Actions: [
            "Conduct manual security assessment of all detected CVEs",
            "Prioritize Critical and High severity vulnerabilities",
            "Implement emergency compensating controls",
            "Notify security and infrastructure teams"
          ],
          Resources_Required: ["Security team", "Infrastructure team", "Vulnerability scanning tools"],
          Success_Criteria: ["All Critical CVEs assessed", "Emergency controls implemented", "Teams notified"]
        },
        Phase_2_Short_Term: {
          Timeline: "1-7 days",
          Actions: [
            "Apply patches for Critical vulnerabilities",
            "Implement patches for High severity vulnerabilities",
            "Test patches in non-production environment",
            "Document all remediation actions"
          ],
          Dependencies: ["Manual CVE analysis completed", "Patch availability confirmed"],
          Rollback_Plan: ["Maintain system snapshots", "Document rollback procedures", "Test rollback in staging"]
        },
        Phase_3_Long_Term: {
          Timeline: "1-4 weeks",
          Actions: [
            "Complete remediation of all Medium severity CVEs",
            "Implement automated vulnerability scanning",
            "Establish regular patch management process",
            "Conduct security awareness training"
          ],
          Process_Improvements: [
            "Implement automated CVE monitoring",
            "Establish regular security assessment schedule",
            "Create incident response procedures"
          ],
          Monitoring_Strategy: [
            "Continuous vulnerability scanning",
            "Regular security assessments",
            "Automated alerting for new CVEs"
          ]
        }
      },
      Operational_Considerations: {
        Change_Management: "All remediation actions must follow standard change management procedures. Emergency changes require expedited approval process.",
        Communication_Plan: "Notify stakeholders immediately about processing failure and manual assessment requirements. Provide regular updates on remediation progress.",
        Testing_Strategy: "Test all patches in isolated environment before production deployment. Validate system functionality after each patch application.",
        Documentation_Requirements: "Document all manual assessments, remediation actions, and lessons learned for future reference and compliance requirements."
      },
      Risk_Mitigation: {
        Compensating_Controls: [
          "Implement network segmentation",
          "Enhance monitoring and logging",
          "Apply temporary access restrictions",
          "Increase security awareness"
        ],
        Monitoring_Enhancements: [
          "Deploy additional security monitoring",
          "Implement real-time threat detection",
          "Enhance log analysis capabilities",
          "Set up automated alerts"
        ],
        Incident_Response: [
          "Activate incident response team",
          "Implement containment measures",
          "Preserve evidence for analysis",
          "Notify relevant stakeholders"
        ],
        Business_Continuity: [
          "Maintain critical services during remediation",
          "Implement backup systems",
          "Prepare communication plans",
          "Ensure minimal business disruption"
        ]
      }
    };
  }
}
