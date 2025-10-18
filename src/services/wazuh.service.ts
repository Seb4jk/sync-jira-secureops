/**
 * Servicio de integración con Wazuh
 * Maneja la comunicación con Elasticsearch de Wazuh para obtener CVEs y vulnerabilidades
 */

import axios, { AxiosInstance } from 'axios';
import https from 'https';
import { config } from '../config';
import { CVE, AffectedServer } from '../types';
import { logger } from '../utils/logger';

/**
 * Interfaz para la respuesta de Elasticsearch del nuevo endpoint wazuh-alerts
 */
interface ElasticsearchHit {
  _index: string;
  _id: string;
  _score: number;
  _source: {
    cluster: {
      node: string;
      name: string;
    };
    agent: {
      ip: string;
      name: string;
      id: string;
    };
    manager: {
      name: string;
    };
    data: {
      vulnerability: {
        severity: string;
        package: {
          condition: string;
          name: string;
          source: string;
          version: string;
          architecture: string;
        };
        assigner: string;
        published: string;
        classification: string;
        title: string;
        type: string;
        rationale: string;
        reference: string;
        score: {
          version: string;
          base: string;
        };
        cve: string;
        scanner: {
          reference: string;
        };
        enumeration: string;
        cvss: {
          cvss3: {
            base_score: string;
            vector: {
              user_interaction: string;
              integrity_impact: string;
              scope: string;
              availability: string;
              confidentiality_impact: string;
              attack_vector: string;
              privileges_required: string;
            };
          };
        };
        updated: string;
        status: string;
      };
    };
    rule: {
      firedtimes: number;
      mail: boolean;
      level: number;
      pci_dss: string[];
      tsc: string[];
      description: string;
      groups: string[];
      id: string;
      gdpr: string[];
    };
    decoder: {
      name: string;
    };
    input: {
      type: string;
    };
    "@timestamp": string;
    location: string;
    id: string;
    timestamp: string;
  };
}

interface ElasticsearchResponse {
  took: number;
  timed_out: boolean;
  hits: {
    total: {
      value: number;
      relation: string;
    };
    max_score: number;
    hits: ElasticsearchHit[];
  };
}

/**
 * Servicio de Wazuh
 */
export class WazuhService {
  constructor() {
    // Ya no necesitamos una instancia persistente de axios
    // Cada método crea su propia instancia temporal
  }

  /**
   * Obtiene los CVEs desde Wazuh Elasticsearch
   * Consulta vulnerabilidades de severidad High y Critical
   */
  async getCVEs(): Promise<CVE[]> {
    try {
      logger.info('Obteniendo CVEs desde Wazuh Elasticsearch');

      // Crear una instancia temporal para la consulta (igual que en Postman)
      const queryInstance = this.createWazuhAxiosInstance();

      // Query específica para buscar vulnerabilidades High y Critical con filtros detallados
      const query = {
        size: 9000,
        query: {
          bool: {
            filter: [
              { match_all: {} },
              { match_phrase: { "cluster.name": "wazuh_cluster" } },
              { match_phrase: { "rule.groups": "vulnerability-detector" } },
              { match_phrase: { "data.vulnerability.status": "Active" } },
              {
                bool: {
                  should: [
                    { match_phrase: { "data.vulnerability.severity": "High" } },
                    { match_phrase: { "data.vulnerability.severity": "Critical" } }
                  ],
                  minimum_should_match: 1
                }
              },
              {
                range: {
                  "rule.level": {
                    gte: 12,
                    lt: 20
                  }
                }
              },
              {
                range: {
                  timestamp: {
                    gte: "now-1y",
                    lte: "now",
                    format: "strict_date_optional_time"
                  }
                }
              },
              { match_phrase: { "manager.name": "ip-10-0-0-145" } }
            ]
          }
        }
      };

      logger.info('Enviando consulta a Elasticsearch', { 
        url: `${config.wazuh.apiUrl}/wazuh-alerts-*/_search?pretty`,
        query,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Basic ${Buffer.from(`${config.wazuh.apiUser}:${config.wazuh.apiPassword}`).toString('base64')}`
        }
      });

      // Hacer consulta a Elasticsearch
      const response = await queryInstance.post<ElasticsearchResponse>(
        `${config.wazuh.apiUrl}/wazuh-alerts-*/_search?pretty`,
        query
      );

      logger.info('Respuesta de Elasticsearch recibida', {
        total: response.data.hits.total.value,
        hits: response.data.hits.hits.length,
        relation: response.data.hits.total.relation
      });

      // Agrupar vulnerabilidades por CVE
      const cveMap = this.groupVulnerabilitiesByCVE(response.data.hits.hits);

      // Convertir a array
      const cves = Array.from(cveMap.values());

      // DEBUG: Log completo de los CVEs procesados
      console.log('=== DATOS DE WAZUH PROCESADOS ===');
      console.log(JSON.stringify(cves, null, 2));
      console.log('================================');

      logger.info('CVEs procesados exitosamente', { 
        hitsOriginales: response.data.hits.hits.length,
        cvesUnicos: cves.length,
        diferencia: response.data.hits.hits.length - cves.length
      });

      return cves;
    } catch (error) {
      logger.error('Error al obtener CVEs desde Wazuh', { 
        error: error instanceof Error ? error.message : 'Error desconocido',
        status: error instanceof Error && 'response' in error ? (error as any).response?.status : 'N/A',
        statusText: error instanceof Error && 'response' in error ? (error as any).response?.statusText : 'N/A',
        data: error instanceof Error && 'response' in error ? (error as any).response?.data : 'N/A'
      });
      throw new Error(`Error al conectar con Wazuh Elasticsearch: ${error instanceof Error ? error.message : 'Error desconocido'}`);
    }
  }

  /**
   * Crea una instancia de axios configurada para Wazuh
   */
  private createWazuhAxiosInstance(): AxiosInstance {
    const httpsAgent = new https.Agent({
      rejectUnauthorized: false,
    });

    return axios.create({
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${Buffer.from(`${config.wazuh.apiUser}:${config.wazuh.apiPassword}`).toString('base64')}`,
      },
      httpsAgent,
    });
  }

  /**
   * Agrupa las vulnerabilidades por CVE ID y combina los servidores afectados
   */
  private groupVulnerabilitiesByCVE(hits: ElasticsearchHit[]): Map<string, CVE> {
    const cveMap = new Map<string, CVE>();

    for (const hit of hits) {
      const source = hit._source;
      const vulnerability = source.data.vulnerability;
      const cveId = vulnerability.cve;

      // Si el CVE ya existe, agregar el servidor afectado
      if (cveMap.has(cveId)) {
        const existingCVE = cveMap.get(cveId)!;
        
        // Verificar si el servidor ya está en la lista
        const serverExists = existingCVE.affectedServers.some(
          (server) => server.id === source.agent.id && server.package === vulnerability.package.name
        );

        if (!serverExists) {
          existingCVE.affectedServers.push(this.mapToAffectedServer(source));
        }
      } else {
        // Crear nuevo CVE
        const cve: CVE = {
          id: cveId,
          cve: cveId,
          title: this.extractTitle(vulnerability),
          severity: this.normalizeSeverity(vulnerability.severity),
          cvss: parseFloat(vulnerability.cvss.cvss3.base_score),
          description: this.buildDescription(vulnerability),
          published: vulnerability.published,
          modified: vulnerability.updated,
          affectedServers: [this.mapToAffectedServer(source)],
        };

        cveMap.set(cveId, cve);
      }
    }

    return cveMap;
  }

  /**
   * Mapea un hit de Elasticsearch a un servidor afectado
   */
  private mapToAffectedServer(source: ElasticsearchHit['_source']): AffectedServer {
    const vulnerability = source.data.vulnerability;
    
    return {
      id: source.agent.id,
      name: source.agent.name,
      hostname: source.agent.name,
      ip: source.agent.ip,
      os: vulnerability.package.architecture || 'Unknown', // Usar arquitectura como OS o 'Unknown' por defecto
      package: vulnerability.package.name,
      version: vulnerability.package.version,
    };
  }

  /**
   * Normaliza la severidad a los valores permitidos
   */
  private normalizeSeverity(severity: string): 'Critical' | 'High' | 'Medium' | 'Low' {
    const normalizedSeverity = severity.toLowerCase();
    switch (normalizedSeverity) {
      case 'critical':
        return 'Critical';
      case 'high':
        return 'High';
      case 'medium':
        return 'Medium';
      case 'low':
        return 'Low';
      default:
        return 'Medium'; // Por defecto
    }
  }

  /**
   * Construye la descripción del CVE usando la nueva estructura
   */
  private buildDescription(vulnerability: ElasticsearchHit['_source']['data']['vulnerability']): string {
    const parts = [];
    
    if (vulnerability.type) {
      parts.push(`Tipo: ${vulnerability.type}`);
    }
    
    if (vulnerability.rationale) {
      parts.push(`Descripción: ${vulnerability.rationale}`);
    }
    
    if (vulnerability.reference) {
      parts.push(`Referencias: ${vulnerability.reference}`);
    }
    
    if (vulnerability.package) {
      parts.push(`Paquete afectado: ${vulnerability.package.name} (${vulnerability.package.version})`);
    }
    
    return parts.join('\n\n');
  }

  /**
   * Extrae el título del CVE desde la nueva estructura
   */
  private extractTitle(vulnerability: ElasticsearchHit['_source']['data']['vulnerability']): string {
    // Usar directamente el título de la vulnerabilidad
    return vulnerability.title || vulnerability.cve;
  }


  /**
   * Obtiene detalles de un CVE específico
   */
  async getCVEDetails(cveId: string): Promise<CVE | null> {
    try {
      const cves = await this.getCVEs();
      return cves.find((cve) => cve.cve === cveId) || null;
    } catch (error) {
      logger.error('Error al obtener detalles del CVE', { cveId, error });
      throw error;
    }
  }

  /**
   * Obtiene servidores afectados por un CVE
   */
  async getAffectedServers(cveId: string): Promise<AffectedServer[]> {
    try {
      const cve = await this.getCVEDetails(cveId);
      return cve?.affectedServers || [];
    } catch (error) {
      logger.error('Error al obtener servidores afectados', { cveId, error });
      throw error;
    }
  }
}

