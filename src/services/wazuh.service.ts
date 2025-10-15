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
 * Interfaz para la respuesta de Elasticsearch
 */
interface ElasticsearchHit {
  _index: string;
  _id: string;
  _score: number;
  _source: {
    agent: {
      id: string;
      name: string;
      type: string;
      version: string;
    };
    host: {
      os: {
        full: string;
        kernel: string;
        name: string;
        platform: string;
        type: string;
        version: string;
      };
    };
    package: {
      architecture: string;
      description: string;
      installed: string;
      name: string;
      size: number;
      type: string;
      version: string;
    };
    vulnerability: {
      category: string;
      classification: string;
      description: string;
      detected_at: string;
      enumeration: string;
      id: string;
      published_at: string;
      reference: string;
      scanner: {
        source: string;
        vendor: string;
      };
      score: {
        base: number;
        version: string;
      };
      severity: string;
      under_evaluation: boolean;
    };
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

      // Query para buscar vulnerabilidades High y Critical (exactamente como Postman)
      const query = {
        query: {
          bool: {
            should: [
              { match: { 'vulnerability.severity': 'High' } },
              { match: { 'vulnerability.severity': 'Critical' } }
            ],
            minimum_should_match: 1
          }
        }
      };

      logger.info('Enviando consulta a Elasticsearch', { 
        url: `${config.wazuh.apiUrl}/wazuh-states-vulnerabilities-*/_search?pretty`,
        query,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Basic ${Buffer.from(`${config.wazuh.apiUser}:${config.wazuh.apiPassword}`).toString('base64')}`
        }
      });

      // Hacer consulta a Elasticsearch
      const response = await queryInstance.post<ElasticsearchResponse>(
        `${config.wazuh.apiUrl}/wazuh-states-vulnerabilities-*/_search?pretty`,
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
      const cveId = source.vulnerability.id;

      // Si el CVE ya existe, agregar el servidor afectado
      if (cveMap.has(cveId)) {
        const existingCVE = cveMap.get(cveId)!;
        
        // Verificar si el servidor ya está en la lista
        const serverExists = existingCVE.affectedServers.some(
          (server) => server.id === source.agent.id && server.name === source.package.name
        );

        if (!serverExists) {
          existingCVE.affectedServers.push(this.mapToAffectedServer(source));
        }
      } else {
        // Crear nuevo CVE
        const cve: CVE = {
          id: cveId,
          cve: cveId,
          title: this.extractTitle(source.vulnerability.description),
          severity: this.normalizeSeverity(source.vulnerability.severity),
          cvss: source.vulnerability.score.base,
          description: source.vulnerability.description,
          published: source.vulnerability.published_at,
          modified: source.vulnerability.detected_at,
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
    return {
      id: source.agent.id,
      name: source.agent.name,
      hostname: source.agent.name,
      ip: 'N/A', // Elasticsearch no proporciona IP directamente
      os: source.host.os.full,
      package: source.package.name,
      version: source.package.version,
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
   * Extrae el título del CVE desde la descripción
   */
  private extractTitle(description: string): string {
    // Buscar la primera línea que parezca un título
    const lines = description.split('\n');
    
    // Buscar líneas con "Security Fix(es):" o similar
    const securityFixIndex = lines.findIndex((line) =>
      line.includes('Security Fix(es):')
    );

    if (securityFixIndex !== -1 && lines[securityFixIndex + 2]) {
      // La siguiente línea después de un espacio suele ser el título
      const titleLine = lines[securityFixIndex + 2].trim();
      // Remover asteriscos y limpiar
      return titleLine.replace(/^\*\s*/, '').split('(CVE-')[0].trim();
    }

    // Si no se encuentra un patrón, usar las primeras palabras
    const firstSentence = description.split('.')[0];
    return firstSentence.length > 100
      ? firstSentence.substring(0, 97) + '...'
      : firstSentence;
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

