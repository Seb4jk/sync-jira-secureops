/**
 * Utilidades para procesamiento de archivos grandes
 */

import fs from 'fs';
import path from 'path';
import { CVE } from '../types';
import { logger } from './logger';

/**
 * Interfaz para datos de archivo JSON de CVEs
 */
interface CVEsFileData {
  timestamp: string;
  count: number;
  cves: CVE[];
}

/**
 * Configuración para chunking
 */
interface ChunkingConfig {
  maxCVEsPerChunk: number;
  maxTokensPerChunk: number;
}

/**
 * Resultado del chunking
 */
export interface ChunkingResult {
  chunks: CVE[][];
  totalChunks: number;
  totalCVEs: number;
  config: ChunkingConfig;
}

/**
 * Lee y parsea un archivo JSON de CVEs
 */
export function readCVEsFile(filePath: string): CVEsFileData {
  try {
    if (!fs.existsSync(filePath)) {
      throw new Error(`El archivo no existe: ${filePath}`);
    }

    const fileContent = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(fileContent) as CVEsFileData;

    if (!data.cves || !Array.isArray(data.cves)) {
      throw new Error('El archivo no contiene un array válido de CVEs');
    }

    logger.info('Archivo de CVEs leído exitosamente', {
      filePath,
      count: data.cves.length,
      timestamp: data.timestamp
    });

    return data;
  } catch (error) {
    logger.error('Error al leer archivo de CVEs', { filePath, error });
    throw new Error(`Error al leer archivo: ${error instanceof Error ? error.message : 'Error desconocido'}`);
  }
}

/**
 * Divide un array de CVEs en chunks para procesamiento
 */
export function chunkCVEs(cves: CVE[], config: ChunkingConfig = getDefaultChunkingConfig()): ChunkingResult {
  try {
    logger.info('Iniciando chunking de CVEs', {
      totalCVEs: cves.length,
      maxCVEsPerChunk: config.maxCVEsPerChunk
    });

    const chunks: CVE[][] = [];
    let currentChunk: CVE[] = [];
    let currentTokenCount = 0;

    for (const cve of cves) {
      // Estimar tokens del CVE (aproximación: 1 token ≈ 4 caracteres)
      const cveTokens = estimateCVETokens(cve);
      
      // Si agregar este CVE excedería los límites, crear nuevo chunk
      if (currentChunk.length >= config.maxCVEsPerChunk || 
          (currentTokenCount + cveTokens) > config.maxTokensPerChunk) {
        
        if (currentChunk.length > 0) {
          chunks.push([...currentChunk]);
          currentChunk = [];
          currentTokenCount = 0;
        }
      }

      currentChunk.push(cve);
      currentTokenCount += cveTokens;
    }

    // Agregar el último chunk si tiene elementos
    if (currentChunk.length > 0) {
      chunks.push(currentChunk);
    }

    const result: ChunkingResult = {
      chunks,
      totalChunks: chunks.length,
      totalCVEs: cves.length,
      config
    };

    logger.info('Chunking completado', {
      totalChunks: result.totalChunks,
      totalCVEs: result.totalCVEs,
      avgCVEsPerChunk: Math.round(result.totalCVEs / result.totalChunks)
    });

    return result;
  } catch (error) {
    logger.error('Error durante chunking de CVEs', { error });
    throw new Error(`Error durante chunking: ${error instanceof Error ? error.message : 'Error desconocido'}`);
  }
}

/**
 * Obtiene la configuración por defecto para chunking
 */
function getDefaultChunkingConfig(): ChunkingConfig {
  return {
    maxCVEsPerChunk: 20, // Reducido a 20 CVEs por chunk para evitar rate limiting
    maxTokensPerChunk: 2000, // Reducido a 2000 tokens por chunk
  };
}

/**
 * Estima el número de tokens que ocupará un CVE
 */
function estimateCVETokens(cve: CVE): number {
  const cveString = JSON.stringify(cve);
  // Aproximación: 1 token ≈ 4 caracteres
  return Math.ceil(cveString.length / 4);
}

/**
 * Lista archivos JSON de CVEs en el directorio downloads
 */
export function listCVEsFiles(): string[] {
  try {
    const downloadsDir = path.join(process.cwd(), 'downloads');
    
    if (!fs.existsSync(downloadsDir)) {
      logger.warn('Directorio downloads no existe');
      return [];
    }

    const files = fs.readdirSync(downloadsDir)
      .filter(file => file.endsWith('.json') && file.startsWith('cves-'))
      .map(file => path.join(downloadsDir, file))
      .sort((a, b) => {
        // Ordenar por fecha de modificación (más reciente primero)
        const statA = fs.statSync(a);
        const statB = fs.statSync(b);
        return statB.mtime.getTime() - statA.mtime.getTime();
      });

    logger.info('Archivos de CVEs encontrados', { count: files.length });
    return files;
  } catch (error) {
    logger.error('Error al listar archivos de CVEs', { error });
    return [];
  }
}

/**
 * Obtiene el archivo más reciente de CVEs
 */
export function getLatestCVEsFile(): string | null {
  const files = listCVEsFiles();
  return files.length > 0 ? files[0] : null;
}
