/**
 * Servidor principal
 * Inicia la aplicación Express y maneja el ciclo de vida del servidor
 */

import { createApp } from './app';
import { config, validateConfig } from './config';
import { logger } from './utils/logger';

/**
 * Valida la configuración antes de iniciar
 */
validateConfig();

/**
 * Crear la aplicación
 */
const app = createApp();

/**
 * Iniciar el servidor
 */
const server = app.listen(config.port, () => {
  logger.info('🚀 Servidor iniciado exitosamente', {
    port: config.port,
    environment: config.nodeEnv,
    version: config.apiVersion,
  });
  logger.info(`📡 API disponible en: http://localhost:${config.port}`);
  logger.info(`🏥 Health check: http://localhost:${config.port}/health`);
});

/**
 * Manejo de señales de terminación
 */
const gracefulShutdown = (signal: string) => {
  logger.info(`${signal} recibido, cerrando servidor gracefully...`);

  server.close(() => {
    logger.info('Servidor cerrado correctamente');
    process.exit(0);
  });

  // Forzar cierre después de 10 segundos
  setTimeout(() => {
    logger.error('Forzando cierre del servidor');
    process.exit(1);
  }, 10000);
};

// Escuchar señales de terminación
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

/**
 * Manejo de errores no capturados
 */
process.on('uncaughtException', (error: Error) => {
  logger.error('Excepción no capturada', { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason: any) => {
  logger.error('Promise rechazada no manejada', { reason });
  process.exit(1);
});

export default server;

