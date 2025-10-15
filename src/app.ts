/**
 * Aplicación Express principal
 * Configura middlewares, rutas y manejo de errores
 */

import express, { Application } from 'express';
import cors from 'cors';
import { config } from './config';
import { httpLogger } from './middlewares/logger.middleware';
import { errorHandler, notFoundHandler } from './middlewares/error.middleware';
import routes from './routes';
import { logger } from './utils/logger';

/**
 * Crea y configura la aplicación Express
 */
export const createApp = (): Application => {
  const app: Application = express();

  // Middlewares globales
  app.use(cors({ origin: config.cors.origin }));
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(httpLogger);

  // Log de inicio
  logger.info('Inicializando aplicación', {
    environment: config.nodeEnv,
    version: config.apiVersion,
  });

  // Rutas principales
  app.use('/', routes);

  // Manejo de rutas no encontradas (404)
  app.use(notFoundHandler);

  // Middleware global de manejo de errores (debe ser el último)
  app.use(errorHandler);

  return app;
};

