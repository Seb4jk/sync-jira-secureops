/**
 * Middleware de logging HTTP
 * Registra todas las peticiones HTTP usando Morgan
 */

import morgan from 'morgan';
import { morganStream } from '../utils/logger';

/**
 * Formato personalizado de Morgan para desarrollo
 */
const devFormat = ':method :url :status :response-time ms - :res[content-length]';

/**
 * Formato combinado para producción
 */
const prodFormat = 'combined';

/**
 * Configuración de Morgan según el entorno
 */
export const httpLogger = morgan(
  process.env.NODE_ENV === 'production' ? prodFormat : devFormat,
  {
    stream: morganStream,
    skip: (req) => {
      // Opcional: Skip health checks en producción para reducir logs
      return process.env.NODE_ENV === 'production' && req.url === '/health';
    },
  }
);

