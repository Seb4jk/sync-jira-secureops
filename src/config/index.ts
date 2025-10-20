/**
 * Configuración centralizada de la aplicación
 * Lee variables de entorno y exporta configuración validada
 */

import dotenv from 'dotenv';

// Cargar variables de entorno
dotenv.config();

/**
 * Configuración del servidor
 */
export const config = {
  // Server
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  apiVersion: process.env.API_VERSION || '1.0.0',

  // JWT
  jwt: {
    secret: process.env.JWT_SECRET || 'default-secret-change-in-production',
    expiresIn: (process.env.JWT_EXPIRES_IN || '24h') as string,
  },

  // Wazuh API
  wazuh: {
    apiUrl: process.env.WAZUH_API_URL || 'https://10.0.0.145:9200',
    apiUser: process.env.WAZUH_API_USER || 'monitoreo_agente',
    apiPassword: process.env.WAZUH_API_PASSWORD || 'Ramdon25$',
  },

  // Jira API
  jira: {
    apiUrl: process.env.JIRA_API_URL || 'https://your-domain.atlassian.net',
    apiEmail: process.env.JIRA_API_EMAIL || 'your-email@example.com',
    apiToken: process.env.JIRA_API_TOKEN || 'your-token',
    projectKey: process.env.JIRA_PROJECT_KEY || 'VULN',
  },

  // OpenAI API
  openai: {
    apiKey: process.env.OPENAI_API_KEY || '',
    model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
    maxTokens: parseInt(process.env.OPENAI_MAX_TOKENS || '4000', 10),
  },

  // CORS
  cors: {
    origin: process.env.CORS_ORIGIN || '*',
  },

  // Logging
  log: {
    level: process.env.LOG_LEVEL || 'debug',
  },
};

/**
 * Valida que las variables de entorno críticas estén configuradas
 */
export const validateConfig = (): void => {
  const requiredEnvVars = ['JWT_SECRET'];

  const missingVars = requiredEnvVars.filter((varName) => !process.env[varName]);

  if (missingVars.length > 0 && config.nodeEnv === 'production') {
    console.warn(
      `⚠️  Las siguientes variables de entorno no están configuradas: ${missingVars.join(', ')}`
    );
    console.warn('⚠️  Usando valores por defecto. Configúralas en producción.');
  }
};

