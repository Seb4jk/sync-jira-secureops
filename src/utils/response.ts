/**
 * Utilidades para formatear respuestas HTTP
 * Proporciona respuestas consistentes en toda la API
 */

import { Response } from 'express';
import { ApiResponse } from '../types';

/**
 * Envía una respuesta exitosa
 */
export const sendSuccess = <T>(
  res: Response,
  message: string,
  data?: T,
  statusCode: number = 200
): Response => {
  const response: ApiResponse<T> = {
    success: true,
    message,
    data,
    timestamp: new Date().toISOString(),
  };

  return res.status(statusCode).json(response);
};

/**
 * Envía una respuesta de error
 */
export const sendError = (
  res: Response,
  message: string,
  error?: string,
  statusCode: number = 500
): Response => {
  const response: ApiResponse = {
    success: false,
    message,
    error,
    timestamp: new Date().toISOString(),
  };

  return res.status(statusCode).json(response);
};

