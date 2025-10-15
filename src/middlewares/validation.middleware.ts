/**
 * Middleware de validación de datos
 * Valida el body, params y query de las peticiones
 */

import { Request, Response, NextFunction } from 'express';
import { AppError } from './error.middleware';

/**
 * Valida que el body de la petición tenga los campos requeridos
 */
export const validateBody = (requiredFields: string[]) => {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const missingFields = requiredFields.filter((field) => !(field in req.body));

    if (missingFields.length > 0) {
      throw new AppError(
        `Campos requeridos faltantes: ${missingFields.join(', ')}`,
        400
      );
    }

    next();
  };
};

/**
 * Valida formato de email
 */
export const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Valida credenciales de login
 */
export const validateLoginCredentials = (
  req: Request,
  _res: Response,
  next: NextFunction
): void => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new AppError('Email y contraseña son requeridos', 400);
  }

  if (!validateEmail(email)) {
    throw new AppError('Formato de email inválido', 400);
  }

  if (password.length < 6) {
    throw new AppError('La contraseña debe tener al menos 6 caracteres', 400);
  }

  next();
};

