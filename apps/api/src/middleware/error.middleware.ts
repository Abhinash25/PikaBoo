import { Request, Response, NextFunction } from 'express';

export interface AppError extends Error {
  statusCode?: number;
  code?: string;
  details?: unknown;
}

export function errorHandler(err: AppError, req: Request, res: Response, _next: NextFunction) {
  const statusCode = err.statusCode || 500;
  const requestId = (req as any).requestId || 'unknown';

  const response = {
    success: false,
    error: {
      code: err.code || 'INTERNAL_SERVER_ERROR',
      message: statusCode === 500 && process.env.NODE_ENV === 'production'
        ? 'An internal server error occurred'
        : err.message,
      ...(err.details ? { details: err.details } : {}),
    },
    timestamp: new Date().toISOString(),
    requestId,
  };

  res.status(statusCode).json(response);
}
