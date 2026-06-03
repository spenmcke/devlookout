import type { NextFunction, Request, RequestHandler, Response } from "express";

export function asyncHandler(handler: RequestHandler): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    error: {
      type: "NotFound",
      message: `No route for ${req.method} ${req.originalUrl}`
    }
  });
}

export function errorHandler(error: unknown, req: Request, res: Response, next: NextFunction): void {
  if (res.headersSent) {
    next(error);
    return;
  }

  const err = error instanceof Error ? error : new Error(String(error));
  res.status(500).json({
    error: {
      type: err.name,
      message: err.message
    },
    request: {
      method: req.method,
      path: req.originalUrl
    }
  });
}
