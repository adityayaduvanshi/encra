import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { UnauthorizedError } from '../errors.js'

declare global {
  namespace Express {
    interface Request {
      developerId: string
    }
  }
}

/**
 * Verifies the JWT Bearer token in Authorization header.
 * Populates `req.developerId` on success.
 * Throws `UnauthorizedError` on missing or invalid token.
 */
export function requireAuth(req: Request, _res: Response, next: NextFunction): void {
  const header = req.headers['authorization']
  if (!header || !header.startsWith('Bearer ')) {
    return next(new UnauthorizedError())
  }

  const token = header.slice(7)
  const secret = process.env['JWT_SECRET']
  if (!secret) {
    return next(new Error('Server misconfiguration: JWT_SECRET is not set.'))
  }

  try {
    const payload = jwt.verify(token, secret) as { developerId: string }
    if (!payload.developerId) {
      return next(new UnauthorizedError('Token payload missing developerId.'))
    }
    req.developerId = payload.developerId
    next()
  } catch {
    next(new UnauthorizedError('Token is invalid or expired.'))
  }
}
