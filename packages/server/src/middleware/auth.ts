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
 * Build VerifyOptions from environment variables.
 * Algorithm is always pinned to HS256.
 * JWT_ISSUER and JWT_AUDIENCE are optional — when set, tokens must match.
 */
function buildVerifyOptions(): jwt.VerifyOptions {
  const options: jwt.VerifyOptions = { algorithms: ['HS256'] }
  if (process.env['JWT_ISSUER'])   options.issuer   = process.env['JWT_ISSUER']
  if (process.env['JWT_AUDIENCE']) options.audience = process.env['JWT_AUDIENCE']
  return options
}

/**
 * Verifies the JWT Bearer token in Authorization header.
 * Populates `req.developerId` on success.
 * Throws `UnauthorizedError` on missing or invalid token.
 *
 * Requirements:
 *  - Algorithm pinned to HS256 (prevents alg:none / confusion attacks)
 *  - Token must contain `developerId` claim
 *  - Token must contain `exp` claim (non-expiring tokens are rejected)
 *  - Optional: JWT_ISSUER / JWT_AUDIENCE env vars enforce iss/aud claims
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
    const payload = jwt.verify(token, secret, buildVerifyOptions()) as jwt.JwtPayload
    if (!payload['developerId']) {
      return next(new UnauthorizedError('Token payload missing developerId.'))
    }
    if (!payload['exp']) {
      return next(new UnauthorizedError('Token must include an expiration (exp) claim.'))
    }
    req.developerId = payload['developerId'] as string
    next()
  } catch {
    next(new UnauthorizedError('Token is invalid or expired.'))
  }
}

/** Exported for use by the WebSocket relay. */
export { buildVerifyOptions }
