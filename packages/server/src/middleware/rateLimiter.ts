import rateLimit from 'express-rate-limit'

/** Skip rate limiting entirely in test environment to keep tests fast and deterministic. */
const skipInTest = () => process.env['NODE_ENV'] === 'test'

/**
 * Global limiter — applied to every HTTP endpoint.
 * 200 requests / minute per IP.  Exceeding returns 429 with Retry-After header.
 */
export const globalLimiter = rateLimit({
  windowMs:       60_000,
  max:            200,
  standardHeaders: 'draft-7',
  legacyHeaders:  false,
  skip:           skipInTest,
  message:        { error: 'Too many requests, please slow down.' },
})

/**
 * Key-registration limiter — applied only to POST /v1/keys.
 * 20 registrations / minute per IP prevents enumeration and key flooding.
 */
export const keyRegistrationLimiter = rateLimit({
  windowMs:       60_000,
  max:            20,
  standardHeaders: 'draft-7',
  legacyHeaders:  false,
  skip:           skipInTest,
  message:        { error: 'Too many key registration requests, please try again later.' },
})
