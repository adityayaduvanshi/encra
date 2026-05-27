import pino from 'pino'

/**
 * Structured JSON logger (pino).
 * Pretty-prints in development; emits JSON in production and test.
 *
 * LOG_LEVEL env var controls verbosity (trace / debug / info / warn / error / fatal).
 * Defaults to 'info' in production, 'warn' in test (to suppress noise).
 */

const isTest       = process.env['NODE_ENV'] === 'test'
const isDev        = process.env['NODE_ENV'] === 'development'
const defaultLevel = isTest ? 'warn' : 'info'

export const logger = pino(
  {
    level: process.env['LOG_LEVEL'] ?? defaultLevel,
    base: { pid: process.pid, service: 'encra-server' },
    timestamp: pino.stdTimeFunctions.isoTime,
  },
  isDev
    ? pino.transport({
        target: 'pino-pretty',
        options: { colorize: true, translateTime: 'HH:MM:ss', ignore: 'pid,hostname' },
      })
    : undefined,
)
