import { Router, Request, Response, NextFunction } from 'express'
import { getPool } from '../db/pool.js'
import { requireAuth } from '../middleware/auth.js'
import { BadRequestError, NotFoundError } from '../errors.js'

const router = Router()

/**
 * POST /v1/keys
 * Register or update a user's public key.
 * Body: { userId: string, publicKey: string (base64) }
 */
router.post('/v1/keys', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId, publicKey } = req.body as { userId?: unknown; publicKey?: unknown }

    if (typeof userId !== 'string' || userId.trim().length === 0) {
      throw new BadRequestError('userId must be a non-empty string.')
    }
    if (typeof publicKey !== 'string' || publicKey.trim().length === 0) {
      throw new BadRequestError('publicKey must be a non-empty base64 string.')
    }

    const pool = getPool()
    await pool.query(
      `INSERT INTO public_keys (user_id, public_key)
       VALUES ($1, $2)
       ON CONFLICT (user_id) DO UPDATE SET public_key = EXCLUDED.public_key`,
      [userId.trim(), publicKey.trim()]
    )

    res.status(201).json({ userId: userId.trim() })
  } catch (err) {
    next(err)
  }
})

/**
 * GET /v1/keys/:userId
 * Fetch a user's public key.
 */
router.get('/v1/keys/:userId', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId } = req.params as { userId: string }
    const pool = getPool()
    const result = await pool.query<{ user_id: string; public_key: string }>(
      'SELECT user_id, public_key FROM public_keys WHERE user_id = $1',
      [userId]
    )

    if (result.rows.length === 0) {
      throw new NotFoundError(
        `Public key for user '${userId}' not found. Make sure ${userId} has registered before sending a message.`
      )
    }

    const row = result.rows[0]!
    res.json({ userId: row.user_id, publicKey: row.public_key })
  } catch (err) {
    next(err)
  }
})

export default router
