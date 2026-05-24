import { Router, Request, Response, NextFunction } from 'express'
import { getPool } from '../db/pool.js'
import { requireAuth } from '../middleware/auth.js'
import { BadRequestError, NotFoundError } from '../errors.js'

const router = Router()

/**
 * POST /v1/keys
 * Register or update a device's public key.
 * Body: { userId: string, publicKey: string (base64), deviceId?: string }
 *
 * Each device registers independently. Multiple devices for the same userId
 * are all stored and returned by GET /v1/keys/:userId.
 */
router.post('/v1/keys', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId, publicKey, deviceId = 'default' } = req.body as {
      userId?:   unknown
      publicKey?: unknown
      deviceId?:  unknown
    }

    if (typeof userId !== 'string' || userId.trim().length === 0) {
      throw new BadRequestError('userId must be a non-empty string.')
    }
    if (typeof publicKey !== 'string' || publicKey.trim().length === 0) {
      throw new BadRequestError('publicKey must be a non-empty base64 string.')
    }
    if (typeof deviceId !== 'string' || (deviceId as string).trim().length === 0) {
      throw new BadRequestError('deviceId must be a non-empty string.')
    }

    const pool = getPool()
    await pool.query(
      `INSERT INTO public_keys (user_id, device_id, public_key)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, device_id) DO UPDATE SET public_key = EXCLUDED.public_key`,
      [userId.trim(), (deviceId as string).trim(), publicKey.trim()]
    )

    res.status(201).json({ userId: userId.trim(), deviceId: (deviceId as string).trim() })
  } catch (err) {
    next(err)
  }
})

/**
 * GET /v1/keys/:userId
 * Fetch all public keys for a user (one per registered device).
 * Returns: { userId, devices: [{ deviceId, publicKey }] }
 */
router.get('/v1/keys/:userId', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId } = req.params as { userId: string }
    const pool = getPool()
    const result = await pool.query<{ device_id: string; public_key: string }>(
      `SELECT device_id, public_key
       FROM   public_keys
       WHERE  user_id = $1
       ORDER  BY device_id`,
      [userId]
    )

    if (result.rows.length === 0) {
      throw new NotFoundError(
        `No keys found for user '${userId}'. Make sure ${userId} has registered before sending.`
      )
    }

    res.json({
      userId,
      devices: result.rows.map((row) => ({
        deviceId:  row.device_id,
        publicKey: row.public_key,
      })),
    })
  } catch (err) {
    next(err)
  }
})

export default router
