import { Router, Request, Response, NextFunction } from 'express'
import { getPool } from '../db/pool.js'
import { requireAuth } from '../middleware/auth.js'
import { BadRequestError, NotFoundError } from '../errors.js'

const router = Router()

/** Hard cap on how many one-time prekeys a single request may upload. */
const MAX_ONE_TIME_PREKEYS = 200

interface SignedPreKeyInput {
  keyId?:     unknown
  publicKey?: unknown
  signature?: unknown
}

interface OneTimePreKeyInput {
  keyId?:     unknown
  publicKey?: unknown
}

function nonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.trim().length > 0
}

/**
 * POST /v1/prekeys
 * Publish (or replenish) a device's X3DH prekey material.
 *
 * Body: {
 *   userId, deviceId,
 *   identityKey: string (base64 Ed25519 public),
 *   signedPreKey: { keyId, publicKey, signature },
 *   oneTimePreKeys?: [{ keyId, publicKey }]
 * }
 *
 * Identity key and signed prekey are upserted (latest wins). One-time prekeys
 * are appended to the device's pool. Returns the resulting pool size.
 */
router.post('/v1/prekeys', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const {
      userId,
      deviceId = 'default',
      identityKey,
      signedPreKey,
      oneTimePreKeys = [],
    } = req.body as {
      userId?:         unknown
      deviceId?:       unknown
      identityKey?:    unknown
      signedPreKey?:   SignedPreKeyInput
      oneTimePreKeys?: OneTimePreKeyInput[]
    }

    if (!nonEmptyString(userId))      throw new BadRequestError('userId must be a non-empty string.')
    if (!nonEmptyString(deviceId))    throw new BadRequestError('deviceId must be a non-empty string.')
    if (!nonEmptyString(identityKey)) throw new BadRequestError('identityKey must be a non-empty base64 string.')

    if (
      !signedPreKey ||
      typeof signedPreKey.keyId !== 'number' ||
      !nonEmptyString(signedPreKey.publicKey) ||
      !nonEmptyString(signedPreKey.signature)
    ) {
      throw new BadRequestError('signedPreKey requires numeric keyId and non-empty publicKey and signature.')
    }

    if (!Array.isArray(oneTimePreKeys)) {
      throw new BadRequestError('oneTimePreKeys must be an array.')
    }
    if (oneTimePreKeys.length > MAX_ONE_TIME_PREKEYS) {
      throw new BadRequestError(`Too many one-time prekeys (max ${MAX_ONE_TIME_PREKEYS} per request).`)
    }
    for (const otp of oneTimePreKeys) {
      if (typeof otp.keyId !== 'number' || !nonEmptyString(otp.publicKey)) {
        throw new BadRequestError('Each one-time prekey requires a numeric keyId and non-empty publicKey.')
      }
    }

    const uid = userId.trim()
    const did = deviceId.trim()
    const pool = getPool()

    await pool.query(
      `INSERT INTO identity_keys (user_id, device_id, identity_key)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, device_id) DO UPDATE SET identity_key = EXCLUDED.identity_key`,
      [uid, did, identityKey.trim()],
    )

    await pool.query(
      `INSERT INTO signed_prekeys (user_id, device_id, key_id, public_key, signature)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, device_id)
       DO UPDATE SET key_id = EXCLUDED.key_id, public_key = EXCLUDED.public_key,
                     signature = EXCLUDED.signature, created_at = NOW()`,
      [uid, did, signedPreKey.keyId, (signedPreKey.publicKey as string).trim(), (signedPreKey.signature as string).trim()],
    )

    for (const otp of oneTimePreKeys) {
      await pool.query(
        `INSERT INTO one_time_prekeys (user_id, device_id, key_id, public_key)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, device_id, key_id) DO NOTHING`,
        [uid, did, otp.keyId, (otp.publicKey as string).trim()],
      )
    }

    const countRes = await pool.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM one_time_prekeys WHERE user_id = $1 AND device_id = $2`,
      [uid, did],
    )

    res.status(201).json({
      userId: uid,
      deviceId: did,
      oneTimePreKeyCount: parseInt(countRes.rows[0]?.count ?? '0', 10),
    })
  } catch (err) {
    next(err)
  }
})

/**
 * GET /v1/prekeys/:userId/:deviceId
 * Fetch a prekey bundle for one device, atomically consuming one one-time
 * prekey if any remain. If the pool is exhausted, the bundle omits the
 * one-time prekey (X3DH falls back to the 3-DH variant).
 *
 * Query param `consumeOneTime=false` returns the identity key + signed prekey
 * WITHOUT consuming a one-time prekey. Used for ephemeral presence sessions,
 * which run the 3-DH X3DH variant and must not drain the chat one-time-prekey
 * pool. Forward secrecy for these sessions comes from signed-prekey rotation.
 *
 * Returns a PreKeyBundle: { identityKey, signedPreKey, oneTimePreKey? }
 */
router.get('/v1/prekeys/:userId/:deviceId', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId, deviceId } = req.params as { userId: string; deviceId: string }
    const consumeOneTime = req.query['consumeOneTime'] !== 'false'
    const pool = getPool()

    const identityRes = await pool.query<{ identity_key: string }>(
      `SELECT identity_key FROM identity_keys WHERE user_id = $1 AND device_id = $2`,
      [userId, deviceId],
    )
    const signedRes = await pool.query<{ key_id: number; public_key: string; signature: string }>(
      `SELECT key_id, public_key, signature FROM signed_prekeys WHERE user_id = $1 AND device_id = $2`,
      [userId, deviceId],
    )

    if (identityRes.rows.length === 0 || signedRes.rows.length === 0) {
      throw new NotFoundError(
        `No prekey bundle for user '${userId}' device '${deviceId}'. Make sure they have published prekeys.`,
      )
    }

    // Atomically consume the oldest unused one-time prekey, if any.
    // FOR UPDATE SKIP LOCKED makes concurrent fetches hand out distinct keys.
    // Skipped entirely for non-consuming (presence) fetches.
    const otpRes = consumeOneTime
      ? await pool.query<{ key_id: number; public_key: string }>(
          `DELETE FROM one_time_prekeys
           WHERE id = (
             SELECT id FROM one_time_prekeys
             WHERE user_id = $1 AND device_id = $2
             ORDER BY id
             LIMIT 1
             FOR UPDATE SKIP LOCKED
           )
           RETURNING key_id, public_key`,
          [userId, deviceId],
        )
      : { rows: [] as Array<{ key_id: number; public_key: string }> }

    const identity = identityRes.rows[0]!
    const signed   = signedRes.rows[0]!
    const bundle: {
      identityKey:  string
      signedPreKey: { keyId: number; publicKey: string; signature: string }
      oneTimePreKey?: { keyId: number; publicKey: string }
    } = {
      identityKey:  identity.identity_key,
      signedPreKey: { keyId: signed.key_id, publicKey: signed.public_key, signature: signed.signature },
    }

    if (otpRes.rows.length > 0) {
      const otp = otpRes.rows[0]!
      bundle.oneTimePreKey = { keyId: otp.key_id, publicKey: otp.public_key }
    }

    res.json(bundle)
  } catch (err) {
    next(err)
  }
})

/**
 * GET /v1/prekeys/:userId/:deviceId/count
 * Returns the number of one-time prekeys remaining for a device, so the owner
 * can decide when to replenish the pool.
 */
router.get('/v1/prekeys/:userId/:deviceId/count', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId, deviceId } = req.params as { userId: string; deviceId: string }
    const countRes = await getPool().query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM one_time_prekeys WHERE user_id = $1 AND device_id = $2`,
      [userId, deviceId],
    )
    res.json({ oneTimePreKeyCount: parseInt(countRes.rows[0]?.count ?? '0', 10) })
  } catch (err) {
    next(err)
  }
})

export default router
