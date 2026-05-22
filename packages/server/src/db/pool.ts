import { Pool } from 'pg'

let _pool: Pool | null = null

export function getPool(): Pool {
  if (!_pool) {
    _pool = new Pool({
      connectionString: process.env['DATABASE_URL'],
      max: 10,
    })
  }
  return _pool
}

export function setPool(pool: Pool): void {
  _pool = pool
}
