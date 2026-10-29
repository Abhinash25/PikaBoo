/**
 * Privacy Gateway Migration Runner
 * Transactional SQL Migration Engine
 */

import fs from 'fs';
import path from 'path';
import pg from 'pg';
import crypto from 'crypto';

export interface MigrationResult {
  applied: string[];
  skipped: string[];
  failed?: {
    migration: string;
    error: string;
  };
}

export async function runMigrations(pool: pg.Pool): Promise<MigrationResult> {
  const client = await pool.connect();
  const result: MigrationResult = {
    applied: [],
    skipped: []
  };

  try {
    // 1. Ensure migrations table exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS _migrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        applied_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
        checksum VARCHAR(64)
      );
    `);

    // 2. Query applied migrations
    const { rows: existingRows } = await client.query<{ name: string }>(
      'SELECT name FROM _migrations ORDER BY id ASC'
    );
    const appliedSet = new Set(existingRows.map(r => r.name));

    // 3. Read migration files
    const migrationsDir = typeof __dirname !== 'undefined'
      ? path.resolve(__dirname)
      : path.resolve(process.cwd(), 'infrastructure/migrations');
    const files = fs.readdirSync(migrationsDir)
      .filter(f => f.endsWith('.sql'))
      .sort();

    for (const file of files) {
      if (appliedSet.has(file)) {
        result.skipped.push(file);
        continue;
      }

      const filePath = path.join(migrationsDir, file);
      const sql = fs.readFileSync(filePath, 'utf-8');
      const checksum = crypto.createHash('sha256').update(sql).digest('hex');

      // Transactional execution of migration
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query(
          'INSERT INTO _migrations (name, checksum) VALUES ($1, $2)',
          [file, checksum]
        );
        await client.query('COMMIT');
        result.applied.push(file);
      } catch (err) {
        await client.query('ROLLBACK');
        result.failed = {
          migration: file,
          error: (err as Error).message
        };
        throw err;
      }
    }

    return result;
  } finally {
    client.release();
  }
}
