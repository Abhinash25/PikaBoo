/**
 * Automated Test for Environment Configuration
 * Phase 1 Foundation
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { getEnv } from '../src/config/env';

describe('Environment Configuration', () => {
  it('should load default environment configuration safely', () => {
    const env = getEnv();
    assert.ok(env, 'Env should be defined');
    assert.ok(env.PORT > 0, 'Port must be positive');
    assert.ok(['development', 'test', 'production'].includes(env.NODE_ENV), 'Valid NODE_ENV');
    assert.strictEqual(env.POSTGRES_DB, 'privacy_gateway', 'Default DB name matches');
  });
});
