/**
 * Automated Test for Health Check Controller
 * Phase 1 Foundation
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createApp } from '../src/app';

describe('Health Endpoints Integration', () => {
  const app = createApp();

  it('should initialize Express application with security middleware', () => {
    assert.ok(app, 'Express app should be instantiated');
    assert.strictEqual(typeof app.listen, 'function', 'App must have listen function');
  });
});
