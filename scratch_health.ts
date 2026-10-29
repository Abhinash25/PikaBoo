import 'dotenv/config';
import { checkRedisHealth } from './apps/api/src/config/redis';
import { checkDatabaseHealth } from './apps/api/src/config/database';

async function run() {
  console.log("Redis Health:", await checkRedisHealth());
  console.log("Database Health:", await checkDatabaseHealth());
  process.exit(0);
}

run();
