import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";

// Setup runs outside per-test storage isolation and may run more than once.
// applyD1Migrations skips migrations that are already applied.
type TestEnv = { DB: D1Database; TEST_MIGRATIONS: Parameters<typeof applyD1Migrations>[1] };

await applyD1Migrations((env as TestEnv).DB, (env as TestEnv).TEST_MIGRATIONS);
