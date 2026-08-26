interface LetMeKnowTestEnv {
  DB: D1Database;
  CREATE_RATE_LIMIT: {
    limit(options: { key: string }): Promise<{ success: boolean }>;
  };
  TEST_MIGRATIONS: D1Migration[];
}

declare namespace Cloudflare {
  interface Env extends LetMeKnowTestEnv {}
}
