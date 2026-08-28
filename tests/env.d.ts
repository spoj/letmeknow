interface LetMeKnowTestEnv {
  SESSIONS: DurableObjectNamespace<import("../src/index").Session>;
}

declare namespace Cloudflare {
  interface Env extends LetMeKnowTestEnv {}
}
