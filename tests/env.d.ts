interface LetMeKnowTestEnv {
  QUESTIONS: DurableObjectNamespace;
}

declare namespace Cloudflare {
  interface Env extends LetMeKnowTestEnv {}
}
