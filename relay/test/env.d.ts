interface RelayTestEnv {
  GROUPS: DurableObjectNamespace<import("../src/index").Group>;
  INVITES: DurableObjectNamespace<import("../src/index").Invite>;
}

declare namespace Cloudflare {
  interface Env extends RelayTestEnv {}
}
