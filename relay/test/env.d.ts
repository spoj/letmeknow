interface RelayTestEnv {
  GROUPS: DurableObjectNamespace<import("../src/index").Group>;
  INVITES: DurableObjectNamespace<import("../src/index").Invite>;
  BOXES: DurableObjectNamespace<import("../src/index").Box>;
}

declare namespace Cloudflare {
  interface Env extends RelayTestEnv {}
}
