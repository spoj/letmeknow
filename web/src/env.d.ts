declare const DEFAULT_MEMBERSHIP: string;

declare module "*.wasm" {
  const url: string;
  export default url;
}
