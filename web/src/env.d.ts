/** backend.json: the default membership domain, and its directory, used until one is fetched. */
declare const BACKEND: { domain: string; directory: object };

declare module "*.wasm" {
  const url: string;
  export default url;
}
