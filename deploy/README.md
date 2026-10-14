# Deploying letmeknow

- `https://letmeknow.dev`: the web app, built by the release workflow and served by GitHub Pages.
- `https://relay.letmeknow.dev`: `letmeknow serve`, the membership service and iroh relay, on the VPS (129.212.227.207, 2400:6180:0:d2:0:3:37cd:7000; Ubuntu with a `letmeknow` user, a swap file and unattended security updates). It needs TCP 22, 80 and 443 and UDP 7842 and 7843 open, gets its own TLS certificate, and serves no app: it answers `/health` (version and public key), `/stats` (totals of the last 7 completed UTC days), `/ping` and `/.well-known/letmeknow.json` (its directory).

Its domain, directory and public key are in web/backend.json; crates/proto/src/links.rs holds its domain, relay and key. Its private key exists only in the VPS's state directory, /var/lib/letmeknow, which has no backup.

## A release

`deploy/release.sh X.Y.Z <notes file>` publishes the release, then prints two commands. Both take the release run's artifacts and check them against its tag and commit; neither rebuilds. A new minor (X.Y.0) also moves the `@letmeknow/cli@` pins in README.md, SKILL.md, web/src/index.html and AGENTS.md to it, in the release commit, and prints the pi-letmeknow `MINOR` to set by hand.

1. Backend: `deploy/deploy.sh root@129.212.227.207 relay.letmeknow.dev spoj/letmeknow <run> vX.Y.Z <sha>` installs the Linux binary and systemd unit, restarts the service, and checks that `/health` reports the version and key, and that the live directory is web/backend.json's. A first start may still be getting its certificate: rerun the check with `deploy/check-backend.py web/backend.json vX.Y.Z`.
2. Frontend: `gh workflow run pages.yml --repo spoj/letmeknow -f release_run=<run> -f release_tag=vX.Y.Z -f release_sha=<sha>`, then approve its `github-pages` deployment. It deploys only while the backend's `/health` matches the app's configuration.

## A new minor

Nothing carries over: it gets a new service, and the previous minor's sessions stop working once the old one goes. In this order:

1. Before the release: make the new service's state into /var/lib/letmeknow.new ("A new service", below), and commit its key in web/backend.json and crates/proto/src/links.rs.
2. npm: `release.sh` publishes `@letmeknow/cli@X.Y.0`, which the pins and `npx` start.
3. The service: stop it, delete /var/lib/letmeknow, move /var/lib/letmeknow.new there, and run the backend command above.
4. pi-letmeknow: set its `MINOR`, so Pi agents start sessions of the new minor.
5. Pages, last: browsers take the new app through their service worker, and it must find the service already running the new version.

## A new service

`serve` runs only on state that `serve --initialize` made. To make it, as the `letmeknow` user, into a directory that does not exist yet:

    letmeknow serve --initialize --domain relay.letmeknow.dev --state /var/lib/letmeknow

It prints the new domain and public key: put the key in web/backend.json's directory and in crates/proto/src/links.rs, and release. The directory is what the service publishes at `/.well-known/letmeknow.json` once it runs; its `addrs` name port 7843 and its `relay` the domain. A new key is a new service: groups and identities of the old one do not move to it.

## Browsers on your own server

For a server of your own (README.md), either build the app for it, with a copy of web/backend.json naming its domain and directory: `LMK_FRONTEND_CONFIG=/absolute/path.json npm run build` in web/ (`LMK_FRONTEND_OUT` sets the output directory), served from any static HTTPS host, `/i/index.html` included. Or, on letmeknow.dev, set localStorage `lmk membership` to the domain, `relay.example.com`, and `lmk relay` to the chosen relays, comma-separated, optionally; then reload: new groups and identities use it.

Browsers fetch the directory cross-origin, which the service allows, and reach the relay over WSS. The service worker offers updates, but pins nothing: whoever controls letmeknow.dev's DNS, Pages or releases controls the app.
