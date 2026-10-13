# Deploying letmeknow

- `https://letmeknow.dev`: the web app, built by the release workflow and served by GitHub Pages.
- `https://relay.letmeknow.dev`: `letmeknow serve`, the membership service and iroh relay, on the VPS (129.212.227.207, 2400:6180:0:d2:0:3:37cd:7000; Ubuntu with a `letmeknow` user, a swap file and unattended security updates). It needs TCP 22, 80 and 443 and UDP 7842 and 7843 open, gets its own TLS certificate, and serves no app: it answers `/health` (version and public key), `/stats` (totals of the last 7 completed UTC days) and `/ping`.

The service's public key is in web/backend.json and crates/proto/src/links.rs. Its private key exists only in the VPS's state directory, /var/lib/letmeknow, which has no backup.

## A release

`deploy/release.sh X.Y.Z <notes file>` publishes the release, then prints two commands. Both take the release run's artifacts and check them against its tag and commit; neither rebuilds. A new minor (X.Y.0) also moves the `@letmeknow/cli@` pins in README.md, SKILL.md, web/src/index.html and AGENTS.md to it, in the release commit, and prints the pi-letmeknow `MINOR` to set by hand.

1. Backend: `deploy/deploy.sh root@129.212.227.207 relay.letmeknow.dev spoj/letmeknow <run> vX.Y.Z <sha>` installs the Linux binary and systemd unit, restarts the service, and checks that `/health` reports the version and key. A first start may still be getting its certificate: rerun the check with `deploy/check-backend.py web/backend.json vX.Y.Z`.
2. Frontend: `gh workflow run pages.yml --repo spoj/letmeknow -f release_run=<run> -f release_tag=vX.Y.Z -f release_sha=<sha>`, then approve its `github-pages` deployment. It deploys only while the backend's `/health` matches the app's configuration.

## A new minor

Its groups and homes are new, so agents and browsers move to it in this order:

1. npm: `release.sh` publishes `@letmeknow/cli@X.Y.0`, which the pins and `npx` start.
2. The service: the backend command above. Its API is unchanged, so the previous minor's sessions keep working through it (`test/compat.py` checks this in CI).
3. pi-letmeknow: set its `MINOR`, so Pi agents start sessions of the new minor.
4. Pages, last: browsers take the new app through their service worker, and it must find the service already running the new version.

## A new service

`serve` runs only on state that `serve --initialize` made. To make it, as the `letmeknow` user, into a directory that does not exist yet:

    letmeknow serve --initialize --domain relay.letmeknow.dev --state /var/lib/letmeknow

It prints the new public key: put it in web/backend.json and crates/proto/src/links.rs, and release. A new key is a new service: groups and identities of the old one do not move to it.

## Browsers on your own server

For a server of your own (README.md), either build the app for it, with a copy of web/backend.json naming its key and relay: `LMK_FRONTEND_CONFIG=/absolute/path.json npm run build` in web/ (`LMK_FRONTEND_OUT` sets the output directory), served from any static HTTPS host, `/i/index.html` included. Or, on letmeknow.dev, set localStorage `lmk membership` to `<key>@https://relay.example.com` (and `lmk relay`, optionally), then reload: new groups and identities use it.

Browsers reach the relay over cross-origin WSS, which needs no CORS. The service worker offers updates, but pins nothing: whoever controls letmeknow.dev's DNS, Pages or releases controls the app.
