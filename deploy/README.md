# Deploying letmeknow

- `https://letmeknow.dev`: a static page, `site/`, served by GitHub Pages, which invite links open: it shows the commands that join with them.
- `https://relay.letmeknow.dev`: `letmeknow serve`, the membership service and iroh relay, on the VPS (129.212.227.207, 2400:6180:0:d2:0:3:37cd:7000; Ubuntu with a `letmeknow` user, a swap file and unattended security updates). It needs TCP 22, 80 and 443 and UDP 7842 open, gets its own TLS certificate, and serves no pages: it answers `/health` (version and public key), `/stats` (totals of the last 7 completed UTC days), `/ping` and `/.well-known/letmeknow.json` (its directory).

Its domain, directory and public key are in deploy/backend.json; crates/proto/src/links.rs holds its domain, relay and key. Its private key exists only in the VPS's state directory, /var/lib/letmeknow, which has no backup.

## A release

`deploy/release.sh X.Y.Z <notes file>` publishes the release, then prints two commands. The backend's takes the release run's artifacts and checks them against its tag and commit, and rebuilds nothing. A new minor (X.Y.0) also moves the `@letmeknow/cli@` pins in README.md, SKILL.md, site/index.html and AGENTS.md to it, in the release commit, and prints the pi-letmeknow `MINOR` and the claude-letmeknow pin to set by hand.

1. Backend: `deploy/deploy.sh root@129.212.227.207 relay.letmeknow.dev spoj/letmeknow <run> vX.Y.Z <sha>` installs the Linux binary and systemd unit, restarts the service, and checks that `/health` reports the version and key, and that the live directory is deploy/backend.json's. A first start may still be getting its certificate: rerun the check with `deploy/check-backend.py deploy/backend.json vX.Y.Z`.
2. Site: `gh workflow run pages.yml --repo spoj/letmeknow -f release_tag=vX.Y.Z` publishes the tag's `site/`; approve its `github-pages` deployment.

## A new minor

Nothing carries over: it gets a new service, and the previous minor's sessions stop working once the old one goes. In this order:

1. Before the release: make the new service's state into /var/lib/letmeknow.new ("A new service", below), and commit its key in deploy/backend.json and crates/proto/src/links.rs.
2. npm: `release.sh` publishes `@letmeknow/cli@X.Y.0`, which the pins and `npx` start.
3. The service: stop it, delete /var/lib/letmeknow, move /var/lib/letmeknow.new there, and run the backend command above.
4. pi-letmeknow and claude-letmeknow: set pi-letmeknow's `MINOR` and claude-letmeknow's `@letmeknow/cli@` pin, so Pi and Claude Code agents start sessions of the new minor.
5. The site, whose commands pin the new minor.

## A new service

`serve` runs only on state that `serve --initialize` of its own minor made, so a new minor's state is made before its release, by a binary built from `main` (`cargo build --release --target x86_64-unknown-linux-musl -p letmeknow`) and copied to the VPS. There, as root, into a directory that does not exist yet:

    ./letmeknow serve --initialize --domain relay.letmeknow.dev --state /var/lib/letmeknow.new
    chown -R letmeknow: /var/lib/letmeknow.new

It prints the new domain and public key: put the key in deploy/backend.json's directory and in crates/proto/src/links.rs, and release. The directory is what the service publishes at `/.well-known/letmeknow.json` once it runs; its `relay` names the domain. A new key is a new service: groups and identities of the old one do not move to it.
