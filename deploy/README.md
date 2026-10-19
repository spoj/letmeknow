# Deploying letmeknow

- `https://letmeknow.dev`: a static page, `site/`, served by GitHub Pages, which invite links open: it shows the commands that join with them.
- `https://relay.letmeknow.dev`: `letmeknow serve`, the membership service and iroh relay, on the VPS (129.212.227.207, 2400:6180:0:d2:0:3:37cd:7000; Ubuntu with a `letmeknow` user, a swap file and unattended security updates). It needs TCP 22, 80 and 443 and UDP 7842 open, gets its own TLS certificate, and serves no pages: it answers `/health` (version and public key), `/ping` and `/.well-known/letmeknow.json` (its directory).

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

It prints the new domain and public key: put the key in deploy/backend.json's directory and in crates/proto/src/links.rs, and release. The directory is what the service publishes at `/.well-known/letmeknow.json` once it runs; its `relay` names the domain. A new key is a new service: groups of the old one do not move to it.

## Limits

The protocol's limits (entry and page sizes, the 30 days a log let go is remembered, the 28 days a session waits before taking a log as let go) are fixed. The service's are its own, set by `serve` flags sized to its machine; each defaults as below:

| Flag | Default | Limits |
| --- | --- | --- |
| `--disk <MiB>` | 4096 | the database's pages and WAL; appends past it are refused as quota |
| `--retention <days>` | 7 | days a log is kept after its first entry, 7 to 25 |
| `--appends-per-minute` | 600 | appends of each address |
| `--append-mib-per-day` | 256 | bytes appended by each address |
| `--reads-per-minute` | 600 | reads of each address |
| `--read-mib-per-minute` | 64 | bytes read by each address |
| `--new-logs-per-day` | 2000 | logs each address starts, by their first entries: about one per commit |
| `--requests-at-once` | 8 | requests in flight from each source |
| `--mib-at-once` | 16 | bytes in flight from each source |
| `--mib-at-once-in-all` | 256 | bytes in flight over all sources |
| `--db-work` | 4 | requests working on the database at once |
| `--sources` | 1048576 | sources each rate limit tracks; new ones past it are refused |
| `--relay-kib-per-second` | 1024 | what the relay reads from each connection |

Per address means an IPv4 address or an IPv6 /64, and a /48 gets 16 times as much.

## Sizing

The target is one node for 100,000 active devices, each starting 10 sessions a day in two groups (its own, and one it shares) and sending about 20 messages from each. Messages go between members, through the relay when they must; the service holds only commits. Each session's joins commit an Add and the joiner's first update in each group, and members update only after a message or membership change, a day apart at most: about 2.5 million appends a day of commits of 4 to 16 KiB, and 22 million reads (each send reads its group's log first). That is 29 appends and 255 reads a second on average; a peak of 10 times that is 290 and 2,500.

A week's entries are then about 140 GB: `--disk` 204800 on a 250 GB SSD. `crates/membership/tests/load.rs` runs the store at the peak's mix (`cargo test --release -p lmk-membership --test load -- --ignored --nocapture`). Each append syncs the disk once, so appends are bound by its sync latency: on a Samsung 970 EVO Plus (consumer NVMe), 138 appends a second with 1,244 reads; where syncs are free (tmpfs), 1,813 with 16,320, on a Ryzen 9 7950X. The average needs any SSD; the peak needs one that syncs in about 3 ms or less, as datacenter SSDs with power-loss protection do. So: 4 cores, 16 GB of memory, a 250 GB datacenter SSD, and the relay's traffic, a few tens of GB a day.

