# letmeknow.dev

`deploy.sh <ssh host> <domain>` builds and installs `letmeknow serve` and the web client on an Ubuntu host, with Litestream backing the database up to Spaces, a 1 GB swap file, and security updates that reboot at 20:00 UTC when they need to.

What it runs on, made by hand in DigitalOcean (project first-project):

- Droplet `s-1vcpu-1gb` in sgp1, IPv6 on, 129.212.227.207 and 2400:6180:0:d2:0:3:37cd:7000.
- Cloud firewall `letmeknow`: TCP 22, 80, 443; UDP 7842 (QUIC address discovery), 7843 (the membership service).
- Spaces bucket `letmeknow-litestream` (sgp1): Litestream replicas under `<domain>/membership.db`, and the membership service's key under `keys/`. Its access key is limited to that bucket.
- Uptime check on https://letmeknow.dev/ping from three regions, emailing the account when it is down or its certificate has under 14 days left.
- DNS at Cloudflare: letmeknow.dev's A and AAAA records, DNS only.

Restoring: on a new host, `deploy.sh` restores the database from Spaces before it starts the service; the membership key comes from `~/.config/letmeknow-deploy/membership.key` (or the bucket).
