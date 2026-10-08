#!/bin/sh
# deploy/deploy.sh <ssh host> <domain>: builds `letmeknow serve` and the web client, and installs them with Litestream,
# which backs the database up to Spaces. Needs ~/.config/letmeknow-deploy/spaces.json (the Spaces key) and membership.key (the
# membership service's key, also kept in the bucket under keys/).
set -eu
host=$1 domain=$2
conf=$HOME/.config/letmeknow-deploy
cd "$(dirname "$0")/.."
cargo build --release --target x86_64-unknown-linux-musl -p letmeknow
scp -q target/x86_64-unknown-linux-musl/release/letmeknow "$host:/usr/local/bin/letmeknow.new"
(cd web && npm ci --no-audit --no-fund && npm run build)
tar -C web/dist -czf - . | ssh "$host" 'set -e; w=/usr/local/share/letmeknow; rm -rf $w/web.new; mkdir -p $w/web.new; tar -C $w/web.new -xzf -; rm -rf $w/web; mv $w/web.new $w/web'
scp -q deploy/letmeknow.service deploy/litestream.yml "$conf/membership.key" "$host:/tmp/"
access=$(jq -r .key.access_key "$conf/spaces.json")
secret=$(jq -r .key.secret_key "$conf/spaces.json")
ssh "$host" sh -s <<REMOTE
set -eu
id letmeknow >/dev/null 2>&1 || useradd --system --home-dir /var/lib/letmeknow --shell /usr/sbin/nologin letmeknow
install -d -o letmeknow -g letmeknow -m 700 /var/lib/letmeknow
install -d -m 755 /usr/local/share/letmeknow/web
[ -e /var/lib/letmeknow/membership.key ] || install -o letmeknow -g letmeknow -m 600 /tmp/membership.key /var/lib/letmeknow/
rm /tmp/membership.key
[ -e /swapfile ] || { fallocate -l 1G /swapfile; chmod 600 /swapfile; mkswap -q /swapfile; swapon /swapfile; echo '/swapfile none swap sw 0 0' >> /etc/fstab; }
command -v litestream >/dev/null || {
  curl -fsSL -o /tmp/litestream.deb https://github.com/benbjohnson/litestream/releases/download/v0.5.17/litestream-0.5.17-linux-x86_64.deb
  dpkg -i /tmp/litestream.deb >/dev/null
}
sed "s|@DOMAIN@|$domain|" /tmp/litestream.yml > /etc/litestream.yml
install -d -m 700 /etc/systemd/system/litestream.service.d
printf '[Service]\nEnvironment=LITESTREAM_ACCESS_KEY_ID=$access\nEnvironment=LITESTREAM_SECRET_ACCESS_KEY=$secret\n' > /etc/systemd/system/litestream.service.d/credentials.conf
chmod 600 /etc/systemd/system/litestream.service.d/credentials.conf
sed "s|@DOMAIN@|$domain|" /tmp/letmeknow.service > /etc/systemd/system/letmeknow.service
rm /tmp/letmeknow.service /tmp/litestream.yml
systemctl daemon-reload
systemctl stop letmeknow 2>/dev/null || true
[ -e /var/lib/letmeknow/membership.db ] || LITESTREAM_ACCESS_KEY_ID=$access LITESTREAM_SECRET_ACCESS_KEY=$secret \
  litestream restore -if-replica-exists -o /var/lib/letmeknow/membership.db /var/lib/letmeknow/membership.db
chown -R letmeknow:letmeknow /var/lib/letmeknow
mv /usr/local/bin/letmeknow.new /usr/local/bin/letmeknow
systemctl enable -q --now letmeknow litestream
systemctl restart letmeknow litestream
REMOTE
