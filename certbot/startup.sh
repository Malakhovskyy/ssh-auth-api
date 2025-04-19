#!/bin/sh

DOMAIN=${DOMAIN}
EMAIL=${SMTP_TO}

if [ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
  echo "[Certbot] No cert found for $DOMAIN. Requesting..."
  certbot certonly --webroot \
    --webroot-path=/usr/share/nginx/html \
    -d $DOMAIN \
    --email $EMAIL \
    --agree-tos \
    --no-eff-email \
    --noninteractive
else
  echo "[Certbot] Certificate already exists for $DOMAIN."
fi

# Keep container alive doing renew every 12h
trap exit TERM; while :; do certbot renew; sleep 12h; done