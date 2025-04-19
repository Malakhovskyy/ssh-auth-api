#!/bin/bash

# Load environment variables
DOMAIN=${DOMAIN}
EMAIL=${SMTP_TO}

# Check if cert already exists
if [ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
  echo "[Startup] No SSL certificate found, requesting new certificate for ${DOMAIN}..."

  certbot certonly --webroot \
    --webroot-path=/usr/share/nginx/html \
    -d ${DOMAIN} \
    --email ${EMAIL} \
    --agree-tos \
    --no-eff-email --noninteractive
  
  if [ $? -eq 0 ]; then
    echo "[Startup] SSL certificate successfully obtained."
  else
    echo "[Startup] Failed to obtain SSL certificate."
    exit 1
  fi
else
  echo "[Startup] SSL certificate already exists for ${DOMAIN}."
fi

# Now proceed with nginx config substitution
if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
  echo "[Startup] Starting full HTTPS nginx..."
  envsubst '${DOMAIN}' < /etc/nginx/conf.d/default.ssl.conf > /etc/nginx/conf.d/default.conf
else
  echo "[Startup] Starting temporary HTTP-only nginx..."
  envsubst '${DOMAIN}' < /etc/nginx/conf.d/default.http.conf > /etc/nginx/conf.d/default.conf
fi

# Start nginx
nginx -g "daemon off;"