#!/bin/bash

if [ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
  echo "[Startup] SSL certificates not found, starting temporary HTTP-only nginx..."
  envsubst '${DOMAIN}' < /etc/nginx/conf.d/default.http.conf > /etc/nginx/conf.d/default.conf
else
  echo "[Startup] SSL certificates found, starting full HTTPS nginx..."
  envsubst '${DOMAIN}' < /etc/nginx/conf.d/default.ssl.conf > /etc/nginx/conf.d/default.conf
fi

nginx -g "daemon off;"