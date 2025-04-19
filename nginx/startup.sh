#!/bin/bash



if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
  echo "[Startup] SSL certificates found. Starting full HTTPS nginx..."
  cp /etc/nginx/conf.d/default.ssl.conf /etc/nginx/conf.d/default.conf
else
  echo "[Startup] No certificates found. Starting HTTP nginx for challenge..."
  cp /etc/nginx/conf.d/default.http.conf /etc/nginx/conf.d/default.conf
fi

# Start nginx
nginx -g "daemon off;"