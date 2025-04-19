#!/bin/bash

# Load DOMAIN variable from .env
export $(grep DOMAIN .env | xargs)
export $(grep SMTP_TO .env | xargs)

if [ -z "$DOMAIN" ]; then
  echo "Error: DOMAIN is not set in .env file."
  exit 1
fi

if [ -z "$SMTP_TO" ]; then
  echo "Error: SMTP_TO is not set in .env file."
  exit 1
fi

echo "[Prepare] Using domain: $DOMAIN"

# Replace $DOMAIN inside nginx conf files
for file in nginx/conf.d/*.conf
do
  echo "[Prepare] Processing $file..."
  sed -i "s|\$DOMAIN|$DOMAIN|g" "$file"
done

chmod +x certbot/startup.sh
chmod +x nginx/startup.sh
chmod 777 nginx/certs
chmod 777 nginx/html
chmod 777 data


echo "[Prepare] Startup scripts ready. Starting Docker Compose..."
docker-compose up -d --force-recreate