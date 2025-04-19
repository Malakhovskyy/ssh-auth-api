#!/bin/bash

# Replace ${DOMAIN} with real env variable
envsubst '${DOMAIN}' < /etc/nginx/conf.d/default.conf > /etc/nginx/conf.d/default.conf.out
mv /etc/nginx/conf.d/default.conf.out /etc/nginx/conf.d/default.conf

# Start nginx
nginx -g "daemon off;"