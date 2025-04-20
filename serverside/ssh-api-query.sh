#!/bin/bash

# Config
API_URL="https://your-api-domain/ssh-keys"    # <-- Change to your real API endpoint
SERVER_NAME="$(hostname -f)"                  # Get full server hostname
USERNAME="$1"                                 # SSH passes username as $1

LOG_FILE="/var/log/ssh_api/ssh_api_query.log"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Server: ${SERVER_NAME}, User: ${USERNAME}, Status: $1" >> "$LOG_FILE"
}

# Validate inputs
if [ -z "$USERNAME" ]; then
    log "ERROR: Empty username"
    exit 1
fi

# Call API
RESPONSE=$(curl -s --max-time 3 "${API_URL}/${SERVER_NAME}/${USERNAME}")

if echo "$RESPONSE" | grep -q "ssh-"; then
    echo "$RESPONSE"
    log "SUCCESS"
    exit 0
else
    log "BLOCKED or NO KEY"
    exit 1
fi