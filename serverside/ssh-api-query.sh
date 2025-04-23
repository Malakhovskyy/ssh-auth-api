#!/bin/bash

# Config
API_URL="https://domain.com/ssh-keys"    # <-- Change to your real API endpoint
SERVER_NAME="host_name"                                    # Hostname or server record name
AUTH_TOKEN="toke_for_server"           # Replace with actual token
USERNAME="$1"                                           # SSH passes username as $1

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

# Call API with Authorization header
RESPONSE=$(curl -s --max-time 3 -H "Authorization: ${AUTH_TOKEN}" "${API_URL}/${SERVER_NAME}/${USERNAME}")

# Check for valid SSH key in response
if echo "$RESPONSE" | grep -q "ssh-"; then
    echo "$RESPONSE"
    log "SUCCESS"
    exit 0
else
    log "BLOCKED or NO KEY"
    exit 1
fi