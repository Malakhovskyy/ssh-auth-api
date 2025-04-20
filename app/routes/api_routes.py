from fastapi import APIRouter, HTTPException
from fastapi import Request
from fastapi.responses import PlainTextResponse
from models.models import get_db_connection
from services.ip_filter_service import is_ip_allowed
from services.encryption_service import decrypt_sensitive_value
from datetime import datetime

api_router = APIRouter()

@api_router.get("/ssh-keys/{server}/{username}")
async def get_ssh_key(server: str, username: str, request: Request):
    # Retrieve the client's IP address from the request headers
    client_ip = request.headers.get("x-forwarded-for")
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    else:
        client_ip = request.client.host

    # Check if the client's IP address is allowed to access the API
    if not is_ip_allowed(client_ip):
        log_api_access(server, username, client_ip, "BLOCKED", "IP not allowed")
        raise HTTPException(status_code=403, detail="Access denied")

    # Establish a database connection to retrieve user and server information
    conn = get_db_connection()

    # Query the database to find the user by username
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()

    # Query the database to find the server by server name
    server_rec = conn.execute('SELECT id FROM servers WHERE server_name = ?', (server,)).fetchone()

    # Check if the user or server was not found in the database
    if not user or not server_rec:
        conn.close()
        log_api_access(server, username, client_ip, "NOT FOUND", "User or Server not found")
        raise HTTPException(status_code=404, detail="User or server not found")

    # Check if the user is assigned to the specified server
    assignment = conn.execute('SELECT * FROM server_assignments WHERE user_id = ? AND server_id = ?', (user["id"], server_rec["id"])).fetchone()

    # If the user is not assigned to the server, raise an error
    if not assignment:
        conn.close()
        log_api_access(server, username, client_ip, "NOT ASSIGNED", "User not assigned to server")
        raise HTTPException(status_code=404, detail="User not assigned to server")

    # Retrieve the SSH key data using the ssh_key_id from the assignment
    ssh_key_rec = conn.execute('SELECT ssh_key_data, expiration_date FROM ssh_keys WHERE id = ?', (assignment["ssh_key_id"],)).fetchone()
    conn.close()

    # If the SSH key was not found, log the access and raise an error
    if not ssh_key_rec:
        log_api_access(server, username, client_ip, "NO KEY", "SSH Key not found")
        raise HTTPException(status_code=404, detail="SSH Key not found")

    # Check if the SSH key has expired
    current_utc_time = datetime.utcnow()
    if ssh_key_rec["expiration_date"] < current_utc_time:
        log_api_access(server, username, client_ip, "EXPIRED", "SSH Key expired")
        raise HTTPException(status_code=403, detail="SSH Key expired")

    # Decrypt the SSH key data before returning it in the response
    ssh_key_data = decrypt_sensitive_value(ssh_key_rec["ssh_key_data"])

    # Log the successful retrieval of the SSH key and return it as a plain text response
    log_api_access(server, username, client_ip, "SUCCESS", "SSH Key provided")
    return PlainTextResponse(content=ssh_key_data)

def log_api_access(server, username, client_ip, status, reason):
    # Establish a database connection to log the API access
    conn = get_db_connection()

    # Determine if the access was successful based on the status
    success = 1 if status == "SUCCESS" else 0

    # Insert the access log into the database
    conn.execute('''
        INSERT INTO api_logs (server_name, username, success, client_ip, reason)
        VALUES (?, ?, ?, ?, ?)
    ''', (server, username, success, client_ip, reason))

    # Commit the transaction and close the database connection
    conn.commit()
    conn.close()