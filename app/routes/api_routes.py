from fastapi import APIRouter, HTTPException
from fastapi import Request
from models.models import get_db_connection
from services.ip_filter_service import is_ip_allowed
from services.encryption_service import decrypt_sensitive_value

api_router = APIRouter()

@api_router.get("/ssh-keys/{server}/{username}")
async def get_ssh_key(server: str, username: str, request: Request):
    # Get real client IP
    client_ip = request.headers.get("x-forwarded-for")
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    else:
        client_ip = request.client.host

    if not is_ip_allowed(client_ip):
        log_api_access(server, username, client_ip, "BLOCKED", "IP not allowed")
        raise HTTPException(status_code=403, detail="Access denied")

    conn = get_db_connection()

    # Find user
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()

    # Find server
    server_rec = conn.execute('SELECT id FROM servers WHERE server_name = ?', (server,)).fetchone()

    if not user or not server_rec:
        conn.close()
        log_api_access(server, username, client_ip, "NOT FOUND", "User or Server not found")
        raise HTTPException(status_code=404, detail="User or server not found")

    # Check if user assigned to server
    assignment = conn.execute('SELECT * FROM server_assignments WHERE user_id = ? AND server_id = ?', (user["id"], server_rec["id"])).fetchone()

    if not assignment:
        conn.close()
        log_api_access(server, username, client_ip, "NOT ASSIGNED", "User not assigned to server")
        raise HTTPException(status_code=404, detail="User not assigned to server")

    # Get SSH Key using assigned ssh_key_id
    ssh_key_rec = conn.execute('SELECT ssh_key_data FROM ssh_keys WHERE id = ?', (assignment["ssh_key_id"],)).fetchone()
    conn.close()

    if not ssh_key_rec:
        log_api_access(server, username, client_ip, "NO KEY", "SSH Key not found")
        raise HTTPException(status_code=404, detail="SSH Key not found")

   from services.encryption_service import decrypt_sensitive_value

    # Decrypt SSH Key before returning
    ssh_key_data = decrypt_sensitive_value(ssh_key_rec["ssh_key_data"])

    log_api_access(server, username, client_ip, "SUCCESS", "SSH Key provided")
    return ssh_key_data

def log_api_access(server, username, client_ip, status, reason):
    conn = get_db_connection()

    success = 1 if status == "SUCCESS" else 0

    conn.execute('''
        INSERT INTO api_logs (server_name, username, success, client_ip, reason)
        VALUES (?, ?, ?, ?, ?)
    ''', (server, username, success, client_ip, reason))

    conn.commit()
    conn.close()