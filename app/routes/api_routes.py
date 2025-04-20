from fastapi import APIRouter, HTTPException
from models.models import get_db_connection
from services.ip_filter_service import is_ip_allowed
from fastapi import Request

api_router = APIRouter()

@api_router.get("/ssh-keys/{server}/{username}")
async def get_ssh_key(server: str, username: str, request: Request):
    client_ip = request.client.host

    if not is_ip_allowed(client_ip):
        log_api_access(server, username, client_ip, "BLOCKED", "IP not allowed")
        raise HTTPException(status_code=403, detail="Access denied")

    conn = get_db_connection()
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    server_rec = conn.execute('SELECT id FROM servers WHERE server_name = ?', (server,)).fetchone()

    if not user or not server_rec:
        conn.close()
        log_api_access(server, username, client_ip, "NOT FOUND", "User or Server not found")
        raise HTTPException(status_code=404, detail="User or server not found")

    assignment = conn.execute('SELECT * FROM assignments WHERE user_id = ? AND server_id = ?', (user["id"], server_rec["id"])).fetchone()
    if not assignment:
        conn.close()
        log_api_access(server, username, client_ip, "NOT ASSIGNED", "User not assigned to server")
        raise HTTPException(status_code=404, detail="User not assigned to server")

    keys = conn.execute('SELECT ssh_key FROM ssh_keys WHERE user_id = ?', (user["id"],)).fetchall()
    conn.close()

    if not keys:
        log_api_access(server, username, client_ip, "NO KEYS", "No SSH keys found")
        raise HTTPException(status_code=404, detail="No SSH keys found")

    ssh_keys = "\n".join([k["ssh_key"] for k in keys])

    log_api_access(server, username, client_ip, "SUCCESS", "SSH keys provided")
    return ssh_keys

def log_api_access(server, username, client_ip, status, reason):
    conn = get_db_connection()

    success = 1 if status == "SUCCESS" else 0

    conn.execute('''
        INSERT INTO api_logs (server_name, username, success, client_ip, reason)
        VALUES (?, ?, ?, ?, ?)
    ''', (server, username, success, client_ip, reason))

    conn.commit()
    conn.close()