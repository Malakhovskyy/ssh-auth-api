from fastapi import APIRouter, HTTPException
from models.models import get_db_connection
from services.ip_filter_service import is_ip_allowed
from fastapi import Request

api_router = APIRouter()

@api_router.get("/ssh-keys/{server}/{username}")
async def get_ssh_key(server: str, username: str, request: Request):
    client_ip = request.client.host
    if not is_ip_allowed(client_ip):
        log_api_access(server, username, client_ip, "BLOCKED")
        raise HTTPException(status_code=403, detail="Access denied")

    conn = get_db_connection()
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    server_rec = conn.execute('SELECT id FROM servers WHERE server_name = ?', (server,)).fetchone()

    if not user or not server_rec:
        conn.close()
        log_api_access(server, username, client_ip, "NOT FOUND")
        raise HTTPException(status_code=404, detail="User or server not found")

    assignment = conn.execute('SELECT * FROM assignments WHERE user_id = ? AND server_id = ?', (user["id"], server_rec["id"])).fetchone()
    if not assignment:
        conn.close()
        log_api_access(server, username, client_ip, "NOT ASSIGNED")
        raise HTTPException(status_code=404, detail="User not assigned to server")

    keys = conn.execute('SELECT ssh_key FROM ssh_keys WHERE user_id = ?', (user["id"],)).fetchall()
    conn.close()

    if not keys:
        log_api_access(server, username, client_ip, "NO KEYS")
        raise HTTPException(status_code=404, detail="No SSH keys found")

    ssh_keys = "\n".join([k["ssh_key"] for k in keys])

    log_api_access(server, username, client_ip, "SUCCESS")
    return ssh_keys

def log_api_access(server, username, client_ip, status):
    conn = get_db_connection()
    conn.execute('INSERT INTO api_logs (server_name, username, status) VALUES (?, ?, ?)',
                 (server, username, f"{status} from {client_ip}"))
    conn.commit()
    conn.close()