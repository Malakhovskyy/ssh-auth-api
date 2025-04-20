from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from services.ip_filter_service import is_ip_allowed
from models.models import get_db_connection

api_router = APIRouter()

class SSHKeyRequest(BaseModel):
    server_name: str
    username: str

# Log API access attempt
def log_api_access(server, username, client_ip, status, reason):
    conn = get_db_connection()

    success = 1 if status == "SUCCESS" else 0

    conn.execute('''
        INSERT INTO api_logs (server_name, username, success, client_ip, reason)
        VALUES (?, ?, ?, ?, ?)
    ''', (server, username, success, client_ip, reason))

    conn.commit()
    conn.close()

@api_router.post("/ssh-key")
async def get_ssh_key(request: Request, ssh_req: SSHKeyRequest):
    client_ip = request.client.host
    server = ssh_req.server_name
    username = ssh_req.username

    if not is_ip_allowed(client_ip):
        log_api_access(server, username, client_ip, "BLOCKED", "IP not allowed")
        raise HTTPException(status_code=403, detail="Access Denied")

    conn = get_db_connection()

    # Find SSH key assigned for user
    result = conn.execute('''
        SELECT ssh_keys.ssh_key_data
        FROM assignments
        JOIN ssh_keys ON assignments.ssh_key_id = ssh_keys.id
        JOIN users ON assignments.user_id = users.id
        WHERE users.username = ? 
    ''', (username,)).fetchone()

    conn.close()

    if not result:
        log_api_access(server, username, client_ip, "BLOCKED", "User not assigned or SSH Key missing")
        raise HTTPException(status_code=404, detail="SSH Key not found")

    ssh_key_data = result["ssh_key_data"]

    log_api_access(server, username, client_ip, "SUCCESS", "Key provided")
    return {"ssh_key": ssh_key_data}