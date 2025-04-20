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

# -- List SSH Keys --
@admin_router.get("/admin/ssh-keys", response_class=HTMLResponse)
async def ssh_keys_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    # Fetch keys and assigned users
    keys = conn.execute('SELECT * FROM ssh_keys').fetchall()
    ssh_keys = []

    for key in keys:
        assigned_users = conn.execute(
            '''
            SELECT users.id, users.username 
            FROM assignments 
            JOIN users ON assignments.user_id = users.id
            WHERE assignments.ssh_key_id = ?
            ''',
            (key["id"],)
        ).fetchall()

        ssh_keys.append({
            "id": key["id"],
            "key_name": key["key_name"],
            "expiration_date": key["expiration_date"],
            "locked": key["locked"],
            "assigned_users": assigned_users
        })

    conn.close()
    return templates.TemplateResponse("ssh_keys.html", {"request": request, "ssh_keys": ssh_keys})

# -- Lock SSH Key --
@admin_router.post("/admin/ssh-keys/lock/{key_id}")
async def lock_ssh_key(key_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    conn.execute('UPDATE ssh_keys SET locked = 1 WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("admin_user"), "Locked SSH key", str(key_id))
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

# -- Unlock SSH Key --
@admin_router.post("/admin/ssh-keys/unlock/{key_id}")
async def unlock_ssh_key(key_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    conn.execute('UPDATE ssh_keys SET locked = 0 WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("admin_user"), "Unlocked SSH key", str(key_id))
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

# -- Delete SSH Key --
@admin_router.post("/admin/ssh-keys/delete/{key_id}")
async def delete_ssh_key(key_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    # Optional: First delete assignments related to this key
    conn.execute('DELETE FROM assignments WHERE ssh_key_id = ?', (key_id,))
    conn.execute('DELETE FROM ssh_keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("admin_user"), "Deleted SSH key", str(key_id))
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

# -- Unassign User from SSH Key --
@admin_router.post("/admin/ssh-keys/unassign/{key_id}/{user_id}")
async def unassign_ssh_user(key_id: int, user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    conn.execute('DELETE FROM assignments WHERE ssh_key_id = ? AND user_id = ?', (key_id, user_id))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("admin_user"), "Unassigned user from SSH key", f"KeyID {key_id} UserID {user_id}")
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)
