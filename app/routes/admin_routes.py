from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from auth.auth import authenticate_admin, get_current_admin_user, logout_admin
from services.ip_filter_service import is_admin_ip_allowed
from services.security_service import update_admin_password, verify_admin_password, create_user, update_user, is_admin, is_ssh_user
from models.models import init_db, get_db_connection, log_admin_action, get_setting, set_setting, encrypt_password
from services.email_service import send_email
from services.token_service import generate_reset_token, verify_reset_token, delete_reset_token
from services.encryption_service import encrypt_sensitive_value, decrypt_sensitive_value, ENCRYPTION_KEY
from config import templates
import secrets
import os
import hmac
from datetime import datetime, timedelta
from services.provisioning_service import trigger_provisioning_task, trigger_unprovisioning_task







init_db()

admin_router = APIRouter()


    # Dashboard


    # Change password



# Settings

@admin_router.get("/admin/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user: str = Depends(get_current_admin_user)):
    settings = {key: get_setting(key) for key in ["enforce_password_complexity", "restrict_admin_ip", "admin_session_timeout", "domain", "smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_from"]}
    success = request.query_params.get("success")
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "settings": settings,
            "success": success
        }
    )

@admin_router.post("/admin/settings")
async def update_settings(
    request: Request,
    enforce_password_complexity: str = Form(None),
    restrict_admin_ip: str = Form(None),
    admin_session_timeout: str = Form(""),
    domain: str = Form(""),
    smtp_host: str = Form(""),
    smtp_port: str = Form(""),
    smtp_user: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form("")
):
    set_setting('enforce_password_complexity', '1' if enforce_password_complexity else '0')
    set_setting('restrict_admin_ip', '1' if restrict_admin_ip else '0')
    set_setting('admin_session_timeout', admin_session_timeout)
    set_setting('domain', domain)
    set_setting('smtp_host', smtp_host)
    set_setting('smtp_port', smtp_port)
    set_setting('smtp_user', smtp_user)

    smtp_password = smtp_password.strip()
    if smtp_password:
        encrypted_smtp_password = encrypt_sensitive_value(smtp_password)
        set_setting('smtp_password', encrypted_smtp_password)
    else:
        existing_encrypted_password = get_setting('smtp_password')
        set_setting('smtp_password', existing_encrypted_password)

    set_setting('smtp_from', smtp_from)

    return RedirectResponse(url="/admin/settings?success=1", status_code=303)
    # --- SSH USERS MANAGEMENT ---



# --- SSH KEYS MANAGEMENT ---


    # -- Unassign User from SSH Key --
@admin_router.post("/admin/ssh-keys/unassign/{key_id}/{user_id}")
async def unassign_ssh_user(key_id: int, user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    if is_ssh_user(request):
        conn.close()
        raise HTTPException(status_code=403, detail="Unauthorized to unassign SSH keys.")

    key_rec = conn.execute('SELECT key_name FROM ssh_keys WHERE id = ?', (key_id,)).fetchone()
    key_name = key_rec["key_name"] if key_rec else f"KeyID {key_id}"

    user_rec = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    username = user_rec["username"] if user_rec else f"UserID {user_id}"

    conn.execute('DELETE FROM assignments WHERE ssh_key_id = ? AND user_id = ?', (key_id, user_id))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Unassigned SSH key from user", f"{key_name} ← {username}")

    return RedirectResponse(url="/admin/ssh-keys", status_code=303)


# -- Assign SSH Keys to User --
@admin_router.get("/admin/assign-key/{user_id}", response_class=HTMLResponse)
async def assign_key_page(user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    if is_ssh_user(request):
        raise HTTPException(status_code=403, detail="Unauthorized to assign SSH keys.")
    conn = get_db_connection()

    user_row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user_row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    all_keys = conn.execute('SELECT * FROM ssh_keys').fetchall()
    assigned_keys = conn.execute('SELECT ssh_key_id FROM assignments WHERE user_id = ?', (user_id,)).fetchall()
    assigned_key_ids = [row["ssh_key_id"] for row in assigned_keys]

    conn.close()

    return templates.TemplateResponse("assign_key_to_user.html", {
        "request": request,
        "user": user_row,
        "ssh_keys": all_keys,
        "assigned_key_ids": assigned_key_ids
    })

@admin_router.post("/admin/assign-key/{user_id}")
async def assign_key_submit(user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    if is_ssh_user(request):
        raise HTTPException(status_code=403, detail="Unauthorized to assign SSH keys.")

    form = await request.form()
    selected_keys = form.getlist("ssh_keys")

    conn = get_db_connection()

    conn.execute('DELETE FROM assignments WHERE user_id = ?', (user_id,))

    for key_id in selected_keys:
        conn.execute('INSERT INTO assignments (ssh_key_id, user_id) VALUES (?, ?)', (key_id, user_id))

    conn.commit()

    user_rec = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    username = user_rec["username"] if user_rec else f"UserID {user_id}"

    if selected_keys:
        key_ids = tuple(int(k) for k in selected_keys)
        placeholders = "(?)" if len(key_ids) == 1 else f"({','.join(['?']*len(key_ids))})"
        key_names_query = f'SELECT key_name FROM ssh_keys WHERE id IN {placeholders}'
        key_recs = conn.execute(key_names_query, key_ids).fetchall()
        key_names = [rec["key_name"] for rec in key_recs]
        key_names_str = ", ".join(key_names)
    else:
        key_names_str = "No Keys Assigned"

    conn.close()

    log_admin_action(request.session.get("username"), "Assigned SSH keys to user", f"[{key_names_str}] → {username}")

    return RedirectResponse(url="/admin/ssh-users", status_code=303)




# --- Server Management (no change needed, admin-only already protected properly) ---
#Server Manager key assign


# --- Allowed IPs Management (no change needed, admin-only already protected properly) ---
#allowed IPs

@admin_router.get("/admin/allowed-ips", response_class=HTMLResponse)
async def allowed_ips_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    allowed_ips = conn.execute('SELECT * FROM allowed_api_sources').fetchall()
    conn.close()
    return templates.TemplateResponse("allowed_ips.html", {"request": request, "allowed_ips": allowed_ips})

@admin_router.get("/admin/allowed-ips/add", response_class=HTMLResponse)
async def add_allowed_ip_page(request: Request, user: str = Depends(get_current_admin_user)):
    return templates.TemplateResponse("add_allowed_ip.html", {"request": request})

@admin_router.post("/admin/allowed-ips/add")
async def add_allowed_ip(request: Request, 
                          ip_or_cidr_or_asn: str = Form(...), 
                          type: str = Form(...),
                          description: str = Form(""),
                          context: str = Form("api"),
                          user: str = Depends(get_current_admin_user)):
    if type not in ("ip", "cidr", "asn"):
        raise HTTPException(status_code=400, detail="Invalid type value. Must be 'ip', 'cidr', or 'asn'.")
    conn = get_db_connection()
    conn.execute('INSERT INTO allowed_api_sources (ip_or_cidr_or_asn, type, description, context) VALUES (?, ?, ?, ?)',
                 (ip_or_cidr_or_asn, type, description, context))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Added Allowed IP/ASN", ip_or_cidr_or_asn)

    return RedirectResponse(url="/admin/allowed-ips", status_code=303)

@admin_router.get("/admin/allowed-ips/edit/{allowed_id}", response_class=HTMLResponse)
async def edit_allowed_ip_page(allowed_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    allowed_ip = conn.execute('SELECT * FROM allowed_api_sources WHERE id = ?', (allowed_id,)).fetchone()
    conn.close()

    if not allowed_ip:
        raise HTTPException(status_code=404, detail="Allowed IP/ASN not found")

    return templates.TemplateResponse("edit_allowed_ip.html", {"request": request, "allowed_ip": allowed_ip})

@admin_router.post("/admin/allowed-ips/edit/{allowed_id}")
async def edit_allowed_ip(allowed_id: int,
                          request: Request,
                          ip_or_cidr_or_asn: str = Form(...),
                          type: str = Form(...),
                          description: str = Form(""),
                          context: str = Form("api"),
                          user: str = Depends(get_current_admin_user)):
    if type not in ("ip", "cidr", "asn"):
        raise HTTPException(status_code=400, detail="Invalid type value. Must be 'ip', 'cidr', or 'asn'.")
    conn = get_db_connection()
    conn.execute('UPDATE allowed_api_sources SET ip_or_cidr_or_asn = ?, type = ?, description = ?, context = ? WHERE id = ?',
                 (ip_or_cidr_or_asn, type, description, context, allowed_id))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Edited Allowed IP/ASN", ip_or_cidr_or_asn)

    return RedirectResponse(url="/admin/allowed-ips", status_code=303)

@admin_router.post("/admin/allowed-ips/delete/{allowed_id}")
async def delete_allowed_ip(allowed_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    allowed_ip = conn.execute('SELECT * FROM allowed_api_sources WHERE id = ?', (allowed_id,)).fetchone()
    if not allowed_ip:
        conn.close()
        raise HTTPException(status_code=404, detail="Allowed IP/ASN not found")

    conn.execute('DELETE FROM allowed_api_sources WHERE id = ?', (allowed_id,))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Deleted Allowed IP/ASN", allowed_ip["ip_or_cidr_or_asn"])

    return RedirectResponse(url="/admin/allowed-ips", status_code=303)

# --- API Logs Page ---
@admin_router.get("/admin/api-logs", response_class=HTMLResponse)
async def api_logs_page(request: Request, user: str = Depends(get_current_admin_user)):
    search = request.query_params.get("search", "").strip()
    conn = get_db_connection()
    if search:
        query = """
        SELECT * FROM api_logs
        WHERE LOWER(username) LIKE ?
           OR LOWER(server_name) LIKE ?
           OR LOWER(client_ip) LIKE ?
           OR LOWER(reason) LIKE ?
        ORDER BY timestamp DESC
        LIMIT 100
        """
        pattern = f"%{search.lower()}%"
        api_logs = conn.execute(query, (pattern, pattern, pattern, pattern)).fetchall()
    else:
        query = "SELECT * FROM api_logs ORDER BY timestamp DESC LIMIT 100"
        api_logs = conn.execute(query).fetchall()
    conn.close()
    return templates.TemplateResponse("api_logs.html", {"request": request, "api_logs": api_logs, "search": search})

# --- ADMIN LOGS ---
@admin_router.get("/admin/logs", response_class=HTMLResponse)
async def view_admin_logs(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    # Fetch admin action logs
    admin_logs = conn.execute('SELECT id, admin_username, action, object_modified, NULL as ip_address, timestamp FROM admin_logs').fetchall()

    # Fetch login attempts (both success and failed) and map action dynamically
    login_logs_raw = conn.execute('SELECT id, username as admin_username, success, ip_address, timestamp FROM login_attempts').fetchall()

    login_logs = []
    for log in login_logs_raw:
        action_text = "Login Success" if log["success"] else "Login Failed"
        login_logs.append({
            "id": log["id"],
            "admin_username": log["admin_username"],
            "action": action_text,
            "object_modified": None,
            "ip_address": log["ip_address"],
            "timestamp": log["timestamp"]
        })

    conn.close()

# Merge admin_logs + login_logs
    all_logs = list(admin_logs) + login_logs
    all_logs.sort(key=lambda x: x["timestamp"], reverse=True)

    return templates.TemplateResponse("admin_logs.html", {"request": request, "logs": all_logs})

 # EMAIL LOGS
@admin_router.get("/admin/email-logs", response_class=HTMLResponse)
async def view_email_logs(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    email_logs = conn.execute('SELECT * FROM email_logs ORDER BY timestamp DESC').fetchall()
    conn.close()

    return templates.TemplateResponse("email_logs.html", {"request": request, "logs": email_logs})


# proxy
@admin_router.get("/admin/gateway-proxies", response_class=HTMLResponse)
async def list_gateway_proxies(request: Request):
    conn = get_db_connection()
    proxies = conn.execute('SELECT * FROM gateway_proxies').fetchall()
    conn.close()
    return templates.TemplateResponse("gateway_proxies.html", {"request": request, "proxies": proxies})

@admin_router.get("/admin/gateway-proxies/add", response_class=HTMLResponse)
async def add_gateway_proxy_form(request: Request):
    return templates.TemplateResponse("add_gateway_proxy.html", {"request": request})

@admin_router.post("/admin/gateway-proxies/add")
async def add_gateway_proxy(request: Request, proxy_name: str = Form(...), proxy_ip: str = Form(...), proxy_port: int = Form(...)):
    proxy_auth_token = secrets.token_hex(32)
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO gateway_proxies (proxy_name, proxy_ip, proxy_port, proxy_type, proxy_auth_token)
        VALUES (?, ?, ?, 'active', ?)
    ''', (proxy_name, proxy_ip, proxy_port, proxy_auth_token))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/gateway-proxies", status_code=303)

@admin_router.post("/admin/gateway-proxies/delete/{proxy_id}")
async def delete_gateway_proxy(request: Request, proxy_id: int):
    conn = get_db_connection()
    conn.execute('DELETE FROM gateway_proxies WHERE id = ?', (proxy_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/gateway-proxies", status_code=303)

#tasks logs
@admin_router.get("/admin/provision-task", response_class=HTMLResponse)
async def provision_task_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    tasks_raw = conn.execute('''
        SELECT pt.id, pt.status, pt.type, u.username, s.server_name, gp.proxy_name
        FROM provisioning_tasks pt
        JOIN users u ON pt.user_id = u.id
        JOIN servers s ON pt.server_id = s.id
        LEFT JOIN gateway_proxies gp ON s.proxy_id = gp.id
        ORDER BY pt.id DESC
        LIMIT 50
    ''').fetchall()
    logs = conn.execute('SELECT task_id, log_text FROM provisioning_logs ORDER BY id DESC').fetchall()
    conn.close()

    logs_dict = {}
    for log in logs:
        if log["task_id"] not in logs_dict:
            logs_dict[log["task_id"]] = []
        logs_dict[log["task_id"]].append(log["log_text"])

    # Ensure tasks includes type field for template context
    tasks = []
    for t in tasks_raw:
        tasks.append({
            "id": t["id"],
            "status": t["status"],
            "type": t["type"],
            "username": t["username"],
            "server_name": t["server_name"],
            "proxy_name": t["proxy_name"],
        })

    return templates.TemplateResponse("provision_tasks.html", {
        "request": request,
        "tasks": tasks,
        "logs": logs_dict
    })

# system ssh key
@admin_router.get("/admin/system-ssh-keys", response_class=HTMLResponse)
async def system_ssh_keys(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    keys = conn.execute("SELECT id, key_name, created_at, comment FROM system_ssh_keys ORDER BY id DESC").fetchall()
    conn.close()
    return templates.TemplateResponse("system_ssh_keys.html", {
        "request": request,
        "keys": keys
    })

    
@admin_router.get("/admin/system-ssh-keys/add", response_class=HTMLResponse)
async def add_system_ssh_key_form(request: Request, user: str = Depends(get_current_admin_user)):
    return templates.TemplateResponse("add_system_ssh_key.html", {"request": request})

@admin_router.post("/admin/system-ssh-keys/add", response_class=HTMLResponse)
async def save_system_ssh_key(
    request: Request,
    key_name: str = Form(...),
    key_data: str = Form(...),
    key_password: str = Form(None),
    comment: str = Form(None),
    user: str = Depends(get_current_admin_user)
):
    encrypted_key = encrypt_sensitive_value(key_data)
    encrypted_password = encrypt_sensitive_value(key_password) if key_password else None

    conn = get_db_connection()
    conn.execute('''
        INSERT INTO system_ssh_keys (key_name, key_data, key_password, comment)
        VALUES (?, ?, ?, ?)
    ''', (key_name, encrypted_key, encrypted_password, comment))
    conn.commit()
    conn.close()

    log_admin_action(user, f"Added system SSH key: {key_name}")
    return RedirectResponse(url="/admin/system-ssh-keys", status_code=303)

@admin_router.post("/admin/system-ssh-keys/delete/{key_id}", response_class=HTMLResponse)
async def delete_system_ssh_key(
    request: Request,
    key_id: int,
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()
    key = conn.execute("SELECT key_name FROM system_ssh_keys WHERE id = ?", (key_id,)).fetchone()

    if key:
        conn.execute("DELETE FROM system_ssh_keys WHERE id = ?", (key_id,))
        conn.commit()
        log_admin_action(user, f"Deleted system SSH key: {key['key_name']}")

    conn.close()
    return RedirectResponse(url="/admin/system-ssh-keys", status_code=303)

@admin_router.get("/admin/system-ssh-keys/edit/{key_id}", response_class=HTMLResponse)
async def edit_system_ssh_key_form(request: Request, key_id: int, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    key = conn.execute("SELECT id, key_name, comment FROM system_ssh_keys WHERE id = ?", (key_id,)).fetchone()
    conn.close()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    return templates.TemplateResponse("edit_system_ssh_key.html", {"request": request, "key": key})

@admin_router.post("/admin/system-ssh-keys/edit/{key_id}", response_class=HTMLResponse)
async def update_system_ssh_key(
    request: Request,
    key_id: int,
    key_name: str = Form(...),
    comment: str = Form(None),
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()
    conn.execute('''
        UPDATE system_ssh_keys
        SET key_name = ?, comment = ?
        WHERE id = ?
    ''', (key_name, comment, key_id))
    conn.commit()
    conn.close()

    log_admin_action(user, f"Updated system SSH key #{key_id}: {key_name}")
    return RedirectResponse(url="/admin/system-ssh-keys", status_code=303)

@admin_router.get("/admin/system-ssh-keys/rotate/{key_id}", response_class=HTMLResponse)
async def rotate_system_ssh_key_form(request: Request, key_id: int, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    key = conn.execute("SELECT id, key_name FROM system_ssh_keys WHERE id = ?", (key_id,)).fetchone()
    conn.close()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    return templates.TemplateResponse("rotate_system_ssh_key.html", {"request": request, "key": key})

from services.encryption_service import encrypt_sensitive_value

@admin_router.post("/admin/system-ssh-keys/rotate/{key_id}", response_class=HTMLResponse)
async def rotate_system_ssh_key(
    request: Request,
    key_id: int,
    key_data: str = Form(...),
    key_password: str = Form(None),
    user: str = Depends(get_current_admin_user)
):
    encrypted_key = encrypt_sensitive_value(key_data)
    encrypted_password = encrypt_sensitive_value(key_password) if key_password else None

    conn = get_db_connection()
    conn.execute('''
        UPDATE system_ssh_keys
        SET key_data = ?, key_password = ?
        WHERE id = ?
    ''', (encrypted_key, encrypted_password, key_id))
    conn.commit()
    conn.close()

    log_admin_action(user, f"Rotated system SSH key #{key_id}")
    return RedirectResponse(url="/admin/system-ssh-keys", status_code=303)

#email send
@admin_router.post("/admin/internal/user-to-server-assigned")
async def notify_user_password_post(request: Request, task_id: int = Form(...), token: str = Form(...)):

    if not hmac.compare_digest(token, ENCRYPTION_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_db_connection()
    task = conn.execute("SELECT * FROM provisioning_tasks WHERE id = ?", (task_id,)).fetchone()
    if not task:
        conn.close()
        raise HTTPException(status_code=404, detail="Task not found")

    user = conn.execute("SELECT username, email FROM users WHERE id = ?", (task["user_id"],)).fetchone()
    server = conn.execute("SELECT server_name FROM servers WHERE id = ?", (task["server_id"],)).fetchone()

    if not user or not server or not task["generated_password"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Incomplete data")

    password = decrypt_sensitive_value(task["generated_password"])

    email_body = templates.get_template("email/assignment_notification.html").render({
        "username": user["username"],
        "server": server["server_name"],
        "password": password,
        "year": datetime.utcnow().year
    })

    send_email(user["email"], f"Your SSH Access to {server['server_name']}", email_body)

    conn.execute("UPDATE provisioning_tasks SET generated_password = NULL WHERE id = ?", (task_id,))
    conn.commit()
    conn.close()

    log_admin_action(user["username"], "SSH credentials sent via email", server["server_name"])
    return {"status": "ok"}

@admin_router.post("/admin/internal/user-to-server-unassigned")
async def notify_user_unassigned_post(request: Request, task_id: int = Form(...), token: str = Form(...)):
    from services.encryption_service import decrypt_sensitive_value, ENCRYPTION_KEY
    import hmac
    from jinja2 import Environment, FileSystemLoader
    from datetime import datetime
    from services.email_service import send_email

    if not hmac.compare_digest(token, ENCRYPTION_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_db_connection()
    task = conn.execute("SELECT * FROM provisioning_tasks WHERE id = ?", (task_id,)).fetchone()
    if not task:
        conn.close()
        raise HTTPException(status_code=404, detail="Task not found")

    user = conn.execute("SELECT username, email FROM users WHERE id = ?", (task["user_id"],)).fetchone()
    server = conn.execute("SELECT server_name FROM servers WHERE id = ?", (task["server_id"],)).fetchone()
    conn.close()

    if not user or not server:
        raise HTTPException(status_code=400, detail="Incomplete data")

    templates = Environment(loader=FileSystemLoader("templates"))
    email_body = templates.get_template("email/unassignment_notification.html").render({
        "username": user["username"],
        "server": server["server_name"],
        "year": datetime.utcnow().year
    })

    send_email(user["email"], f"Access Revoked: {server['server_name']}", email_body)
    log_admin_action(user["username"], "SSH access revoked", server["server_name"])
    return {"status": "ok"}