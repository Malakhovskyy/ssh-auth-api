from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from auth.auth import authenticate_admin, get_current_admin_user, logout_admin
from services.ip_filter_service import is_admin_ip_allowed
from services.security_service import update_admin_password, verify_admin_password, create_user, update_user, is_admin, is_ssh_user
from models.models import init_db, get_db_connection, log_admin_action, get_setting, set_setting, encrypt_password
from services.email_service import send_password_reset_email
from services.token_service import generate_reset_token, verify_reset_token
from services.encryption_service import encrypt_sensitive_value, decrypt_sensitive_value
from config import templates
import os
from datetime import datetime, timedelta

init_db()

admin_router = APIRouter()

@admin_router.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request):
    restrict_admin_ip = get_setting('restrict_admin_ip')
    if restrict_admin_ip == '1':
        x_forwarded_for = request.headers.get('x-forwarded-for')
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.client.host
        if not is_admin_ip_allowed(client_ip):
            return templates.TemplateResponse("access_denied.html", {"request": request})

    error = request.query_params.get("error")
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

@admin_router.post("/admin/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    x_forwarded_for = request.headers.get('x-forwarded-for')
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(',')[0].strip()
    else:
        ip_address = request.client.host

    restrict_admin_ip = get_setting('restrict_admin_ip')
    if restrict_admin_ip == '1':
        if not is_admin_ip_allowed(ip_address):
            return templates.TemplateResponse("access_denied.html", {"request": request})

    user = authenticate_admin(username, password, ip_address)
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    # ✅ Set session values
    request.session["username"] = user["username"]
    request.session["login_time"] = datetime.utcnow().isoformat()  # ✅ Save login time for timeout control
    request.session["context"] = user["context"]  # Store user context (admin/ssh_user)
    request.session["user_id"] = user["id"]        # Store user id
    if user["must_change_password"]:
        return RedirectResponse(url="/admin/change-password", status_code=303)
    return RedirectResponse(url="/admin/dashboard", status_code=303)

@admin_router.get("/admin/logout")
async def logout(request: Request):
    logout_admin(request)
    return RedirectResponse(url="/admin/login")
    # Dashboard

@admin_router.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: str = Depends(get_current_admin_user)):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "data": {
            "db_size": 0,
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "top_users": [],
            "top_servers": [],
            "top_failed_users": [],
            "period": "1h"
        }
    })

@admin_router.get("/admin/dashboard-dbsize")
async def dashboard_dbsize():
    db_path = "/app/data/sshkeys.db"
    db_size = round(os.path.getsize(db_path) / 1024 / 1024, 2) if os.path.exists(db_path) else 0
    return {"db_size": db_size}

@admin_router.get("/admin/dashboard-totals")
async def dashboard_totals(period: str = "1h"):
    conn = get_db_connection()
    try:
        hours = int(period.replace('h', ''))
        since_api = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

        total_requests = conn.execute("SELECT COUNT(*) FROM api_logs WHERE timestamp >= ?", (since_api,)).fetchone()[0]
        successful_requests = conn.execute("SELECT COUNT(*) FROM api_logs WHERE success = 1 AND timestamp >= ?", (since_api,)).fetchone()[0]
        failed_requests = total_requests - successful_requests
    finally:
        conn.close()

    return {
        "total_requests": total_requests,
        "successful_requests": successful_requests,
        "failed_requests": failed_requests
    }

@admin_router.get("/admin/dashboard-users")
async def dashboard_users(period: str = "1h"):
    conn = get_db_connection()
    since = (datetime.utcnow() - timedelta(hours=int(period.replace('h', '')))).strftime("%Y-%m-%d %H:%M:%S")
    users = conn.execute("""
        SELECT username, COUNT(*) as cnt FROM api_logs
        WHERE success = 1 AND timestamp >= ?
        GROUP BY username ORDER BY cnt DESC LIMIT 5
    """, (since,)).fetchall()
    conn.close()
    return [{"name": row["username"], "success_count": row["cnt"]} for row in users]

@admin_router.get("/admin/dashboard-servers")
async def dashboard_servers(period: str = "1h"):
    conn = get_db_connection()
    since = (datetime.utcnow() - timedelta(hours=int(period.replace('h', '')))).strftime("%Y-%m-%d %H:%M:%S")
    servers = conn.execute("""
        SELECT server_name, COUNT(*) as cnt FROM api_logs
        WHERE success = 1 AND timestamp >= ?
        GROUP BY server_name ORDER BY cnt DESC LIMIT 5
    """, (since,)).fetchall()
    conn.close()
    return [{"name": row["server_name"], "request_count": row["cnt"]} for row in servers]

@admin_router.get("/admin/dashboard-failed-users")
async def dashboard_failed_users(period: str = "1h"):
    conn = get_db_connection()
    since = (datetime.utcnow() - timedelta(hours=int(period.replace('h', '')))).strftime("%Y-%m-%d %H:%M:%S")
    users = conn.execute("""
        SELECT username, COUNT(*) as cnt FROM api_logs
        WHERE success = 0 AND timestamp >= ?
        GROUP BY username ORDER BY cnt DESC LIMIT 5
    """, (since,)).fetchall()
    conn.close()
    return [{"name": row["username"], "failure_count": row["cnt"]} for row in users]
    # Change password

@admin_router.get("/admin/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    return templates.TemplateResponse("change_password.html", {"request": request})

@admin_router.post("/admin/change-password")
async def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...), confirm_password: str = Form(...)):
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_db_connection()
    user_record = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user_record:
        conn.close()
        raise HTTPException(status_code=400, detail="User not found.")

    valid = await verify_admin_password(user_record, old_password)
    if not valid:
        conn.close()
        return templates.TemplateResponse("change_password.html", {"request": request, "error": "Incorrect old password"})

    if new_password != confirm_password:
        conn.close()
        return templates.TemplateResponse("change_password.html", {"request": request, "error": "New passwords do not match"})

    conn.close()

    success, error = await update_admin_password(username, new_password)
    if not success:
        return templates.TemplateResponse("change_password.html", {"request": request, "error": error})

    log_admin_action(username, "Changed password")
    request.session.pop("username", None)
    return RedirectResponse(url="/admin/login", status_code=303)


# Forgot password

@admin_router.get("/admin/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@admin_router.post("/admin/forgot-password")
async def forgot_password(request: Request, email: str = Form(...)):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()

    if not user:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Email not found."})

    token = generate_reset_token(user['username'])
    reset_link = f"{request.url.scheme}://{request.url.hostname}/admin/reset-password/{token}"

    send_password_reset_email(email, reset_link)

    return templates.TemplateResponse("forgot_password.html", {"request": request, "message": "Password reset link sent to your email."})

@admin_router.get("/admin/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_page(token: str, request: Request):
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})

@admin_router.post("/admin/reset-password/{token}")
async def reset_password(token: str, request: Request, new_password: str = Form(...), confirm_password: str = Form(...)):
    if new_password != confirm_password:
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "error": "Passwords do not match."})

    username = verify_reset_token(token)
    if not username:
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "error": "Invalid or expired token."})

    success, error = await update_admin_password(username, new_password)
    if not success:
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "error": error})

    return RedirectResponse(url="/admin/login", status_code=303)


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

@admin_router.get("/admin/ssh-users", response_class=HTMLResponse)
async def ssh_users_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return templates.TemplateResponse("ssh_users.html", {"request": request, "users": users})

@admin_router.get("/admin/ssh-users/add", response_class=HTMLResponse)
async def add_ssh_user_page(request: Request, user: str = Depends(get_current_admin_user)):
    return templates.TemplateResponse("add_ssh_user.html", {"request": request})

@admin_router.post("/admin/ssh-users/add")
async def add_ssh_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    expiration_date: str = Form(...),
    never_expires: str = Form(None),
    locked: str = Form(None),
    password: str = Form(None),
    context: str = Form(...),
    user: str = Depends(get_current_admin_user)
):
    if never_expires:
        expiration_date = "2099-12-31 23:59:59"

    if context == "admin" and not password:
        return templates.TemplateResponse(
            "add_ssh_user.html",
            {
                "request": request,
                "error": "Password is required for Admin users.",
                "prefill_username": username,
                "prefill_email": email,
                "prefill_expiration_date": expiration_date,
                "prefill_locked": locked
            }
        )

    success, error = await create_user(username, password or "", email, context)
    if not success:
        return templates.TemplateResponse(
            "add_ssh_user.html",
            {
                "request": request,
                "error": error,
                "prefill_username": username,
                "prefill_email": email,
                "prefill_expiration_date": expiration_date,
                "prefill_locked": locked
            }
        )

    log_admin_action(request.session.get("username"), "Added user", username)
    return RedirectResponse(url="/admin/ssh-users", status_code=303)


# --- SSH KEYS MANAGEMENT ---

@admin_router.get("/admin/ssh-keys", response_class=HTMLResponse)
async def ssh_keys_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    current_user_id = request.session.get("user_id")

    if is_ssh_user(request):
        keys = conn.execute('''
            SELECT ssh_keys.*, users.username AS owner_name
            FROM ssh_keys
            LEFT JOIN users ON ssh_keys.owner_id = users.id
            WHERE ssh_keys.owner_id = ?
        ''', (current_user_id,)).fetchall()
    else:
        keys = conn.execute('''
            SELECT ssh_keys.*, users.username AS owner_name
            FROM ssh_keys
            LEFT JOIN users ON ssh_keys.owner_id = users.id
        ''').fetchall()

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
            "assigned_users": assigned_users,
            "owner_name": key["owner_name"]
        })

    conn.close()
    return templates.TemplateResponse("ssh_keys.html", {"request": request, "ssh_keys": ssh_keys})
    # -- Add SSH Key (GET page) --
@admin_router.get("/admin/ssh-keys/add", response_class=HTMLResponse)
async def add_ssh_key_page(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    users = conn.execute('SELECT id, username FROM users').fetchall()
    conn.close()

    return templates.TemplateResponse("add_ssh_key.html", {
        "request": request,
        "users": users
    })

# -- Add SSH Key (POST form submit) --
@admin_router.post("/admin/ssh-keys/add")
async def add_ssh_key(
    request: Request,
    key_name: str = Form(...),
    expiration_date: str = Form(...),
    never_expires: str = Form(None),
    locked: str = Form(None),
    ssh_key_data: str = Form(...),
    owner_id: int = Form(...),
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()

    if never_expires:
        expiration_date = "2099-12-31 23:59:59"
    is_locked = 1 if locked else 0

    encrypted_key_data = encrypt_sensitive_value(ssh_key_data)

    owner_id_final = request.session.get("user_id") if is_ssh_user(request) else owner_id

    conn.execute(
        'INSERT INTO ssh_keys (key_name, expiration_date, locked, ssh_key_data, owner_id) VALUES (?, ?, ?, ?, ?)',
        (key_name, expiration_date, is_locked, encrypted_key_data, owner_id_final)
    )

    new_key_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

    if is_ssh_user(request):
        conn.execute(
            'INSERT INTO assignments (ssh_key_id, user_id) VALUES (?, ?)',
            (new_key_id, request.session.get("user_id"))
        )

    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Created SSH key", key_name)

    return RedirectResponse(url="/admin/ssh-keys", status_code=303)


# -- Edit SSH Key (GET page) --
@admin_router.get("/admin/ssh-keys/edit/{key_id}", response_class=HTMLResponse)
async def edit_ssh_key_page(key_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    key_data = conn.execute('SELECT * FROM ssh_keys WHERE id = ?', (key_id,)).fetchone()
    users = conn.execute('SELECT id, username FROM users').fetchall()

    if not key_data:
        conn.close()
        return RedirectResponse(url="/admin/ssh-keys", status_code=303)

    if is_ssh_user(request) and key_data["owner_id"] != request.session.get("user_id"):
        conn.close()
        raise HTTPException(status_code=403, detail="Unauthorized to edit this key")

    conn.close()

    decrypted_key_data = decrypt_sensitive_value(key_data['ssh_key_data'])

    return templates.TemplateResponse("edit_ssh_key.html", {
        "request": request,
        "key_data": key_data,
        "decrypted_key_data": decrypted_key_data,
        "users": users
    })

# -- Edit SSH Key (POST) --
@admin_router.post("/admin/ssh-keys/edit/{key_id}")
async def edit_ssh_key(
    key_id: int,
    request: Request,
    key_name: str = Form(...),
    expiration_date: str = Form(...),
    never_expires: str = Form(None),
    locked: str = Form(None),
    ssh_key_data: str = Form(...),
    owner_id: int = Form(...),
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()

    if never_expires:
        expiration_date = "2099-12-31 23:59:59"
    is_locked = 1 if locked else 0
    encrypted_key_data = encrypt_sensitive_value(ssh_key_data)

    owner_id_final = request.session.get("user_id") if is_ssh_user(request) else owner_id

    conn.execute(
        'UPDATE ssh_keys SET key_name = ?, expiration_date = ?, locked = ?, ssh_key_data = ?, owner_id = ? WHERE id = ?',
        (key_name, expiration_date, is_locked, encrypted_key_data, owner_id_final, key_id)
    )
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Edited SSH key", key_name)
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

# -- Delete SSH Key --
@admin_router.post("/admin/ssh-keys/delete/{key_id}")
async def delete_ssh_key(key_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    row = conn.execute('SELECT key_name, owner_id FROM ssh_keys WHERE id = ?', (key_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="SSH Key not found")

    if is_ssh_user(request) and row["owner_id"] != request.session.get("user_id"):
        conn.close()
        raise HTTPException(status_code=403, detail="Unauthorized to delete this key")

    key_name = row["key_name"]

    assigned_users = conn.execute('''
        SELECT users.username 
        FROM assignments 
        JOIN users ON assignments.user_id = users.id 
        WHERE assignments.ssh_key_id = ?
    ''', (key_id,)).fetchall()

    usernames = [u["username"] for u in assigned_users]

    conn.execute('DELETE FROM assignments WHERE ssh_key_id = ?', (key_id,))
    conn.execute('DELETE FROM ssh_keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()

    if usernames:
        user_list = ", ".join(usernames)
        modified_object = f"Deleted SSH Key '{key_name}' assigned to users: {user_list}"
    else:
        modified_object = f"Deleted SSH Key '{key_name}' (no users assigned)"

    log_admin_action(request.session.get("username"), "Deleted SSH key", modified_object)

    return RedirectResponse(url="/admin/ssh-keys", status_code=303)
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


# --- Allowed IPs Management (no change needed, admin-only already protected properly) ---


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