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
    redirect_url = "/admin/ssh-keys" if user["context"] == "ssh_user" else "/admin/dashboard"
    return RedirectResponse(url=redirect_url, status_code=303)

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
        log_admin_action("unknown", f"Password reset requested for non-existent email: {email}")
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Email not found."})

    domainname = get_setting('domain')
    token = generate_reset_token(user['username'])
    reset_link = f"https://{domainname}/admin/reset-password/{token}"
    subject = "SSH Key Manager - Password Reset"
    
    # Render the email body using the HTML template
    email_body = templates.get_template("email/password_reset_email.html").render({
        "reset_link": reset_link,
        "year": datetime.utcnow().year
    })
    send_email(email, subject, email_body)
    log_admin_action(user["username"], "Password reset requested", email)

    return RedirectResponse(url="/admin/forgot-password-sent", status_code=303)


# Confirmation page after sending password reset link
@admin_router.get("/admin/forgot-password-sent", response_class=HTMLResponse)
async def forgot_password_sent_page(request: Request):
    return templates.TemplateResponse("forgot_password_sent.html", {"request": request})

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

    # Get user's email from the username
    conn = get_db_connection()
    row = conn.execute('''
        SELECT email
        FROM users
        WHERE username = ?
    ''', (username,)).fetchone()
    conn.close()
    print(f"[DEBUG] row before if from users lookup: {row}")
    # Send confirmation email if possible
    if row:
        print(f"[DEBUG] row from users lookup: {row}")
        email = row["email"]
        subject = "SSH Key Manager - Password Changed"
        email_body = templates.get_template("email/password_changed_email.html").render({
            "year": datetime.utcnow().year
        })
        print(f"[DEBUG] Sending password changed email to {email}")
        send_email(email, subject, email_body)

    # Delete the reset token after successful password update
    delete_reset_token(token)
    # Write log
    log_admin_action(username, "Password reset completed")

    # Add a message to be displayed to the user after successful password reset
    return RedirectResponse(url="/admin/login?message=Password+updated+successfully", status_code=303)


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

# -- Edit SSH User (GET page) --
@admin_router.get("/admin/ssh-users/edit/{user_id}", response_class=HTMLResponse)
async def edit_ssh_user_page(user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if not user_data:
        raise HTTPException(status_code=404, detail="SSH user not found")

    return templates.TemplateResponse("edit_ssh_user.html", {"request": request, "user_data": user_data})

# -- Edit SSH User (POST save) --
@admin_router.post("/admin/ssh-users/edit/{user_id}")
async def edit_ssh_user(
    user_id: int,
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

    is_locked = 1 if locked else 0

    success, error = await update_user(user_id, username, email, expiration_date, is_locked, context, password)
    if not success:
        return templates.TemplateResponse("edit_ssh_user.html", {
            "request": request,
            "error": error,
            "user_data": {"id": user_id, "username": username, "email": email, "expiration_date": expiration_date, "locked": locked, "context": context}
        })

    log_admin_action(request.session.get("username"), "Edited SSH user", username)
    return RedirectResponse(url="/admin/ssh-users", status_code=303)
# -- Delete SSH User --
@admin_router.post("/admin/ssh-users/delete/{user_id}")
async def delete_ssh_user(user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user_data:
        conn.close()
        raise HTTPException(status_code=404, detail="SSH user not found")

    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Deleted SSH user", user_data["username"])

    return RedirectResponse(url="/admin/ssh-users", status_code=303)

# -- Lock SSH User --
@admin_router.post("/admin/ssh-users/lock/{user_id}")
async def lock_ssh_user(user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    row = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="SSH user not found")

    username = row["username"]  # ✅ Save username into variable

    conn.execute('UPDATE users SET locked = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    # ✅ Now safe to log
    log_admin_action(request.session.get("username"), "Locked SSH user", username)

    return RedirectResponse(url="/admin/ssh-users", status_code=303)

# -- Unlock SSH User --
@admin_router.post("/admin/ssh-users/unlock/{user_id}")
async def unlock_ssh_user(user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    row = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="SSH user not found")

    username = row["username"]

    conn.execute('UPDATE users SET locked = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Unlocked SSH user", username)

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

# lock key
@admin_router.post("/admin/ssh-keys/lock/{ssh_key_id}")
async def lock_ssh_key(request: Request, ssh_key_id: int):
    conn = get_db_connection()
    conn.execute('UPDATE ssh_keys SET locked = 1 WHERE id = ?', (ssh_key_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

@admin_router.post("/admin/ssh-keys/unlock/{ssh_key_id}")
async def unlock_ssh_key(request: Request, ssh_key_id: int):
    conn = get_db_connection()
    conn.execute('UPDATE ssh_keys SET locked = 0 WHERE id = ?', (ssh_key_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)


# --- Server Management (no change needed, admin-only already protected properly) ---
#Server Manager key assign
@admin_router.get("/admin/servers", response_class=HTMLResponse)
async def servers_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    servers = conn.execute('''
        SELECT servers.id, servers.server_name, servers.server_ip, servers.system_username,
               servers.server_ssh_port, servers.auth_token,
               gateway_proxies.proxy_name,
               ssh_keys.key_name as ssh_key_name
        FROM servers
        LEFT JOIN gateway_proxies ON servers.proxy_id = gateway_proxies.id
        LEFT JOIN ssh_keys ON servers.system_ssh_key_id = ssh_keys.id
    ''').fetchall()

    servers_data = []

    for server in servers:
        assigned_users = conn.execute('''
            SELECT users.id as user_id, users.username, ssh_keys.key_name
            FROM server_assignments
            JOIN users ON server_assignments.user_id = users.id
            JOIN ssh_keys ON server_assignments.ssh_key_id = ssh_keys.id
            WHERE server_assignments.server_id = ?
        ''', (server["id"],)).fetchall()

        servers_data.append({
            "id": server["id"],
            "server_name": server["server_name"],
            "server_ip": server["server_ip"],
            "system_username": server["system_username"],
            "server_ssh_port": server["server_ssh_port"],
            "auth_token": server["auth_token"],
            "proxy_name": server["proxy_name"],
            "ssh_key_name": server["ssh_key_name"],
            "assigned_users": assigned_users
        })

    conn.close()
    return templates.TemplateResponse("servers.html", {"request": request, "servers": servers_data})

@admin_router.get("/admin/servers/add", response_class=HTMLResponse)
async def add_server_page(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    ssh_keys = conn.execute('SELECT id, key_name FROM system_ssh_keys').fetchall()
    gateway_proxies = conn.execute('SELECT id, proxy_name, proxy_ip FROM gateway_proxies').fetchall()
    conn.close()
    return templates.TemplateResponse("add_server.html", {
        "request": request,
        "ssh_keys": ssh_keys,
        "gateway_proxies": gateway_proxies
    })

@admin_router.post("/admin/servers/add")
async def add_server(
    request: Request,
    server_name: str = Form(...),
    server_ip: str = Form(...),
    server_ssh_port: int = Form(...),
    system_username: str = Form(...),
    system_ssh_key_id: int = Form(...),
    proxy_id: int = Form(...),
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()
    existing_server = conn.execute('SELECT id FROM servers WHERE server_name = ?', (server_name,)).fetchone()
    if existing_server:
        ssh_keys = conn.execute('SELECT id, key_name FROM system_ssh_keys').fetchall()
        gateway_proxies = conn.execute('SELECT id, proxy_name, proxy_ip FROM gateway_proxies').fetchall()
        conn.close()
        return templates.TemplateResponse("add_server.html", {
            "request": request,
            "error": "Server name already exists.",
            "ssh_keys": ssh_keys,
            "gateway_proxies": gateway_proxies
        })

    auth_token = secrets.token_hex(32)
    conn.execute('''
        INSERT INTO servers (
            server_name, server_ip, server_ssh_port, system_username, 
            system_ssh_key_id, proxy_id, auth_token
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        server_name, server_ip, server_ssh_port, system_username,
        system_ssh_key_id, proxy_id, auth_token
    ))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Created server", server_name)
    return RedirectResponse(url="/admin/servers", status_code=303)

@admin_router.get("/admin/servers/edit/{server_id}", response_class=HTMLResponse)
async def edit_server_page(server_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    server = conn.execute('SELECT * FROM servers WHERE id = ?', (server_id,)).fetchone()
    ssh_keys = conn.execute('SELECT id, key_name FROM system_ssh_keys').fetchall()
    gateway_proxies = conn.execute('SELECT id, proxy_name, proxy_ip FROM gateway_proxies').fetchall()
    conn.close()

    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    return templates.TemplateResponse("edit_server.html", {
        "request": request,
        "server": server,
        "ssh_keys": ssh_keys,
        "gateway_proxies": gateway_proxies,
        "token_preview": server["auth_token"][-8:] if server["auth_token"] else "N/A"
    })

@admin_router.post("/admin/servers/edit/{server_id}")
async def edit_server(
    server_id: int,
    request: Request,
    server_name: str = Form(...),
    server_ip: str = Form(...),
    server_ssh_port: int = Form(...),
    system_username: str = Form(...),
    system_ssh_key_id: int = Form(...),
    proxy_id: int = Form(...),
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()

    form = await request.form()
    if "regenerate_token" in form:
        new_token = secrets.token_hex(32)
        conn.execute('''
            UPDATE servers
            SET server_name = ?, server_ip = ?, server_ssh_port = ?, system_username = ?,
                system_ssh_key_id = ?, proxy_id = ?, auth_token = ?
            WHERE id = ?
        ''', (server_name, server_ip, server_ssh_port, system_username, system_ssh_key_id, proxy_id, new_token, server_id))
    else:
        conn.execute('''
            UPDATE servers
            SET server_name = ?, server_ip = ?, server_ssh_port = ?, system_username = ?,
                system_ssh_key_id = ?, proxy_id = ?
            WHERE id = ?
        ''', (server_name, server_ip, server_ssh_port, system_username, system_ssh_key_id, proxy_id, server_id))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Edited server", server_name)
    return RedirectResponse(url="/admin/servers", status_code=303)

@admin_router.post("/admin/servers/delete/{server_id}")
async def delete_server(server_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    server = conn.execute('SELECT * FROM servers WHERE id = ?', (server_id,)).fetchone()
    if not server:
        conn.close()
        raise HTTPException(status_code=404, detail="Server not found")

    conn.execute('DELETE FROM server_assignments WHERE server_id = ?', (server_id,))
    conn.execute('DELETE FROM servers WHERE id = ?', (server_id,))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Deleted server", server["server_name"])

    return RedirectResponse(url="/admin/servers", status_code=303)

@admin_router.get("/admin/servers/assign-user/{server_id}", response_class=HTMLResponse)
async def assign_user_to_server_page(server_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    server = conn.execute('SELECT * FROM servers WHERE id = ?', (server_id,)).fetchone()
    if not server:
        conn.close()
        raise HTTPException(status_code=404, detail="Server not found")

    users = conn.execute('SELECT * FROM users').fetchall()
    # Only load SSH keys that are assigned to the selected user (server["id"])
    ssh_keys = conn.execute('''
        SELECT ssh_keys.* FROM ssh_keys
        JOIN assignments ON ssh_keys.id = assignments.ssh_key_id
        WHERE assignments.user_id = ?
    ''', (server["id"],)).fetchall()

    conn.close()

    return templates.TemplateResponse("assign_user_to_server.html", {
        "request": request,
        "server": server,
        "users": users,
        "ssh_keys": ssh_keys
    })

@admin_router.get("/admin/api/ssh-keys-for-user/{user_id}")
async def api_ssh_keys_for_user(user_id: int):
    conn = get_db_connection()
    keys = conn.execute('''
        SELECT ssh_keys.id, ssh_keys.key_name
        FROM ssh_keys
        JOIN assignments ON ssh_keys.id = assignments.ssh_key_id
        WHERE assignments.user_id = ?
    ''', (user_id,)).fetchall()
    conn.close()
    return [{"id": key["id"], "key_name": key["key_name"]} for key in keys]


@admin_router.post("/admin/servers/assign-user/{server_id}")
async def assign_user_to_server(server_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    form = await request.form()
    user_id = int(form.get("user_id"))
    ssh_key_id = int(form.get("ssh_key_id"))

    conn = get_db_connection()

    # Fetch all users and keys early
    users = conn.execute('SELECT * FROM users').fetchall()
    ssh_keys = conn.execute('SELECT * FROM ssh_keys').fetchall()

    # Validate that the selected SSH key is actually assigned to the user
    key_check = conn.execute('''
        SELECT 1 FROM assignments
        WHERE user_id = ? AND ssh_key_id = ?
    ''', (user_id, ssh_key_id)).fetchone()

    if not key_check:
        conn.close()
        return templates.TemplateResponse(
            "assign_user_to_server.html",
            {
                "request": request,
                "error": "Selected SSH key is not assigned to the selected user.",
                "server": {"id": server_id},
                "users": users,
                "ssh_keys": ssh_keys,
                "assigned_user_id": user_id
            }
        )

    # Check if user already assigned
    existing_assignment = conn.execute(
        'SELECT id FROM server_assignments WHERE server_id = ? AND user_id = ?',
        (server_id, user_id)
    ).fetchone()

    if existing_assignment:
        conn.close()
        return templates.TemplateResponse(
            "assign_user_to_server.html",
            {
                "request": request,
                "error": "User already assigned to this server!",
                "server": {"id": server_id},
                "users": users,
                "ssh_keys": ssh_keys,
                "assigned_user_id": user_id
            }
        )

    # Insert assignment
    conn.execute(
        'INSERT INTO server_assignments (server_id, user_id, ssh_key_id) VALUES (?, ?, ?)',
        (server_id, user_id, ssh_key_id)
    )
    conn.commit()

    # Trigger background provisioning task
    trigger_provisioning_task(user_id, server_id)

    # Fetch server name and username for logging
    server = conn.execute('SELECT server_name FROM servers WHERE id = ?', (server_id,)).fetchone()
    user_obj = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()

    conn.close()

    # Log with real names
    server_name = server["server_name"] if server else f"ServerID {server_id}"
    username = user_obj["username"] if user_obj else f"UserID {user_id}"

    log_admin_action(
        request.session.get("username"),
        "Assigned user to server",
        f"{username} → {server_name}"
    )

    return RedirectResponse(url="/admin/servers", status_code=303)

@admin_router.post("/admin/servers/unassign-user/{server_id}/{user_id}")
async def unassign_user_from_server(server_id: int, user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    # Check if assignment exists
    assignment = conn.execute('SELECT id FROM server_assignments WHERE server_id = ? AND user_id = ?', (server_id, user_id)).fetchone()
    if not assignment:
        conn.close()
        raise HTTPException(status_code=404, detail="Assignment not found")

    # Delete the assignment
    conn.execute('DELETE FROM server_assignments WHERE server_id = ? AND user_id = ?', (server_id, user_id))
    conn.commit()

    server = conn.execute('SELECT server_name FROM servers WHERE id = ?', (server_id,)).fetchone()
    user_rec = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()

    server_name = server["server_name"] if server else f"ServerID {server_id}"
    username = user_rec["username"] if user_rec else f"UserID {user_id}"

    conn.close()
    # Trigger background provisioning task
    trigger_unprovisioning_task(user_id, server_id)
    log_admin_action(request.session.get("username"), "Unassigned user from server", f"{username} ← {server_name}")

    return RedirectResponse(url="/admin/servers", status_code=303)

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