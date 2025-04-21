from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from auth.auth import authenticate_admin, get_current_admin_user, logout_admin
from services.ip_filter_service import is_admin_ip_allowed
from models.models import init_db, get_db_connection, log_admin_action, get_setting, set_setting, encrypt_password
from services.email_service import send_password_reset_email
from services.token_service import generate_reset_token, verify_reset_token
from services.security_service import update_admin_password, verify_admin_password
from services.security_service import create_admin_with_password
from services.encryption_service import encrypt_sensitive_value, decrypt_sensitive_value
from config import templates

init_db()  # Ensure DB initialized

import os
from datetime import datetime, timedelta

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
    return templates.TemplateResponse("login.html", {"request": request})

from datetime import datetime

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
    if user["must_change_password"]:
        return RedirectResponse(url="/admin/change-password", status_code=303)
    return RedirectResponse(url="/admin/dashboard", status_code=303)

@admin_router.get("/admin/logout")
async def logout(request: Request):
    logout_admin(request)
    return RedirectResponse(url="/admin/login")

#dashboard

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


# Dashboard totals endpoint
from datetime import datetime, timedelta

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

@admin_router.get("/admin/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    return templates.TemplateResponse("change_password.html", {"request": request})

# # --- DEUBG ONLY --- #
# @admin_router.get("/admin/debug-test", response_class=HTMLResponse)
# async def debug_test(request: Request):
#     return templates.TemplateResponse("debug_test.html", {"request": request})
# # --- DEUBG ONLY --- #    

@admin_router.post("/admin/change-password")
async def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...), confirm_password: str = Form(...)):
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM users WHERE username = ? AND context = "admin"', (username,)).fetchone()
    if not admin:
        conn.close()
        raise HTTPException(status_code=400, detail="Admin not found.")
    
    # ✅ Now use centralized verify_admin_password
    valid = await verify_admin_password(admin, old_password)
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

@admin_router.get("/admin/admins", response_class=HTMLResponse)
async def admins_page(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    admins = conn.execute('SELECT * FROM users WHERE context = "admin"').fetchall()
    conn.close()
    return templates.TemplateResponse("admin_list.html", {"request": request, "admins": admins})

@admin_router.get("/admin/admins/add", response_class=HTMLResponse)
async def add_admin_page(request: Request, user: str = Depends(get_current_admin_user)):
    return templates.TemplateResponse("admin_add.html", {"request": request})

@admin_router.post("/admin/admins/add")
async def add_admin(request: Request, username: str = Form(...), password: str = Form(...), confirm_password: str = Form(...), email: str = Form(...)):
    if password != confirm_password:
        return templates.TemplateResponse("admin_add.html", {"request": request, "error": "Passwords do not match", "username": username, "email": email})

    conn = get_db_connection()
    existing_admin = conn.execute('SELECT * FROM users WHERE username = ? AND context = "admin"', (username,)).fetchone()
    if existing_admin:
        conn.close()
        return templates.TemplateResponse("admin_add.html", {"request": request, "error": "Admin username already exists", "username": username, "email": email})

    # Insert into users table with context = 'admin'
    encrypted_password = encrypt_password(password)
    salt = encrypted_password["salt"]
    password_md5salted = encrypted_password["password"]
    conn.execute('INSERT INTO users (username, email, password_md5salted, salt, context, enabled, must_change_password, expiration_date, locked, created_at) VALUES (?, ?, ?, ?, "admin", 1, 0, ?, 0, datetime("now"))',
                 (username, email, password_md5salted, salt, "2099-12-31 23:59:59"))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Created new admin", object_modified=username)
    return RedirectResponse(url="/admin/admins", status_code=303)

@admin_router.get("/admin/admins/edit/{admin_id}", response_class=HTMLResponse)
async def edit_admin_page(admin_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM users WHERE id = ? AND context = "admin"', (admin_id,)).fetchone()
    conn.close()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    return templates.TemplateResponse("admin_edit.html", {"request": request, "admin": admin})

@admin_router.post("/admin/admins/edit/{admin_id}")
async def edit_admin(admin_id: int, request: Request, email: str = Form(...), password: str = Form(None), confirm_password: str = Form(None), enabled: int = Form(...), force_password_change: int = Form(0)):
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM users WHERE id = ? AND context = "admin"', (admin_id,)).fetchone()
    if not admin:
        conn.close()
        raise HTTPException(status_code=404, detail="Admin not found")

    if password:
        if password != confirm_password:
            conn.close()
            return templates.TemplateResponse("admin_edit.html", {"request": request, "admin": admin, "error": "Passwords do not match"})

        success, error = await update_admin_password(admin['username'], password)
        if not success:
            conn.close()
            return templates.TemplateResponse("admin_edit.html", {"request": request, "admin": admin, "error": error})

    conn.execute('UPDATE users SET email = ?, enabled = ?, must_change_password = ? WHERE id = ? AND context = "admin"', (email, enabled, force_password_change, admin_id))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Edited admin", object_modified=admin["username"])
    return RedirectResponse(url="/admin/admins", status_code=303)


# settings #
@admin_router.get("/admin/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user: str = Depends(get_current_admin_user)):
    settings = {key: get_setting(key) for key in ["enforce_password_complexity", "restrict_admin_ip", "admin_session_timeout", "domain", "smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_from"]}
    success = request.query_params.get("success")  # ✅ Read from query params
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "settings": settings,
            "success": success  # ✅ Pass success explicitly
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
        # ✅ New password provided → Encrypt and save
        encrypted_smtp_password = encrypt_sensitive_value(smtp_password)
        set_setting('smtp_password', encrypted_smtp_password)
    else:
        # ✅ No new password provided → Keep existing one
        existing_encrypted_password = get_setting('smtp_password')
        set_setting('smtp_password', existing_encrypted_password)

    set_setting('smtp_from', smtp_from)

    return RedirectResponse(url="/admin/settings?success=1", status_code=303)

# --- DELETE ADMIN (SHOW CONFIRMATION PAGE) ---

@admin_router.get("/admin/admins/delete/{admin_id}", response_class=HTMLResponse)
async def delete_admin_confirm(admin_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM users WHERE id = ? AND context = "admin"', (admin_id,)).fetchone()
    conn.close()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    return templates.TemplateResponse("admin_delete_confirm.html", {"request": request, "admin": admin})

# --- DELETE ADMIN (AFTER CONFIRM) ---

@admin_router.post("/admin/admins/delete/{admin_id}")
async def delete_admin(admin_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    admin = conn.execute('SELECT * FROM users WHERE id = ? AND context = "admin"', (admin_id,)).fetchone()

    if not admin:
        conn.close()
        raise HTTPException(status_code=404, detail="Admin not found")

    conn.execute('DELETE FROM users WHERE id = ?', (admin_id,))
    conn.commit()
    conn.close()

    log_admin_action(
        request.session.get("username"),
        "Deleted admin",
        admin["username"]
    )
    return RedirectResponse(url="/admin/admins", status_code=303)

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


# --- Forgot Password ---
@admin_router.get("/admin/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@admin_router.post("/admin/forgot-password")
async def forgot_password(request: Request, email: str = Form(...)):
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM users WHERE email = ? AND context = "admin"', (email,)).fetchone()
    conn.close()

    if not admin:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Email not found."})

    token = generate_reset_token(admin['username'])
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


 # EMAIL LOGS
@admin_router.get("/admin/email-logs", response_class=HTMLResponse)
async def view_email_logs(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    email_logs = conn.execute('SELECT * FROM email_logs ORDER BY timestamp DESC').fetchall()
    conn.close()

    return templates.TemplateResponse("email_logs.html", {"request": request, "logs": email_logs})



# -- List SSH Users --
@admin_router.get("/admin/ssh-users", response_class=HTMLResponse)
async def ssh_users_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return templates.TemplateResponse("ssh_users.html", {"request": request, "users": users})

# -- Add SSH User (GET page) --
@admin_router.get("/admin/ssh-users/add", response_class=HTMLResponse)
async def add_ssh_user_page(request: Request, user: str = Depends(get_current_admin_user)):
    return templates.TemplateResponse("add_ssh_user.html", {"request": request})

# -- Add SSH User (POST save) --
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
    conn = get_db_connection()

    existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing_user:
        conn.close()
        return templates.TemplateResponse(
            "add_ssh_user.html",
            {
                "request": request,
                "error": "Username already exists.",
                "prefill_username": username,
                "prefill_email": email,
                "prefill_expiration_date": expiration_date,
                "prefill_locked": locked
            }
        )

    existing_email = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    if existing_email:
        conn.close()
        return templates.TemplateResponse(
            "add_ssh_user.html",
            {
                "request": request,
                "error": "Email already exists.",
                "prefill_username": username,
                "prefill_email": email,
                "prefill_expiration_date": expiration_date,
                "prefill_locked": locked
            }
        )

    if never_expires:
        expiration_date = "2099-12-31 23:59:59"

    is_locked = 1 if locked else 0

    # Prepare fields
    password_md5salted = None
    salt = None
    if context == "admin":
        if not password:
            conn.close()
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
        encrypted = encrypt_password(password)
        salt = encrypted["salt"]
        password_md5salted = encrypted["password"]

    conn.execute(
        'INSERT INTO users (username, email, expiration_date, locked, context, password_md5salted, salt) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (username, email, expiration_date, is_locked, context, password_md5salted, salt)
    )
    conn.commit()
    conn.close()

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
    conn = get_db_connection()

    # Check duplicate username (excluding self)
    existing_user = conn.execute('SELECT * FROM users WHERE username = ? AND id != ?', (username, user_id)).fetchone()
    if existing_user:
        conn.close()
        return templates.TemplateResponse("edit_ssh_user.html", {
            "request": request,
            "error": "Username already exists.",
            "user_data": {"id": user_id, "username": username, "email": email, "expiration_date": expiration_date, "locked": locked, "context": context}
        })

    # Check duplicate email (excluding self)
    existing_email = conn.execute('SELECT * FROM users WHERE email = ? AND id != ?', (email, user_id)).fetchone()
    if existing_email:
        conn.close()
        return templates.TemplateResponse("edit_ssh_user.html", {
            "request": request,
            "error": "Email already exists.",
            "user_data": {"id": user_id, "username": username, "email": email, "expiration_date": expiration_date, "locked": locked, "context": context}
        })

    if never_expires:
        expiration_date = "2099-12-31 23:59:59"

    is_locked = 1 if locked else 0

    if password:
        # Correct: generate salt and encrypt password
        from services.security_service import generate_salt
        salt = generate_salt(8)
        encrypted_password = encrypt_password(password, salt)
        conn.execute('''
            UPDATE users
            SET username = ?, email = ?, expiration_date = ?, locked = ?, context = ?, password_md5salted = ?, salt = ?
            WHERE id = ?
        ''', (username, email, expiration_date, is_locked, context, encrypted_password, salt, user_id))
    else:
        # No password change
        conn.execute('''
            UPDATE users
            SET username = ?, email = ?, expiration_date = ?, locked = ?, context = ?
            WHERE id = ?
        ''', (username, email, expiration_date, is_locked, context, user_id))

    conn.commit()
    conn.close()

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

# -- List SSH Keys --
@admin_router.get("/admin/ssh-keys", response_class=HTMLResponse)
async def ssh_keys_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    # Fetch keys with owner info
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
            "owner_name": key["owner_name"]  # <-- Added owner name
        })

    conn.close()
    return templates.TemplateResponse("ssh_keys.html", {"request": request, "ssh_keys": ssh_keys})

# -- Lock SSH Key --
@admin_router.post("/admin/ssh-keys/lock/{key_id}")
async def lock_ssh_key(key_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    row = conn.execute('SELECT key_name FROM ssh_keys WHERE id = ?', (key_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="SSH Key not found")
    key_name = row["key_name"]
    conn.execute('UPDATE ssh_keys SET locked = 1 WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()
    log_admin_action(request.session.get("username"), "Locked SSH key", key_name)
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

# -- Unlock SSH Key --
@admin_router.post("/admin/ssh-keys/unlock/{key_id}")
async def unlock_ssh_key(key_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    row = conn.execute('SELECT key_name FROM ssh_keys WHERE id = ?', (key_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="SSH Key not found")
    key_name = row["key_name"]
    conn.execute('UPDATE ssh_keys SET locked = 0 WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()
    log_admin_action(request.session.get("username"), "Unlocked SSH key", key_name)
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

# -- Delete SSH Key --
@admin_router.post("/admin/ssh-keys/delete/{key_id}")
async def delete_ssh_key(key_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    # Get key name
    row = conn.execute('SELECT key_name FROM ssh_keys WHERE id = ?', (key_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="SSH Key not found")

    key_name = row["key_name"]

    # Fetch all users assigned to this key before deleting
    assigned_users = conn.execute('''
        SELECT users.username 
        FROM assignments 
        JOIN users ON assignments.user_id = users.id 
        WHERE assignments.ssh_key_id = ?
    ''', (key_id,)).fetchall()

    usernames = [u["username"] for u in assigned_users]

    # First delete assignments
    conn.execute('DELETE FROM assignments WHERE ssh_key_id = ?', (key_id,))
    conn.execute('DELETE FROM ssh_keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()

    # Prepare log message
    if usernames:
        user_list = ", ".join(usernames)
        modified_object = f"Deleted SSH Key '{key_name}' assigned to users: {user_list}"
    else:
        modified_object = f"Deleted SSH Key '{key_name}' (no users assigned)"

    log_admin_action(
        request.session.get("username"),
        "Deleted SSH key",
        modified_object
    )

    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

# -- Unassign User from SSH Key --
@admin_router.post("/admin/ssh-keys/unassign/{key_id}/{user_id}")
async def unassign_ssh_user(key_id: int, user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    # Fetch key name
    key_rec = conn.execute('SELECT key_name FROM ssh_keys WHERE id = ?', (key_id,)).fetchone()
    key_name = key_rec["key_name"] if key_rec else f"KeyID {key_id}"

    # Fetch username
    user_rec = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    username = user_rec["username"] if user_rec else f"UserID {user_id}"

    # Unassign
    conn.execute('DELETE FROM assignments WHERE ssh_key_id = ? AND user_id = ?', (key_id, user_id))
    conn.commit()
    conn.close()

    # Log with real names
    log_admin_action(
        request.session.get("username"),
        "Unassigned SSH key from user",
        f"{key_name} ← {username}"
    )

    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

# -- Add SSH Key (GET form) --
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
    owner_id: int = Form(...),  # <--- new
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()

    if never_expires:
        expiration_date = "2099-12-31 23:59:59"
    is_locked = 1 if locked else 0

    encrypted_key_data = encrypt_sensitive_value(ssh_key_data)

    conn.execute(
        'INSERT INTO ssh_keys (key_name, expiration_date, locked, ssh_key_data, owner_id) VALUES (?, ?, ?, ?, ?)',
        (key_name, expiration_date, is_locked, encrypted_key_data, owner_id)
    )
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Created SSH key", key_name)

    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

    # Check if SSH key with the same key_name already exists
    existing_key = conn.execute('SELECT id FROM ssh_keys WHERE key_name = ?', (key_name,)).fetchone()
    if existing_key:
        conn.close()
        return templates.TemplateResponse(
            "add_ssh_key.html",
            {
                "request": request,
                "error": "SSH Key with this name already exists.",
                "prefill_key_name": key_name,
                "prefill_expiration_date": expiration_date,
                "prefill_ssh_key_data": ssh_key_data,
                "prefill_locked": locked
            }
        )

    if never_expires:
        expiration_date = "2099-12-31 23:59:59"

    is_locked = 1 if locked else 0

    # ✅ Encrypt the SSH Key content
    encrypted_key_data = encrypt_sensitive_value(ssh_key_data)

    conn.execute(
        'INSERT INTO ssh_keys (key_name, expiration_date, locked, ssh_key_data) VALUES (?, ?, ?, ?)',
        (key_name, expiration_date, is_locked, encrypted_key_data)
    )
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Created SSH key", key_name)

    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

# -- EDIT SSH Key (POST form submit) --
@admin_router.get("/admin/ssh-keys/edit/{key_id}", response_class=HTMLResponse)
async def edit_ssh_key_page(key_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    key_data = conn.execute('SELECT * FROM ssh_keys WHERE id = ?', (key_id,)).fetchone()
    users = conn.execute('SELECT id, username FROM users').fetchall()
    conn.close()

    if not key_data:
        return RedirectResponse(url="/admin/ssh-keys", status_code=303)

    decrypted_key_data = decrypt_sensitive_value(key_data['ssh_key_data'])

    return templates.TemplateResponse("edit_ssh_key.html", {
        "request": request,
        "key_data": key_data,
        "decrypted_key_data": decrypted_key_data,
        "users": users
    })

@admin_router.post("/admin/ssh-keys/edit/{key_id}")
async def edit_ssh_key(
    key_id: int,
    request: Request,
    key_name: str = Form(...),
    expiration_date: str = Form(...),
    never_expires: str = Form(None),
    locked: str = Form(None),
    ssh_key_data: str = Form(...),
    owner_id: int = Form(...),  # <--- new
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()

    if never_expires:
        expiration_date = "2099-12-31 23:59:59"
    is_locked = 1 if locked else 0
    encrypted_key_data = encrypt_sensitive_value(ssh_key_data)

    conn.execute(
        'UPDATE ssh_keys SET key_name = ?, expiration_date = ?, locked = ?, ssh_key_data = ?, owner_id = ? WHERE id = ?',
        (key_name, expiration_date, is_locked, encrypted_key_data, owner_id, key_id)
    )
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Edited SSH key", key_name)
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

#SSH key assign
@admin_router.get("/admin/assign-key/{user_id}", response_class=HTMLResponse)
async def assign_key_page(user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
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
    form = await request.form()
    selected_keys = form.getlist("ssh_keys")  # List of selected SSH key IDs

    conn = get_db_connection()

    # Remove all existing assignments first
    conn.execute('DELETE FROM assignments WHERE user_id = ?', (user_id,))

    # Add new assignments
    for key_id in selected_keys:
        conn.execute('INSERT INTO assignments (ssh_key_id, user_id) VALUES (?, ?)', (key_id, user_id))

    conn.commit()

    # Fetch username
    user_rec = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    username = user_rec["username"] if user_rec else f"UserID {user_id}"

    # Fetch SSH key names
    if selected_keys:
        # Convert selected_keys to tuple of integers
        key_ids = tuple(int(k) for k in selected_keys)

        if len(key_ids) == 1:
            placeholders = "(?)"
        else:
            placeholders = f"({','.join(['?']*len(key_ids))})"

        key_names_query = f'SELECT key_name FROM ssh_keys WHERE id IN {placeholders}'
        key_recs = conn.execute(key_names_query, key_ids).fetchall()
        key_names = [rec["key_name"] for rec in key_recs]
        key_names_str = ", ".join(key_names)
    else:
        key_names_str = "No Keys Assigned"

    conn.close()

    # Log human-readable
    log_admin_action(
        request.session.get("username"),
        "Assigned SSH keys to user",
        f"[{key_names_str}] → {username}"
    )

    return RedirectResponse(url="/admin/ssh-users", status_code=303)

#Server Manager key assign
@admin_router.get("/admin/servers", response_class=HTMLResponse)
async def servers_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    servers = conn.execute('SELECT * FROM servers').fetchall()
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
            "assigned_users": assigned_users
        })

    conn.close()
    return templates.TemplateResponse("servers.html", {"request": request, "servers": servers_data})

@admin_router.get("/admin/servers/add", response_class=HTMLResponse)
async def add_server_page(request: Request, user: str = Depends(get_current_admin_user)):
    return templates.TemplateResponse("add_server.html", {"request": request})

@admin_router.post("/admin/servers/add")
async def add_server(request: Request, server_name: str = Form(...), user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    existing_server = conn.execute('SELECT id FROM servers WHERE server_name = ?', (server_name,)).fetchone()
    if existing_server:
        conn.close()
        return templates.TemplateResponse("add_server.html", {"request": request, "error": "Server name already exists."})

    conn.execute('INSERT INTO servers (server_name) VALUES (?)', (server_name,))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Created server", server_name)

    return RedirectResponse(url="/admin/servers", status_code=303)

@admin_router.get("/admin/servers/edit/{server_id}", response_class=HTMLResponse)
async def edit_server_page(server_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    server = conn.execute('SELECT * FROM servers WHERE id = ?', (server_id,)).fetchone()
    conn.close()

    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    return templates.TemplateResponse("edit_server.html", {"request": request, "server": server})

@admin_router.post("/admin/servers/edit/{server_id}")
async def edit_server(server_id: int, request: Request, server_name: str = Form(...), user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    conn.execute('UPDATE servers SET server_name = ? WHERE id = ?', (server_name, server_id))
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
    ssh_keys = conn.execute('SELECT * FROM ssh_keys').fetchall()

    conn.close()

    return templates.TemplateResponse("assign_user_to_server.html", {
        "request": request,
        "server": server,
        "users": users,
        "ssh_keys": ssh_keys
    })

@admin_router.post("/admin/servers/assign-user/{server_id}")
async def assign_user_to_server(server_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    form = await request.form()
    user_id = int(form.get("user_id"))
    ssh_key_id = int(form.get("ssh_key_id"))

    conn = get_db_connection()

    # Fetch all users and keys early
    users = conn.execute('SELECT * FROM users').fetchall()
    ssh_keys = conn.execute('SELECT * FROM ssh_keys').fetchall()

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
    conn.close()

    log_admin_action(request.session.get("username"), "Unassigned user from server", f"ServerID {server_id} UserID {user_id}")

    return RedirectResponse(url="/admin/servers", status_code=303)


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

# API LOGS
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