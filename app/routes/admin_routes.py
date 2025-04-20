from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from auth.auth import authenticate_admin, get_current_admin_user, logout_admin
from models.models import init_db, get_db_connection, log_admin_action, get_setting, set_setting, encrypt_password
from services.email_service import send_password_reset_email
from services.token_service import generate_reset_token, verify_reset_token
from services.security_service import update_admin_password, verify_admin_password
from services.security_service import create_admin_with_password
from services.encryption_service import encrypt_sensitive_value
from datetime import datetime

init_db()  # Ensure DB initialized

import os
from datetime import datetime, timedelta

templates = Jinja2Templates(directory="templates")
admin_router = APIRouter()

@admin_router.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

from datetime import datetime

@admin_router.post("/admin/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    x_forwarded_for = request.headers.get('x-forwarded-for')
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(',')[0].strip()
    else:
        ip_address = request.client.host
    admin = authenticate_admin(username, password, ip_address)
    if not admin:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    # ✅ Set session values
    request.session["admin_user"] = admin["admin_username"]
    request.session["login_time"] = datetime.utcnow().isoformat()  # ✅ Save login time for timeout control
    if admin["must_change_password"]:
        return RedirectResponse(url="/admin/change-password", status_code=303)
    return RedirectResponse(url="/admin/dashboard", status_code=303)

@admin_router.get("/admin/logout")
async def logout(request: Request):
    logout_admin(request)
    return RedirectResponse(url="/admin/login")

@admin_router.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: str = Depends(get_current_admin_user)):
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

@admin_router.get("/admin/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    return templates.TemplateResponse("change_password.html", {"request": request})

from services.security_service import update_admin_password, verify_admin_password

@admin_router.post("/admin/change-password")
async def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...), confirm_password: str = Form(...)):
    username = request.session.get("admin_user")
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM admins WHERE admin_username = ?', (username,)).fetchone()
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
    request.session.pop("admin_user", None)
    return RedirectResponse(url="/admin/login", status_code=303)

@admin_router.get("/admin/admins", response_class=HTMLResponse)
async def admins_page(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    admins = conn.execute('SELECT * FROM admins').fetchall()
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
    existing_admin = conn.execute('SELECT * FROM admins WHERE admin_username = ?', (username,)).fetchone()
    if existing_admin:
        conn.close()
        return templates.TemplateResponse("admin_add.html", {"request": request, "error": "Admin username already exists", "username": username, "email": email})

    success, error = await create_admin_with_password(username, password, email)
    if not success:
        conn.close()
        return templates.TemplateResponse("admin_add.html", {"request": request, "error": error, "username": username, "email": email})

    conn.execute('UPDATE admins SET email = ? WHERE admin_username = ?', (email, username))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("admin_user"), "Created new admin", object_modified=username)
    return RedirectResponse(url="/admin/admins", status_code=303)

@admin_router.get("/admin/admins/edit/{admin_id}", response_class=HTMLResponse)
async def edit_admin_page(admin_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
    conn.close()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    return templates.TemplateResponse("admin_edit.html", {"request": request, "admin": admin})

@admin_router.post("/admin/admins/edit/{admin_id}")
async def edit_admin(admin_id: int, request: Request, email: str = Form(...), password: str = Form(None), confirm_password: str = Form(None), enabled: int = Form(...), force_password_change: int = Form(0)):
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
    if not admin:
        conn.close()
        raise HTTPException(status_code=404, detail="Admin not found")

    if password:
        if password != confirm_password:
            conn.close()
            return templates.TemplateResponse("admin_edit.html", {"request": request, "admin": admin, "error": "Passwords do not match"})

        success, error = await update_admin_password(admin['admin_username'], password)
        if not success:
            conn.close()
            return templates.TemplateResponse("admin_edit.html", {"request": request, "admin": admin, "error": error})

    conn.execute('UPDATE admins SET email = ?, enabled = ?, must_change_password = ? WHERE id = ?', (email, enabled, force_password_change, admin_id))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("admin_user"), "Edited admin", object_modified=admin["admin_username"])
    return RedirectResponse(url="/admin/admins", status_code=303)


# settings #
@admin_router.get("/admin/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user: str = Depends(get_current_admin_user)):
    settings = {key: get_setting(key) for key in ["enforce_password_complexity", "admin_session_timeout", "domain", "smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_from"]}
    success = request.query_params.get("success")  # ✅ Read from query params
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "settings": settings,
            "success": success  # ✅ Pass success explicitly
        }
    )

from services.encryption_service import encrypt_sensitive_value

@admin_router.post("/admin/settings")
async def update_settings(
    request: Request,
    enforce_password_complexity: str = Form(None),
    admin_session_timeout: str = Form(""),
    domain: str = Form(""),
    smtp_host: str = Form(""),
    smtp_port: str = Form(""),
    smtp_user: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form("")
):
    set_setting('enforce_password_complexity', '1' if enforce_password_complexity else '0')
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
    admin = conn.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
    conn.close()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    return templates.TemplateResponse("admin_delete_confirm.html", {"request": request, "admin": admin})

# --- DELETE ADMIN (AFTER CONFIRM) ---

@admin_router.post("/admin/admins/delete/{admin_id}")
async def delete_admin(admin_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    admin = conn.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()

    if not admin:
        conn.close()
        raise HTTPException(status_code=404, detail="Admin not found")

    conn.execute('DELETE FROM admins WHERE id = ?', (admin_id,))
    conn.commit()
    conn.close()

    # ✅ Correct positional call
    log_admin_action(
        request.session.get("admin_user"),
        "Deleted admin",
        admin["admin_username"]
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
    admin = conn.execute('SELECT * FROM admins WHERE email = ?', (email,)).fetchone()
    conn.close()

    if not admin:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Email not found."})

    token = generate_reset_token(admin['admin_username'])
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