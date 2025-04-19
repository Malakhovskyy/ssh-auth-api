from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from auth.auth import authenticate_admin, get_current_admin_user, logout_admin, hash_password
from models.models import init_db, get_db_connection, generate_salt, log_admin_action
from services.email_service import send_password_reset_email
from services.token_service import generate_reset_token, verify_reset_token
import os
from datetime import datetime, timedelta

templates = Jinja2Templates(directory="templates")
admin_router = APIRouter()

init_db()  # Ensure DB initialized


@admin_router.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@admin_router.post("/admin/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    x_forwarded_for = request.headers.get('x-forwarded-for')
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(',')[0].strip()
    else:
        ip_address = request.client.host
    # ✅ Only pass username and password!
    admin = authenticate_admin(username, password)
    if not admin:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    request.session["admin_user"] = admin["admin_username"]
    if admin["must_change_password"]:
        return RedirectResponse(url="/admin/change-password", status_code=303)
    return RedirectResponse(url="/admin/dashboard", status_code=303)


@admin_router.get("/admin/logout")
async def logout(request: Request):
    username = request.session.get("admin_user", "unknown")
    logout_admin(request)
#    log_admin_action(username, "Logged out")
    return RedirectResponse(url="/admin/login")

@admin_router.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: str = Depends(get_current_admin_user)):
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

@admin_router.get("/admin/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    return templates.TemplateResponse("change_password.html", {"request": request})

@admin_router.post("/admin/change-password")
async def change_password(request: Request, 
                           old_password: str = Form(...), 
                           new_password: str = Form(...), 
                           confirm_password: str = Form(...)):
    username = request.session.get("admin_user")
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM admins WHERE admin_username = ?', (username,)).fetchone()

    if not admin:
        conn.close()
        raise HTTPException(status_code=400, detail="Admin not found.")

    # Check old password
    if hash_password(old_password, admin['salt']) != admin['password_md5salted']:
        conn.close()
        return templates.TemplateResponse("change_password.html", {"request": request, "error": "Incorrect old password"})

    # Check new password confirmation
    if new_password != confirm_password:
        conn.close()
        return templates.TemplateResponse("change_password.html", {"request": request, "error": "New passwords do not match"})

    # Update to new password
    new_salt = generate_salt()
    new_hash = hash_password(new_password, new_salt)

    conn.execute('''
        UPDATE admins
        SET password_md5salted = ?, salt = ?, must_change_password = 0
        WHERE admin_username = ?
    ''', (new_hash, new_salt, username))

    conn.commit()
    conn.close()

    log_admin_action(username, "Changed password")

    request.session.pop("admin_user", None)
    return RedirectResponse(url="/admin/login", status_code=303)

# Additional admin routes (for managing users, servers, keys) can be added here...

# --- ADD ADMIN (LIST) ---

@admin_router.get("/admin/admins", response_class=HTMLResponse)
async def admins_page(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    admins = conn.execute('SELECT * FROM admins').fetchall()
    conn.close()
    return templates.TemplateResponse("admin_list.html", {"request": request, "admins": admins})

# --- ADD ADMIN (GET + POST) ---

@admin_router.get("/admin/admins/add", response_class=HTMLResponse)
async def add_admin_page(request: Request, user: str = Depends(get_current_admin_user)):
    return templates.TemplateResponse("admin_add.html", {"request": request})

@admin_router.post("/admin/admins/add")
async def add_admin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    email: str = Form(...)
):
    if password != confirm_password:
        return templates.TemplateResponse(
            "admin_add.html",
            {
                "request": request,
                "error": "Passwords do not match",
                "username": username,
                "email": email
            }
        )

    conn = get_db_connection()

    # Check if username already exists
    existing_admin = conn.execute('SELECT * FROM admins WHERE admin_username = ?', (username,)).fetchone()
    if existing_admin:
        conn.close()
        return templates.TemplateResponse(
            "admin_add.html",
            {
                "request": request,
                "error": "Admin username already exists",
                "username": username,
                "email": email
            }
        )

    salt = generate_salt()
    password_hash = hash_password(password, salt)

    conn.execute('''
        INSERT INTO admins (admin_username, email, password_md5salted, salt, must_change_password, enabled)
        VALUES (?, ?, ?, ?, 1, 1)
    ''', (username, email, password_hash, salt))
    conn.commit()
    conn.close()

    # ✅ Log admin action
    log_admin_action(
        request.session.get("admin_user"),
        "Created new admin",
        object_modified=username
    )

    return RedirectResponse(url="/admin/admins", status_code=303)

# --- EDIT ADMIN (GET + POST) ---

@admin_router.get("/admin/admins/edit/{admin_id}", response_class=HTMLResponse)
async def edit_admin_page(admin_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
    conn.close()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    return templates.TemplateResponse("admin_edit.html", {"request": request, "admin": admin})

@admin_router.post("/admin/admins/edit/{admin_id}")
async def edit_admin(
    admin_id: int,
    request: Request,
    email: str = Form(...),
    password: str = Form(None),
    confirm_password: str = Form(None),
    enabled: int = Form(...),
    force_password_change: int = Form(0)
):
    conn = get_db_connection()

    # Fetch current admin data
    admin = conn.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
    if not admin:
        conn.close()
        raise HTTPException(status_code=404, detail="Admin not found")

    if password:
        if password != confirm_password:
            conn.close()
            return templates.TemplateResponse(
                "admin_edit.html",
                {"request": request, "admin": admin, "error": "Passwords do not match"}
            )

        salt = generate_salt()
        password_hash = hash_password(password, salt)

        conn.execute('''
            UPDATE admins
            SET email = ?, password_md5salted = ?, salt = ?, enabled = ?, must_change_password = ?
            WHERE id = ?
        ''', (email, password_hash, salt, enabled, force_password_change, admin_id))
    else:
        conn.execute('''
            UPDATE admins
            SET email = ?, enabled = ?, must_change_password = ?
            WHERE id = ?
        ''', (email, enabled, force_password_change, admin_id))

    conn.commit()
    conn.close()

    # ✅ Log admin action
    log_admin_action(
        request.session.get("admin_user"),
        "Edited admin",
        object_modified=admin["admin_username"]
    )

    return RedirectResponse(url="/admin/admins", status_code=303)

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

    # Fetch login attempt logs
    login_logs = conn.execute('SELECT id, username as admin_username, "Login Attempt" as action, NULL as object_modified, ip_address, timestamp FROM login_attempts').fetchall()

    conn.close()

    # Merge and sort by timestamp descending
    all_logs = list(admin_logs) + list(login_logs)
    all_logs.sort(key=lambda x: x["timestamp"], reverse=True)

    return templates.TemplateResponse("admin_logs.html", {"request": request, "logs": all_logs})