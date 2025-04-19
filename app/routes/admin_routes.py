from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from auth.auth import authenticate_admin, get_current_admin_user, logout_admin, hash_password
from models.models import init_db, get_db_connection, generate_salt
from services.email_service import send_password_reset_email
from services.token_service import generate_reset_token, verify_reset_token
import os
from datetime import datetime, timedelta

templates = Jinja2Templates(directory="templates")
admin_router = APIRouter()

init_db()  # Ensure DB initialized

# Helper: log admin actions
def log_admin_action(username, action):
    conn = get_db_connection()
    conn.execute('INSERT INTO admin_logs (admin_username, action) VALUES (?, ?)', (username, action))
    conn.commit()
    conn.close()

@admin_router.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@admin_router.post("/admin/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    admin = authenticate_admin(username, password)
    if not admin:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    request.session["admin_user"] = admin["admin_username"]

    if admin["must_change_password"]:
        return RedirectResponse(url="/admin/change-password", status_code=303)

    log_admin_action(admin["admin_username"], "Logged in")
    return RedirectResponse(url="/admin/dashboard", status_code=303)

@admin_router.get("/admin/logout")
async def logout(request: Request):
    username = request.session.get("admin_user", "unknown")
    logout_admin(request)
    log_admin_action(username, "Logged out")
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