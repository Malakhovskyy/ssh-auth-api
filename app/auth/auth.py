from fastapi import Request, HTTPException
from starlette.responses import RedirectResponse
from models.models import get_db_connection, log_login_attempt, encrypt_password
from datetime import datetime, timedelta


def authenticate_admin(username: str, password: str, ip_address: str):
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM admins WHERE admin_username = ?', (username,)).fetchone()
    conn.close()

    if not admin:
        log_login_attempt(username, ip_address, success=0)
        return None

    if not admin['enabled']:
        log_login_attempt(username, ip_address, success=0)
        return None

    hashed = encrypt_password(password, admin['salt'])
    if hashed == admin['password_md5salted']:
        log_login_attempt(username, ip_address, success=1)
        return admin
    else:
        log_login_attempt(username, ip_address, success=0)
        return None

def get_current_admin_user(request: Request):
    if "admin_user" not in request.session:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return request.session["admin_user"]

def logout_admin(request: Request):
    request.session.pop("admin_user", None)
    return RedirectResponse(url="/admin/login")

def get_current_admin_user(request: Request):
    if "admin_user" not in request.session:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Check session timeout
    login_time_str = request.session.get("login_time")
    if login_time_str:
        login_time = datetime.fromisoformat(login_time_str)
        timeout_minutes = int(get_setting('admin_session_timeout') or 15)
        if datetime.utcnow() > login_time + timedelta(minutes=timeout_minutes):
            # Session expired
            request.session.clear()
            raise HTTPException(status_code=401, detail="Session expired")

    return request.session["admin_user"]