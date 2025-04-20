from fastapi import Request, HTTPException
from starlette.responses import RedirectResponse
from models.models import get_db_connection, log_login_attempt, encrypt_password

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