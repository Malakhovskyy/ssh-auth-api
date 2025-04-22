from fastapi import Request, HTTPException
from starlette.responses import RedirectResponse
from models.models import get_db_connection, log_login_attempt, encrypt_password
from datetime import datetime, timedelta
from models.models import get_setting

def authenticate_admin(username: str, password: str, ip_address: str):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND context IN ("admin", "ssh_user")', (username,)).fetchone()
    conn.close()

    if not user:
        log_login_attempt(username, ip_address, success=0)
        return None

    if not user['enabled']:
        log_login_attempt(username, ip_address, success=0)
        return None

    hashed = encrypt_password(password, user['salt'])
    if hashed == user['password_md5salted']:
        log_login_attempt(username, ip_address, success=1)
        return user
    else:
        log_login_attempt(username, ip_address, success=0)
        return None

def get_current_admin_user(request: Request):
    if "username" not in request.session:
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

    return request.session["username"]

def logout_admin(request: Request):
    request.session.pop("username", None)
    request.session.pop("context", None)
    request.session.pop("user_id", None)
    return RedirectResponse(url="/admin/login")