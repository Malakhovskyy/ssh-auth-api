from fastapi import Request, HTTPException
from starlette.responses import RedirectResponse
from hashlib import md5
from models.models import get_db_connection  # <-- important!

def hash_password(password, salt):
    return md5((salt + password).encode('utf-8')).hexdigest()

def authenticate_admin(username: str, password: str):
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM admins WHERE admin_username = ?', (username,)).fetchone()
    conn.close()
    if admin:
        hashed = hash_password(password, admin['salt'])
        if hashed == admin['password_md5salted']:
            return admin
    return None

def get_current_admin_user(request: Request):
    if "admin_user" not in request.session:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return request.session["admin_user"]

def logout_admin(request: Request):
    request.session.pop("admin_user", None)
    return RedirectResponse(url="/admin/login")