import time
from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from config import templates, static_files
from starlette.middleware.sessions import SessionMiddleware
import os
from dotenv import load_dotenv
from models.models import init_db

# Add small wait before full startup
print("[DEBUG] Waiting 2 seconds for DB mount...")
time.sleep(2)

from auth.auth import get_current_admin_user, authenticate_admin, logout_admin
from routes.admin_routes import admin_router
from routes.api_routes import api_router
from services.backup_service import schedule_daily_backup


load_dotenv()
init_db()

app = FastAPI()

# Load environment variables
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SMTP_PASS", "default_secret_key"))

# Mount static files
app.mount("/static", static_files, name="static")


# Routers
app.include_router(admin_router)
app.include_router(api_router)

# Background backup scheduler
schedule_daily_backup()

# Root Redirect
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if request.session.get("admin_user"):
        return RedirectResponse(url="/admin/dashboard")
    return RedirectResponse(url="/admin/login")