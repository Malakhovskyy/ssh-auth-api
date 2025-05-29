




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