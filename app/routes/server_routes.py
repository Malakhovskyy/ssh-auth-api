








@admin_router.get("/admin/servers", response_class=HTMLResponse)
async def servers_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    servers = conn.execute('''
        SELECT servers.id, servers.server_name, servers.server_ip, servers.system_username,
               servers.server_ssh_port, servers.auth_token,
               gateway_proxies.proxy_name,
               ssh_keys.key_name as ssh_key_name
        FROM servers
        LEFT JOIN gateway_proxies ON servers.proxy_id = gateway_proxies.id
        LEFT JOIN ssh_keys ON servers.system_ssh_key_id = ssh_keys.id
    ''').fetchall()

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
            "server_ip": server["server_ip"],
            "system_username": server["system_username"],
            "server_ssh_port": server["server_ssh_port"],
            "auth_token": server["auth_token"],
            "proxy_name": server["proxy_name"],
            "ssh_key_name": server["ssh_key_name"],
            "assigned_users": assigned_users
        })

    conn.close()
    return templates.TemplateResponse("servers.html", {"request": request, "servers": servers_data})

@admin_router.get("/admin/servers/add", response_class=HTMLResponse)
async def add_server_page(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    ssh_keys = conn.execute('SELECT id, key_name FROM system_ssh_keys').fetchall()
    gateway_proxies = conn.execute('SELECT id, proxy_name, proxy_ip FROM gateway_proxies').fetchall()
    conn.close()
    return templates.TemplateResponse("add_server.html", {
        "request": request,
        "ssh_keys": ssh_keys,
        "gateway_proxies": gateway_proxies
    })

@admin_router.post("/admin/servers/add")
async def add_server(
    request: Request,
    server_name: str = Form(...),
    server_ip: str = Form(...),
    server_ssh_port: int = Form(...),
    system_username: str = Form(...),
    system_ssh_key_id: int = Form(...),
    proxy_id: int = Form(...),
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()
    existing_server = conn.execute('SELECT id FROM servers WHERE server_name = ?', (server_name,)).fetchone()
    if existing_server:
        ssh_keys = conn.execute('SELECT id, key_name FROM system_ssh_keys').fetchall()
        gateway_proxies = conn.execute('SELECT id, proxy_name, proxy_ip FROM gateway_proxies').fetchall()
        conn.close()
        return templates.TemplateResponse("add_server.html", {
            "request": request,
            "error": "Server name already exists.",
            "ssh_keys": ssh_keys,
            "gateway_proxies": gateway_proxies
        })

    auth_token = secrets.token_hex(32)
    conn.execute('''
        INSERT INTO servers (
            server_name, server_ip, server_ssh_port, system_username, 
            system_ssh_key_id, proxy_id, auth_token
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        server_name, server_ip, server_ssh_port, system_username,
        system_ssh_key_id, proxy_id, auth_token
    ))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Created server", server_name)
    return RedirectResponse(url="/admin/servers", status_code=303)

@admin_router.get("/admin/servers/edit/{server_id}", response_class=HTMLResponse)
async def edit_server_page(server_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    server = conn.execute('SELECT * FROM servers WHERE id = ?', (server_id,)).fetchone()
    ssh_keys = conn.execute('SELECT id, key_name FROM system_ssh_keys').fetchall()
    gateway_proxies = conn.execute('SELECT id, proxy_name, proxy_ip FROM gateway_proxies').fetchall()
    conn.close()

    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    return templates.TemplateResponse("edit_server.html", {
        "request": request,
        "server": server,
        "ssh_keys": ssh_keys,
        "gateway_proxies": gateway_proxies,
        "token_preview": server["auth_token"][-8:] if server["auth_token"] else "N/A"
    })

@admin_router.post("/admin/servers/edit/{server_id}")
async def edit_server(
    server_id: int,
    request: Request,
    server_name: str = Form(...),
    server_ip: str = Form(...),
    server_ssh_port: int = Form(...),
    system_username: str = Form(...),
    system_ssh_key_id: int = Form(...),
    proxy_id: int = Form(...),
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()

    form = await request.form()
    if "regenerate_token" in form:
        new_token = secrets.token_hex(32)
        conn.execute('''
            UPDATE servers
            SET server_name = ?, server_ip = ?, server_ssh_port = ?, system_username = ?,
                system_ssh_key_id = ?, proxy_id = ?, auth_token = ?
            WHERE id = ?
        ''', (server_name, server_ip, server_ssh_port, system_username, system_ssh_key_id, proxy_id, new_token, server_id))
    else:
        conn.execute('''
            UPDATE servers
            SET server_name = ?, server_ip = ?, server_ssh_port = ?, system_username = ?,
                system_ssh_key_id = ?, proxy_id = ?
            WHERE id = ?
        ''', (server_name, server_ip, server_ssh_port, system_username, system_ssh_key_id, proxy_id, server_id))
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
    # Only load SSH keys that are assigned to the selected user (server["id"])
    ssh_keys = conn.execute('''
        SELECT ssh_keys.* FROM ssh_keys
        JOIN assignments ON ssh_keys.id = assignments.ssh_key_id
        WHERE assignments.user_id = ?
    ''', (server["id"],)).fetchall()

    conn.close()

    return templates.TemplateResponse("assign_user_to_server.html", {
        "request": request,
        "server": server,
        "users": users,
        "ssh_keys": ssh_keys
    })

@admin_router.get("/admin/api/ssh-keys-for-user/{user_id}")
async def api_ssh_keys_for_user(user_id: int):
    conn = get_db_connection()
    keys = conn.execute('''
        SELECT ssh_keys.id, ssh_keys.key_name
        FROM ssh_keys
        JOIN assignments ON ssh_keys.id = assignments.ssh_key_id
        WHERE assignments.user_id = ?
    ''', (user_id,)).fetchall()
    conn.close()
    return [{"id": key["id"], "key_name": key["key_name"]} for key in keys]


@admin_router.post("/admin/servers/assign-user/{server_id}")
async def assign_user_to_server(server_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    form = await request.form()
    user_id = int(form.get("user_id"))
    ssh_key_id = int(form.get("ssh_key_id"))

    conn = get_db_connection()

    # Fetch all users and keys early
    users = conn.execute('SELECT * FROM users').fetchall()
    ssh_keys = conn.execute('SELECT * FROM ssh_keys').fetchall()

    # Validate that the selected SSH key is actually assigned to the user
    key_check = conn.execute('''
        SELECT 1 FROM assignments
        WHERE user_id = ? AND ssh_key_id = ?
    ''', (user_id, ssh_key_id)).fetchone()

    if not key_check:
        conn.close()
        return templates.TemplateResponse(
            "assign_user_to_server.html",
            {
                "request": request,
                "error": "Selected SSH key is not assigned to the selected user.",
                "server": {"id": server_id},
                "users": users,
                "ssh_keys": ssh_keys,
                "assigned_user_id": user_id
            }
        )

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

    # Trigger background provisioning task
    trigger_provisioning_task(user_id, server_id)

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

    server = conn.execute('SELECT server_name FROM servers WHERE id = ?', (server_id,)).fetchone()
    user_rec = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()

    server_name = server["server_name"] if server else f"ServerID {server_id}"
    username = user_rec["username"] if user_rec else f"UserID {user_id}"

    conn.close()
    # Trigger background provisioning task
    trigger_unprovisioning_task(user_id, server_id)
    log_admin_action(request.session.get("username"), "Unassigned user from server", f"{username} ← {server_name}")

    return RedirectResponse(url="/admin/servers", status_code=303)