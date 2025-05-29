






@admin_router.get("/admin/ssh-users", response_class=HTMLResponse)
async def ssh_users_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return templates.TemplateResponse("ssh_users.html", {"request": request, "users": users})

@admin_router.get("/admin/ssh-users/add", response_class=HTMLResponse)
async def add_ssh_user_page(request: Request, user: str = Depends(get_current_admin_user)):
    return templates.TemplateResponse("add_ssh_user.html", {"request": request})

@admin_router.post("/admin/ssh-users/add")
async def add_ssh_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    expiration_date: str = Form(...),
    never_expires: str = Form(None),
    locked: str = Form(None),
    password: str = Form(None),
    context: str = Form(...),
    user: str = Depends(get_current_admin_user)
):
    if never_expires:
        expiration_date = "2099-12-31 23:59:59"

    if context == "admin" and not password:
        return templates.TemplateResponse(
            "add_ssh_user.html",
            {
                "request": request,
                "error": "Password is required for Admin users.",
                "prefill_username": username,
                "prefill_email": email,
                "prefill_expiration_date": expiration_date,
                "prefill_locked": locked
            }
        )

    success, error = await create_user(username, password or "", email, context)
    if not success:
        return templates.TemplateResponse(
            "add_ssh_user.html",
            {
                "request": request,
                "error": error,
                "prefill_username": username,
                "prefill_email": email,
                "prefill_expiration_date": expiration_date,
                "prefill_locked": locked
            }
        )

    log_admin_action(request.session.get("username"), "Added user", username)
    return RedirectResponse(url="/admin/ssh-users", status_code=303)

# -- Edit SSH User (GET page) --
@admin_router.get("/admin/ssh-users/edit/{user_id}", response_class=HTMLResponse)
async def edit_ssh_user_page(user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if not user_data:
        raise HTTPException(status_code=404, detail="SSH user not found")

    return templates.TemplateResponse("edit_ssh_user.html", {"request": request, "user_data": user_data})

# -- Edit SSH User (POST save) --
@admin_router.post("/admin/ssh-users/edit/{user_id}")
async def edit_ssh_user(
    user_id: int,
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    expiration_date: str = Form(...),
    never_expires: str = Form(None),
    locked: str = Form(None),
    password: str = Form(None),
    context: str = Form(...),
    user: str = Depends(get_current_admin_user)
):
    if never_expires:
        expiration_date = "2099-12-31 23:59:59"

    is_locked = 1 if locked else 0

    success, error = await update_user(user_id, username, email, expiration_date, is_locked, context, password)
    if not success:
        return templates.TemplateResponse("edit_ssh_user.html", {
            "request": request,
            "error": error,
            "user_data": {"id": user_id, "username": username, "email": email, "expiration_date": expiration_date, "locked": locked, "context": context}
        })

    log_admin_action(request.session.get("username"), "Edited SSH user", username)
    return RedirectResponse(url="/admin/ssh-users", status_code=303)
# -- Delete SSH User --

@admin_router.post("/admin/ssh-users/delete/{user_id}")
async def delete_ssh_user(user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user_data:
        conn.close()
        raise HTTPException(status_code=404, detail="SSH user not found")

    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Deleted SSH user", user_data["username"])

    return RedirectResponse(url="/admin/ssh-users", status_code=303)

# -- Lock SSH User --
@admin_router.post("/admin/ssh-users/lock/{user_id}")
async def lock_ssh_user(user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    row = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="SSH user not found")

    username = row["username"]  # ✅ Save username into variable

    conn.execute('UPDATE users SET locked = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    # ✅ Now safe to log
    log_admin_action(request.session.get("username"), "Locked SSH user", username)

    return RedirectResponse(url="/admin/ssh-users", status_code=303)

# -- Unlock SSH User --
@admin_router.post("/admin/ssh-users/unlock/{user_id}")
async def unlock_ssh_user(user_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    row = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="SSH user not found")

    username = row["username"]

    conn.execute('UPDATE users SET locked = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Unlocked SSH user", username)

    return RedirectResponse(url="/admin/ssh-users", status_code=303)

@admin_router.get("/admin/ssh-keys", response_class=HTMLResponse)
async def ssh_keys_list(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    current_user_id = request.session.get("user_id")

    if is_ssh_user(request):
        keys = conn.execute('''
            SELECT ssh_keys.*, users.username AS owner_name
            FROM ssh_keys
            LEFT JOIN users ON ssh_keys.owner_id = users.id
            WHERE ssh_keys.owner_id = ?
        ''', (current_user_id,)).fetchall()
    else:
        keys = conn.execute('''
            SELECT ssh_keys.*, users.username AS owner_name
            FROM ssh_keys
            LEFT JOIN users ON ssh_keys.owner_id = users.id
        ''').fetchall()

    ssh_keys = []

    for key in keys:
        assigned_users = conn.execute(
            '''
            SELECT users.id, users.username 
            FROM assignments 
            JOIN users ON assignments.user_id = users.id
            WHERE assignments.ssh_key_id = ?
            ''',
            (key["id"],)
        ).fetchall()

        ssh_keys.append({
            "id": key["id"],
            "key_name": key["key_name"],
            "expiration_date": key["expiration_date"],
            "locked": key["locked"],
            "assigned_users": assigned_users,
            "owner_name": key["owner_name"]
        })

    conn.close()
    return templates.TemplateResponse("ssh_keys.html", {"request": request, "ssh_keys": ssh_keys})
    # -- Add SSH Key (GET page) --
@admin_router.get("/admin/ssh-keys/add", response_class=HTMLResponse)
async def add_ssh_key_page(request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    users = conn.execute('SELECT id, username FROM users').fetchall()
    conn.close()

    return templates.TemplateResponse("add_ssh_key.html", {
        "request": request,
        "users": users
    })

# -- Add SSH Key (POST form submit) --
@admin_router.post("/admin/ssh-keys/add")
async def add_ssh_key(
    request: Request,
    key_name: str = Form(...),
    expiration_date: str = Form(...),
    never_expires: str = Form(None),
    locked: str = Form(None),
    ssh_key_data: str = Form(...),
    owner_id: int = Form(...),
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()

    if never_expires:
        expiration_date = "2099-12-31 23:59:59"
    is_locked = 1 if locked else 0

    encrypted_key_data = encrypt_sensitive_value(ssh_key_data)

    owner_id_final = request.session.get("user_id") if is_ssh_user(request) else owner_id

    conn.execute(
        'INSERT INTO ssh_keys (key_name, expiration_date, locked, ssh_key_data, owner_id) VALUES (?, ?, ?, ?, ?)',
        (key_name, expiration_date, is_locked, encrypted_key_data, owner_id_final)
    )

    new_key_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

    if is_ssh_user(request):
        conn.execute(
            'INSERT INTO assignments (ssh_key_id, user_id) VALUES (?, ?)',
            (new_key_id, request.session.get("user_id"))
        )

    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Created SSH key", key_name)

    return RedirectResponse(url="/admin/ssh-keys", status_code=303)


# -- Edit SSH Key (GET page) --
@admin_router.get("/admin/ssh-keys/edit/{key_id}", response_class=HTMLResponse)
async def edit_ssh_key_page(key_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    key_data = conn.execute('SELECT * FROM ssh_keys WHERE id = ?', (key_id,)).fetchone()
    users = conn.execute('SELECT id, username FROM users').fetchall()

    if not key_data:
        conn.close()
        return RedirectResponse(url="/admin/ssh-keys", status_code=303)

    if is_ssh_user(request) and key_data["owner_id"] != request.session.get("user_id"):
        conn.close()
        raise HTTPException(status_code=403, detail="Unauthorized to edit this key")

    conn.close()

    decrypted_key_data = decrypt_sensitive_value(key_data['ssh_key_data'])

    return templates.TemplateResponse("edit_ssh_key.html", {
        "request": request,
        "key_data": key_data,
        "decrypted_key_data": decrypted_key_data,
        "users": users
    })

# -- Edit SSH Key (POST) --
@admin_router.post("/admin/ssh-keys/edit/{key_id}")
async def edit_ssh_key(
    key_id: int,
    request: Request,
    key_name: str = Form(...),
    expiration_date: str = Form(...),
    never_expires: str = Form(None),
    locked: str = Form(None),
    ssh_key_data: str = Form(...),
    owner_id: int = Form(...),
    user: str = Depends(get_current_admin_user)
):
    conn = get_db_connection()

    if never_expires:
        expiration_date = "2099-12-31 23:59:59"
    is_locked = 1 if locked else 0
    encrypted_key_data = encrypt_sensitive_value(ssh_key_data)

    owner_id_final = request.session.get("user_id") if is_ssh_user(request) else owner_id

    conn.execute(
        'UPDATE ssh_keys SET key_name = ?, expiration_date = ?, locked = ?, ssh_key_data = ?, owner_id = ? WHERE id = ?',
        (key_name, expiration_date, is_locked, encrypted_key_data, owner_id_final, key_id)
    )
    conn.commit()
    conn.close()

    log_admin_action(request.session.get("username"), "Edited SSH key", key_name)
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

# -- Delete SSH Key --
@admin_router.post("/admin/ssh-keys/delete/{key_id}")
async def delete_ssh_key(key_id: int, request: Request, user: str = Depends(get_current_admin_user)):
    conn = get_db_connection()

    row = conn.execute('SELECT key_name, owner_id FROM ssh_keys WHERE id = ?', (key_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="SSH Key not found")

    if is_ssh_user(request) and row["owner_id"] != request.session.get("user_id"):
        conn.close()
        raise HTTPException(status_code=403, detail="Unauthorized to delete this key")

    key_name = row["key_name"]

    assigned_users = conn.execute('''
        SELECT users.username 
        FROM assignments 
        JOIN users ON assignments.user_id = users.id 
        WHERE assignments.ssh_key_id = ?
    ''', (key_id,)).fetchall()

    usernames = [u["username"] for u in assigned_users]

    conn.execute('DELETE FROM assignments WHERE ssh_key_id = ?', (key_id,))
    conn.execute('DELETE FROM ssh_keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()

    if usernames:
        user_list = ", ".join(usernames)
        modified_object = f"Deleted SSH Key '{key_name}' assigned to users: {user_list}"
    else:
        modified_object = f"Deleted SSH Key '{key_name}' (no users assigned)"

    log_admin_action(request.session.get("username"), "Deleted SSH key", modified_object)

    return RedirectResponse(url="/admin/ssh-keys", status_code=303)


# lock key
@admin_router.post("/admin/ssh-keys/lock/{ssh_key_id}")
async def lock_ssh_key(request: Request, ssh_key_id: int):
    conn = get_db_connection()
    conn.execute('UPDATE ssh_keys SET locked = 1 WHERE id = ?', (ssh_key_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)

@admin_router.post("/admin/ssh-keys/unlock/{ssh_key_id}")
async def unlock_ssh_key(request: Request, ssh_key_id: int):
    conn = get_db_connection()
    conn.execute('UPDATE ssh_keys SET locked = 0 WHERE id = ?', (ssh_key_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/ssh-keys", status_code=303)


