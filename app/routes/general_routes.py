




@admin_router.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request):
    restrict_admin_ip = get_setting('restrict_admin_ip')
    if restrict_admin_ip == '1':
        x_forwarded_for = request.headers.get('x-forwarded-for')
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.client.host
        if not is_admin_ip_allowed(client_ip):
            return templates.TemplateResponse("access_denied.html", {"request": request})

    error = request.query_params.get("error")
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

@admin_router.post("/admin/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    x_forwarded_for = request.headers.get('x-forwarded-for')
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(',')[0].strip()
    else:
        ip_address = request.client.host

    restrict_admin_ip = get_setting('restrict_admin_ip')
    if restrict_admin_ip == '1':
        if not is_admin_ip_allowed(ip_address):
            return templates.TemplateResponse("access_denied.html", {"request": request})

    user = authenticate_admin(username, password, ip_address)
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    # ✅ Set session values
    request.session["username"] = user["username"]
    request.session["login_time"] = datetime.utcnow().isoformat()  # ✅ Save login time for timeout control
    request.session["context"] = user["context"]  # Store user context (admin/ssh_user)
    request.session["user_id"] = user["id"]        # Store user id
    if user["must_change_password"]:
        return RedirectResponse(url="/admin/change-password", status_code=303)
    redirect_url = "/admin/ssh-keys" if user["context"] == "ssh_user" else "/admin/dashboard"
    return RedirectResponse(url=redirect_url, status_code=303)

@admin_router.get("/admin/logout")
async def logout(request: Request):
    logout_admin(request)
    return RedirectResponse(url="/admin/login")



@admin_router.get("/admin/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    return templates.TemplateResponse("change_password.html", {"request": request})

@admin_router.post("/admin/change-password")
async def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...), confirm_password: str = Form(...)):
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_db_connection()
    user_record = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user_record:
        conn.close()
        raise HTTPException(status_code=400, detail="User not found.")

    valid = await verify_admin_password(user_record, old_password)
    if not valid:
        conn.close()
        return templates.TemplateResponse("change_password.html", {"request": request, "error": "Incorrect old password"})

    if new_password != confirm_password:
        conn.close()
        return templates.TemplateResponse("change_password.html", {"request": request, "error": "New passwords do not match"})

    conn.close()

    success, error = await update_admin_password(username, new_password)
    if not success:
        return templates.TemplateResponse("change_password.html", {"request": request, "error": error})

    log_admin_action(username, "Changed password")
    request.session.pop("username", None)
    return RedirectResponse(url="/admin/login", status_code=303)


# Forgot password

@admin_router.get("/admin/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})


@admin_router.post("/admin/forgot-password")
async def forgot_password(request: Request, email: str = Form(...)):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()

    if not user:
        log_admin_action("unknown", f"Password reset requested for non-existent email: {email}")
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Email not found."})

    domainname = get_setting('domain')
    token = generate_reset_token(user['username'])
    reset_link = f"https://{domainname}/admin/reset-password/{token}"
    subject = "SSH Key Manager - Password Reset"
    
    # Render the email body using the HTML template
    email_body = templates.get_template("email/password_reset_email.html").render({
        "reset_link": reset_link,
        "year": datetime.utcnow().year
    })
    send_email(email, subject, email_body)
    log_admin_action(user["username"], "Password reset requested", email)

    return RedirectResponse(url="/admin/forgot-password-sent", status_code=303)


# Confirmation page after sending password reset link
@admin_router.get("/admin/forgot-password-sent", response_class=HTMLResponse)
async def forgot_password_sent_page(request: Request):
    return templates.TemplateResponse("forgot_password_sent.html", {"request": request})

@admin_router.get("/admin/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_page(token: str, request: Request):
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})

@admin_router.post("/admin/reset-password/{token}")
async def reset_password(token: str, request: Request, new_password: str = Form(...), confirm_password: str = Form(...)):
    if new_password != confirm_password:
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "error": "Passwords do not match."})

    username = verify_reset_token(token)
    if not username:
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "error": "Invalid or expired token."})

    success, error = await update_admin_password(username, new_password)
    if not success:
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "error": error})

    # Get user's email from the username
    conn = get_db_connection()
    row = conn.execute('''
        SELECT email
        FROM users
        WHERE username = ?
    ''', (username,)).fetchone()
    conn.close()
    print(f"[DEBUG] row before if from users lookup: {row}")
    # Send confirmation email if possible
    if row:
        print(f"[DEBUG] row from users lookup: {row}")
        email = row["email"]
        subject = "SSH Key Manager - Password Changed"
        email_body = templates.get_template("email/password_changed_email.html").render({
            "year": datetime.utcnow().year
        })
        print(f"[DEBUG] Sending password changed email to {email}")
        send_email(email, subject, email_body)

    # Delete the reset token after successful password update
    delete_reset_token(token)
    # Write log
    log_admin_action(username, "Password reset completed")

    # Add a message to be displayed to the user after successful password reset
    return RedirectResponse(url="/admin/login?message=Password+updated+successfully", status_code=303)
