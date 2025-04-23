from models.models import get_setting

def send_backup_email(backup_path):
    subject = "SSH Key Manager - Daily Backup"
    body = "Attached is the daily database backup."
    # SMTP_TO must still be provided separately because backup may go to fixed email
    admin_email = get_setting('smtp_from') or get_setting('smtp_user')
    queue_email(subject, f"Backup is available at {backup_path}", admin_email)

def queue_email(subject, body, to_email):
    send_email_task.delay(subject, body, to_email)

def send_password_reset_email(admin_email, token):
    domain = get_setting('domain')  # Domain should also be stored in settings!
    reset_link = f"https://{domain}/admin/reset-password/{token}"
    subject = "SSH Key Manager - Password Reset"
    body = f"Reset your password here: {reset_link}"
    queue_email(subject, body, admin_email)