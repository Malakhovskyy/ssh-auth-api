from tasks.tasks import send_email_task
import smtplib
from email.mime.text import MIMEText
from models.models import get_setting, log_email, queue_email, get_db_connection
from services.encryption_service import decrypt_sensitive_value

from models.models import log_email

def send_email(subject, body, to_email):
    # Load SMTP settings from database
    smtp_server = get_setting('smtp_host')
    smtp_port = int(get_setting('smtp_port') or 587)
    smtp_user = get_setting('smtp_user')
    smtp_pass_encrypted = get_setting('smtp_password')
    smtp_from = get_setting('smtp_from') or smtp_user

    smtp_pass = decrypt_sensitive_value(smtp_pass_encrypted)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = to_email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [to_email], msg.as_string())

        # ✅ Log success
        log_email(to_email, subject, "Success")

    except Exception as e:
        # ✅ Log failure
        log_email(to_email, subject, "Failed", str(e))
        raise

def send_backup_email(backup_path):
    subject = "SSH Key Manager - Daily Backup"
    body = "Attached is the daily database backup."
    # SMTP_TO must still be provided separately because backup may go to fixed email
    admin_email = get_setting('smtp_from') or get_setting('smtp_user')
    send_email(subject, f"Backup is available at {backup_path}", admin_email)

def queue_email(subject, body, to_email):
    send_email_task.delay(subject, body, to_email)

def send_password_reset_email(admin_email, token):
    domain = get_setting('domain')  # Domain should also be stored in settings!
    reset_link = f"https://{domain}/admin/reset-password/{token}"
    subject = "SSH Key Manager - Password Reset"
    body = f"Reset your password here: {reset_link}"
    queue_email(subject, body, admin_email)