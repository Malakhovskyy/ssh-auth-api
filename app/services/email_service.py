import smtplib
import os
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_TO = os.getenv("SMTP_TO")

def send_email(subject, body, to_email):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [to_email], msg.as_string())

def send_backup_email(backup_path):
    subject = "SSH Key Manager - Daily Backup"
    body = "Attached is the daily database backup."
    send_email(subject, f"Backup is available at {backup_path}", SMTP_TO)

def send_password_reset_email(admin_email, token):
    reset_link = f"https://{os.getenv('DOMAIN')}/admin/reset-password/{token}"
    subject = "SSH Key Manager - Password Reset"
    body = f"Reset your password here: {reset_link}"
    send_email(subject, body, admin_email)