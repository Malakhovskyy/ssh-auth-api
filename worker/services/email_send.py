import smtplib
from email.mime.text import MIMEText
from models.models import get_setting, log_email
from celery_config import celery_app
from services.encryption_service import decrypt_sensitive_value

@celery_app.task(name="services.email_send.send_email_task", bind=True, default_retry_delay=60)
def send_email_task(self, email: str, subject: str, email_body: str):
    # Load SMTP settings from database
    smtp_server = get_setting('smtp_host')
    smtp_port = int(get_setting('smtp_port') or 587)
    smtp_user = get_setting('smtp_user')
    smtp_pass_encrypted = get_setting('smtp_password')
    smtp_from = get_setting('smtp_from') or smtp_user

    smtp_pass = decrypt_sensitive_value(smtp_pass_encrypted)

    msg = MIMEText(email_body, "html")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [email], msg.as_string())

        # ✅ Log success
        log_email(email, subject, "Success")

    except Exception as e:
        # ✅ Log failure
        log_email(email, subject, "Failed", str(e))
        raise self.retry(exc=e)