import smtplib
from email.mime.text import MIMEText
from models.models import get_setting, log_email
from celery_config import celery_app
from services.encryption_service import decrypt_sensitive_value

@celery_app.task(name="services.email_send.send_email_task")
def send_email_task(subject: str, body: str, to_email: str):
    try:
        smtp_host = get_setting("smtp_host")
        smtp_port = int(get_setting("smtp_port"))
        smtp_user = get_setting("smtp_user")
        smtp_pass_encrypted = get_setting('smtp_password')
        smtp_from = get_setting("smtp_from") or smtp_user
        smtp_use_tls = get_setting("smtp_use_tls") == "1"

        smtp_pass = decrypt_sensitive_value(smtp_pass_encrypted)

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = to_email

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if smtp_use_tls:
                server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [to_email], msg.as_string())
            log_email(to_email, subject, "Success")

        print(f"[✓] Email sent to {to_email}")

    except Exception as e:
        log_email(to_email, subject, "Failed", str(e))
        print(f"[!] Failed to send email to {to_email}: {str(e)}")