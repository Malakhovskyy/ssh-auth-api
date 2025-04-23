from ..services.email_service import send_email
from app.celery_worker import celery_app

@celery_app.task
def send_email_task(subject: str, body: str, to_email: str):
    try:
        send_email(subject, body, to_email)
        print(f"[✓] Email sent to {to_email}")
    except Exception as e:
        print(f"[!] Failed to send email to {to_email}: {str(e)}")