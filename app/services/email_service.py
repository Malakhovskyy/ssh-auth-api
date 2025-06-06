from models.models import get_setting
from celery import Celery

def queue_email(subject, body, to_email):
    celery_app = Celery(
        "ssh_auth_tasks",
        broker="amqp://guest:guest@rabbitmq:5672//",
        backend="rpc://"
    )
    celery_app.send_task("services.email_send.send_email_task", args=[subject, body, to_email])


# def send_backup_email(backup_path):
#     subject = "SSH Key Manager - Daily Backup"
#     body = "Attached is the daily database backup."
#     # SMTP_TO must still be provided separately because backup may go to fixed email
#     admin_email = get_setting('smtp_from') or get_setting('smtp_user')
#     queue_email(subject, f"Backup is available at {backup_path}", admin_email)

def send_email(email, subject, email_body):
    queue_email(email, subject, email_body)