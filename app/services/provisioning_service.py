import secrets
import string
from models.models import get_db_connection
from celery import Celery
from services.encryption_service import encrypt_sensitive_value

def queue_provisioning_task(task_id: int):
    celery_app = Celery(
        "ssh_auth_tasks",
        broker="amqp://guest:guest@rabbitmq:5672//",
        backend="rpc://"
    )
    celery_app.send_task("services.provision_user.provision_user_task", args=[task_id])


def trigger_provisioning_task(user_id: int, server_id: int):
    # Generate a secure random password
    password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    encrypted_password = encrypt_sensitive_value(password)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Insert provisioning task with encrypted password
    cursor.execute('''
        INSERT INTO provisioning_tasks (server_id, user_id, status, generated_password)
        VALUES (?, ?, 'pending', ?)
    ''', (server_id, user_id, encrypted_password))

    task_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Send task to RabbitMQ via Celery
    queue_provisioning_task(task_id)

    return task_id