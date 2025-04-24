from models.models import get_db_connection
from celery import Celery

def queue_provisioning_task(task_id: int):
    celery_app = Celery(
        "ssh_auth_tasks",
        broker="amqp://guest:guest@rabbitmq:5672//",
        backend="rpc://"
    )
    celery_app.send_task("services.provision_user.provision_user_task", args=[task_id])


def trigger_provisioning_task(user_id: int, server_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Insert provisioning task
    cursor.execute('''
        INSERT INTO provisioning_tasks (server_id, user_id, status)
        VALUES (?, ?, 'pending')
    ''', (server_id, user_id))
    task_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Send task to RabbitMQ via Celery
    queue_provisioning_task(task_id)

    return task_id