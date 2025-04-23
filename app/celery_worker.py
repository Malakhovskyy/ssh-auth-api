from celery import Celery
from tasks.tasks import send_email_task

celery_app = Celery(
    "ssh_auth_tasks",
    broker="amqp://guest:guest@rabbitmq:5672//",
    backend="rpc://"
)

celery_app.conf.task_routes = {
    "app.tasks.*": {"queue": "default"}
}