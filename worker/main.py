from celery import Celery
from services import email_send  # ensures task is registered

celery_app = Celery(
    "ssh_auth_tasks",
    broker="amqp://guest:guest@rabbitmq:5672//",
    backend="rpc://"
)

celery_app.conf.task_routes = {
    "services.email_send.*": {"queue": "default"}
}