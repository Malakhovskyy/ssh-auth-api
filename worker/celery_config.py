from celery import Celery

celery_app = Celery(
    "ssh_auth_tasks",
    broker="amqp://guest:guest@rabbitmq:5672//",
    backend="rpc://"
)

celery_app.conf.task_routes = {
    "services.email_send.*": {"queue": "default"}
}

celery_app.conf.update(
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)