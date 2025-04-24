from celery import Celery
from services import email_send  # Still needed to register task
from services import provision_user  # Registers provisioning task
from celery_config import celery_app  # New import location