from apscheduler.schedulers.background import BackgroundScheduler
import shutil
import os
from services.email_service import send_email

def create_backup():
    source_db = os.path.abspath("./data/sshkeys.db")
    backup_dir = os.path.abspath("./backups/")
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, "sshkeys_backup.db")

    if os.path.exists(source_db):
        shutil.copy(source_db, backup_path)
        send_backup_email(backup_path)
        print("[Backup] Backup created and email sent.")
    else:
        print("[Backup] Source DB does not exist, skipping backup.")

def schedule_daily_backup():
    scheduler = BackgroundScheduler()
    scheduler.add_job(create_backup, 'interval', hours=24)
    scheduler.start()