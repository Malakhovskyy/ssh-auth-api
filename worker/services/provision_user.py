import requests
from datetime import datetime
from models.models import get_db_connection
from celery_config import celery_app
from services.encryption_service import decrypt_sensitive_value


@celery_app.task(bind=True, max_retries=None)
def provision_user_task(self, task_id: int):
    try:
        conn = get_db_connection()

        task = conn.execute("SELECT * FROM provisioning_tasks WHERE id = ?", (task_id,)).fetchone()
        if not task:
            return

        server = conn.execute("SELECT * FROM servers WHERE id = ?", (task["server_id"],)).fetchone()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (task["user_id"],)).fetchone()
        proxy = conn.execute("SELECT * FROM gateway_proxies WHERE id = ?", (server["proxy_id"],)).fetchone()
        ssh_key = conn.execute("SELECT ssh_key_data FROM ssh_keys WHERE id = ?", (server["system_ssh_key_id"],)).fetchone()

        if not server or not user or not proxy or not ssh_key:
            conn.execute("UPDATE provisioning_tasks SET status = 'failed' WHERE id = ?", (task_id,))
            conn.commit()
            conn.close()
            return

        payload = {
            "task_id": task_id,
            "username": user["username"],
            "server_ip": server["server_ip"],
            "server_ssh_port": server["server_ssh_port"],
            "system_username": server["system_username"],
            "system_ssh_key": decrypt_sensitive_value(ssh_key["ssh_key_data"])
        }

        headers = {
            "Authorization": f"Bearer {proxy['proxy_auth_token']}"
        }

        proxy_url = f"https://{proxy['proxy_ip']}:{proxy['proxy_port']}/post_task/{task_id}"
        response = requests.post(proxy_url, json=payload, headers=headers, timeout=10, verify=False)

        if response.status_code == 200:
            conn.execute("UPDATE provisioning_tasks SET status = 'in_progress' WHERE id = ?", (task_id,))
            conn.commit()
            conn.close()
            monitor_provisioning_status.delay(task_id)
        else:
            conn.execute("UPDATE provisioning_tasks SET status = 'failed' WHERE id = ?", (task_id,))
            conn.execute("INSERT INTO provisioning_logs (task_id, log_text) VALUES (?, ?)", (task_id, f"Failed to send task: {response.text}"))
            conn.commit()
            conn.close()

    except Exception as e:
        log_msg = f"[!] Exception during task execution: {str(e)}"
        conn = get_db_connection()
        conn.execute("UPDATE provisioning_tasks SET status = 'failed' WHERE id = ?", (task_id,))
        conn.execute("INSERT INTO provisioning_logs (task_id, log_text) VALUES (?, ?)", (task_id, log_msg))
        conn.commit()
        conn.close()
        raise self.retry(exc=e, countdown=10)


@celery_app.task(bind=True, max_retries=None)
def monitor_provisioning_status(self, task_id: int):
    import time

    conn = get_db_connection()
    task = conn.execute("SELECT * FROM provisioning_tasks WHERE id = ?", (task_id,)).fetchone()
    server = conn.execute("SELECT * FROM servers WHERE id = ?", (task["server_id"],)).fetchone()
    proxy = conn.execute("SELECT * FROM gateway_proxies WHERE id = ?", (server["proxy_id"],)).fetchone()
    conn.close()

    headers = {
        "Authorization": f"Bearer {proxy['proxy_auth_token']}"
    }

    for _ in range(20):  # 60 seconds, 3s intervals
        try:
            get_url = f"https://{proxy['proxy_ip']}:{proxy['proxy_port']}/get_task/{task_id}"
            response = requests.get(get_url, headers=headers, timeout=5, verify=False)
            print(f"[DEBUG] Raw response from proxy for task {task_id}: {response.text}")
            data = response.json()
            status = data.get("status")
            log = data.get("log", "")

            print(f"[DEBUG] Polling task {task_id}: status={status}")

            if status in ["done", "failed"]:
                with get_db_connection() as conn:
                    conn.execute("UPDATE provisioning_tasks SET status = ? WHERE id = ?", (status, task_id))
                    conn.execute("INSERT INTO provisioning_logs (task_id, log_text) VALUES (?, ?)", (task_id, log))
                    conn.commit()
                return
        except Exception:
            pass

        time.sleep(3)

    print(f"[DEBUG] Task {task_id} polling timed out after 60 seconds.")
    with get_db_connection() as conn:
        conn.execute("UPDATE provisioning_tasks SET status = 'timeout' WHERE id = ?", (task_id,))
        conn.execute("INSERT INTO provisioning_logs (task_id, log_text) VALUES (?, ?)", (task_id, "SSH Gateway Timeout"))
        conn.commit()