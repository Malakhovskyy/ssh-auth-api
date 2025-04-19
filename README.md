# SSH Key Manager API

Full system to manage SSH public keys via API with server access control, admin panel, logs, backups, and SSL.

---

## 📦 Features

- FastAPI backend for performance
- Admin Panel (create admins, users, servers, assign users to servers)
- API: fetch SSH public keys based on server/user
- IP / CIDR / ASN protection (only allow API access from specific sources)
- Daily automatic DB backups to email
- Full admin action and API access logging
- Password reset via email
- Forced password change on first login
- Nginx reverse proxy + Let's Encrypt auto SSL
- Bash script for servers to fetch SSH keys dynamically

---

## 🚀 Quick Start

### 1. Clone the repo:

```bash
git clone https://github.com/yourname/ssh-key-manager.git
cd ssh-key-manager