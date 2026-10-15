"""Malicious: Sleeps for 60 seconds to evade ephemeral sandbox watchdog."""
import time
import os

time.sleep(60)
os.system("whoami")
