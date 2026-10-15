"""Malicious: Multi-layered nested base64 dynamic exec."""
import base64

# Layer 2: base64 of 'import os; os.system("uname -a")'
layer2 = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oInVuYW1lIC1hIik="
# Layer 1: base64 of exec(b64decode(...))
layer1 = base64.b64encode(f"import base64; exec(base64.b64decode('{layer2}'))".encode()).decode()

exec(base64.b64decode(layer1))
