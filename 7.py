"""
Digital Signature Standard (DSS/DSA) demo for a government e-procurement portal.

Shows:
  1. Authentication    - signature verifies only with the vendor's real public key
  2. Integrity         - any change to the tender document breaks the signature
  3. Non-repudiation   - only the private-key holder could sign, and the public key
                         is bound to the vendor's identity (simulated CA registry)
"""

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa


def verify(public_key, message: bytes, signature: bytes) -> bool:
    """Return True if the signature is valid for the message."""
    try:
        public_key.verify(signature, message, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Step 1: Key generation (vendor)
# ---------------------------------------------------------------------------
vendor_private_key = dsa.generate_private_key(key_size=2048)  # kept secret
vendor_public_key = vendor_private_key.public_key()           # shared with the portal
print("Step 1: Vendor DSA key pair generated (2048 bit)\n")

# Simulated Certificate Authority registry: binds vendor identity -> public key.
# In real life this is an X.509 certificate issued by a trusted CA.
ca_registry = {"Vendor ABC Pvt. Ltd.": vendor_public_key}
print("Step 1b: Vendor's public key registered with CA (identity binding)\n")

# ---------------------------------------------------------------------------
# Step 2: Vendor signs the tender document
# ---------------------------------------------------------------------------
tender = (
    b"Tender No. GOV/2026/041: Vendor ABC Pvt. Ltd. quotes "
    b"Rs. 12,50,000 for supply of 100 laptops"
)
digest = hashlib.sha256(tender).hexdigest()
signature = vendor_private_key.sign(tender, hashes.SHA256())  # hash with SHA-256, then sign

print("Step 2: Tender signed by vendor")
print("Tender    :", tender.decode())
print("SHA-256   :", digest[:60], "...")
print("Signature :", signature.hex()[:60], "...\n")

# ---------------------------------------------------------------------------
# Step 3: Portal verifies the original tender (authentication + non-repudiation)
# ---------------------------------------------------------------------------
print("Step 3: Portal verifies original tender using vendor's CA-registered public key")
registered_key = ca_registry["Vendor ABC Pvt. Ltd."]
if verify(registered_key, tender, signature):
    print("Result: Signature VALID -> Authentic, unchanged, vendor cannot deny\n")
else:
    print("Result: Signature INVALID\n")

# ---------------------------------------------------------------------------
# Step 4: Tampered tender (integrity test)
# ---------------------------------------------------------------------------
tampered = (
    b"Tender No. GOV/2026/041: Vendor ABC Pvt. Ltd. quotes "
    b"Rs. 2,50,000 for supply of 100 laptops"
)
print("Step 4: Verifying tampered tender")
print("Tampered  :", tampered.decode())
print("SHA-256   :", hashlib.sha256(tampered).hexdigest()[:60], "... (differs from original)")
if verify(registered_key, tampered, signature):
    print("Result: Signature VALID\n")
else:
    print("Result: Signature INVALID -> Tender was modified (integrity violated)\n")

# ---------------------------------------------------------------------------
# Step 5: Attacker's public key (authentication test)
# ---------------------------------------------------------------------------
attacker_public_key = dsa.generate_private_key(key_size=2048).public_key()
print("Step 5: Verifying with an attacker's public key")
if verify(attacker_public_key, tender, signature):
    print("Result: Signature VALID\n")
else:
    print("Result: Signature INVALID -> Sender identity not authenticated\n")
