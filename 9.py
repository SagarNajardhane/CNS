import os, hashlib, hmac 
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad 
from Crypto.Protocol.KDF import PBKDF2 
from Crypto.Hash import SHA256 
from PIL import Image, ImageDraw 
 
def make_sample_image(path="original.png"): 
    img = Image.new("RGB", (200, 120), "white") 
    d = ImageDraw.Draw(img) 
    d.rectangle([10, 10, 190, 110], outline="blue", width=4) 
    d.ellipse([60, 30, 140, 90], fill="orange") 
    d.text((70, 52), "SECRET", fill="black") 
    img.save(path) 
 
def derive_keys(password, salt): 
    # 64 bytes -> 32-byte AES-256 key + 32-byte HMAC key 
    k = PBKDF2(password, salt, dkLen=64, count=100000, 
               hmac_hash_module=SHA256) 
    return k[:32], k[32:] 
 
def sender_encrypt(path, password): 
    data = open(path, "rb").read() 
    salt, iv = os.urandom(16), os.urandom(16) 
    enc_key, mac_key = derive_keys(password, salt) 
    cipher = AES.new(enc_key, AES.MODE_CBC, iv) 
    ciphertext = cipher.encrypt(pad(data, AES.block_size)) 
    # Encrypt-then-MAC 
    tag = hmac.new(mac_key, salt + iv + ciphertext, hashlib.sha256).digest() 
    packet = salt + iv + ciphertext + tag 
    return packet, hashlib.sha256(data).hexdigest() 
 
def receiver_decrypt(packet, password): 
    salt, iv, tag = packet[:16], packet[16:32], packet[-32:] 
    ciphertext = packet[32:-32] 
    enc_key, mac_key = derive_keys(password, salt) 
    expected = hmac.new(mac_key, salt + iv + ciphertext, hashlib.sha256).digest() 
    if not hmac.compare_digest(tag, expected): 
        raise ValueError("HMAC verification FAILED - image tampered or wrong key!") 
    return unpad(AES.new(enc_key, AES.MODE_CBC, iv).decrypt(ciphertext), 
                 AES.block_size) 
 
if __name__ == "__main__": 
    password = b"SharedSecret@123" 
    make_sample_image() 
    print("[Sender] Original image: original.png (%d bytes)" % os.path.getsize("original.png")) 
    packet, h1 = sender_encrypt("original.png", password) 
    open("encrypted.bin", "wb").write(packet) 
    print("[Sender] SHA-256 of original :", h1) 
    print("[Sender] Encrypted packet    : encrypted.bin (%d bytes)" % len(packet)) 
    print("[Network] Ciphertext (first 32 bytes hex):", packet[32:64].hex()) 
 
    plain = receiver_decrypt(open("encrypted.bin", "rb").read(), password) 
    open("decrypted.png", "wb").write(plain) 
    h2 = hashlib.sha256(plain).hexdigest() 
    print("[Receiver] HMAC verification : PASSED") 
    print("[Receiver] SHA-256 of decrypted:", h2) 
    print("[Receiver] Image intact?     :", h1 == h2) 
 
    print("\n--- Test 1: attacker modifies ciphertext ---") 
    bad = bytearray(packet); bad[100] ^= 0xFF 
    try: receiver_decrypt(bytes(bad), password) 
    except ValueError as e: print("[Receiver]", e) 
 
    print("\n--- Test 2: wrong password ---") 
    try: receiver_decrypt(packet, b"WrongPassword") 
    except ValueError as e: print("[Receiver]", e)