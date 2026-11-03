MASK = 0xFFFFFFFF   # keep numbers to 32 bits
ROUNDS = 8
BLOCK = 8           # bytes per block


def make_keys(password):
    seed = 0x12345678
    for b in password.encode():
        seed = (seed * 31 + b) & MASK
    keys = []
    for _ in range(ROUNDS):
        seed = (seed * 1103515245 + 12345) & MASK
        keys.append(seed)
    return keys


def f(right, key):
    rotated = ((right << 5) | (right >> 27)) & MASK
    return ((right + key) & MASK) ^ rotated


def encrypt_block(block, keys):
    left, right = block >> 32, block & MASK
    for k in keys:
        left, right = right, left ^ f(right, k)
    return (left << 32) | right


def decrypt_block(block, keys):
    left, right = block >> 32, block & MASK
    for k in reversed(keys):
        left, right = right ^ f(left, k), left
    return (left << 32) | right


def encrypt(text, password):
    data = text.encode()
    pad = BLOCK - len(data) % BLOCK
    data += bytes([pad]) * pad

    keys = make_keys(password)
    out = b""
    for i in range(0, len(data), BLOCK):
        block = int.from_bytes(data[i:i + BLOCK], "big")
        out += encrypt_block(block, keys).to_bytes(BLOCK, "big")
    return out.hex().upper()


def decrypt(hex_text, password):
    data = bytes.fromhex(hex_text)
    keys = make_keys(password)
    out = b""
    for i in range(0, len(data), BLOCK):
        block = int.from_bytes(data[i:i + BLOCK], "big")
        out += decrypt_block(block, keys).to_bytes(BLOCK, "big")
    return out[:-out[-1]].decode()


if __name__ == "__main__":
    text = input("Enter plaintext: ")
    key = input("Enter secret key: ")

    cipher = encrypt(text, key)
    print("Ciphertext:", cipher)

    plain = decrypt(cipher, key)
    print("Decrypted :", plain)
    print("SUCCESS" if plain == text else "FAILURE")