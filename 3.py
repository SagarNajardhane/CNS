import rsa 
import time 
 
key_sizes = [512, 1024, 2048] 
message = input("Enter the message: ").encode() 
 
for bits in key_sizes: 
    print("\n" + "=" * 50) 
    print(f"RSA Key Size: {bits} bits") 
 
    # Key generation 
    start = time.perf_counter() 
    public_key, private_key = rsa.newkeys(bits) 
    key_time = time.perf_counter() - start 
 
    # Encryption 
    start = time.perf_counter() 
    cipher = rsa.encrypt(message, public_key) 
    encrypt_time = time.perf_counter() - start 
 
    # Decryption 
    start = time.perf_counter() 
    decrypted = rsa.decrypt(cipher, private_key) 
    decrypt_time = time.perf_counter() - start 
 
    print("\nOriginal Message :", message.decode()) 
    print("Encrypted Message:", cipher) 
    print("Decrypted Message:", decrypted.decode()) 
 
    print("\nTime Required") 
    print(f"Key Generation : {key_time:.6f} seconds") 
    print(f"Encryption     : {encrypt_time:.6f} seconds") 
    print(f"Decryption     : {decrypt_time:.6f} seconds")