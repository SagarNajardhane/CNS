import hashlib


def sha1_digest(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def bit_difference(h1, h2):
    return bin(int(h1, 16) ^ int(h2, 16)).count("1")


def compare(t1, t2):
    h1, h2 = sha1_digest(t1), sha1_digest(t2)
    diff = bit_difference(h1, h2)
    print(f"\nInput 1       : {t1}")
    print(f"SHA-1         : {h1}")
    print(f"Input 2       : {t2}")
    print(f"SHA-1         : {h2}")
    print(f"Hashes equal? : {h1 == h2}")
    print(f"Bits changed  : {diff} / 160 ({diff / 160 * 100:.2f}%)")


def main():
    print("=" * 70)
    print("SHA-1 MESSAGE DIGEST AND AVALANCHE EFFECT DEMONSTRATION")
    print("=" * 70)

    while True:
        t1 = input("\nEnter first text  (or 'q' to quit): ")
        if t1.strip().lower() == "q":
            break
        t2 = input("Enter second text (a slightly modified version): ")
        compare(t1, t2)


if __name__ == "__main__":
    main()