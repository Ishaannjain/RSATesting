"""
bleichenbacher.py
----------------------

Demonstration of the Bleichenbacher padding oracle attack
against the intentionally vulnerable RSA implementation.

This script:
    • Generates a small (384-bit) RSA keypair
    • Pads a plaintext using PKCS#1 v1.5
    • Encrypts the padded message
    • Queries the padding oracle (True/False)
    • Runs the Bleichenbacher attack to recover plaintext

    Authors: Sankalp Dasari, Aryan Shiva, Ishaan Jain, Sophia Chukka
"""

from rsa import gen_rsa, os2ip, i2osp
from rsa_vulnerable import pkcs1_pad, padding_oracle
from rsa_attacks import bleichenbacher_attack


from rsa import gen_rsa, os2ip, i2osp
from rsa_vulnerable import pkcs1_pad, padding_oracle
from rsa_attacks import bleichenbacher_attack

def main():
    print("BLEICHENBACHER ATTACK\n")

    # 1. Generate small RSA key
    print("[*] Generating a 256-bit RSA keypair...")
    keys = gen_rsa(256)
    n, e, d = keys["n"], keys["e"], keys["d"]
    k = (n.bit_length() + 7) // 8
    print(f"[*] Modulus size: {n.bit_length()} bits ({k} bytes)\n")

    # 2. Choose a message
    message = b"Cryptography II"
    print(f"[*] Original message: {message}\n")

    # 3. PKCS1 padding
    padded = pkcs1_pad(message, k, n)  # new version
    m = os2ip(padded)
    c = pow(m, e, n)
    ciphertext = i2osp(c, k)

    # 4. Encrypt
    m = os2ip(padded)
    c = pow(m, e, n)
    ct = i2osp(c, k)
    print("[*] Ciphertext generated.")

    # 5. Run the optimized attack
    print("[*] Running optimized Bleichenbacher attack...\n")
    recovered_block, logs = bleichenbacher_attack(
        ct, n, e,
        oracle=lambda ct: padding_oracle(ct, n, d),
        max_rounds=200
    )

    if recovered_block is None:
        print("[!] Attack failed\n")
        print(logs)
        return

    print("=== ATTACK SUCCESSFUL ===")
    print("Recovered block:", recovered_block.hex())

    # Extract message
    idx = recovered_block.index(b"\x00", 2)
    recovered_msg = recovered_block[idx+1:]
    print("Recovered message:", recovered_msg)

    print("\n--- Debug Log ---")
    print(logs)

if __name__ == "__main__":
    main()