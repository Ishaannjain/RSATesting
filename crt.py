"""
Demonstration of the Bellcore/Lenstra RSA CRT fault attack.

The CRT optimization of RSA performs:
    m1 = c^dp mod p
    m2 = c^dq mod q
    m  = CRT(m1, m2)

If an attacker induces a *fault* in m1 (e.g., bit flip),
then the result m' is incorrect *mod p* but correct *mod q*.

Therefore:
    gcd(n, m - m') = p

This demo:
    • Generates RSA (384-bit)
    • Performs correct CRT-decryption
    • Performs FAULTY CRT-decryption (flip bit in m1)
    • Recovers p using gcd
    • Recovers q
    • Verifies factorization

    Authors: Sankalp Dasari, Aryan Shiva, Ishaan Jain, Sophia Chukka
"""

from rsa import gen_rsa, os2ip, i2osp
from rsa_vulnerable import crt_decrypt, crt_decrypt_faulty
from rsa_attacks import perform_crt_fault_attack


def main():
    print("CRT FAULT ATTACK\n")

    # ---------------------------------------------------------
    # 1. Generate a SMALL RSA key (for fast CRT operations)
    # ---------------------------------------------------------
    print(" Generating 384-bit RSA keypair...")
    keys = gen_rsa(384)
    n, e, d = keys["n"], keys["e"], keys["d"]
    p, q = keys["p"], keys["q"]

    print(f" Modulus n size: {n.bit_length()} bits")
    print(f"p = {p}\nq = {q}\n")

    # ---------------------------------------------------------
    # 2. Choose message and encrypt
    # ---------------------------------------------------------
    message = b"CRTAttack!"
    print(f" Original message: {message}")

    m_int = os2ip(message)
    c = pow(m_int, e, n)

    print(f"Ciphertext c = {c}\n")

    # ---------------------------------------------------------
    # 3. Compute correct CRT-based decryption
    # ---------------------------------------------------------
    m_correct, (m1, m2) = crt_decrypt(c, p, q, d, n)
    print(f" Correct m  = {m_correct}")

    # ---------------------------------------------------------
    # 4. Compute FAULTY CRT-based decryption
    # ---------------------------------------------------------
    print("\n Introducing fault in CRT computation...")
    m_faulty, (m1_fault, m2_fixed) = crt_decrypt_faulty(c, p, q, d, n, mode='flip')
    print(f" Faulty m' = {m_faulty}")

    # ---------------------------------------------------------
    # 5. Recover factors using Bellcore/Lenstra method
    # ---------------------------------------------------------
    print("\n Recovering prime factor using gcd(n, m - m') ...")
    p_recovered, q_recovered = perform_crt_fault_attack(c, p, q, d, n)

    print("\n=== RECOVERED FACTORS ===")
    print(f"p' = {p_recovered}")
    print(f"q' = {q_recovered}")

    # ---------------------------------------------------------
    # 6. Validate
    # ---------------------------------------------------------
    print("\n Validation:")
    if {p_recovered, q_recovered} == {p, q}:

        print("    SUCCESS → Factors match original primes.")
    else:
        print("    ERROR → Factors incorrect.")

    print("\nDone.")


if __name__ == "__main__":
    main()
