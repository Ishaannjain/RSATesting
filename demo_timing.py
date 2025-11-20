"""
demo_timing.py
--------------

Demonstration of a timing side-channel attack
against the non-constant-time RSA decryption implemented
in rsa_vulnerable.decrypt_slow_timing().

This is an implementation of the Brumley & Boneh (2003) attack.

The vulnerable function:
    - Performs modular exponentiation using square-and-multiply
    - Introduces extra delay on "multiply" steps when d_i = 1
    - Therefore: decrypt time correlates with the bits of d

    Authors: Sankalp Dasari, Aryan Shiva, Ishaan Jain, Sophia Chukka
"""

from rsa import gen_rsa, os2ip, i2osp
from rsa_vulnerable import decrypt_slow_timing
from rsa_attacks import timing_attack_recover_bit


def main():
    print(" TIMING SIDE-CHANNEL ATTACK \n")

    # ------------------------------------------------------
    # 1. Generate vulnerable RSA key
    # ------------------------------------------------------
    print("Generating 384-bit RSA keypair...")
    keys = gen_rsa(384)
    n, e, d = keys["n"], keys["e"], keys["d"]

    print(f"Modulus size: {n.bit_length()} bits")
    print(f"Private exponent bit length: {d.bit_length()}\n")

    # ------------------------------------------------------
    # 2. Choose a ciphertext to test with
    # ------------------------------------------------------
    test_msg = b"TimingAttack"
    m = os2ip(test_msg)
    c = pow(m, e, n)

    print("Test ciphertext prepared")

    # ------------------------------------------------------
    # 3. Demonstrate timing-based information leak
    # ------------------------------------------------------
    print("Measuring timing leakage...")
    print("    (Decrypting the same ciphertext several times...)")

    # Example: recover last 6 bits of d
    bits_to_recover = 6
    real_bits = bin(d)[-bits_to_recover:]
    guessed_bits = ""

    print("\n Attempting to recover last 6 bits of d:")
    print(f"    Real bits (for comparison after attack): {real_bits}")

    for bit_index in range(bits_to_recover):
        guess, avg_time, actual_bit = timing_attack_recover_bit(
            c, bit_index, d, n, trials=8
        )

        guessed_bits += guess

        print(f"\n  - Bit {bit_index}:")
        print(f"      Measured avg time = {avg_time:.5f} sec")
        print(f"      Guessed bit       = {guess}")
        print(f"      Actual bit        = {actual_bit}")

    print("\n=== RESULTS ===")
    print(f"Guessed bits (LSB → ...): {guessed_bits}")
    print(f"Actual bits  (LSB → ...): {real_bits}")


if __name__ == "__main__":
    main()
