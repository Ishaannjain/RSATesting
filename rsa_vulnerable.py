"""
INTENTIONALLY VULNERABLE RSA IMPLEMENTATIONS
============================================
This file contains a vulnerable version of RSA operations that the attacks
(Bleichenbacher padding oracle, timing attack, and CRT fault attack)
will exploit.

Features:
    PKCS#1 v1.5 padding oracle (True/False leak)
    Non-constant-time RSA decryption (timing varies with key bits)
    CRT RSA decryption

Authors: Sankalp Dasari, Aryan Shiva, Ishaan Jain, Sophia Chukka
"""

import time
from math import ceil
from secrets import randbits

# --- utilities imported from the rsa.py ---
def os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")

def i2osp(x: int, k: int) -> bytes:
    return x.to_bytes(k, "big")

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


# =====================================================================
#          1.  PKCS#1 v1.5 PADDING ORACLE
# =====================================================================

def pkcs1_pad(msg, k, n):
    from secrets import token_bytes

    while True:
        ps_len = k - len(msg) - 3
        ps = token_bytes(ps_len)
        if b"\x00" in ps:
            continue

        padded = b"\x00\x02" + ps + b"\x00" + msg
        m = int.from_bytes(padded, "big")

        if m < n:      
            return padded


def pkcs1_unpad(block: bytes) -> bool:
    """
    Return TRUE if block has valid PKCS#1 v1.5 structure, FALSE otherwise.
    This is EXACTLY the leak Bleichenbacher exploits.

    VALID = 00 02  [nonzero padding] 00  <message...>
    """
    # must start with 0x00 0x02
    if len(block) < 11:
        return False
    if block[0] != 0 or block[1] != 2:
        return False

    # find zero separator after padding
    try:
        sep_index = block.index(b'\x00', 2)
    except ValueError:
        return False

    # padding must be non-empty
    if sep_index < 10:
        return False

    return True


def padding_oracle(ciphertext: bytes, n: int, d: int) -> bool:
    """Return True only if PKCS#1 v1.5 padding is *valid*."""

    k = (n.bit_length() + 7) // 8
    c = os2ip(ciphertext)
    m = pow(c, d, n)
    m_bytes = i2osp(m, k)

    # Must start with 00 02
    if not (m_bytes[0] == 0x00 and m_bytes[1] == 0x02):
        return False

    # Next bytes until the 0x00 separator must be nonzero
    # Separator must not appear too early
    try:
        sep_index = m_bytes.index(0x00, 2)  # find first zero byte after block type
    except ValueError:
        return False  # no separator found → invalid

    # PS must be at least 8 bytes
    if sep_index < 10:   # 2 bytes header + 8 bytes minimum padding
        return False

    # All padding bytes must be NONZERO
    if any(b == 0x00 for b in m_bytes[2:sep_index]):
        return False

    return True



# =====================================================================
#        2.  NON-CONSTANT-TIME RSA DECRYPTION (TIMING ATTACK)
# =====================================================================

def decrypt_slow_timing(ct: int, d: int, n: int):
    """
    Vulnerable RSA exponentiation — processes bits of d one-by-one
    and sleeps slightly more for '1' bits.

    This leak allows Brumley & Boneh (2003)–style timing analysis.
    """

    start = time.perf_counter()

    result = 1
    base = ct % n

    # Iterate through bits of d
    for bit in bin(d)[2:]:
        # always do one square
        result = (result * result) % n

        if bit == "1":
            # multiply step AND add artificial delay
            time.sleep(0.00025)     # ← vulnerability
            result = (result * base) % n

    end = time.perf_counter()
    return result, (end - start)


# =====================================================================
#                  3.  CRT RSA DECRYPTION
# =====================================================================

def crt_decrypt(c: int, p: int, q: int, d: int, n: int):
    """
    Compute RSA decryption using Chinese Remainder Theorem.
    Returns (m, (m1, m2)).
    """
    dp = d % (p - 1)
    dq = d % (q - 1)

    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)

    # CRT recombination
    q_inv = pow(q, -1, p)
    h = (q_inv * (m1 - m2)) % p
    m = (m2 + h * q) % n
    return m, (m1, m2)


def crt_decrypt_faulty(c: int, p: int, q: int, d: int, n: int, mode='flip'):
    """
    Introduce a FAULT in the CRT computation.
    This models a power glitch or hardware injection attack.

    Options:
        mode = 'flip' → flip last bit of m1
        mode = 'zero' → set m1 to zero

    Returns:
        faulty_m, (faulty_m1, m2)
    """
    dp = d % (p - 1)
    dq = d % (q - 1)

    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)

    # introduce the fault
    if mode == 'flip':
        m1_fault = m1 ^ 1    # flip least significant bit
    elif mode == 'zero':
        m1_fault = 0
    else:
        raise ValueError("unknown fault mode")

    # CRT recombination 
    q_inv = pow(q, -1, p)
    h = (q_inv * (m1_fault - m2)) % p
    m_faulty = (m2 + h * q) % n

    return m_faulty, (m1_fault, m2)


def recover_factor_from_fault(m_correct: int, m_faulty: int, n: int) -> int:
    """
    Bellcore / Lenstra attack:
        p = gcd(n, m_correct - m_faulty)

    One faulty CRT operation reveals the entire RSA factorization!
    """
    diff = (m_correct - m_faulty) % n
    return gcd(diff, n)


