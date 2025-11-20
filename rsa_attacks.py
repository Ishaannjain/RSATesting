"""
rsa_attacks.py
-----------------

This file implements the *attacks* against the intentionally vulnerable
RSA services defined in rsa_vulnerable.py.

Attacks Implemented:
    1. Bleichenbacher Padding Oracle Attack (PKCS#1 v1.5)
    2. Timing Side-Channel Attack (Brumley & Boneh 2003 style demo)
    3. CRT Fault Attack (Bellcore/Lenstra fault-based factor recovery)

These functions are used by:
    demo_bleichenbacher.py
    demo_timing.py
    demo_crt_fault.py

Each attack is intentionally simplified to work on small RSA moduli
(256–384 bits) for demonstrtion.

Authors: Sankalp Dasari, Aryan Shiva, Ishaan Jain, Sophia Chukka
"""

from typing import Tuple, List
from math import ceil
from rsa_vulnerable import (
    padding_oracle,
    decrypt_slow_timing,
    crt_decrypt,
    crt_decrypt_faulty,
    recover_factor_from_fault,
    os2ip,
    i2osp
)


# ============================================================================
#  1. BLEICHENBACHER PADDING ORACLE ATTACK
# ============================================================================
def bleichenbacher_attack(ciphertext: bytes, n: int, e: int, oracle, max_rounds=200):
    """
    Fully corrected + optimized Bleichenbacher padding oracle attack.
    This version includes the *correct* Case-1 r-loop search from
    Bleichenbacher (1998), ensuring convergence.
    """

    k = (n.bit_length() + 7) // 8
    B = 2 ** (8 * (k - 2))
    c0 = os2ip(ciphertext)

    # Step 1 — Initial interval
    M = [(2 * B, 3 * B - 1)]
    debug = ["=== Optimized Bleichenbacher Attack ==="]

    # Step 2 — Find s1
    s = ceil(n / (3 * B))
    debug.append(f"[Round 1] Searching s1 starting at {s}")

    while True:
        c_test = (c0 * pow(s, e, n)) % n
        if oracle(i2osp(c_test, k)):
            debug.append(f"  ✓ Found s1 = {s}")
            break
        s += 1

    # MAIN LOOP
    for i in range(2, max_rounds + 1):

        debug.append(f"\n[Round {i}] Starting with {len(M)} intervals")

        # ------------------------------------------------------------------
        # CASE 1 — EXACTLY ONE INTERVAL REMAINS
        # (We must use the r-loop search from Bleichenbacher’s paper)
        # ------------------------------------------------------------------
        if len(M) == 1:
            a, b = M[0]

            # Correct r starting value
            r = ceil((a * s - 3 * B + 1) / n)

            found = False
            while not found:
                # Correct bounds on s
                s_lo = ceil((2 * B + r * n) / b)
                s_hi = (3 * B - 1 + r * n) // a

                for s_candidate in range(s_lo, s_hi + 1):
                    c_test = (c0 * pow(s_candidate, e, n)) % n
                    if oracle(i2osp(c_test, k)):
                        s = s_candidate
                        found = True
                        break

                r += 1

        # ------------------------------------------------------------------
        # CASE 2 — MULTIPLE INTERVALS
        # Linear search for next s (fast enough for small keys)
        # ------------------------------------------------------------------
        else:
            s += 1
            while True:
                c_test = (c0 * pow(s, e, n)) % n
                if oracle(i2osp(c_test, k)):
                    break
                s += 1

        # ------------------------------------------------------------------
        # STEP 3 — UPDATE INTERVALS
        # ------------------------------------------------------------------
        new_M = []

        for (a, b) in M:
            r_min = ceil((a * s - (3 * B - 1)) / n)
            r_max = (b * s - (2 * B)) // n

            for r in range(r_min, r_max + 1):
                lower = max(a, ceil((2 * B + r * n) / s))
                upper = min(b, (3 * B - 1 + r * n) // s)

                if lower <= upper:
                    new_M.append((lower, upper))

        # Merge intervals
        new_M.sort()
        merged = []
        curL, curH = new_M[0]

        for L, H in new_M[1:]:
            if L <= curH:
                curH = max(curH, H)
            else:
                merged.append((curL, curH))
                curL, curH = L, H

        merged.append((curL, curH))
        M = merged

        debug.append(f"  → After merging: {len(M)} intervals")

        # ------------------------------------------------------------------
        # STEP 4 — CHECK FOR FINISH
        # ------------------------------------------------------------------
        if len(M) == 1 and M[0][0] == M[0][1]:
            recovered_int = M[0][0]
            recovered_bytes = i2osp(recovered_int, k)
            return recovered_bytes, "\n".join(debug)

    # Attack failed
    return None, "\n".join(debug) + "\n\nAttack failed after max rounds."



# ============================================================================
#  2. TIMING SIDE-CHANNEL ATTACK
# ============================================================================

def timing_attack_recover_bit(ct: int, d_bit_count: int, d: int, n: int, trials=4):
    """
    Recover a SINGLE BIT of d by timing decryptions.

    Idea:
        If the current bit of d is 1 → multiply step happens → extra delay.
        If it is 0 → no multiplication → faster.

    Parameters:
        ct (int): ciphertext
        d_bit_count (int): which bit index of d we want to target
        d (int): private exponent
        n (int): modulus
        trials (int): average over multiple decryptions

    Returns:
        ("0" or "1", avg_time_0, avg_time_1)
    """

    d_bits = bin(d)[2:].zfill(d_bit_count + 1)
    target_bit = d_bits[-1 - d_bit_count]

    # Measure average timing
    total_time = 0
    for _ in range(trials):
        _, t = decrypt_slow_timing(ct, d, n)
        total_time += t
    avg = total_time / trials

    # Threshold for decision
    guess = "1" if avg > 0.003 else "0"
    return guess, avg, target_bit


# ============================================================================
#  3. CRT FAULT ATTACK — FACTOR RECOVERY
# ============================================================================

def perform_crt_fault_attack(c: int, p: int, q: int, d: int, n: int, mode='flip'):
    """
    Executes the full CRT fault attack process.

    Steps:
        1. Compute correct m using CRT
        2. Compute faulty m' using injected fault
        3. Compute gcd(n, m - m') = p (or q)
        4. Recover the missing factor, then the entire RSA private key

    Returns:
        (recovered_p, recovered_q)
    """

    m_correct, _ = crt_decrypt(c, p, q, d, n)
    m_faulty, _ = crt_decrypt_faulty(c, p, q, d, n, mode=mode)

    p_recovered = recover_factor_from_fault(m_correct, m_faulty, n)
    q_recovered = n // p_recovered

    return p_recovered, q_recovered
