"""
rsa.py
------

This file Contains:
    - Prime generation using Miller–Rabin probabilistic testing
    - Key generation (public modulus n, public exponent e, private exponent d)
    - Integer/byte conversion utilities (OS2IP / I2OSP)
    - Raw textbook RSA encryption and decryption (no padding)

IMPORTANT:
    This is a *secure* reference implementation Of Textbook RSA
    but does NOT include padding (e.g., PKCS#1). Raw textbook RSA is
    insecure in real-world deployments. We intentionally omit padding
    because the project demonstrates padding oracle attacks separately.

Authors: Sankalp Dasari, Aryan Shiva, Ishaan Jain, Sophia Chukka
"""
from secrets import randbits

# ============================================================================
#  BASIC MATH UTILITIES
# ============================================================================

"""
 Compute gcd(a, b) using the Euclidean Algorithm.

Parameters:
    a (int)
    b (int)

Returns:
    int: The greatest common divisor of a and b.
"""
def gcd(a, b) -> int:
    
     while b:
        a, b = b, a % b
     return abs(a)

"""
Extended Euclidean Algorithm.
Solves for integers (x, y) such that:

a*x + b*y = gcd(a, b)

Parameters:
    a (int)
    b (int)

Returns:
    (g, x, y) where:
        g = gcd(a, b)
        x = Bezout coefficient for a
        y = Bezout coefficient for b
"""
def egcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


"""
Compute the modular inverse of a modulo m.
That is, find x such that:

    a*x ≡ 1 (mod m)

Parameters:
    a (int)
    m (int)

Returns:
    int: The modular inverse (0 < x < m).

 Raises:
    ValueError: If the inverse does not exist.
"""
def modinv(a, m):
    g, x, _ = egcd(a % m, m)    
    return x % m

# ============================================================================
#  MILLER RABIN PRIMALITY TESTING
# ============================================================================
"""
Miller–Rabin probabilistic primality test.

This function returns True for primes and “probably prime”
composites. For cryptographic key sizes, the bases chosen below
are sufficient for strong correctness guarantees.

Parameters:
    n (int): Candidate number

Returns:
    bool: True if probably prime, False if composite.
"""
def is_probable_prime(n):
    if n < 2:
        return False
    small = [2,3,5,7,11,13,17,19,23,29,31,37]
    for p in small:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    bases = [2,3,5,7,11,13,17,19,23]
    for a in bases:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        ok = False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                ok = True
                break
        if not ok:
            return False
    return True


# ============================================================================
#  PRIME GENERATION
# ============================================================================

"""
Generate a random odd integer with a fixed bit length.

Ensures:
    - MSB set  => correct bit length
    - LSB set  => odd number

This produces a valid candidate for primality testing.
"""
def rand_odd_bits(bits):
    x = randbits(bits)
    x |= (1 << (bits - 1))
    x |= 1
    return x

"""
    Generate a prime number of a given bit length.

    Parameters:
        bits (int): Desired bit length.

    Returns:
        int: A probable prime.
"""
def gen_prime(bits) -> int:
    while True:
        candidate = rand_odd_bits(bits)
        if is_probable_prime(candidate):
            return candidate


# ============================================================================
#  RSA KEY GENERATION
# ============================================================================

"""
    Generate an RSA keypair.

    Parameters:
        bits (int): Size of modulus n in bits.

    Returns:
        dict containing:
            n  (int) — modulus
            e  (int) — public exponent
            d  (int) — private exponent
            p, q (int) — prime factors of n
"""
def gen_rsa(bits=1024):
    e = 65537 # Standard public exponent

    # Split bit size across p and q
    p = gen_prime(bits // 2)
    q = gen_prime(bits - bits // 2)
    while p == q:
        q = gen_prime(bits - bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Ensure e and phi(n) are coprime
    if gcd(e, phi) != 1:
        return gen_rsa(bits)
    d = modinv(e, phi)
    return {"n": n, "e": e, "d": d, "p": p, "q": q}


# ============================================================================
#  INTEGER <-> BYTE CONVERSIONS (OS2IP / I2OSP)
# ============================================================================

"""
    Convert an octet string to a non-negative integer.
    (Big-endian per PKCS#1 convention.)

    Parameters:
        b (bytes): Input byte string.

    Returns:
        int: Non-negative integer value.
"""
def os2ip(b):
    return int.from_bytes(b, "big")


"""
    Convert a non-negative integer to a byte string of length k.
    (Big-endian per PKCS#1 convention.)

    Parameters:
        x (int): Integer to convert.
        k (int): Output length in bytes.

    Returns:
        bytes: The byte representation.
"""
def i2osp(x, k):
    return x.to_bytes(k, "big")

# ============================================================================
#  RAW (UNPADDED) RSA — TEXTBOOK RSA
# ============================================================================

"""
   RSA encryption: c = m^e mod n
"""
def rsa_encrypt_int(m, n, e):
    return pow(m, e, n)


"""
    RSA decryption: m = c^d mod n
"""
def rsa_decrypt_int(c, n, d):
    return pow(c, d, n)


"""
Encrypt arbitrary bytes using raw RSA (textbook RSA — insecure).

Parameters:
    msg (bytes)
    n (int)
    e (int)

Returns:
    bytes: RSA ciphertext of fixed length.
"""
def encrypt_bytes(msg, n, e):
    k = (n.bit_length() + 7) // 8
    m = os2ip(msg)
    c = rsa_encrypt_int(m, n, e)
    return i2osp(c, k)


"""
    Decrypt ciphertext bytes using raw RSA (no padding).

    Parameters:
        ct (bytes)
        n (int)
        d (int)

    Returns:
        bytes: Plaintext block (right-aligned in output).
"""
def decrypt_bytes(ct, n, d) -> bytes:
    k = (n.bit_length() + 7) // 8
    c = os2ip(ct)
    m = rsa_decrypt_int(c, n, d)
    return i2osp(m, k)


# ============================================================================
#  DEMO
# ============================================================================

if __name__ == "__main__":
    keys = gen_rsa(1024)
    n, e, d = keys["n"], keys["e"], keys["d"]


    msg = b"hello RSA"
    ct = encrypt_bytes(msg, n, e)
    pt_block = decrypt_bytes(ct, n, d)


    print("n bits:", n.bit_length())
    print("cipher len:", len(ct))
    print("plaintext recovered:", pt_block.endswith(msg))