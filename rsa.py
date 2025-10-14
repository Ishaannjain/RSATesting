from secrets import randbits

def gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)

def egcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def modinv(a, m):
    g, x, _ = egcd(a % m, m)    
    return x % m

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

def rand_odd_bits(bits):
    x = randbits(bits)
    x |= (1 << (bits - 1))
    x |= 1
    return x

def gen_prime(bits):
    while True:
        c = rand_odd_bits(bits)
        if is_probable_prime(c):
            return c

def gen_rsa(bits=1024):
    e = 65537
    p = gen_prime(bits // 2)
    q = gen_prime(bits - bits // 2)
    while p == q:
        q = gen_prime(bits - bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        return gen_rsa(bits)
    d = modinv(e, phi)
    return {"n": n, "e": e, "d": d, "p": p, "q": q}

def os2ip(b):
    return int.from_bytes(b, "big")

def i2osp(x, k):
    return x.to_bytes(k, "big")

def rsa_encrypt_int(m, n, e):
    return pow(m, e, n)

def rsa_decrypt_int(c, n, d):
    return pow(c, d, n)

def encrypt_bytes(msg, n, e):
    k = (n.bit_length() + 7) // 8
    m = os2ip(msg)
    c = rsa_encrypt_int(m, n, e)
    return i2osp(c, k)

def decrypt_bytes(ct, n, d):
    k = (n.bit_length() + 7) // 8
    c = os2ip(ct)
    m = rsa_decrypt_int(c, n, d)
    return i2osp(m, k)

if __name__ == "__main__":
    keys = gen_rsa(1024)
    n, e, d = keys["n"], keys["e"], keys["d"]
    msg = b"hello RSA"
    ct = encrypt_bytes(msg, n, e)
    pt_block = decrypt_bytes(ct, n, d)
    print("n bits:", n.bit_length())
    print("cipher len:", len(ct))
    print("plaintext recovered (right-aligned):", pt_block.endswith(msg))