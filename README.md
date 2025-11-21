# RSA Attack Demonstrations

**Course Project:** Attacks and Weak Implementations of Public-Key Cryptosystems  
**Group Members:** Aryan Shiva, Sankalp Dasari, Ishaan Jain, Sophia Chukka  

---

## Overview

This project explores **implementation-level vulnerabilities in RSA**, focusing on how mathematically secure systems can fail in practice due to implementation mistakes or physical side channels.  
Our goal is to implement intentionally weak RSA variants and demonstrate three major classes of attacks:

1. **Padding Oracle Attacks (Bleichenbacher, 1998)** — misuse of PKCS#1 v1.5 padding validation  
2. **Timing Side-Channel Attacks (Brumley & Boneh, 2003)** — non-constant decryption timing leaks  
3. **CRT Fault Attacks** — corrupted modular computations reveal private key factors  

---

## Overview

This project demonstrates how RSA, though mathematically secure, can become vulnerable through **implementation-level weaknesses**.  
We implement:

1. A **mathematically correct RSA system** (`rsa.py`)
2. **Intentionally insecure RSA implementations** (`rsa_vulnerable.py`)
3. Executable **attacks** exploiting these weaknesses (`rsa_attacks.py`)

The three demonstrated attacks are:

- **Bleichenbacher padding oracle attack (PKCS#1 v1.5)**
- **Timing side-channel attack (Brumley & Boneh, 2003)**
- **CRT fault attack (Bellcore/Lenstra)**


---

## Project Structure
├── rsa.py
├── rsa_vulnerable.py
├── rsa_attacks.py
├── bleichenbacher.py
├── demo_timing.py
├── demo_crt_fault.py
├── crt.py
├── README.md


### 1. `rsa.py`
We have completed a **from-scratch RSA implementation** including:
- Prime generation using Miller–Rabin probabilistic test  
- Modular inverse and Euclidean algorithms  
- RSA key generation with public/private exponents  
- Integer and byte conversion utilities (`os2ip`, `i2osp`)  
- Working encryption and decryption routines  

### **`rsa_vulnerable.py` — Intentionally Insecure RSA**
Implements historic flaws that have broken RSA deployments:

1. **Padding Oracle (PKCS#1 v1.5)**  
   Returns boolean based on padding validity → Bleichenbacher attack.

2. **Non-constant-time RSA Decryption**  
   Adds delays for “1” bits during exponentiation → timing attack.

3. **Faulty CRT RSA Decryption**  
   Corrupts `m1` in CRT branch → Bellcore/Lenstra factorization attack.

All vulnerabilities are clearly commented and modeled after real-world failures.

---

### **`rsa_attacks.py` — Attack Implementations**
Contains the attack logic used by the demo scripts.

- `bleichenbacher_attack()` — Adaptive chosen-ciphertext attack  
- `timing_attack_recover_bit()` — Recovers bits of private exponent  
- `perform_crt_fault_attack()` — Recovers RSA prime factors via gcd  

These functions directly exploit vulnerabilities in `rsa_vulnerable.py`.

---

### **Demonstrations**

#### **`bleichenbacher.py`**
Runs PKCS#1 v1.5 Bleichenbacher attack to fully recover plaintext.

#### **`demo_timing.py`**
Demonstrates timing leakage and recovers bits of the private exponent.

#### **`crt.py`**
Runs a single-fault CRT attack and correctly recovers RSA prime factors.

---


---

### **Run the Attacks**

python3 bleichenbacher.py

python3 demo_timing.py

python3 crt.py

---

---
References

Bleichenbacher, D. Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1. CRYPTO 1998.

Boneh, D. Twenty Years of Attacks on the RSA Cryptosystem. Notices of the AMS, 1999.

Brumley, D. & Boneh, D. Remote Timing Attacks are Practical. USENIX Security Symposium, 2003.

Koblitz, N. & Menezes, A. A Survey of Public-Key Cryptosystems. SIAM Review, 2015.

Bleichenbacher attack implementation- https://github.com/alexandru-dinu/bleichenbacher/blob/master/src/main.py

Side Channel Time Attack - https://github.com/outidrarine/side-channel-attack/blob/master/TimeAttack.py

---