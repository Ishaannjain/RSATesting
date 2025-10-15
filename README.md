# RSA Attack Demonstrations — Progress Report

**Course Project:** Attacks and Weak Implementations of Public-Key Cryptosystems  
**Group Members:** Aryan Shiva, Sankalp Dasari, Ishaan Jain, Sophia Chukka  
**Date:** October 2025  

---

## Overview

This project explores **implementation-level vulnerabilities in RSA**, focusing on how mathematically secure systems can fail in practice due to developer mistakes or physical side channels.  
Our goal is to implement intentionally weak RSA variants and demonstrate three major classes of attacks:

1. **Padding Oracle Attacks (Bleichenbacher, 1998)** — misuse of PKCS#1 v1.5 padding validation  
2. **Timing Side-Channel Attacks (Brumley & Boneh, 2003)** — non-constant decryption timing leaks  
3. **CRT Fault Attacks** — corrupted modular computations reveal private key factors  

---

## Current Progress

### 1. `rsa.py`
We have completed a **from-scratch RSA implementation** including:
- Prime generation using Miller–Rabin probabilistic test  
- Modular inverse and Euclidean algorithms  
- RSA key generation with public/private exponents  
- Integer and byte conversion utilities (`os2ip`, `i2osp`)  
- Working encryption and decryption routines  

**Verified Functionality:**

$ python rsa.py
n bits: 1024
cipher len: 128
plaintext recovered (right-aligned): True

### 2. rsa_attacks.py

This file defines method stubs and pseudocode for the main attack experiments that will be developed next.

Implemented:

Function structure and signatures for:

padding_oracle()

bleichenbacher_recover_plaintext()

crt_decrypt(), crt_decrypt_with_fault()

recover_factor_from_fault()

Detailed pseudocode and docstrings outlining the mathematical steps for each attack.

Modular structure to integrate later with rsa.py key generation and encrypt/decrypt functions.

Purpose:

rsa_attacks.py acts as the project skeleton for the attack phase, showing exactly how Bleichenbacher and CRT attacks will be coded and tested in the final deliverable.
rsa_attacks.py is not yet executable — it contains pseudocode and function skeletons for the final submission.


References

Bleichenbacher, D. Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1. CRYPTO 1998.

Boneh, D. Twenty Years of Attacks on the RSA Cryptosystem. Notices of the AMS, 1999.

Brumley, D. & Boneh, D. Remote Timing Attacks are Practical. USENIX Security Symposium, 2003.

Koblitz, N. & Menezes, A. A Survey of Public-Key Cryptosystems. SIAM Review, 2015.