# Cryptographic Attacks & Solver Patterns

> Domain: CTF Cryptography & Classical/Modern Cryptanalysis
> Classification: SECURITY KNOWLEDGE BASE

## Purpose

Katalog rumus matematika, vulnerability signatures, dan metode penyelesaian tantangan CTF Kriptografi (RSA, AES, XOR, PRNG, LCG, ECC).

---

## 1. RSA Cryptanalysis

RSA Parameters: $N = p \cdot q$, $\phi(N) = (p-1)(q-1)$, $e \cdot d \equiv 1 \pmod{\phi(N)}$, $c = m^e \pmod N$.

### A. Small Public Exponent ($e = 3$)
- **Condition:** Pesan $m$ pendek sehingga $m^e < N$.
- **Attack:** Plain integer root: $m = \sqrt[e]{c}$ (tanpa modulo).
- **Python Solver:**
  ```python
  import gmpy2
  m, exact = gmpy2.iroot(c, e)
  if exact:
      print(bytes.fromhex(hex(m)[2:]))
  ```

### B. Wiener's Attack (Small Private Exponent $d$)
- **Condition:** $d < \frac{1}{3} N^{1/4}$.
- **Method:** Fraksi berlanjut (*continued fractions*) dari $\frac{e}{N}$ mendekati $\frac{k}{d}$.
- **Tool:** Library `owil` atau script Continued Fraction `wiener_attack.py`.

### C. Common Modulus Attack
- **Condition:** Pesan yang sama $m$ dienkripsi dengan 2 public key $(N, e_1)$ dan $(N, e_2)$ di mana $\gcd(e_1, e_2) = 1$.
- **Method:** Extended Euclidean Algorithm mencari $a, b$ sehingga $a \cdot e_1 + b \cdot e_2 = 1$.
- **Formula:** $c_1^a \cdot c_2^b \equiv (m^{e_1})^a \cdot (m^{e_2})^b \equiv m^{a \cdot e_1 + b \cdot e_2} \equiv m \pmod N$.

### D. Fermat's Factorization (Close Primes $p \approx q$)
- **Condition:** Jarak $|p - q|$ kecil ($< N^{1/4}$).
- **Formula:** $N = a^2 - b^2 = (a - b)(a + b)$. Nilai $a \approx \lceil\sqrt{N}\rceil$.
- **Python Solver:**
  ```python
  import gmpy2
  a = gmpy2.isqrt(N)
  while True:
      b2 = a*a - N
      if gmpy2.is_square(b2):
          b = gmpy2.isqrt(b2)
          p = a - b
          q = a + b
          break
      a += 1
  ```

---

## 2. Symmetric Ciphers & Block Modes

### A. Repeated-Key XOR
- **Attack Method:**
  1. Tentukan estimasi panjang key menggunakan **Hamming Distance / Index of Coincidence (IoC)**.
  2. Pecah ciphertext menjadi blok-blok sepanjang key length $K$.
  3. Transposisi blok menjadi kolom $i$, lalu selesaikan setiap kolom sebagai **Single-Byte XOR** berdasarkan distribusi frekuensi huruf bahasa Inggris (ETAOIN SHRDLU).

### B. AES Electronic Codebook (ECB) Chosen-Plaintext Attack
- **Vulnerability:** Blok plaintext yang identik menghasilkan blok ciphertext yang identik.
- **Byte-at-a-Time Decryption (ECB Oracle):**
  1. Kirim padding $16 - 1$ bytes (`"A" * 15`).
  2. Server mengenkripsi `"A"*15 + secret[0]`.
  3. Brute-force 256 kemungkinan byte karakter pertama.
  4. Geser offset untuk menebak karakter berikutnya.

### C. CBC Padding Oracle Attack
- **Condition:** Server merespons beda antara valid padding PKCS#7 vs invalid padding (Decryption Error).
- **Mechanism:** Memanipulasi Initialization Vector (IV) atau blok ciphertext $C_{i-1}$ untuk mendekripsi blok $C_i$ byte per byte dari belakang.

---

## 3. Pseudo-Random Number Generators (PRNG)

### Linear Congruential Generator (LCG)
- **Formula:** $S_{n+1} = (a \cdot S_n + c) \pmod m$.
- **Attack:** Jika 3 atau lebih output berurutan diketahui, parameter $(a, c, m)$ dapat dipecahkan menggunakan sistem persamaan linear modular.
