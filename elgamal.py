# -*- coding: utf-8 -*-
"""Криптосистема Ель-Гамаля: генерація ключів, шифрування, підпис.

Модуль p - безпечне просте число (p = 2q + 1, q - просте) довжиною
R десяткових знаків. Генератор g - первісний корінь за модулем p.
Закритий ключ x, відкритий ключ y = g^x mod p.
"""
import hashlib
import random

import config

_rng = random.SystemRandom()   # криптографічно стійке джерело випадковості
SMALL_PRIMES = [p for p in range(3, 2000)
                if all(p % d for d in range(2, int(p ** 0.5) + 1))]


# ---------- арифметика за модулем ----------
def mod_pow(base, exp, mod):
    """Швидке піднесення до степеня (метод «піднести до квадрата і помножити»)."""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        base = base * base % mod
        exp >>= 1
    return result


def ext_gcd(a, b):
    """Розширений алгоритм Евкліда: повертає (d, u, v), d = a*u + b*v."""
    if b == 0:
        return a, 1, 0
    d, u, v = ext_gcd(b, a % b)
    return d, v, u - (a // b) * v


def mod_inverse(a, m):
    d, u, _ = ext_gcd(a % m, m)
    if d != 1:
        raise ValueError("Оберненого елемента не існує")
    return u % m


# ---------- прості числа ----------
def is_probable_prime(n, rounds=40):
    """Імовірнісний тест Міллера-Рабіна."""
    if n < 2:
        return False
    for p in SMALL_PRIMES[:50]:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = _rng.randrange(2, n - 1)
        x = mod_pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_safe_prime(digits):
    """Безпечне просте p = 2q + 1, що має рівно digits десяткових знаків."""
    low, high = 10 ** (digits - 1), 10 ** digits
    while True:
        q = _rng.randrange(low // 2, high // 2) | 1
        p = 2 * q + 1
        if not low <= p < high:
            continue
        # швидке відсіювання дільниками з невеликих простих чисел
        if any(q % sp == 0 or p % sp == 0 for sp in SMALL_PRIMES):
            continue
        if is_probable_prime(q, 20) and is_probable_prime(p, 20):
            return p


def find_generator(p):
    """Первісний корінь за модулем безпечного простого p = 2q + 1."""
    q = (p - 1) // 2
    while True:
        g = _rng.randrange(2, p - 1)
        if mod_pow(g, 2, p) != 1 and mod_pow(g, q, p) != 1:
            return g


# ---------- ключі ----------
def generate_keys(digits=config.R_DIGITS):
    p = gen_safe_prime(digits)
    g = find_generator(p)
    x = _rng.randrange(2, p - 2)          # закритий ключ
    y = mod_pow(g, x, p)                  # відкритий ключ
    return {"p": p, "g": g, "y": y, "x": x}


def save_keys(keys, path=config.KEYS_FILE):
    with open(path, "w", encoding="utf-8") as f:
        for k in ("p", "g", "y", "x"):
            f.write("{}={}\n".format(k, keys[k]))


def load_keys(path=config.KEYS_FILE):
    keys = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            k, v = line.strip().split("=")
            keys[k] = int(v)
    return keys


# ---------- шифрування ----------
def block_size(p):
    """Кількість байтів тексту в одному блоці (з урахуванням байта-маркера)."""
    return (p.bit_length() - 1) // 8 - 1


def encrypt_block(m, p, g, y, k=None):
    if k is None:
        k = _rng.randrange(2, p - 1)
        while ext_gcd(k, p - 1)[0] != 1:
            k = _rng.randrange(2, p - 1)
    a = mod_pow(g, k, p)
    b = mod_pow(y, k, p) * m % p
    return a, b


def decrypt_block(a, b, p, x):
    # m = b * a^(p-1-x) mod p  (те саме, що b * (a^x)^-1 mod p)
    return b * mod_pow(a, p - 1 - x, p) % p


def encrypt_text(text, keys):
    p, g, y = keys["p"], keys["g"], keys["y"]
    data = text.encode("utf-8")
    bs = block_size(p)
    pairs = []
    for i in range(0, len(data), bs):
        chunk = b"\x01" + data[i:i + bs]          # маркер зберігає нулі на початку
        m = int.from_bytes(chunk, "big")
        pairs.append(encrypt_block(m, p, g, y))
    return pairs


def decrypt_pairs(pairs, keys, errors="strict"):
    p, x = keys["p"], keys["x"]
    data = b""
    for a, b in pairs:
        m = decrypt_block(a, b, p, x)
        chunk = m.to_bytes((m.bit_length() + 7) // 8, "big")
        data += chunk[1:]                          # відкидаємо маркер 0x01
    return data.decode("utf-8", errors=errors)   # "replace" - показати зіпсований текст


def encrypt_file(keys, src=config.INPUT_FILE, dst=config.CLOSE_FILE):
    with open(src, encoding="utf-8") as f:
        pairs = encrypt_text(f.read(), keys)
    with open(dst, "w", encoding="utf-8") as f:
        for a, b in pairs:
            f.write("{} {}\n".format(a, b))
    return pairs


def decrypt_file(keys, src=config.CLOSE_FILE, dst=config.OUT_FILE):
    with open(src, encoding="utf-8") as f:
        pairs = [tuple(int(v) for v in line.split()) for line in f if line.strip()]
    text = decrypt_pairs(pairs, keys)
    with open(dst, "w", encoding="utf-8") as f:
        f.write(text)
    return text


# ---------- цифровий підпис ----------
def hash_message(data, p):
    """H(m) = SHA-256(m) mod (p - 1)."""
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % (p - 1)


def sign_hash(h, keys, k=None):
    p, g, x = keys["p"], keys["g"], keys["x"]
    while True:
        kk = k if k is not None else _rng.randrange(2, p - 1)
        if ext_gcd(kk, p - 1)[0] != 1:
            if k is not None:
                raise ValueError("k має бути взаємно простим з p - 1")
            continue
        r = mod_pow(g, kk, p)
        s = (h - x * r) * mod_inverse(kk, p - 1) % (p - 1)
        if s != 0 or k is not None:
            return r, s


def verify_hash(h, r, s, keys):
    p, g, y = keys["p"], keys["g"], keys["y"]
    if not 0 < r < p:
        return False
    return mod_pow(g, h, p) == mod_pow(y, r, p) * mod_pow(r, s, p) % p


def sign_message(text, keys):
    h = hash_message(text.encode("utf-8"), keys["p"])
    r, s = sign_hash(h, keys)
    return h, r, s


def verify_message(text, r, s, keys):
    h = hash_message(text.encode("utf-8"), keys["p"])
    return verify_hash(h, r, s, keys)
