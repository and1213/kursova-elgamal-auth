# -*- coding: utf-8 -*-
"""Перевірка правильності роботи модулів на контрольних прикладах."""
import math

import config
import elgamal as e
import passwords
from handshake import Handshake


def test_elgamal_manual():
    # приклад, розв'язаний вручну: p = 23, g = 5, x = 6, k = 3, m = 10, H = 7
    keys = {"p": 23, "g": 5, "x": 6, "y": e.mod_pow(5, 6, 23)}
    assert keys["y"] == 8
    assert e.encrypt_block(10, 23, 5, 8, k=3) == (10, 14)
    assert e.decrypt_block(10, 14, 23, 6) == 10
    assert e.sign_hash(7, keys, k=3) == (10, 19)
    assert e.verify_hash(7, 10, 19, keys)
    assert not e.verify_hash(8, 10, 19, keys)


def test_elgamal_full():
    keys = e.generate_keys(config.R_DIGITS)
    assert len(str(keys["p"])) == config.R_DIGITS
    text = "Перевірка шифрування ElGamal: 0123456789 ABC"
    assert e.decrypt_pairs(e.encrypt_text(text, keys), keys) == text
    h, r, s = e.sign_message(text, keys)
    assert e.verify_message(text, r, s, keys)
    assert not e.verify_message(text + ".", r, s, keys)


def test_handshake():
    hs = Handshake([2.5, 25])
    assert hs.check(2.5, "1")          # lg(4*2,5) = lg 10 = 1
    assert hs.check(25, "2,000")       # lg 100 = 2
    assert hs.check(10, "1.602")       # lg 40 = 1,60206
    assert not hs.check(10, "1.61")
    assert abs(config.F(10) - math.log10(40)) < 1e-12


def test_passwords():
    assert not passwords.check_password("ivan", "abc123")[0]
    ok, days, _ = passwords.check_password("olena", "sonechko")
    assert ok and days == 14
    assert passwords.check_password("ivan", "Qwerty12")[1] == 180


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("OK ", name)
