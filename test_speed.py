# -*- coding: utf-8 -*-
"""Вимірювання швидкодії ElGamal для різних довжин модуля R."""
import statistics
import time

import elgamal as e

TEXT = ("Службове повідомлення для перевірки швидкодії. " * 25)[:1000]


def measure(digits, runs):
    gen, enc, dec, sig, ver = [], [], [], [], []
    for _ in range(runs):
        t = time.perf_counter()
        keys = e.generate_keys(digits)
        gen.append(time.perf_counter() - t)
        t = time.perf_counter()
        pairs = e.encrypt_text(TEXT, keys)
        enc.append(time.perf_counter() - t)
        t = time.perf_counter()
        assert e.decrypt_pairs(pairs, keys) == TEXT
        dec.append(time.perf_counter() - t)
        t = time.perf_counter()
        h, r, s = e.sign_message(TEXT, keys)
        sig.append(time.perf_counter() - t)
        t = time.perf_counter()
        assert e.verify_message(TEXT, r, s, keys)
        ver.append(time.perf_counter() - t)
    ms = lambda v: statistics.mean(v) * 1000
    print("R={:>3} ({:>3} біт): ключі {:7.1f} мс, шифр. {:6.1f} мс, "
          "розшифр. {:6.1f} мс,\n"
          "                 підпис {:5.2f} мс, перевірка {:5.2f} мс, блоків {}".format(
              digits, keys["p"].bit_length(), ms(gen), ms(enc), ms(dec), ms(sig),
              ms(ver), len(pairs)))


if __name__ == "__main__":
    print("Текст: {} символів, {} байтів UTF-8".format(len(TEXT), len(TEXT.encode())))
    for d in (32, 64, 96, 128):
        measure(d, 8 if d <= 64 else 5)
