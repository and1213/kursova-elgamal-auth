# -*- coding: utf-8 -*-
"""Параметри варіанта курсової роботи.

Варіант визначено за першими літерами імені та прізвища (таблиця В.1):
  В (Владислав) -> N = 8, S = 3, F(x) = lg(a*x), T = 10
  К (Колесник)  -> R = 64 десяткових знаки, шифр ElGamal
  a = 4
"""
import math
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DISKS_DIR = os.path.join(BASE_DIR, "disks")

USERS_FILE = os.path.join(DATA_DIR, "nameuser.txt")    # реєстраційний журнал
JOURNAL_FILE = os.path.join(DATA_DIR, "us_book.txt")   # операційний журнал
ASK_FILE = os.path.join(DATA_DIR, "ask.txt")           # запитання X
INPUT_FILE = os.path.join(DATA_DIR, "input.txt")       # вихідний текст
CLOSE_FILE = os.path.join(DATA_DIR, "close.txt")       # шифротекст
OUT_FILE = os.path.join(DATA_DIR, "out.txt")           # розшифрований текст
KEYS_FILE = os.path.join(DATA_DIR, "keys.txt")         # ключі ElGamal

# ---- параметри варіанта ----
N_MAX_USERS = 8       # N - максимальна кількість користувачів у журналі
S_LEVELS = 3          # S - кількість рівнів доступу
A_PARAM = 4           # a - параметр функції рукостискання
T_PERIOD = 10         # T - період повторної автентифікації, хв
DEMO_PERIOD_SEC = 60  # період перевірки в демо-режимі (--demo), с
R_DIGITS = 64         # R - довжина модуля p, десяткових знаків
CIPHER_NAME = "ElGamal"

F_TEXT = "F(x) = lg(4·x)"
ANSWER_DIGITS = 3     # точність відповіді Y, знаків після коми


def F(x):
    """Функція одностороннього рукостискання F(x) = lg(a*x)."""
    return math.log10(A_PARAM * x)


# ---- логічні диски та права доступу ----
DISKS = ("A", "B", "C", "D", "E")
# E - виконання, R - читання, W - запис, A - доповнення
RIGHT_SETS = ("-", "R", "E", "RE", "REA", "ERWA")
LEVEL_OF_SET = {"-": 0, "R": 1, "E": 1, "RE": 2, "REA": 2, "ERWA": 3}
LEVEL_NAMES = {0: "немає доступу", 1: "мінімальний",
               2: "середній", 3: "максимальний"}

# ---- політика паролів (формула Андерсона: P = V*T / A^L) ----
GUESS_SPEED_PER_MIN = 1000   # V - швидкість перебору, паролів за хвилину
GUESS_PROBABILITY = 1e-4     # P - допустима ймовірність підбору пароля
MIN_SAFE_DAYS = 7            # пароль із меншим безпечним часом відхиляється
MAX_VALID_DAYS = 180         # найбільший строк дії пароля, днів
MAX_ATTEMPTS = 3             # невдалих спроб до блокування входу
LOCK_SECONDS = 60            # тривалість блокування, с

ADMIN_NAME = "admin"
ADMIN_DEFAULT_PASSWORD = "Adm1n#2026"
