# -*- coding: utf-8 -*-
"""Оцінка стійкості пароля та безпечного часу його використання.

Використано формулу Андерсона P = V*T / S, де S = A^L - кількість
можливих паролів (A - потужність алфавіту, L - довжина пароля),
V - швидкість перебору, T - час використання, P - ймовірність підбору.
Звідси безпечний час використання пароля T = P * A^L / V.
"""
import datetime
import string

import config

CYR_LOWER = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"
CYR_UPPER = CYR_LOWER.upper()


def alphabet_size(password):
    """Потужність алфавіту A за класами символів, що є в паролі."""
    size = 0
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in CYR_LOWER for c in password):
        size += 33
    if any(c in CYR_UPPER for c in password):
        size += 33
    if any(c in string.punctuation or c == " " for c in password):
        size += 33
    return size


def safe_time_days(password):
    """Безпечний час використання пароля, діб: T = P * A^L / V."""
    a = alphabet_size(password)
    s = a ** len(password)                       # S = A^L
    minutes = config.GUESS_PROBABILITY * s / config.GUESS_SPEED_PER_MIN
    return minutes / (60 * 24)


def check_password(name, password):
    """Перевіряє пароль. Повертає (придатний, строк_дії_днів, повідомлення)."""
    if len(password) < 6:
        return False, 0, "Пароль коротший за 6 символів"
    if password.lower() == name.lower():
        return False, 0, "Пароль збігається з іменем"
    if "|" in password:
        return False, 0, "Символ | не допускається"
    days = safe_time_days(password)
    if days < config.MIN_SAFE_DAYS:
        return False, 0, ("Безпечний час {:.2f} доби менший за {} діб"
                          .format(days, config.MIN_SAFE_DAYS))
    valid = int(min(days, config.MAX_VALID_DAYS))
    shown = "понад 10^6" if days > 1e6 else "{:.0f}".format(days)
    return True, valid, "Безпечний час {} діб, строк дії {} діб".format(shown, valid)


def expires_on(user):
    """Дата, після якої пароль користувача треба змінити."""
    return user.pwd_date + datetime.timedelta(days=user.valid_days)


def is_expired(user, today=None):
    today = today or datetime.date.today()
    return today > expires_on(user)
