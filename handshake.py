# -*- coding: utf-8 -*-
"""Періодична автентифікація за схемою одностороннього рукостискання.

Комп'ютер надсилає запит X (випадкове значення з файлу ask.txt),
користувач повертає Y = F(X) = lg(4*X). Відповідь порівнюється
з обчисленою програмою з точністю config.ANSWER_DIGITS знаків.
"""
import random

import config


class Handshake:
    def __init__(self, questions):
        if not questions:
            raise ValueError("Файл ask.txt порожній")
        self.questions = questions
        self.last = None

    def next_question(self):
        """Випадкове запитання, відмінне від попереднього."""
        choices = [x for x in self.questions if x != self.last] or self.questions
        self.last = random.choice(choices)
        return self.last

    @staticmethod
    def expected(x):
        return round(config.F(x), config.ANSWER_DIGITS)

    def check(self, x, answer_text):
        """True, якщо відповідь користувача дорівнює F(X)."""
        try:
            y = float(answer_text.strip().replace(",", "."))
        except ValueError:
            return False
        eps = 0.5 * 10 ** (-config.ANSWER_DIGITS) + 1e-9
        return abs(y - config.F(x)) <= eps
