# -*- coding: utf-8 -*-
"""Програмний макет підсистеми ідентифікації та автентифікації користувачів.

Запуск:  python main.py          (період перевірки T = 10 хв)
         python main.py --demo   (перевірка щохвилини, для демонстрації)
Адміністратор за замовчуванням: admin / Adm1n#2026
"""
import sys

import storage
from gui import App


def main():
    storage.init_data()
    App(demo="--demo" in sys.argv).run()


if __name__ == "__main__":
    main()
