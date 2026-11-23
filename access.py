# -*- coding: utf-8 -*-
"""Розмежування доступу до логічних дисків A-E.

Права: E - виконання, R - читання, W - запис, A - доповнення.
Диски, до яких користувач не має жодного права, від нього приховуються.
"""
import os

import config


class AccessDenied(Exception):
    pass


def visible_disks(user):
    """Список (диск, права) лише для дозволених дисків."""
    return [(d, user.rights.get(d, "-")) for d in config.DISKS
            if user.rights.get(d, "-") != "-"]


def can(user, disk, right):
    return right in user.rights.get(disk, "-")


def _path(disk, fname=""):
    return os.path.join(config.DISKS_DIR, disk, fname)


def list_files(user, disk):
    if user.rights.get(disk, "-") == "-":
        raise AccessDenied("Диск {} недоступний".format(disk))
    return sorted(os.listdir(_path(disk)))


def read_file(user, disk, fname):
    if not can(user, disk, "R"):
        raise AccessDenied("Немає права читання (R) на диску " + disk)
    with open(_path(disk, fname), encoding="utf-8") as f:
        return f.read()


def write_file(user, disk, fname, text):
    if not can(user, disk, "W"):
        raise AccessDenied("Немає права запису (W) на диску " + disk)
    with open(_path(disk, fname), "w", encoding="utf-8") as f:
        f.write(text)


def append_file(user, disk, fname, text):
    if not can(user, disk, "A"):
        raise AccessDenied("Немає права доповнення (A) на диску " + disk)
    with open(_path(disk, fname), "a", encoding="utf-8") as f:
        f.write(text)


def execute_file(user, disk, fname):
    """Імітація виконання файлу (реальний запуск не виконується)."""
    if not can(user, disk, "E"):
        raise AccessDenied("Немає права виконання (E) на диску " + disk)
    size = os.path.getsize(_path(disk, fname))
    return "Файл {}:\\{} запущено (імітація), розмір {} байт".format(
        disk, fname, size)
