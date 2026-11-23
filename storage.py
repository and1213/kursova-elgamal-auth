# -*- coding: utf-8 -*-
"""Робота з файлами системи: nameuser.txt, us_book.txt, ask.txt.

Формат рядка nameuser.txt (поля розділені символом |):
    ім'я|пароль|права|дата_встановлення_пароля|строк_дії_днів
    права: A=RE;B=ERWA;C=-;D=R;E=-   (для адміністратора - ADMIN)
"""
import datetime
import os

import config


class User:
    def __init__(self, name, password, rights, pwd_date, valid_days):
        self.name = name
        self.password = password
        self.rights = rights              # словник {диск: набір прав}
        self.pwd_date = pwd_date          # datetime.date
        self.valid_days = valid_days

    @property
    def is_admin(self):
        return self.name == config.ADMIN_NAME

    def level(self):
        """Рівень доступу користувача (найвищий серед дисків)."""
        if not self.rights:
            return 0
        return max(config.LEVEL_OF_SET[r] for r in self.rights.values())

    def to_line(self):
        if self.is_admin:
            rights = "ADMIN"
        else:
            rights = ";".join("{}={}".format(d, self.rights.get(d, "-"))
                              for d in config.DISKS)
        return "|".join([self.name, self.password, rights,
                         self.pwd_date.isoformat(), str(self.valid_days)])

    @staticmethod
    def from_line(line):
        name, password, rights_s, date_s, days_s = line.strip().split("|")
        rights = {}
        if rights_s != "ADMIN":
            for part in rights_s.split(";"):
                disk, rset = part.split("=")
                rights[disk] = rset
        return User(name, password, rights,
                    datetime.date.fromisoformat(date_s), int(days_s))


def load_users():
    """Читає реєстраційний журнал. Повертає словник {ім'я: User}."""
    users = {}
    with open(config.USERS_FILE, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                u = User.from_line(line)
                users[u.name] = u
    return users


def save_users(users):
    with open(config.USERS_FILE, "w", encoding="utf-8") as f:
        for u in users.values():
            f.write(u.to_line() + "\n")


def count_regular(users):
    return sum(1 for u in users.values() if not u.is_admin)


def log_event(user_name, event):
    """Додає запис в операційний журнал us_book.txt."""
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(config.JOURNAL_FILE, "a", encoding="utf-8") as f:
        f.write("{} | {:<10} | {}\n".format(stamp, user_name, event))


def read_journal():
    if not os.path.exists(config.JOURNAL_FILE):
        return ""
    with open(config.JOURNAL_FILE, encoding="utf-8") as f:
        return f.read()


def load_questions():
    """Значення X для рукостискання з файлу ask.txt."""
    with open(config.ASK_FILE, encoding="utf-8") as f:
        return [float(s.replace(",", ".")) for s in f.read().split()]


def init_data():
    """Створює робочі файли та каталоги під час першого запуску."""
    os.makedirs(config.DATA_DIR, exist_ok=True)
    if not os.path.exists(config.USERS_FILE):
        admin = User(config.ADMIN_NAME, config.ADMIN_DEFAULT_PASSWORD, {},
                     datetime.date.today(), config.MAX_VALID_DAYS)
        save_users({admin.name: admin})
    if not os.path.exists(config.ASK_FILE):
        xs = [1.5, 2, 2.5, 3, 5, 7.5, 10, 12, 15, 20,
              25, 30, 40, 50, 75, 100, 125, 150, 200, 250]
        with open(config.ASK_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(str(x) for x in xs) + "\n")
    if not os.path.exists(config.INPUT_FILE):
        with open(config.INPUT_FILE, "w", encoding="utf-8") as f:
            f.write("Службове повідомлення: резервне копіювання "
                    "диска C виконати о 22:00.\n")
    for disk in config.DISKS:
        path = os.path.join(config.DISKS_DIR, disk)
        os.makedirs(path, exist_ok=True)
        sample = os.path.join(path, "readme_{}.txt".format(disk.lower()))
        if not os.listdir(path):
            with open(sample, "w", encoding="utf-8") as f:
                f.write("Файл на логічному диску {}.\n".format(disk))
