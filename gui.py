# -*- coding: utf-8 -*-
"""Віконний інтерфейс підсистеми ідентифікації та автентифікації."""
import datetime
import time
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk

import access
import config
import elgamal
import passwords
import storage
from handshake import Handshake

PAD = {"padx": 6, "pady": 4}


class App:
    """Головне вікно: ідентифікація користувача за іменем і паролем."""

    def __init__(self, demo=False):
        self.demo = demo                      # у демо-режимі перевірка щохвилини
        self.failed = 0
        self.locked_until = 0.0
        self.root = tk.Tk()
        self.root.title("Підсистема ідентифікації та автентифікації")
        self.root.resizable(False, False)
        ttk.Style().theme_use("clam")
        for fname in ("TkDefaultFont", "TkTextFont", "TkFixedFont"):
            tkfont.nametofont(fname).configure(size=10)

        frm = ttk.Frame(self.root, padding=16)
        frm.pack()
        ttk.Label(frm, text="Вхід у систему",
                  font=("TkDefaultFont", 13, "bold")).grid(row=0, column=0,
                                                           columnspan=2, pady=(0, 10))
        ttk.Label(frm, text="Ім'я користувача:").grid(row=1, column=0, sticky="w",
                                                      **PAD)
        ttk.Label(frm, text="Пароль:").grid(row=2, column=0, sticky="w", **PAD)
        self.name_var, self.pwd_var = tk.StringVar(), tk.StringVar()
        self.name_entry = ttk.Entry(frm, textvariable=self.name_var, width=24)
        self.name_entry.grid(row=1, column=1, **PAD)
        self.pwd_entry = ttk.Entry(frm, textvariable=self.pwd_var, show="•", width=24)
        self.pwd_entry.grid(row=2, column=1, **PAD)
        ttk.Button(frm, text="Увійти", command=self.login).grid(
            row=3, column=0, columnspan=2, pady=(10, 4), sticky="ew")
        self.status = ttk.Label(frm, text="", foreground="#a00000", wraplength=300)
        self.status.grid(row=4, column=0, columnspan=2)
        info = "Варіант: N = {}, S = {}, {}, T = {}, R = {}, {}".format(
            config.N_MAX_USERS, config.S_LEVELS, config.F_TEXT,
            config.T_PERIOD, config.R_DIGITS, config.CIPHER_NAME)
        ttk.Label(frm, text=info, foreground="#555").grid(row=5, column=0,
                                                          columnspan=2, pady=(8, 0))
        self.root.bind("<Return>", lambda e: self.login())

    def login(self):
        now = time.time()
        if now < self.locked_until:
            self.status.config(text="Вхід заблоковано ще на {} с".format(
                int(self.locked_until - now) + 1))
            return
        name, pwd = self.name_var.get().strip(), self.pwd_var.get()
        users = storage.load_users()
        user = users.get(name)
        if user is None or user.password != pwd:
            self.failed += 1
            storage.log_event(name or "?", "НЕВДАЛА СПРОБА ВХОДУ")
            left = config.MAX_ATTEMPTS - self.failed
            if left <= 0:
                self.failed = 0
                self.locked_until = now + config.LOCK_SECONDS
                storage.log_event(name or "?", "ВХІД ЗАБЛОКОВАНО")
                self.status.config(text="Забагато спроб. Вхід заблоковано на {} с"
                                   .format(config.LOCK_SECONDS))
            else:
                self.status.config(text="Невірне ім'я або пароль. Залишилось "
                                        "спроб: {}".format(left))
            return
        self.failed = 0
        self.status.config(text="")
        self.pwd_var.set("")
        storage.log_event(name, "ВХІД У СИСТЕМУ")
        if passwords.is_expired(user):
            storage.log_event(name, "ПАРОЛЬ ПРОСТРОЧЕНО")
            ChangePasswordDialog(self.root, user, users)
            if passwords.is_expired(user):
                return
        if user.is_admin:
            AdminWindow(self.root)
        else:
            UserWindow(self.root, user, self.demo)

    def run(self):
        self.root.mainloop()


class ChangePasswordDialog(tk.Toplevel):
    """Примусова зміна пароля після закінчення безпечного часу."""

    def __init__(self, master, user, users):
        super().__init__(master)
        self.user, self.users = user, users
        self.title("Зміна пароля")
        self.resizable(False, False)
        frm = ttk.Frame(self, padding=14)
        frm.pack()
        ttk.Label(frm, text="Строк дії пароля закінчився {}.\nВведіть новий пароль."
                  .format(passwords.expires_on(user).strftime("%d.%m.%Y"))).pack(**PAD)
        self.var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.var, show="•", width=26).pack(**PAD)
        self.msg = ttk.Label(frm, text="", foreground="#a00000")
        self.msg.pack(**PAD)
        ttk.Button(frm, text="Зберегти", command=self.save).pack(**PAD)
        self.grab_set()
        self.wait_window()

    def save(self):
        ok, days, msg = passwords.check_password(self.user.name, self.var.get())
        if not ok or self.var.get() == self.user.password:
            self.msg.config(text=msg if not ok else "Новий пароль має відрізнятися")
            return
        self.user.password = self.var.get()
        self.user.pwd_date = datetime.date.today()
        self.user.valid_days = days
        storage.save_users(self.users)
        storage.log_event(self.user.name, "ПАРОЛЬ ЗМІНЕНО")
        self.destroy()


class AdminWindow(tk.Toplevel):
    """Реєстрація та видалення користувачів (лише для адміністратора)."""

    COLUMNS = ("name",) + config.DISKS + ("level", "valid")

    def __init__(self, master):
        super().__init__(master)
        self.title("Адміністрування: реєстраційний журнал nameuser.txt")
        self.resizable(False, False)
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both")

        self.tree = ttk.Treeview(frm, columns=self.COLUMNS, show="headings", height=8)
        heads = ["Користувач"] + list(config.DISKS) + ["Рівень", "Пароль діє до"]
        widths = [110] + [52] * 5 + [110, 110]
        for col, head, w in zip(self.COLUMNS, heads, widths):
            self.tree.heading(col, text=head)
            self.tree.column(col, width=w, anchor="center")
        self.tree.grid(row=0, column=0, columnspan=4, **PAD)
        self.count = ttk.Label(frm)
        self.count.grid(row=1, column=0, columnspan=4, sticky="w", **PAD)

        box = ttk.LabelFrame(frm, text="Реєстрація нового користувача", padding=8)
        box.grid(row=2, column=0, columnspan=4, sticky="ew", **PAD)
        ttk.Label(box, text="Ім'я:").grid(row=0, column=0, sticky="w")
        ttk.Label(box, text="Пароль:").grid(row=1, column=0, sticky="w")
        self.name_var, self.pwd_var = tk.StringVar(), tk.StringVar()
        ttk.Entry(box, textvariable=self.name_var, width=18).grid(row=0, column=1,
                                                                   **PAD)
        ttk.Entry(box, textvariable=self.pwd_var, width=18).grid(row=1, column=1, **PAD)
        self.pwd_var.trace_add("write", lambda *a: self.show_safe_time())
        self.safe = ttk.Label(box, text="", width=46)
        self.safe.grid(row=1, column=2, columnspan=6, sticky="w")
        ttk.Label(box, text="Права на дисках:").grid(row=2, column=0, sticky="w")
        self.rights = {}
        rf = ttk.Frame(box)
        rf.grid(row=2, column=1, columnspan=7, sticky="w")
        for disk in config.DISKS:
            ttk.Label(rf, text=disk + ":").pack(side="left", padx=(6, 1))
            self.rights[disk] = ttk.Combobox(rf, values=config.RIGHT_SETS,
                                             width=6, state="readonly")
            self.rights[disk].set("-")
            self.rights[disk].pack(side="left")

        buttons = (("Зареєструвати", self.add_user),
                   ("Видалити вибраного", self.del_user),
                   ("Журнал us_book.txt", self.show_journal))
        for col, (caption, cmd) in enumerate(buttons):
            ttk.Button(frm, text=caption, command=cmd).grid(row=3, column=col, **PAD)
        ttk.Button(frm, text="Закрити", command=self.close).grid(row=3, column=3, **PAD)
        self.refresh()

    def refresh(self):
        self.users = storage.load_users()
        self.tree.delete(*self.tree.get_children())
        for u in self.users.values():
            if u.is_admin:
                continue
            values = [u.name] + [u.rights.get(d, "-") for d in config.DISKS]
            values += [config.LEVEL_NAMES[u.level()],
                       passwords.expires_on(u).strftime("%d.%m.%Y")]
            self.tree.insert("", "end", iid=u.name, values=values)
        self.count.config(text="Зареєстровано користувачів: {} з {} (N = {})".format(
            storage.count_regular(self.users), config.N_MAX_USERS, config.N_MAX_USERS))

    def show_safe_time(self):
        pwd = self.pwd_var.get()
        if not pwd:
            self.safe.config(text="")
            return
        ok, days, msg = passwords.check_password(self.name_var.get(), pwd)
        self.safe.config(text=("✔ " if ok else "✘ ") + msg,
                         foreground="#106010" if ok else "#a00000")

    def add_user(self):
        name, pwd = self.name_var.get().strip(), self.pwd_var.get()
        if not name or "|" in name or name in self.users:
            messagebox.showerror("Помилка", "Порожнє або вже зайняте ім'я", parent=self)
            return
        if storage.count_regular(self.users) >= config.N_MAX_USERS:
            messagebox.showerror("Помилка", "Досягнуто ліміт N = {} користувачів"
                                 .format(config.N_MAX_USERS), parent=self)
            return
        ok, days, msg = passwords.check_password(name, pwd)
        if not ok:
            messagebox.showerror("Слабкий пароль", msg, parent=self)
            return
        rights = {d: self.rights[d].get() for d in config.DISKS}
        self.users[name] = storage.User(name, pwd, rights, datetime.date.today(), days)
        storage.save_users(self.users)
        storage.log_event(config.ADMIN_NAME, "ЗАРЕЄСТРОВАНО КОРИСТУВАЧА " + name)
        self.name_var.set("")
        self.pwd_var.set("")
        self.refresh()

    def del_user(self):
        sel = self.tree.selection()
        if not sel:
            return
        name = sel[0]
        if messagebox.askyesno("Видалення", "Видалити користувача {}?".format(name),
                               parent=self):
            del self.users[name]
            storage.save_users(self.users)
            storage.log_event(config.ADMIN_NAME, "ВИДАЛЕНО КОРИСТУВАЧА " + name)
            self.refresh()

    def show_journal(self):
        TextViewer(self, "Операційний журнал us_book.txt", storage.read_journal())

    def close(self):
        storage.log_event(config.ADMIN_NAME, "ВИХІД")
        self.destroy()


class TextViewer(tk.Toplevel):
    def __init__(self, master, title, text):
        super().__init__(master)
        self.title(title)
        t = tk.Text(self, width=90, height=22, font=("TkFixedFont", 10))
        t.insert("1.0", text)
        t.config(state="disabled")
        t.pack(fill="both", expand=True)


class UserWindow(tk.Toplevel):
    """Робоче вікно користувача: лише дозволені диски та операції."""

    def __init__(self, master, user, demo=False):
        super().__init__(master)
        self.user = user
        self.period = config.DEMO_PERIOD_SEC if demo else config.T_PERIOD * 60    # секунд
        self.left = self.period
        self.hs = Handshake(storage.load_questions())
        self.title("Робоче місце користувача " + user.name)
        self.protocol("WM_DELETE_WINDOW", self.logout)

        top = ttk.Frame(self, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text="Користувач: {}   Рівень доступу: {}".format(
            user.name, config.LEVEL_NAMES[user.level()]),
            font=("TkDefaultFont", 10, "bold")).pack(side="left")
        self.timer = ttk.Label(top, text="")
        self.timer.pack(side="right")

        body = ttk.Frame(self, padding=(10, 0))
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Доступні диски").grid(row=0, column=0, sticky="w")
        ttk.Label(body, text="Файли").grid(row=0, column=1, sticky="w")
        ttk.Label(body, text="Вміст файлу").grid(row=0, column=2, sticky="w")
        self.disks = tk.Listbox(body, width=16, height=10, exportselection=False)
        self.files = tk.Listbox(body, width=22, height=10, exportselection=False)
        self.text = tk.Text(body, width=44, height=10, wrap="word")
        self.disks.grid(row=1, column=0, **PAD)
        self.files.grid(row=1, column=1, **PAD)
        self.text.grid(row=1, column=2, **PAD)
        self.disk_list = access.visible_disks(user)
        for d, r in self.disk_list:
            self.disks.insert("end", "{}:\\  [{}]".format(d, r))
        self.disks.bind("<<ListboxSelect>>", lambda e: self.show_files())

        btns = ttk.Frame(self, padding=10)
        btns.pack(fill="x")
        self.buttons = {}
        for right, label in (("R", "Читати (R)"), ("W", "Записати (W)"),
                             ("A", "Доповнити (A)"), ("E", "Виконати (E)")):
            b = ttk.Button(btns, text=label, command=lambda r=right: self.action(r))
            b.pack(side="left", padx=3)
            self.buttons[right] = b
        ttk.Button(btns, text="Вийти", command=self.logout).pack(side="right", padx=3)
        ttk.Button(btns, text="Криптографія ElGamal",
                   command=lambda: CryptoWindow(self, user)).pack(side="right", padx=3)
        self.status = ttk.Label(self, text="", padding=(10, 0, 10, 8))
        self.status.pack(fill="x")
        self.update_buttons()
        self.after_id = self.after(1000, self.tick)

    def current_disk(self):
        sel = self.disks.curselection()
        return self.disk_list[sel[0]][0] if sel else None

    def show_files(self):
        disk = self.current_disk()
        self.files.delete(0, "end")
        for f in access.list_files(self.user, disk):
            self.files.insert("end", f)
        storage.log_event(self.user.name, "ВІДКРИТО ДИСК " + disk)
        self.update_buttons()

    def update_buttons(self):
        disk = self.current_disk()
        for right, b in self.buttons.items():
            ok = disk is not None and access.can(self.user, disk, right)
            b.state(["!disabled"] if ok else ["disabled"])

    def action(self, right):
        disk = self.current_disk()
        sel = self.files.curselection()
        if disk is None or not sel:
            self.status.config(text="Оберіть диск і файл")
            return
        fname = self.files.get(sel[0])
        try:
            if right == "R":
                self.text.delete("1.0", "end")
                self.text.insert("1.0", access.read_file(self.user, disk, fname))
                msg = "Прочитано " + fname
            elif right == "W":
                access.write_file(self.user, disk, fname,
                                  self.text.get("1.0", "end-1c"))
                msg = "Записано " + fname
            elif right == "A":
                access.append_file(self.user, disk, fname,
                                   self.text.get("1.0", "end-1c"))
                msg = "Доповнено " + fname
            else:
                msg = access.execute_file(self.user, disk, fname)
        except access.AccessDenied as exc:
            msg = "Відмова: {}".format(exc)
        storage.log_event(self.user.name,
                          "{} {}:\\{} -> {}".format(right, disk, fname, msg))
        self.status.config(text=msg)

    def tick(self):
        self.left -= 1
        if self.left <= 0:
            self.left = self.period
            if not self.authenticate():
                return
        self.timer.config(text="Наступна перевірка через {:02d}:{:02d}".format(
            self.left // 60, self.left % 60))
        self.after_id = self.after(1000, self.tick)

    def authenticate(self):
        """Одностороннє рукостискання: запит X, відповідь Y = F(X)."""
        x = self.hs.next_question()
        dlg = HandshakeDialog(self, x)
        if self.hs.check(x, dlg.answer):
            storage.log_event(self.user.name, "АВТЕНТИФІКАЦІЯ X={} Y={} - УСПІХ".format(
                x, dlg.answer))
            return True
        storage.log_event(self.user.name, "АВТЕНТИФІКАЦІЯ X={} Y={} - ВІДМОВА".format(
            x, dlg.answer))
        messagebox.showerror("Доступ припинено",
                             "Неправильна відповідь. Права доступу скасовано,\n"
                             "увійдіть у систему повторно.", parent=self)
        self.destroy()
        return False

    def logout(self):
        self.after_cancel(self.after_id)
        storage.log_event(self.user.name, "ВИХІД")
        self.destroy()


class HandshakeDialog(tk.Toplevel):
    def __init__(self, master, x):
        super().__init__(master)
        self.answer = ""
        self.title("Перевірка автентичності")
        self.resizable(False, False)
        frm = ttk.Frame(self, padding=14)
        frm.pack()
        ttk.Label(frm, text="Запит комп'ютера:  X = {:g}".format(x),
                  font=("TkDefaultFont", 11, "bold")).pack(**PAD)
        func = config.F_TEXT.replace("F(x) = ", "").replace("x", "X")
        ttk.Label(frm, text="Введіть відповідь Y = {} з точністю до 0,001"
                  .format(func)).pack(**PAD)
        self.var = tk.StringVar()
        e = ttk.Entry(frm, textvariable=self.var, width=14)
        e.pack(**PAD)
        e.focus_set()
        ttk.Button(frm, text="Відповісти", command=self.ok).pack(**PAD)
        self.bind("<Return>", lambda ev: self.ok())
        self.grab_set()
        self.wait_window()

    def ok(self):
        self.answer = self.var.get()
        self.destroy()


class CryptoWindow(tk.Toplevel):
    """Генерація ключів, шифрування та цифровий підпис за алгоритмом Ель-Гамаля."""

    def __init__(self, master, user):
        super().__init__(master)
        self.user = user
        self.title("Криптографічний захист: ElGamal, R = {} десяткових знаків"
                   .format(config.R_DIGITS))
        try:
            self.keys = elgamal.load_keys()
        except (OSError, ValueError):
            self.keys = None
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tab_keys(nb)
        self.tab_cipher(nb)
        self.tab_sign(nb)
        self.tab_manual(nb)

    # --- вкладка «Ключі» ---
    def tab_keys(self, nb):
        f = ttk.Frame(nb, padding=8)
        nb.add(f, text="Ключі")
        ttk.Button(f, text="Згенерувати ключі (R = {})".format(config.R_DIGITS),
                   command=self.gen_keys).pack(anchor="w")
        self.keys_text = tk.Text(f, width=86, height=14, font=("TkFixedFont", 10))
        self.keys_text.pack(fill="both", pady=6)
        self.show_keys()

    def show_keys(self, extra=""):
        self.keys_text.delete("1.0", "end")
        if not self.keys:
            self.keys_text.insert("end", "Ключі ще не згенеровано")
            return
        k = self.keys
        self.keys_text.insert("end", (
            "Відкритий ключ (p, g, y):\n p = {p}\n g = {g}\n y = {y}\n\n"
            "Закритий ключ:\n x = {x}\n\n"
            "Довжина p: {d} десяткових знаків ({b} біт){e}").format(
            p=k["p"], g=k["g"], y=k["y"], x=k["x"], d=len(str(k["p"])),
            b=k["p"].bit_length(), e=extra))

    def gen_keys(self):
        t0 = time.time()
        self.keys = elgamal.generate_keys(config.R_DIGITS)
        elgamal.save_keys(self.keys)
        storage.log_event(self.user.name, "ЗГЕНЕРОВАНО КЛЮЧІ ELGAMAL")
        self.show_keys("\nЧас генерації: {:.2f} с".format(time.time() - t0))

    # --- вкладка «Шифрування» ---
    def tab_cipher(self, nb):
        f = ttk.Frame(nb, padding=8)
        nb.add(f, text="Шифрування")
        ttk.Label(f, text="input.txt").grid(row=0, column=0, sticky="w")
        self.in_text = tk.Text(f, width=86, height=4, wrap="word")
        self.in_text.grid(row=1, column=0, columnspan=3)
        with open(config.INPUT_FILE, encoding="utf-8") as fh:
            self.in_text.insert("1.0", fh.read())
        ttk.Button(f, text="Зашифрувати → close.txt", command=self.encrypt).grid(
            row=2, column=0, sticky="w", pady=4)
        ttk.Button(f, text="Розшифрувати → out.txt", command=self.decrypt).grid(
            row=2, column=1, sticky="w", pady=4)
        ttk.Label(f, text="close.txt (пари a b)").grid(row=3, column=0, sticky="w")
        self.close_text = tk.Text(f, width=86, height=7, wrap="char",
                                  font=("TkFixedFont", 9))
        self.close_text.grid(row=4, column=0, columnspan=3)
        ttk.Label(f, text="out.txt").grid(row=5, column=0, sticky="w")
        self.out_text = tk.Text(f, width=86, height=3, wrap="word")
        self.out_text.grid(row=6, column=0, columnspan=3)
        self.cmp = ttk.Label(f, text="")
        self.cmp.grid(row=7, column=0, columnspan=3, sticky="w", pady=4)

    def need_keys(self):
        if not self.keys:
            messagebox.showwarning("Ключі", "Спочатку згенеруйте ключі", parent=self)
            return False
        return True

    def encrypt(self):
        if not self.need_keys():
            return
        with open(config.INPUT_FILE, "w", encoding="utf-8") as fh:
            fh.write(self.in_text.get("1.0", "end-1c"))
        pairs = elgamal.encrypt_file(self.keys)
        with open(config.CLOSE_FILE, encoding="utf-8") as fh:
            self.close_text.delete("1.0", "end")
            self.close_text.insert("1.0", fh.read())
        storage.log_event(self.user.name,
                          "ЗАШИФРОВАНО input.txt ({} блоків)".format(len(pairs)))
        self.cmp.config(text="Зашифровано блоків: {} (по {} байтів)".format(
            len(pairs), elgamal.block_size(self.keys["p"])))

    def decrypt(self):
        if not self.need_keys():
            return
        # розшифровується саме те, що зараз у полі close.txt (його можна змінити вручну)
        raw = self.close_text.get("1.0", "end-1c")
        try:
            pairs = [tuple(int(v) for v in line.split())
                     for line in raw.splitlines() if line.strip()]
            if not pairs or any(len(pr) != 2 for pr in pairs):
                raise ValueError
        except ValueError:
            messagebox.showerror("Помилка", "У полі close.txt мають бути лише пари чисел: a b",
                                 parent=self)
            return
        with open(config.CLOSE_FILE, "w", encoding="utf-8") as fh:
            fh.write(raw if raw.endswith("\n") else raw + "\n")
        try:
            text = elgamal.decrypt_pairs(pairs, self.keys, errors="replace")
        except (ValueError, OverflowError):
            text = "(шифротекст пошкоджено - розшифрувати не вдалося)"
        with open(config.OUT_FILE, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.out_text.delete("1.0", "end")
        self.out_text.insert("1.0", text)
        same = text == self.in_text.get("1.0", "end-1c")
        storage.log_event(self.user.name, "РОЗШИФРОВАНО close.txt")
        self.cmp.config(text="Розшифрований текст збігається з input.txt: " +
                        ("так" if same else "НІ"))

    # --- вкладка «Цифровий підпис» ---
    def tab_sign(self, nb):
        f = ttk.Frame(nb, padding=8)
        nb.add(f, text="Цифровий підпис")
        ttk.Label(f, text="Повідомлення:").pack(anchor="w")
        self.msg_text = tk.Text(f, width=86, height=4, wrap="word")
        self.msg_text.pack()
        with open(config.INPUT_FILE, encoding="utf-8") as fh:
            self.msg_text.insert("1.0", fh.read().strip())
        row = ttk.Frame(f)
        row.pack(anchor="w", pady=4)
        ttk.Button(row, text="Підписати", command=self.sign).pack(side="left")
        ttk.Button(row, text="Перевірити підпис",
                   command=self.verify).pack(side="left", padx=6)
        self.sig_text = tk.Text(f, width=86, height=10, font=("TkFixedFont", 10))
        self.sig_text.pack()
        self.sig = None

    def sign(self):
        if not self.need_keys():
            return
        msg = self.msg_text.get("1.0", "end-1c")
        h, r, s = elgamal.sign_message(msg, self.keys)
        self.sig = (r, s)
        self.sig_text.delete("1.0", "end")
        self.sig_text.insert("end", "H(m) = SHA-256(m) mod (p-1) =\n {}\n\n"
                             "Підпис:\n r = {}\n s = {}\n".format(h, r, s))
        storage.log_event(self.user.name, "ПІДПИСАНО ПОВІДОМЛЕННЯ")

    def verify(self):
        if not self.need_keys() or not self.sig:
            return
        msg = self.msg_text.get("1.0", "end-1c")
        ok = elgamal.verify_message(msg, self.sig[0], self.sig[1], self.keys)
        self.sig_text.insert("end", "\nПеревірка g^H ≡ y^r · r^s (mod p): {}\n".format(
            "ПІДПИС ДІЙСНИЙ" if ok else "ПІДПИС НЕДІЙСНИЙ (повідомлення змінено)"))
        storage.log_event(self.user.name,
                          "ПЕРЕВІРКА ПІДПИСУ: " + ("так" if ok else "ні"))

    # --- вкладка «Ручна перевірка» ---
    def tab_manual(self, nb):
        f = ttk.Frame(nb, padding=8)
        nb.add(f, text="Ручна перевірка")
        self.mvars = {}
        defaults = (("p", 23), ("g", 5), ("x", 6), ("k", 3), ("m", 10), ("H", 7))
        row = ttk.Frame(f)
        row.pack(anchor="w")
        for name, val in defaults:
            ttk.Label(row, text=name + " =").pack(side="left", padx=(8, 2))
            v = tk.StringVar(value=str(val))
            ttk.Entry(row, textvariable=v, width=6).pack(side="left")
            self.mvars[name] = v
        ttk.Button(row, text="Обчислити",
                   command=self.manual).pack(side="left", padx=10)
        self.man_text = tk.Text(f, width=86, height=14, font=("TkFixedFont", 10))
        self.man_text.pack(pady=6)

    def manual(self):
        try:
            p, g, x, k, m, h = (int(self.mvars[n].get()) for n in "pgxkmH")
            keys = {"p": p, "g": g, "x": x, "y": elgamal.mod_pow(g, x, p)}
            y = keys["y"]
            a, b = elgamal.encrypt_block(m, p, g, y, k)
            m2 = elgamal.decrypt_block(a, b, p, x)
            r, s = elgamal.sign_hash(h, keys, k)
            ok = elgamal.verify_hash(h, r, s, keys)
            k_inv = elgamal.mod_inverse(k, p - 1)
        except (ValueError, ZeroDivisionError) as exc:
            self.man_text.delete("1.0", "end")
            self.man_text.insert("1.0", "Помилка: {}".format(exc))
            return
        lines = [
            "Відкритий ключ: y = g^x mod p = {}^{} mod {} = {}".format(g, x, p, y),
            "Шифрування m = {}, k = {}:".format(m, k),
            "  a = g^k mod p = {}^{} mod {} = {}".format(g, k, p, a),
            "  b = y^k · m mod p = {}^{} · {} mod {} = {}".format(y, k, m, p, b),
            "Розшифрування: m = b · a^(p-1-x) mod p = {} · {}^{} mod {} = {}".format(
                b, a, p - 1 - x, p, m2),
            "Підпис H = {}:".format(h),
            "  r = g^k mod p = {}".format(r),
            "  k^(-1) mod (p-1) = {}".format(k_inv),
            "  s = (H - x·r) · k^(-1) mod (p-1) = ({} - {}·{}) · {} mod {} = {}".format(
                h, x, r, k_inv, p - 1, s),
            "Перевірка: g^H mod p = {}, y^r · r^s mod p = {} -> {}".format(
                elgamal.mod_pow(g, h, p),
                elgamal.mod_pow(y, r, p) * elgamal.mod_pow(r, s, p) % p,
                "підпис дійсний" if ok else "підпис недійсний"),
        ]
        self.man_text.delete("1.0", "end")
        self.man_text.insert("1.0", "\n".join(lines))
