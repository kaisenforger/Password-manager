import base64
import hashlib
import os
import secrets
import sqlite3
import string
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    raise SystemExit(
        "Missing dependency. Run: pip install -r requirements.txt"
    )

DB_NAME = "password_manager.db"
APP_TITLE = "Secure Password Manager"


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from the master password."""
    key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        200_000,
        dklen=32,
    )
    return base64.urlsafe_b64encode(key)


def hash_master_password(password: str, salt: bytes) -> bytes:
    """Create a verification hash for the master password."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000,
        dklen=32,
    )


def generate_password(length=16, use_symbols=True):
    """Generate a strong random password."""
    if length < 8:
        length = 8

    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+"

    # Ensure the password contains different character classes.
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if use_symbols:
        required.append(secrets.choice("!@#$%^&*()-_=+"))

    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    result = required + remaining
    secrets.SystemRandom().shuffle(result)
    return "".join(result)


class PasswordManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_NAME)
        self.create_tables()
        self.fernet = None

    def create_tables(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                master_hash BLOB NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                username BLOB NOT NULL,
                password BLOB NOT NULL
            )
        """)
        self.conn.commit()

    def is_initialized(self):
        cur = self.conn.cursor()
        cur.execute("SELECT id FROM settings WHERE id=1")
        return cur.fetchone() is not None

    def setup_master_password(self, password):
        salt = os.urandom(16)
        master_hash = hash_master_password(password, salt)
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO settings (id, salt, master_hash) VALUES (1, ?, ?)",
            (salt, master_hash),
        )
        self.conn.commit()
        self.fernet = Fernet(derive_key(password, salt))

    def login(self, password):
        cur = self.conn.cursor()
        cur.execute("SELECT salt, master_hash FROM settings WHERE id=1")
        row = cur.fetchone()
        if not row:
            return False

        salt, stored_hash = row
        candidate_hash = hash_master_password(password, salt)

        if secrets.compare_digest(candidate_hash, stored_hash):
            self.fernet = Fernet(derive_key(password, salt))
            return True
        return False

    def add_entry(self, website, username, password):
        if not self.fernet:
            raise RuntimeError("Manager is locked.")

        encrypted_username = self.fernet.encrypt(username.encode("utf-8"))
        encrypted_password = self.fernet.encrypt(password.encode("utf-8"))

        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)",
            (website, encrypted_username, encrypted_password),
        )
        self.conn.commit()

    def get_entries(self):
        if not self.fernet:
            raise RuntimeError("Manager is locked.")

        cur = self.conn.cursor()
        cur.execute("SELECT id, website, username, password FROM passwords ORDER BY website")
        rows = cur.fetchall()

        result = []
        for row_id, website, encrypted_username, encrypted_password in rows:
            try:
                username = self.fernet.decrypt(encrypted_username).decode("utf-8")
                password = self.fernet.decrypt(encrypted_password).decode("utf-8")
                result.append((row_id, website, username, password))
            except InvalidToken:
                continue
        return result

    def delete_entry(self, entry_id):
        cur = self.conn.cursor()
        cur.execute("DELETE FROM passwords WHERE id=?", (entry_id,))
        self.conn.commit()

    def close(self):
        self.conn.close()


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("760x520")
        self.root.minsize(700, 480)

        self.manager = PasswordManager()

        if self.manager.is_initialized():
            self.show_login()
        else:
            self.show_setup()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_setup(self):
        self.clear_window()

        frame = ttk.Frame(self.root, padding=30)
        frame.pack(expand=True)

        ttk.Label(
            frame,
            text="Create Master Password",
            font=("Segoe UI", 20, "bold"),
        ).grid(row=0, column=0, columnspan=2, pady=(0, 20))

        ttk.Label(frame, text="Master password:").grid(row=1, column=0, sticky="w", pady=8)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=password_var, show="*", width=35)
        password_entry.grid(row=1, column=1, pady=8)

        ttk.Label(frame, text="Confirm password:").grid(row=2, column=0, sticky="w", pady=8)
        confirm_var = tk.StringVar()
        confirm_entry = ttk.Entry(frame, textvariable=confirm_var, show="*", width=35)
        confirm_entry.grid(row=2, column=1, pady=8)

        def create():
            password = password_var.get()
            confirm = confirm_var.get()

            if len(password) < 8:
                messagebox.showwarning("Weak Password", "Use at least 8 characters.")
                return
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                return

            self.manager.setup_master_password(password)
            messagebox.showinfo("Success", "Master password created successfully.")
            self.show_main()

        ttk.Button(frame, text="Create & Continue", command=create).grid(
            row=3, column=0, columnspan=2, pady=20
        )

        ttk.Label(
            frame,
            text="Remember your master password. It cannot be recovered by this application.",
            wraplength=450,
        ).grid(row=4, column=0, columnspan=2)

        password_entry.focus()

    def show_login(self):
        self.clear_window()

        frame = ttk.Frame(self.root, padding=30)
        frame.pack(expand=True)

        ttk.Label(
            frame,
            text="Password Manager",
            font=("Segoe UI", 20, "bold"),
        ).grid(row=0, column=0, columnspan=2, pady=(0, 20))

        ttk.Label(frame, text="Master password:").grid(row=1, column=0, sticky="w", pady=8)
        password_var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=password_var, show="*", width=35)
        entry.grid(row=1, column=1, pady=8)

        def login():
            if self.manager.login(password_var.get()):
                self.show_main()
            else:
                messagebox.showerror("Login Failed", "Incorrect master password.")

        ttk.Button(frame, text="Unlock", command=login).grid(
            row=2, column=0, columnspan=2, pady=20
        )
        entry.focus()
        entry.bind("<Return>", lambda event: login())

    def show_main(self):
        self.clear_window()

        top = ttk.Frame(self.root, padding=(15, 12))
        top.pack(fill="x")

        ttk.Label(
            top, text="🔐 Secure Password Manager",
            font=("Segoe UI", 18, "bold")
        ).pack(side="left")

        ttk.Button(top, text="Lock", command=self.show_login).pack(side="right")

        body = ttk.Frame(self.root, padding=15)
        body.pack(fill="both", expand=True)

        columns = ("id", "website", "username")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", height=14)
        self.tree.heading("id", text="ID")
        self.tree.heading("website", text="Website / App")
        self.tree.heading("username", text="Username")
        self.tree.column("id", width=50, anchor="center")
        self.tree.column("website", width=250)
        self.tree.column("username", width=300)

        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        buttons = ttk.Frame(self.root, padding=15)
        buttons.pack(fill="x")

        ttk.Button(buttons, text="Add Password", command=self.add_entry_window).pack(
            side="left", padx=5
        )
        ttk.Button(buttons, text="Generate Password", command=self.generate_window).pack(
            side="left", padx=5
        )
        ttk.Button(buttons, text="View Password", command=self.view_selected).pack(
            side="left", padx=5
        )
        ttk.Button(buttons, text="Delete", command=self.delete_selected).pack(
            side="left", padx=5
        )

        self.refresh_tree()

    def refresh_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for row_id, website, username, _password in self.manager.get_entries():
            self.tree.insert("", "end", values=(row_id, website, username))

    def add_entry_window(self):
        win = tk.Toplevel(self.root)
        win.title("Add Password")
        win.geometry("430x300")
        win.transient(self.root)
        win.grab_set()

        frame = ttk.Frame(win, padding=20)
        frame.pack(fill="both", expand=True)

        website_var = tk.StringVar()
        username_var = tk.StringVar()
        password_var = tk.StringVar()

        ttk.Label(frame, text="Website / App:").pack(anchor="w", pady=(0, 5))
        ttk.Entry(frame, textvariable=website_var, width=45).pack(pady=(0, 12))

        ttk.Label(frame, text="Username / Email:").pack(anchor="w", pady=(0, 5))
        ttk.Entry(frame, textvariable=username_var, width=45).pack(pady=(0, 12))

        ttk.Label(frame, text="Password:").pack(anchor="w", pady=(0, 5))
        ttk.Entry(frame, textvariable=password_var, show="*", width=45).pack(pady=(0, 12))

        def save():
            website = website_var.get().strip()
            username = username_var.get().strip()
            password = password_var.get()

            if not website or not username or not password:
                messagebox.showwarning("Missing Data", "Please fill all fields.", parent=win)
                return

            self.manager.add_entry(website, username, password)
            self.refresh_tree()
            win.destroy()

        ttk.Button(frame, text="Save Password", command=save).pack(pady=8)

    def generate_window(self):
        win = tk.Toplevel(self.root)
        win.title("Strong Password Generator")
        win.geometry("430x250")
        win.transient(self.root)
        win.grab_set()

        frame = ttk.Frame(win, padding=20)
        frame.pack(fill="both", expand=True)

        length_var = tk.IntVar(value=16)
        password_var = tk.StringVar(value=generate_password(16))

        ttk.Label(frame, text="Password length:").pack(anchor="w")
        ttk.Spinbox(frame, from_=8, to=64, textvariable=length_var, width=10).pack(
            anchor="w", pady=(5, 15)
        )

        ttk.Entry(frame, textvariable=password_var, width=45).pack(pady=5)

        def generate():
            password_var.set(generate_password(length_var.get()))

        def copy():
            self.root.clipboard_clear()
            self.root.clipboard_append(password_var.get())
            self.root.update()
            messagebox.showinfo("Copied", "Password copied to clipboard.", parent=win)

        ttk.Button(frame, text="Generate", command=generate).pack(side="left", padx=5, pady=15)
        ttk.Button(frame, text="Copy", command=copy).pack(side="left", padx=5, pady=15)

    def selected_id(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Select Entry", "Please select an account first.")
            return None

        values = self.tree.item(selection[0], "values")
        return int(values[0])

    def view_selected(self):
        entry_id = self.selected_id()
        if entry_id is None:
            return

        for row_id, website, username, password in self.manager.get_entries():
            if row_id == entry_id:
                messagebox.showinfo(
                    "Saved Password",
                    f"Website: {website}\nUsername: {username}\nPassword: {password}",
                )
                return

    def delete_selected(self):
        entry_id = self.selected_id()
        if entry_id is None:
            return

        if messagebox.askyesno("Confirm Delete", "Delete this saved password?"):
            self.manager.delete_entry(entry_id)
            self.refresh_tree()

    def close(self):
        self.manager.close()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()
