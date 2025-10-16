import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import os, json, hashlib, random, string, csv
from cryptography.fernet import Fernet
import pyttsx3
import zxcvbn
from openai import OpenAI
from PIL import Image, ImageTk

# ========================= APP CONFIG =========================
APP_NAME = "DL Password Vault"
LOGO_PATH = "dl_logo.png"  # same folder as this file

# LinkedIn-ish, laid back color scheme
THEMES = {
    "light": {
        "APP_BG": "#F3F2EF",   # soft neutral
        "CARD_BG": "#FFFFFF",
        "PRIMARY": "#0A66C2",  # LinkedIn blue
        "PRIMARY_DARK": "#004182",
        "ACCENT": "#378FE9",
        "DANGER": "#D92D20",
        "TEXT_MAIN": "#1D2226",
        "TEXT_SUB": "#5B6B7A",
        "INPUT_BG": "#FFFFFF",
        "INPUT_FG": "#1D2226",
        "BORDER": "#E0E3E7",
        "FAB_BG": "#0A66C2",
        "FAB_FG": "#FFFFFF",
        "SHADOW": "#D8DDE3",
    },
    "dark": {
        "APP_BG": "#0E1116",
        "CARD_BG": "#12161C",
        "PRIMARY": "#2F7DD1",
        "PRIMARY_DARK": "#1F4E86",
        "ACCENT": "#4BA3FF",
        "DANGER": "#EF4444",
        "TEXT_MAIN": "#E8EAED",
        "TEXT_SUB": "#8A9AA9",
        "INPUT_BG": "#0E1116",
        "INPUT_FG": "#E8EAED",
        "BORDER": "#1F2A36",
        "FAB_BG": "#2F7DD1",
        "FAB_FG": "#FFFFFF",
        "SHADOW": "#0A0D12",
    },
}

current_theme = "light"
def C(k): return THEMES[current_theme][k]

SETTINGS_FILE = "settings.json"
DEFAULT_SETTINGS = {"theme": "light", "voice_enabled": True, "auto_lock_minutes": 5}

# ========================= SETTINGS (persisted) =========================
VOICE_ENABLED = True
AUTO_LOCK_MINUTES = 5
AUTO_LOCK_MS = AUTO_LOCK_MINUTES * 60 * 1000

def load_settings():
    global current_theme, VOICE_ENABLED, AUTO_LOCK_MINUTES, AUTO_LOCK_MS
    data = DEFAULT_SETTINGS.copy()
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data.update(json.load(f))
        except Exception:
            pass
    current_theme = data.get("theme", "light")
    VOICE_ENABLED = bool(data.get("voice_enabled", True))
    AUTO_LOCK_MINUTES = max(1, min(30, int(data.get("auto_lock_minutes", 5))))
    AUTO_LOCK_MS = AUTO_LOCK_MINUTES * 60 * 1000
    return data

def save_settings(theme=None, voice=None, minutes=None):
    data = load_settings()
    if theme is not None: data["theme"] = theme
    if voice is not None: data["voice_enabled"] = bool(voice)
    if minutes is not None: data["auto_lock_minutes"] = max(1, min(30, int(minutes)))
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    load_settings()

load_settings()

# ========================= SPEECH =========================
engine = pyttsx3.init()
engine.setProperty("rate", 175)
def speak(text):
    if VOICE_ENABLED:
        try:
            engine.say(text); engine.runAndWait()
        except:
            pass

# ========================= ENCRYPTION & FILES =========================
DATA_FILE, MASTER_FILE, KEY_FILE = "passwords.txt", "master.hash", "key.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        k = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f: f.write(k)
    with open(KEY_FILE, "rb") as f: return f.read()

fernet = Fernet(load_key())
def encrypt(t): return fernet.encrypt(t.encode()).decode()
def decrypt(t): return fernet.decrypt(t.encode()).decode()

# ========================= STORAGE OPS =========================
def add_entry(site, username, password):
    try:
        with open(DATA_FILE, "a", encoding="utf-8") as f:
            f.write(f"{encrypt(site)}|{encrypt(username)}|{encrypt(password)}\n")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save entry:\n{e}")

def get_entries():
    if not os.path.exists(DATA_FILE): return []
    out = []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) != 3: continue
            try:
                s, u, p = [decrypt(x) for x in parts]
                out.append((s, u, p))
            except Exception:
                continue
    return out

def delete_entry(site, username, password):
    if not os.path.exists(DATA_FILE): return
    kept, deleted = [], False
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                s, u, p = [decrypt(x) for x in line.strip().split("|")]
                if s == site and u == username and p == password:
                    deleted = True
                    continue
                kept.append(line)
            except Exception:
                kept.append(line)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        f.writelines(kept)
    if deleted:
        messagebox.showinfo("Deleted", f"Entry for {site} deleted.")
    else:
        messagebox.showwarning("Not found", "No matching entry found.")

def update_entry(old_site, old_user, old_pwd, new_site, new_user, new_pwd):
    if not os.path.exists(DATA_FILE): return False
    updated, lines = False, []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) != 3:
                lines.append(line); continue
            try:
                s, u, p = [decrypt(x) for x in parts]
                if s == old_site and u == old_user and p == old_pwd and not updated:
                    lines.append(f"{encrypt(new_site)}|{encrypt(new_user)}|{encrypt(new_pwd)}\n")
                    updated = True
                else:
                    lines.append(line)
            except Exception:
                lines.append(line)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)
    return updated

# ========================= MASTER PASSWORD MGMT =========================
def ensure_master_exists():
    if os.path.exists(MASTER_FILE): return
    pwd = simpledialog.askstring("Setup", "Create Master Password:", show="*")
    while not pwd:
        messagebox.showwarning("Required", "Master password cannot be empty.")
        pwd = simpledialog.askstring("Setup", "Create Master Password:", show="*")
    with open(MASTER_FILE, "w", encoding="utf-8") as f:
        f.write(hashlib.sha256(pwd.encode()).hexdigest())
    messagebox.showinfo("Master Created", "Master password set successfully.")
    speak("Master password created successfully.")

def check_master(pwd):
    if not os.path.exists(MASTER_FILE):
        ensure_master_exists()
        return True
    with open(MASTER_FILE, "r", encoding="utf-8") as f:
        stored = f.read().strip()
    return hashlib.sha256(pwd.encode()).hexdigest() == stored

def change_master_password(parent=None):
    if not os.path.exists(MASTER_FILE):
        ensure_master_exists(); return
    old = simpledialog.askstring("Change Master", "Enter current master password:", show="*", parent=parent)
    if not old: return
    if not check_master(old):
        messagebox.showerror("Error", "Incorrect current password.", parent=parent); return
    new1 = simpledialog.askstring("Change Master", "New master password:", show="*", parent=parent)
    new2 = simpledialog.askstring("Change Master", "Confirm new password:", show="*", parent=parent)
    if not new1 or new1 != new2:
        messagebox.showerror("Error", "Passwords do not match or are empty.", parent=parent); return
    with open(MASTER_FILE, "w", encoding="utf-8") as f:
        f.write(hashlib.sha256(new1.encode()).hexdigest())
    messagebox.showinfo("Success", "Master password updated.", parent=parent)
    speak("Master password updated.")

# ========================= PASSWORD UTILS =========================
client = OpenAI(api_key="YOUR_OPENAI_API_KEY")

def generate_password(length=16):
    try:
        if length < 12: length = 12
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Output only a strong random password."},
                {"role": "user", "content": f"Generate a strong password of {length}+ characters with upper/lowercase, digits, symbols, no spaces."}
            ],
            max_tokens=20, temperature=0.85
        )
        pw = resp.choices[0].message.content.strip()
        if zxcvbn.zxcvbn(pw)["score"] < 3:
            raise ValueError("Weak AI password, fallback")
        return pw
    except Exception:
        chars = string.ascii_letters + string.digits + string.punctuation
        return "".join(random.choice(chars) for _ in range(length))

def password_strength_label(password):
    if not password: return ("Strength: N/A", "gray")
    score = zxcvbn.zxcvbn(password)["score"]
    levels = ["Very Weak","Weak","Moderate","Strong","Very Strong"]
    colors = ["#D92D20","#F59E0B","#EAB308","#16A34A","#15803D"]
    return (f"Strength: {levels[score]}", colors[score])

# ========================= LOGO (as-is PNG) =========================
_logo_cache = {}
def get_logo(size=None):
    """Load dl_logo.png as-is; optional resize."""
    key = (size, current_theme)
    if key in _logo_cache: return _logo_cache[key]
    try:
        img = Image.open(LOGO_PATH).convert("RGBA")
        if size:
            img = img.resize((size, size), Image.LANCZOS)
        ph = ImageTk.PhotoImage(img)
    except Exception:
        ph = None
    _logo_cache[key] = ph
    return ph

# ========================= AUTO-LOCK =========================
root = None
_last_job = None
def _cancel_timer():
    global _last_job
    if _last_job:
        try: root.after_cancel(_last_job)
        except: pass
        _last_job = None

def _schedule_timer():
    global _last_job
    _cancel_timer()
    _last_job = root.after(AUTO_LOCK_MS, _auto_lock_trigger)

def _reset_idle_timer(event=None):
    _schedule_timer()

def enable_auto_lock():
    root.bind_all("<Any-KeyPress>", _reset_idle_timer)
    root.bind_all("<Any-Button>", _reset_idle_timer)
    _schedule_timer()

def disable_auto_lock():
    root.unbind_all("<Any-KeyPress>"); root.unbind_all("<Any-Button>"); _cancel_timer()

def _destroy_all_toplevels():
    for w in root.winfo_children():
        if isinstance(w, tk.Toplevel):
            try: w.destroy()
            except: pass

def _auto_lock_trigger():
    _destroy_all_toplevels()
    messagebox.showinfo("Auto-Locked", "Vault locked due to inactivity.")
    speak("Vault locked due to inactivity.")
    show_login()

# ========================= EXPORT (CSV) =========================
def export_all_csv_confirm(parent=None):
    pwd = simpledialog.askstring("Confirm Export", "Enter master password (CSV will be UNENCRYPTED):", show="*", parent=parent)
    if not pwd: return
    if not check_master(pwd):
        messagebox.showerror("Denied", "Master password incorrect. Export cancelled.", parent=parent); return
    entries = get_entries()
    if not entries:
        messagebox.showinfo("No Data", "There are no entries to export.", parent=parent); return
    path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV Files","*.csv")],
        title="Save Decrypted CSV",
        parent=parent
    )
    if not path: return
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["site","username","password"])
            for s,u,p in entries: w.writerow([s,u,p])
        messagebox.showinfo("Exported", f"Decrypted CSV saved to:\n{path}", parent=parent)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to export CSV:\n{e}", parent=parent)

# ========================= SETTINGS (phone-style) =========================
def open_settings(parent=None):
    win = tk.Toplevel(parent)
    win.title("Settings")
    win.geometry("380x560+40+40")   # phone-ish sub-screen
    win.configure(bg=C("APP_BG"))
    win.resizable(False, False)

    # Scroll container (phone-like)
    canvas = tk.Canvas(win, bg=C("APP_BG"), highlightthickness=0)
    scroller = tk.Scrollbar(win, orient="vertical", command=canvas.yview)
    body = tk.Frame(canvas, bg=C("APP_BG"))

    body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0,0), window=body, anchor="nw")
    canvas.configure(yscrollcommand=scroller.set)

    canvas.pack(side="left", fill="both", expand=True)
    scroller.pack(side="right", fill="y")

    # Header
    logo = get_logo(96)
    if logo: tk.Label(body, image=logo, bg=C("APP_BG")).pack(pady=(14,4))
    tk.Label(body, text="Settings", font=("Segoe UI", 18, "bold"), bg=C("APP_BG"), fg=C("TEXT_MAIN")).pack()

    # Card helper
    def card(parent): 
        f = tk.Frame(parent, bg=C("CARD_BG"), padx=16, pady=14, highlightthickness=1, highlightbackground=C("BORDER"))
        f.pack(fill="x", padx=14, pady=8)
        return f

    # Appearance / behavior
    c1 = card(body)
    tk.Label(c1, text="Appearance & Behavior", font=("Segoe UI", 11, "bold"), bg=C("CARD_BG"), fg=C("TEXT_MAIN")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,8))

    tk.Label(c1, text="Theme", bg=C("CARD_BG"), fg=C("TEXT_SUB")).grid(row=1, column=0, sticky="w")
    theme_var = tk.StringVar(value=current_theme)
    ttk.Combobox(c1, textvariable=theme_var, values=["light","dark"], state="readonly", width=12).grid(row=1, column=1, sticky="e")

    tk.Label(c1, text="Voice Assistant", bg=C("CARD_BG"), fg=C("TEXT_SUB")).grid(row=2, column=0, sticky="w", pady=(8,0))
    voice_var = tk.BooleanVar(value=VOICE_ENABLED)
    ttk.Checkbutton(c1, variable=voice_var).grid(row=2, column=1, sticky="e", pady=(8,0))

    tk.Label(c1, text="Auto-lock (minutes)", bg=C("CARD_BG"), fg=C("TEXT_SUB")).grid(row=3, column=0, sticky="w", pady=(8,0))
    minutes_var = tk.IntVar(value=AUTO_LOCK_MINUTES)
    tk.Spinbox(c1, from_=1, to=30, width=6, textvariable=minutes_var,
               bg=C("INPUT_BG"), fg=C("INPUT_FG"), relief="flat",
               highlightthickness=1, highlightbackground=C("BORDER")).grid(row=3, column=1, sticky="e", pady=(8,0))

    # Security
    c2 = card(body)
    tk.Label(c2, text="Security", font=("Segoe UI", 11, "bold"), bg=C("CARD_BG"), fg=C("TEXT_MAIN")).pack(anchor="w", pady=(0,8))
    tk.Button(c2, text="Change Master Password", bg=C("PRIMARY"), fg="white",
              font=("Segoe UI", 10, "bold"), relief="flat", padx=12, pady=8,
              command=lambda: change_master_password(win)).pack(fill="x", pady=(0,8))
    tk.Button(c2, text="Export Decrypted CSV", bg=C("PRIMARY_DARK"), fg="white",
              font=("Segoe UI", 10, "bold"), relief="flat", padx=12, pady=8,
              command=lambda: export_all_csv_confirm(win)).pack(fill="x")

    # Footer actions
    c3 = card(body)
    def apply_restart():
        save_settings(theme_var.get(), voice_var.get(), minutes_var.get())
        speak("Settings applied.")
        # Refresh main UI quickly
        _destroy_all_toplevels()
        show_login()
        win.destroy()
    tk.Button(c3, text="Apply & Restart UI", bg=C("ACCENT"), fg="white",
              font=("Segoe UI", 10, "bold"), relief="flat", padx=12, pady=10,
              command=apply_restart).pack(fill="x")

# ========================= ADD ENTRY (phone-style) =========================
def open_add_entry(parent=None):
    add = tk.Toplevel(parent)
    add.title("Add Password")
    add.geometry("380x560+40+40")
    add.configure(bg=C("APP_BG"))
    add.resizable(False, False)

    canvas = tk.Canvas(add, bg=C("APP_BG"), highlightthickness=0)
    scroller = tk.Scrollbar(add, orient="vertical", command=canvas.yview)
    body = tk.Frame(canvas, bg=C("APP_BG"))
    body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0,0), window=body, anchor="nw")
    canvas.configure(yscrollcommand=scroller.set)
    canvas.pack(side="left", fill="both", expand=True)
    scroller.pack(side="right", fill="y")

    logo = get_logo(88)
    if logo: tk.Label(body, image=logo, bg=C("APP_BG")).pack(pady=(14,6))
    tk.Label(body, text="Add New Password", font=("Segoe UI", 18, "bold"), bg=C("APP_BG"), fg=C("TEXT_MAIN")).pack()

    card = tk.Frame(body, bg=C("CARD_BG"), padx=16, pady=14, highlightthickness=1, highlightbackground=C("BORDER"))
    card.pack(padx=14, pady=10, fill="x")

    def mk_label(t): return tk.Label(card, text=t, bg=C("CARD_BG"), fg=C("TEXT_MAIN"))
    def mk_entry():
        return tk.Entry(card, font=("Segoe UI", 10), bg=C("INPUT_BG"), fg=C("INPUT_FG"),
                        relief="flat", highlightthickness=1, highlightbackground=C("BORDER"))

    mk_label("Website / App").pack(anchor="w"); e_site = mk_entry(); e_site.pack(fill="x", pady=(0,10))
    mk_label("Username").pack(anchor="w"); e_user = mk_entry(); e_user.pack(fill="x", pady=(0,10))
    mk_label("Password").pack(anchor="w")

    row = tk.Frame(card, bg=C("CARD_BG")); row.pack(fill="x")
    e_pwd = tk.Entry(row, show="•", font=("Segoe UI", 10), bg=C("INPUT_BG"), fg=C("INPUT_FG"),
                     relief="flat", highlightthickness=1, highlightbackground=C("BORDER"))
    e_pwd.pack(side="left", fill="x", expand=True)

    show = {"v": False}
    def toggle_show():
        show["v"] = not show["v"]
        e_pwd.config(show="" if show["v"] else "•")
        btn_show.config(text="Hide" if show["v"] else "Show")

    btn_show = tk.Button(row, text="Show", bg=C("PRIMARY"), fg="white",
                         font=("Segoe UI", 9, "bold"), relief="flat", padx=10,
                         command=toggle_show)
    btn_show.pack(side="right", padx=(8,0))

    def do_generate():
        newp = generate_password()
        e_pwd.delete(0, tk.END); e_pwd.insert(0, newp); update_strength()

    tk.Button(row, text="AI Generate 🤖", bg=C("PRIMARY_DARK"), fg="white",
              font=("Segoe UI", 9, "bold"), relief="flat", padx=10,
              command=do_generate).pack(side="right", padx=(8,0))

    strength = tk.Label(card, text="Strength: N/A", bg=C("CARD_BG"), fg=C("TEXT_SUB"), font=("Segoe UI", 9))
    strength.pack(anchor="w", pady=(6,0))

    def update_strength(*_):
        label, color = password_strength_label(e_pwd.get()); strength.config(text=label, fg=color)
    e_pwd.bind("<KeyRelease>", update_strength)

    def save():
        s,u,p = e_site.get().strip(), e_user.get().strip(), e_pwd.get().strip()
        if not s or not u or not p:
            messagebox.showwarning("Missing", "All fields are required.", parent=add); return
        add_entry(s,u,p); messagebox.showinfo("Saved", f"Entry added for {s}.", parent=add); speak("Entry saved.")
        e_site.delete(0,"end"); e_user.delete(0,"end"); e_pwd.delete(0,"end"); show["v"]=False; e_pwd.config(show="•"); btn_show.config(text="Show"); update_strength()

    tk.Button(body, text="Save Entry", bg=C("ACCENT"), fg="white",
              font=("Segoe UI", 11, "bold"), relief="flat", padx=14, pady=10,
              command=save).pack(fill="x", padx=14, pady=(8,14))

# ========================= EDIT ENTRY (phone-style) =========================
def open_edit_entry(parent, site, user, pwd, refresh_callback):
    win = tk.Toplevel(parent)
    win.title(f"Edit — {site}")
    win.geometry("380x560+40+40")
    win.configure(bg=C("APP_BG"))
    win.resizable(False, False)

    canvas = tk.Canvas(win, bg=C("APP_BG"), highlightthickness=0)
    scroller = tk.Scrollbar(win, orient="vertical", command=canvas.yview)
    body = tk.Frame(canvas, bg=C("APP_BG"))
    body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0,0), window=body, anchor="nw")
    canvas.configure(yscrollcommand=scroller.set)
    canvas.pack(side="left", fill="both", expand=True)
    scroller.pack(side="right", fill="y")

    tk.Label(body, text="Edit Entry", font=("Segoe UI", 18, "bold"),
             bg=C("APP_BG"), fg=C("TEXT_MAIN")).pack(pady=(14,6))

    card = tk.Frame(body, bg=C("CARD_BG"), padx=16, pady=14, highlightthickness=1, highlightbackground=C("BORDER"))
    card.pack(padx=14, pady=10, fill="x")

    def mk_label(t): return tk.Label(card, text=t, bg=C("CARD_BG"), fg=C("TEXT_MAIN"))
    def mk_entry():
        return tk.Entry(card, font=("Segoe UI", 10), bg=C("INPUT_BG"), fg=C("INPUT_FG"),
                        relief="flat", highlightthickness=1, highlightbackground=C("BORDER"))

    mk_label("Website / App").pack(anchor="w"); e_site = mk_entry(); e_site.insert(0, site); e_site.pack(fill="x", pady=(0,10))
    mk_label("Username").pack(anchor="w"); e_user = mk_entry(); e_user.insert(0, user); e_user.pack(fill="x", pady=(0,10))
    mk_label("Password").pack(anchor="w")
    row = tk.Frame(card, bg=C("CARD_BG")); row.pack(fill="x")
    e_pwd = tk.Entry(row, show="•", font=("Segoe UI", 10), bg=C("INPUT_BG"), fg=C("INPUT_FG"),
                     relief="flat", highlightthickness=1, highlightbackground=C("BORDER"))
    e_pwd.insert(0, pwd); e_pwd.pack(side="left", fill="x", expand=True)

    show = {"v": False}
    def toggle_show():
        show["v"] = not show["v"]
        e_pwd.config(show="" if show["v"] else "•")
        btn_show.config(text="Hide" if show["v"] else "Show")

    btn_show = tk.Button(row, text="Show", bg=C("PRIMARY"), fg="white",
                         font=("Segoe UI", 9, "bold"), relief="flat", padx=10,
                         command=toggle_show)
    btn_show.pack(side="right", padx=(8,0))

    def do_generate():
        newp = generate_password()
        e_pwd.delete(0, tk.END); e_pwd.insert(0, newp); update_strength()
    tk.Button(row, text="AI Generate 🤖", bg=C("PRIMARY_DARK"), fg="white",
              font=("Segoe UI", 9, "bold"), relief="flat", padx=10,
              command=do_generate).pack(side="right", padx=(8,0))

    strength = tk.Label(card, text="Strength: N/A", bg=C("CARD_BG"), fg=C("TEXT_SUB"), font=("Segoe UI", 9))
    strength.pack(anchor="w", pady=(6,0))
    def update_strength(*_):
        label, color = password_strength_label(e_pwd.get()); strength.config(text=label, fg=color)
    e_pwd.bind("<KeyRelease>", update_strength); update_strength()

    def save_changes():
        ns,nu,np = e_site.get().strip(), e_user.get().strip(), e_pwd.get().strip()
        if not ns or not nu or not np:
            messagebox.showwarning("Missing", "All fields are required.", parent=win); return
        if update_entry(site, user, pwd, ns, nu, np):
            messagebox.showinfo("Updated", "Entry updated successfully.", parent=win); speak("Entry updated."); win.destroy(); refresh_callback()
        else:
            messagebox.showerror("Error", "Failed to update entry.", parent=win)

    tk.Button(body, text="Save Changes", bg=C("ACCENT"), fg="white",
              font=("Segoe UI", 11, "bold"), relief="flat", padx=14, pady=10,
              command=save_changes).pack(fill="x", padx=14, pady=(8,14))

# ========================= VIEW / SEARCH (phone-style) =========================
def view_all_passwords(parent=None):
    win = tk.Toplevel(parent)
    win.title("Passwords")
    win.geometry("420x720+50+20")  # phone portrait
    win.configure(bg=C("APP_BG"))
    win.resizable(False, False)

    # Top bar with title (like mobile)
    top = tk.Frame(win, bg=C("APP_BG"))
    top.pack(fill="x", pady=(12,4))
    tk.Label(top, text="Your Passwords", font=("Segoe UI", 18, "bold"),
             bg=C("APP_BG"), fg=C("TEXT_MAIN")).pack(side="left", padx=14)

    # Settings FAB (top-right gear)
    def open_settings_from_view():
        open_settings(win)
    gear = tk.Button(top, text="⚙️", bg=C("APP_BG"), fg=C("TEXT_MAIN"),
                     relief="flat", font=("Segoe UI", 14, "bold"),
                     command=open_settings_from_view, cursor="hand2")
    gear.pack(side="right", padx=10)

    # Search strip
    bar = tk.Frame(win, bg=C("APP_BG"))
    bar.pack(fill="x", padx=12, pady=(4,8))
    q_var = tk.StringVar()
    ent = tk.Entry(bar, textvariable=q_var, width=24, bg=C("INPUT_BG"), fg=C("INPUT_FG"),
                   relief="flat", highlightthickness=1, highlightbackground=C("BORDER"))
    ent.pack(side="left", fill="x", expand=True)
    scope_var = tk.StringVar(value="All")
    ttk.Combobox(bar, textvariable=scope_var, values=["All","Site","Username"],
                 state="readonly", width=10).pack(side="left", padx=(8,0))

    # Card list (scrollable)
    card = tk.Frame(win, bg=C("CARD_BG"), padx=0, pady=0, highlightthickness=1, highlightbackground=C("BORDER"))
    card.pack(fill="both", expand=True, padx=12, pady=(0,12))

    canvas = tk.Canvas(card, bg=C("CARD_BG"), highlightthickness=0)
    scroll = tk.Scrollbar(card, orient="vertical", command=canvas.yview)
    inner = tk.Frame(canvas, bg=C("CARD_BG"))
    inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0,0), window=inner, anchor="nw")
    canvas.configure(yscrollcommand=scroll.set)
    canvas.pack(side="left", fill="both", expand=True); scroll.pack(side="right", fill="y")

    def render(rows):
        for w in inner.winfo_children(): w.destroy()
        if not rows:
            tk.Label(inner, text="No matching entries.", font=("Segoe UI", 11, "italic"),
                     bg=C("CARD_BG"), fg=C("TEXT_SUB")).pack(pady=16)
            return
        # Mobile card rows
        for site, user, pwd in rows:
            row = tk.Frame(inner, bg=C("CARD_BG"), padx=12, pady=10, highlightthickness=0)
            row.pack(fill="x")
            sep = tk.Frame(inner, bg=C("BORDER"), height=1); sep.pack(fill="x")

            tk.Label(row, text=site, font=("Segoe UI", 11, "bold"),
                     bg=C("CARD_BG"), fg=C("TEXT_MAIN"), anchor="w").grid(row=0, column=0, sticky="w")
            tk.Label(row, text=user, font=("Segoe UI", 9),
                     bg=C("CARD_BG"), fg=C("TEXT_SUB"), anchor="w").grid(row=1, column=0, sticky="w", pady=(2,8))

            # Actions (right side)
            btns = tk.Frame(row, bg=C("CARD_BG")); btns.grid(row=0, column=1, rowspan=2, sticky="e")
            def do_copy(p=pwd, s=site):
                win.clipboard_clear(); win.clipboard_append(p); speak("Password copied.")
                messagebox.showinfo("Copied", f"Password for {s} copied.", parent=win)
            def do_delete(s=site, u=user, p=pwd):
                if messagebox.askyesno("Confirm", f"Delete password for {s}?", parent=win):
                    delete_entry(s,u,p); refresh()
            def do_edit(s=site, u=user, p=pwd):
                open_edit_entry(win, s, u, p, refresh)

            tk.Button(btns, text="Edit", bg=C("PRIMARY"), fg="white", relief="flat",
                      font=("Segoe UI", 9, "bold"), padx=10, pady=4,
                      command=do_edit).pack(side="left", padx=(0,6))
            tk.Button(btns, text="Copy", bg=C("ACCENT"), fg="white", relief="flat",
                      font=("Segoe UI", 9, "bold"), padx=10, pady=4,
                      command=do_copy).pack(side="left", padx=(0,6))
            tk.Button(btns, text="Delete", bg=C("DANGER"), fg="white", relief="flat",
                      font=("Segoe UI", 9, "bold"), padx=10, pady=4,
                      command=do_delete).pack(side="left")

    def filtered():
        term = q_var.get().strip().lower()
        scope = scope_var.get()
        rows = get_entries()
        if not term: return rows
        if scope == "Site": return [r for r in rows if term in r[0].lower()]
        if scope == "Username": return [r for r in rows if term in r[1].lower()]
        return [r for r in rows if term in r[0].lower() or term in r[1].lower()]

    def refresh(*_): render(filtered())
    q_var.trace_add("write", lambda *_: refresh())
    refresh()

# ========================= DASHBOARD (phone-style) =========================
def open_vault():
    dash = tk.Toplevel()
    dash.title(APP_NAME)
    # Phone portrait frame
    dash.geometry("420x720+40+10")
    dash.configure(bg=C("APP_BG"))
    dash.resizable(False, False)

    # Logo as-is
    logo = get_logo(120)
    if logo: tk.Label(dash, image=logo, bg=C("APP_BG")).pack(pady=(18,6))

    tk.Label(dash, text=APP_NAME, font=("Segoe UI", 18, "bold"),
             bg=C("APP_BG"), fg=C("TEXT_MAIN")).pack()
    tk.Label(dash, text="Secure. Smart. Personal.",
             font=("Segoe UI", 10), bg=C("APP_BG"), fg=C("TEXT_SUB")).pack(pady=(0,10))

    # Action card
    card = tk.Frame(dash, bg=C("CARD_BG"), padx=18, pady=16, highlightthickness=1, highlightbackground=C("BORDER"))
    card.pack(fill="x", padx=14, pady=(0,10))

    tk.Label(card, text="Quick Actions", font=("Segoe UI", 11, "bold"),
             bg=C("CARD_BG"), fg=C("TEXT_MAIN")).pack(anchor="w", pady=(0,10))

    # Big touch-friendly buttons
    def big_btn(parent, text, cmd, bg):
        return tk.Button(parent, text=text, bg=bg, fg="white", font=("Segoe UI", 11, "bold"),
                         relief="flat", padx=14, pady=12, command=cmd, cursor="hand2")

    actions = tk.Frame(card, bg=C("CARD_BG"))
    actions.pack(fill="x")
    big_btn(actions, "View / Search Passwords", lambda: view_all_passwords(dash), C("PRIMARY")).pack(fill="x", pady=(0,10))
    big_btn(actions, "Add New Password", lambda: open_add_entry(dash), C("ACCENT")).pack(fill="x")

    # Info block
    info = tk.Frame(dash, bg=C("CARD_BG"), padx=18, pady=12, highlightthickness=1, highlightbackground=C("BORDER"))
    info.pack(fill="x", padx=14, pady=(10,14))
    tk.Label(info, text=f"Auto-lock in {AUTO_LOCK_MINUTES} minute(s).",
             bg=C("CARD_BG"), fg=C("TEXT_SUB"), font=("Segoe UI", 10)).pack(anchor="w")

    # FABs
    # Settings (top-right)
    fab_settings = tk.Button(dash, text="⚙️", bg=C("FAB_BG"), fg=C("FAB_FG"),
                             font=("Segoe UI", 14, "bold"),
                             relief="flat", bd=0, padx=14, pady=6,
                             activebackground=C("PRIMARY_DARK"),
                             command=lambda: open_settings(dash), cursor="hand2")
    fab_settings.place(relx=0.92, rely=0.06, anchor="ne")

    # Add (bottom-right)
    fab_add = tk.Button(dash, text="＋", bg=C("FAB_BG"), fg=C("FAB_FG"),
                        font=("Segoe UI", 20, "bold"),
                        relief="flat", bd=0, padx=14, pady=6,
                        activebackground=C("PRIMARY_DARK"),
                        command=lambda: open_add_entry(dash), cursor="hand2")
    fab_add.place(relx=0.92, rely=0.92, anchor="se")

    # Logout (subtle)
    tk.Button(dash, text="Logout", bg=C("DANGER"), fg="white", font=("Segoe UI", 10, "bold"),
              relief="flat", padx=12, pady=8, command=dash.destroy).pack(pady=(0,12))

# ========================= LOGIN & SPLASH =========================
def show_login():
    ensure_master_exists()
    login = tk.Toplevel()
    login.title(f"{APP_NAME} — Login")
    login.geometry("420x720+40+10")
    login.configure(bg=C("APP_BG"))
    login.resizable(False, False)

    container = tk.Frame(login, bg=C("APP_BG"))
    container.place(relx=0.5, rely=0.28, anchor="n")

    logo = get_logo(140)
    if logo: tk.Label(container, image=logo, bg=C("APP_BG")).pack(pady=(0,8))
    tk.Label(container, text=APP_NAME, font=("Segoe UI", 18, "bold"),
             bg=C("APP_BG"), fg=C("TEXT_MAIN")).pack()
    tk.Label(container, text="Secure. Smart. Personal.", font=("Segoe UI", 10),
             bg=C("APP_BG"), fg=C("TEXT_SUB")).pack(pady=(0,12))

    card = tk.Frame(login, bg=C("CARD_BG"), padx=24, pady=20, highlightthickness=1, highlightbackground=C("BORDER"))
    card.place(relx=0.5, rely=0.48, anchor="n", width=380)

    tk.Label(card, text="Enter Master Password", bg=C("CARD_BG"), fg=C("TEXT_MAIN")).pack(anchor="w")
    e = tk.Entry(card, show="•", width=28, font=("Segoe UI", 11), bg=C("INPUT_BG"), fg=C("INPUT_FG"),
                 relief="flat", highlightthickness=1, highlightbackground=C("BORDER"))
    e.pack(pady=(6,18)); e.focus_set()

    def unlock(event=None):
        if check_master(e.get()):
            login.destroy(); open_vault(); enable_auto_lock()
        else:
            messagebox.showerror("Error", "Incorrect master password.", parent=login)

    tk.Button(card, text="Login", bg=C("PRIMARY"), fg="white", font=("Segoe UI", 11, "bold"),
              relief="flat", padx=14, pady=10, command=unlock).pack(fill="x")
    e.bind("<Return>", unlock)

def show_splash():
    splash = tk.Toplevel()
    splash.overrideredirect(True)
    w,h = 420, 720
    # Center-ish
    x = 60
    y = 20
    splash.geometry(f"{w}x{h}+{x}+{y}")
    splash.configure(bg=C("APP_BG"))

    frame = tk.Frame(splash, bg=C("APP_BG"))
    frame.place(relx=0.5, rely=0.25, anchor="n")

    logo = get_logo(160)
    if logo: tk.Label(frame, image=logo, bg=C("APP_BG")).pack(pady=(32,12))
    tk.Label(frame, text=APP_NAME, font=("Segoe UI", 20, "bold"),
             bg=C("APP_BG"), fg=C("TEXT_MAIN")).pack()
    tk.Label(frame, text="Secure. Smart. Personal.",
             font=("Segoe UI", 11), bg=C("APP_BG"), fg=C("TEXT_SUB")).pack()
    splash.after(1200, lambda: (splash.destroy(), show_login()))

# ========================= BOOT =========================
if __name__ == "__main__":
    load_settings()
    root = tk.Tk(); root.withdraw()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    root.after(80, show_splash)
    root.mainloop()
