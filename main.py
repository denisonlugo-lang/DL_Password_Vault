import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
from cryptography.fernet import Fernet
import os, hashlib, random, string, threading
from PIL import Image, ImageTk
import speech_recognition as sr
import pyttsx3

# ========================= GLOBAL CONFIG =========================
APP_NAME = "DL Password Vault"
LOGO_PATH = "dl_logo.png"

# Voice setting (toggle in Settings)
VOICE_ENABLED = True

# Theme palette (toggle in Settings)
THEMES = {
    "light": {
        "APP_BG": "#f4f4f4",
        "BTN_BG": "#0078D7",
        "BTN_FG": "white",
        "TEXT": "#222222",
        "CARD_BG": "white"
    },
    "dark": {
        "APP_BG": "#0f1012",
        "BTN_BG": "#0ea5e9",
        "BTN_FG": "white",
        "TEXT": "#e5e7eb",
        "CARD_BG": "#17181a"
    }
}
current_theme = "light"

def C(key: str) -> str:
    return THEMES[current_theme][key]

# Auto-lock (adjustable in Settings)
AUTO_LOCK_MINUTES = 5          # default
AUTO_LOCK_MS = AUTO_LOCK_MINUTES * 60 * 1000
_last_activity_job = None
root = None

# ========================= SPEECH (TTS) =========================
engine = pyttsx3.init()
engine.setProperty('rate', 175)
engine.setProperty('volume', 1.0)

def speak(text: str):
    if VOICE_ENABLED:
        try:
            engine.say(text)
            engine.runAndWait()
        except Exception:
            # Fail silently if no audio device, etc.
            pass

# ========================= ENCRYPTION SETUP =========================
DATA_FILE   = "passwords.txt"  # encrypted, one line per entry (site|user|pwd) each field encrypted
MASTER_FILE = "master.hash"    # sha256 hash of master
KEY_FILE    = "key.key"        # Fernet key file

def load_key() -> bytes:
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f: f.write(key)
    with open(KEY_FILE, "rb") as f:
        return f.read()

fernet = Fernet(load_key())

def encrypt(plain: str) -> str:
    return fernet.encrypt(plain.encode()).decode()

def decrypt(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

# ========================= STORAGE OPS =========================
def add_entry(site: str, user: str, pwd: str):
    with open(DATA_FILE, "a", encoding="utf-8") as f:
        f.write(f"{encrypt(site)}|{encrypt(user)}|{encrypt(pwd)}\n")

def get_entries():
    if not os.path.exists(DATA_FILE):
        return []
    out = []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                a, b, c = line.split("|")
                out.append((decrypt(a), decrypt(b), decrypt(c)))
            except Exception:
                # skip corrupted lines
                pass
    return out

def export_vault_dialog(parent):
    if not os.path.exists(DATA_FILE):
        messagebox.showinfo("Export", "No entries to export.", parent=parent)
        return
    path = filedialog.asksaveasfilename(
        title="Export Encrypted Vault",
        defaultextension=".vlt",
        filetypes=[("DL Vault Backup", "*.vlt")]
    )
    if not path: return
    try:
        with open(DATA_FILE, "rb") as src, open(path, "wb") as dst:
            dst.write(src.read())
        messagebox.showinfo("Export", f"Encrypted backup saved to:\n{path}", parent=parent)
    except Exception as e:
        messagebox.showerror("Export Error", str(e), parent=parent)

def import_vault_dialog(parent):
    path = filedialog.askopenfilename(
        title="Import Encrypted Vault",
        filetypes=[("DL Vault Backup", "*.vlt")]
    )
    if not path: return
    try:
        if os.path.exists(DATA_FILE):
            # Safe append: merge lines (encrypted-by-field)
            with open(path, "rb") as src:
                incoming = src.readlines()
            existing = []
            with open(DATA_FILE, "rb") as cur:
                existing = cur.readlines()
            merged = list(dict.fromkeys(existing + incoming))  # keep order, drop dup
            with open(DATA_FILE, "wb") as out:
                out.writelines(merged)
        else:
            with open(path, "rb") as src, open(DATA_FILE, "wb") as dst:
                dst.write(src.read())
        messagebox.showinfo("Import", "Vault import completed.", parent=parent)
    except Exception as e:
        messagebox.showerror("Import Error", str(e), parent=parent)

# ========================= MASTER PASSWORD =========================
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

def check_master(pwd: str) -> bool:
    if not os.path.exists(MASTER_FILE):
        ensure_master_exists()
        return True
    with open(MASTER_FILE, "r", encoding="utf-8") as f:
        stored = f.read().strip()
    return hashlib.sha256(pwd.encode()).hexdigest() == stored

def change_master_password(parent):
    if not os.path.exists(MASTER_FILE):
        ensure_master_exists()
        return
    old = simpledialog.askstring("Change Master Password", "Enter current master password:", show="*", parent=parent)
    if old is None: return
    if not check_master(old):
        messagebox.showerror("Error", "Current master password is incorrect.", parent=parent)
        return
    new1 = simpledialog.askstring("Change Master Password", "Enter new master password:", show="*", parent=parent)
    if not new1:
        messagebox.showwarning("Error", "New password cannot be empty.", parent=parent); return
    new2 = simpledialog.askstring("Change Master Password", "Re-enter new master password:", show="*", parent=parent)
    if new1 != new2:
        messagebox.showerror("Error", "New passwords do not match.", parent=parent); return
    with open(MASTER_FILE, "w", encoding="utf-8") as f:
        f.write(hashlib.sha256(new1.encode()).hexdigest())
    messagebox.showinfo("Success", "Master password updated.", parent=parent)
    speak("Master password updated.")

# ========================= UTIL: THEME & STYLING =========================
def apply_window_theme(win: tk.Toplevel | tk.Tk):
    win.configure(bg=C("APP_BG"))

def style_button(btn: tk.Button):
    btn.configure(bg=C("BTN_BG"), fg=C("BTN_FG"), activebackground=C("BTN_BG"), activeforeground=C("BTN_FG"))

def load_logo(size):
    try:
        img = Image.open(LOGO_PATH).resize((size, size))
        return ImageTk.PhotoImage(img)
    except Exception:
        return None

# ========================= AUTO-LOCK =========================
def _cancel_timer():
    global _last_activity_job
    if _last_activity_job is not None:
        try:
            root.after_cancel(_last_activity_job)
        except Exception:
            pass
        _last_activity_job = None

def _schedule_timer():
    global _last_activity_job
    _cancel_timer()
    _last_activity_job = root.after(AUTO_LOCK_MS, _auto_lock_trigger)

def _reset_idle_timer(event=None):
    _schedule_timer()

def enable_auto_lock():
    root.bind_all("<Any-KeyPress>", _reset_idle_timer)
    root.bind_all("<Any-Button>", _reset_idle_timer)
    _schedule_timer()

def disable_auto_lock():
    root.unbind_all("<Any-KeyPress>")
    root.unbind_all("<Any-Button>")
    _cancel_timer()

def _auto_lock_trigger():
    # Close every Toplevel window and show login
    for w in root.winfo_children():
        if isinstance(w, tk.Toplevel):
            try: w.destroy()
            except Exception: pass
    messagebox.showinfo("Auto Lock", "Vault locked due to inactivity.")
    speak("Vault locked due to inactivity.")
    show_login()

def set_auto_lock_minutes(parent):
    global AUTO_LOCK_MINUTES, AUTO_LOCK_MS
    val = simpledialog.askinteger("Auto Lock", "Set auto-lock (minutes, 1–30):", minvalue=1, maxvalue=30, parent=parent)
    if val is None: return
    AUTO_LOCK_MINUTES = int(val)
    AUTO_LOCK_MS = AUTO_LOCK_MINUTES * 60 * 1000
    _schedule_timer()
    messagebox.showinfo("Auto Lock", f"Auto-lock set to {AUTO_LOCK_MINUTES} minute(s).", parent=parent)
    speak(f"Auto lock set to {AUTO_LOCK_MINUTES} minutes.")

# ========================= AI CHAT (LOCAL) =========================
def open_ai_chat_local():
    ai = tk.Toplevel()
    ai.title(f"{APP_NAME} — AI Assistant")
    apply_window_theme(ai)
    ai.geometry("560x460")

    logo = load_logo(70)
    if logo:
        lbl = tk.Label(ai, image=logo, bg=C("APP_BG"))
        lbl.image = logo
        lbl.pack(pady=(10, 0))

    text_box = tk.Text(ai, bg=C("CARD_BG"), fg=C("TEXT"), wrap="word", height=16, width=64, relief="flat")
    text_box.pack(padx=12, pady=12, fill="both", expand=True)

    entry = tk.Entry(ai)
    entry.pack(padx=12, pady=(0, 8), fill="x")

    def append(sender, msg):
        text_box.insert("end", f"{sender}: {msg}\n")
        text_box.see("end")

    def handle(msg: str) -> str:
        q = msg.lower().strip()
        if "strong" in q and "password" in q:
            resp = "Use 12–16+ characters with upper/lowercase, numbers, and symbols. Prefer unique passwords per site."
        elif "who made you" in q or "author" in q:
            resp = "I was created by Denison Lugo as part of the DL Password Vault project."
        elif "how are you" in q:
            resp = "Feeling secure and responsive."
        elif q.startswith("show all"):
            rows = [f"- {s} ({u})" for s, u, _ in get_entries()]
            resp = "Your entries:\n" + ("\n".join(rows) if rows else "No entries yet.")
        else:
            resp = "Ask about security tips, or say 'show all' to list entries (masked)."
        speak(resp)
        return resp

    def send(event=None):
        msg = entry.get().strip()
        if not msg: return
        append("You", msg); entry.delete(0, "end")
        def run():
            try:
                resp = handle(msg)
            except Exception as e:
                resp = f"Error: {e}"
            append("AI", resp)
        threading.Thread(target=run, daemon=True).start()

    entry.bind("<Return>", send)

    def record_voice():
        def listen():
            append("AI", "🎙 Listening...")
            speak("Listening")
            r = sr.Recognizer()
            try:
                with sr.Microphone() as source:
                    r.adjust_for_ambient_noise(source, duration=0.5)
                    audio = r.listen(source, phrase_time_limit=6)
                text = r.recognize_google(audio)
                append("You", text)
                resp = handle(text)
                append("AI", resp)
            except sr.UnknownValueError:
                append("AI", "Sorry, I didn’t catch that.")
                speak("Sorry, I didn't catch that.")
            except Exception as e:
                append("AI", f"Voice error: {e}")
        threading.Thread(target=listen, daemon=True).start()

    btn_row = tk.Frame(ai, bg=C("APP_BG")); btn_row.pack(pady=(0, 10))
    b_send = tk.Button(btn_row, text="Send", command=send); style_button(b_send); b_send.pack(side="left", padx=6)
    b_mic  = tk.Button(btn_row, text="🎤 Voice Input", command=record_voice); style_button(b_mic); b_mic.pack(side="left", padx=6)

# ========================= DASHBOARD (VAULT) =========================
def open_vault():
    dash = tk.Toplevel()
    dash.title(APP_NAME)
    apply_window_theme(dash)
    dash.geometry("760x580")

    # ----- Menu Bar (Settings) -----
    menubar = tk.Menu(dash)

    settings_menu = tk.Menu(menubar, tearoff=0)
    def toggle_voice():
        global VOICE_ENABLED
        VOICE_ENABLED = not VOICE_ENABLED
        status = "enabled" if VOICE_ENABLED else "muted"
        messagebox.showinfo("Voice", f"Voice feedback {status}.")
        speak(f"Voice {status}.")
        settings_menu.entryconfig(0, label=("🔊 Mute Voice" if VOICE_ENABLED else "🔇 Enable Voice"))

    settings_menu.add_command(label=("🔊 Mute Voice" if VOICE_ENABLED else "🔇 Enable Voice"), command=toggle_voice)

    theme_menu = tk.Menu(settings_menu, tearoff=0)
    def set_theme(name):
        global current_theme
        current_theme = name
        # Rebuild this window to apply theme cleanly
        dash.destroy()
        open_vault()
    theme_menu.add_command(label="Light", command=lambda: set_theme("light"))
    theme_menu.add_command(label="Dark",  command=lambda: set_theme("dark"))

    settings_menu.add_cascade(label="Theme", menu=theme_menu)
    settings_menu.add_command(label="Change Master Password", command=lambda: change_master_password(dash))
    settings_menu.add_separator()
    settings_menu.add_command(label="Export Vault (.vlt)", command=lambda: export_vault_dialog(dash))
    settings_menu.add_command(label="Import Vault (.vlt)", command=lambda: import_vault_dialog(dash))
    settings_menu.add_separator()
    settings_menu.add_command(label=f"Auto-Lock: {AUTO_LOCK_MINUTES} min", command=lambda: [set_auto_lock_minutes(dash), dash.destroy(), open_vault()])

    menubar.add_cascade(label="Settings", menu=settings_menu)
    dash.config(menu=menubar)

    # ----- Header -----
    logo = load_logo(86)
    if logo:
        lbl = tk.Label(dash, image=logo, bg=C("APP_BG"))
        lbl.image = logo
        lbl.pack(pady=(14, 6))
    tk.Label(dash, text="Manage Your Passwords", font=("Segoe UI", 13, "bold"),
             bg=C("APP_BG"), fg=C("TEXT")).pack()

    # ----- Form -----
    card = tk.Frame(dash, bg=C("CARD_BG")); card.pack(pady=12, padx=12, fill="x")
    tk.Label(card, text="Website:",  bg=C("CARD_BG"), fg=C("TEXT")).grid(row=0, column=0, sticky="e", padx=6, pady=6)
    tk.Label(card, text="Username:", bg=C("CARD_BG"), fg=C("TEXT")).grid(row=1, column=0, sticky="e", padx=6, pady=6)
    tk.Label(card, text="Password:", bg=C("CARD_BG"), fg=C("TEXT")).grid(row=2, column=0, sticky="e", padx=6, pady=6)

    e_site = tk.Entry(card, width=40); e_user = tk.Entry(card, width=40); e_pwd = tk.Entry(card, width=40, show="*")
    e_site.grid(row=0, column=1, pady=6); e_user.grid(row=1, column=1, pady=6); e_pwd.grid(row=2, column=1, pady=6)

    def add_now(event=None):
        s, u, p = e_site.get().strip(), e_user.get().strip(), e_pwd.get().strip()
        if not s or not u or not p:
            messagebox.showwarning("Missing", "Please fill in all fields."); return
        add_entry(s, u, p)
        messagebox.showinfo("Saved", f"Entry added for {s}.")
        speak("Entry added.")
        e_site.delete(0, "end"); e_user.delete(0, "end"); e_pwd.delete(0, "end")

    btn_row = tk.Frame(card, bg=C("CARD_BG")); btn_row.grid(row=3, column=0, columnspan=2, pady=(4, 2))
    b_add = tk.Button(btn_row, text="Add Entry", command=add_now); style_button(b_add); b_add.pack(side="left", padx=6)
    b_gen = tk.Button(btn_row, text="Generate Password", command=lambda: e_pwd.insert(0, generate_password())); style_button(b_gen); b_gen.pack(side="left", padx=6)

    e_pwd.bind("<Return>", add_now)

    # ----- Actions -----
    act = tk.Frame(dash, bg=C("APP_BG")); act.pack(pady=8)
    def view_all():
        win = tk.Toplevel(dash); win.title("Stored Passwords"); apply_window_theme(win); win.geometry("640x420")
        txt = tk.Text(win, wrap="word", bg=C("CARD_BG"), fg=C("TEXT"))
        txt.pack(fill="both", expand=True, padx=12, pady=12)
        rows = get_entries()
        if not rows:
            txt.insert("1.0", "No saved passwords yet.")
        else:
            for s, u, p in rows:
                txt.insert("end", f"{s} — {u} — {p}\n")

    b_view = tk.Button(act, text="View All Passwords", command=view_all); style_button(b_view); b_view.pack(side="left", padx=6)
    b_ai   = tk.Button(act, text="AI Assistant 🤖", command=open_ai_chat_local); style_button(b_ai); b_ai.pack(side="left", padx=6)

    # Greeting (non-blocking)
    threading.Thread(target=lambda: speak("Welcome back. Your vault is ready."), daemon=True).start()

    # Enable auto-lock on this screen
    enable_auto_lock()

# ========================= LOGIN =========================
def show_login():
    # Ensure master exists first time
    ensure_master_exists()

    login = tk.Toplevel()
    login.title(f"{APP_NAME} — Login")
    apply_window_theme(login)
    login.geometry("380x320")

    logo = load_logo(90)
    if logo:
        lbl = tk.Label(login, image=logo, bg=C("APP_BG")); lbl.image = logo; lbl.pack(pady=(18, 10))
    tk.Label(login, text="Enter Master Password", font=("Segoe UI", 10, "bold"),
             bg=C("APP_BG"), fg=C("TEXT")).pack()

    e = tk.Entry(login, show="*"); e.pack(pady=8); e.focus_set()

    def unlock(event=None):
        if check_master(e.get()):
            try: login.destroy()
            except Exception: pass
            open_vault()
        else:
            messagebox.showerror("Error", "Incorrect master password.", parent=login)
            speak("Incorrect password.")

    b = tk.Button(login, text="Unlock Vault", command=unlock); style_button(b); b.pack(pady=8)
    e.bind("<Return>", unlock)

# ========================= SPLASH =========================
def show_splash():
    splash = tk.Toplevel()
    splash.overrideredirect(True)
    splash.geometry("360x360+{}+{}".format((splash.winfo_screenwidth()//2)-180, (splash.winfo_screenheight()//2)-180))
    apply_window_theme(splash)

    logo = load_logo(150)
    if logo:
        l = tk.Label(splash, image=logo, bg=C("APP_BG")); l.image = logo; l.pack(expand=True)
    else:
        tk.Label(splash, text="DL", font=("Segoe UI", 44, "bold"), bg=C("APP_BG"), fg=C("TEXT")).pack(expand=True)

    tk.Label(splash, text="Secure. Simple. Smart.", bg=C("APP_BG"), fg=C("TEXT")).pack(pady=(0, 18))
    splash.after(1600, lambda: (splash.destroy(), show_login()))

# ========================= BOOT =========================
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # start hidden; splash/login are Toplevels
    apply_window_theme(root)
    root.after(100, show_splash)
    root.mainloop()
