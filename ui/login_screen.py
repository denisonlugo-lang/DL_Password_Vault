import tkinter as tk
from tkinter import ttk, messagebox

class LoginScreen(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#1e1e1e")
        self.master = master
        self.pack(expand=True, fill="both")

        self.create_widgets()

    def create_widgets(self):
        title = tk.Label(
            self,
            text="SafeRoute Vault",
            bg="#1e1e1e",
            fg="#00bcd4",
            font=("Segoe UI", 20, "bold")
        )
        title.pack(pady=30)

        self.password_entry = ttk.Entry(
            self, show="*", width=30, font=("Segoe UI", 12)
        )
        self.password_entry.pack(pady=10)
        self.password_entry.focus()

        login_btn = ttk.Button(
            self,
            text="Unlock Vault",
            command=self.validate_login
        )
        login_btn.pack(pady=15)

    def validate_login(self):
        entered_password = self.password_entry.get()
        if entered_password == "master123":  # placeholder password
            from ui.dashboard import Dashboard
            self.destroy()  # remove login screen
            Dashboard(self.master)
        else:
            messagebox.showerror("Access Denied", "Incorrect Master Password.")

def validate_login(self):
    entered_password = self.password_entry.get()

    if entered_password == "master123":  # temporary password
        # Clear the login screen
        for widget in self.master.winfo_children():
            widget.destroy()

        # Import and load the dashboard
        from ui.dashboard import Dashboard
        Dashboard(self.master)
    else:
        messagebox.showerror("Access Denied", "Incorrect Master Password.")
