import tkinter as tk
from tkinter import ttk

class AddEntryModal(tk.Toplevel):
    def __init__(self, parent, mode, data=None):
        super().__init__(parent)
        self.title(f"{mode} Password")
        self.geometry("350x250")
        self.configure(bg="#1e1e1e")
        self.resizable(False, False)
        self.mode = mode
        self.parent = parent
        self.data = data or ("", "", "")
        self.create_widgets()

    def create_widgets(self):
        labels = ["Site", "Username", "Password"]
        self.entries = {}

        for i, field in enumerate(labels):
            label = tk.Label(self, text=field, bg="#1e1e1e", fg="#fff")
            label.pack(pady=(10 if i == 0 else 5, 0))
            entry = ttk.Entry(self, width=30)
            entry.insert(0, self.data[i])
            entry.pack(pady=5)
            self.entries[field.lower()] = entry

        ttk.Button(self, text="Save", command=self.save_entry).pack(pady=15)

    def save_entry(self):
        values = (
            self.entries["site"].get(),
            self.entries["username"].get(),
            self.entries["password"].get()
        )

        if self.mode == "Add":
            self.parent.tree.insert("", "end", values=values)
        else:
            selected = self.parent.tree.selection()[0]
            self.parent.tree.item(selected, values=values)

        self.destroy()