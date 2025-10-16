import tkinter as tk
from tkinter import ttk, messagebox
from ui.add_entry_modal import AddEntryModal

class Dashboard(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#1e1e1e")
        self.master = master
        self.pack(expand=True, fill="both")

        self.create_widgets()

    def create_widgets(self):
        header = tk.Label(
            self,
            text="Your Password Vault",
            bg="#1e1e1e",
            fg="#00bcd4",
            font=("Segoe UI", 16, "bold")
        )
        header.pack(pady=10)

        # Table
        columns = ("site", "username", "password")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=10)
        for col in columns:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=120, anchor="center")
        self.tree.pack(pady=10)

        # Buttons
        button_frame = tk.Frame(self, bg="#1e1e1e")
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Add", command=self.add_entry).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Edit", command=self.edit_entry).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="Delete", command=self.delete_entry).grid(row=0, column=2, padx=5)

    def add_entry(self):
        AddEntryModal(self, "Add")

    def edit_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Entry", "Please select an entry to edit.")
            return
        data = self.tree.item(selected[0], "values")
        AddEntryModal(self, "Edit", data)

    def delete_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Entry", "Please select an entry to delete.")
            return
        self.tree.delete(selected[0])
