import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import base64
import secrets
import threading
import argon2
from argon2.low_level import hash_secret_raw, Type

# ... inputs ...
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
# pyperclip removed — using tkinter native clipboard instead

# --- Constants ---
VAULT_PATH = os.path.expanduser("~/.secure_vault.json")
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

# --- Security & Storage Logic ---

class VaultSecurity:
    def __init__(self):
        self.key = None

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a 32-byte key from the password and salt using Argon2id.
        Using argon2-cffi library.
        """
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=2,
            memory_cost=64 * 1024, # 64 MB
            parallelism=4,
            hash_len=KEY_SIZE,
            type=Type.ID
        )

    def encrypt(self, data: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        Returns (nonce, ciphertext).
        New nonce generated for every encryption.
        """
        if not self.key:
            raise ValueError("Vault is locked. Key not present.")
        
        aesgcm = AESGCM(self.key)
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, data, None) # Additional authenticated data is None
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        Raises InvalidTag if decryption fails (wrong key or tampered data).
        """
        if not self.key:
            raise ValueError("Vault is locked. Key not present.")
        
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, None)

class VaultStorage:
    def __init__(self, filepath=VAULT_PATH):
        self.filepath = filepath

    def exists(self):
        return os.path.exists(self.filepath)

    def load_raw(self):
        with open(self.filepath, 'r') as f:
            return json.load(f)

    def save_raw(self, data):
        # Atomic write to prevent corruption
        temp_path = self.filepath + ".tmp"
        with open(temp_path, 'w') as f:
            json.dump(data, f, indent=4)
        os.replace(temp_path, self.filepath)

    def create_vault(self, password: str, security: VaultSecurity):
        """
        Initialize a new vault.
        Generates a new salt, derives key, and stores a 'validation token' 
        to verify correct password later.
        """
        salt = secrets.token_bytes(SALT_SIZE)
        security.key = security.derive_key(password, salt)
        
        # Encrypt a known string to validate password later
        nonce, ciphertext = security.encrypt(b"VALID")
        
        data = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "validation_token": {
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
            },
            "entries": []
        }
        self.save_raw(data)

    def unlock_vault(self, password: str, security: VaultSecurity) -> bool:
        """
        Attempt to unlock the vault with the provided password.
        Returns True if successful, False otherwise.
        """
        data = self.load_raw()
        salt = base64.b64decode(data['salt'])
        
        # Derive potential key
        potential_key = security.derive_key(password, salt)
        temp_security = VaultSecurity()
        temp_security.key = potential_key
        
        # Try to decrypt validation token
        val_nonce = base64.b64decode(data['validation_token']['nonce'])
        val_cipher = base64.b64decode(data['validation_token']['ciphertext'])
        
        try:
            decrypted = temp_security.decrypt(val_nonce, val_cipher)
            if decrypted == b"VALID":
                security.key = potential_key # Set the actual key
                return True
        except InvalidTag:
            pass
        return False

    def add_entry(self, entry_data: dict, security: VaultSecurity):
        """
        Encrypts and saves a new entry to the vault.
        entry_data should be a dictionary (site, user, pass).
        """
        data = self.load_raw()
        
        json_bytes = json.dumps(entry_data).encode('utf-8')
        nonce, ciphertext = security.encrypt(json_bytes)
        
        new_entry = {
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
        
        data['entries'].append(new_entry)
        self.save_raw(data)

    def get_entries(self, security: VaultSecurity):
        """
        Yields decrypted entries. Skips invalid ones silently (or logs them).
        Returns list of dicts: {'id': index, 'site': ..., 'username': ..., 'password': ...}
        """
        data = self.load_raw()
        decrypted_entries = []
        
        for idx, entry in enumerate(data['entries']):
            try:
                nonce = base64.b64decode(entry['nonce'])
                ciphertext = base64.b64decode(entry['ciphertext'])
                plaintext = security.decrypt(nonce, ciphertext)
                entry_dict = json.loads(plaintext.decode('utf-8'))
                entry_dict['id'] = idx # Store index for deletion
                decrypted_entries.append(entry_dict)
            except Exception as e:
                print(f"Failed to decrypt entry {idx}: {e}")
                continue
                
        return decrypted_entries

    def delete_entry(self, index: int):
        data = self.load_raw()
        if 0 <= index < len(data['entries']):
            del data['entries'][index]
            self.save_raw(data)

# --- GUI ---

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Zero-Knowledge Password Manager")
        self.root.geometry("800x600")
        
        # Theme configuration
        self.configure_styles()
        
        self.security = VaultSecurity()
        self.storage = VaultStorage()
        
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.show_initial_screen()

    def configure_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Colors
        bg_color = "#2d2d2d"
        fg_color = "#e0e0e0"
        accent_color = "#007acc"
        button_bg = "#3c3c3c"
        
        self.root.configure(bg=bg_color)
        
        style.configure("TFrame", background=bg_color)
        style.configure("TLabel", background=bg_color, foreground=fg_color, font=("Consolas", 12))
        style.configure("TButton", background=button_bg, foreground=fg_color, font=("Consolas", 10), borderwidth=1)
        style.map("TButton", background=[('active', accent_color)])
        style.configure("Treeview", background="#333333", foreground="white", fieldbackground="#333333", font=("Consolas", 10))
        style.configure("Treeview.Heading", background="#444444", foreground="white", font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[('selected', accent_color)])

    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def show_initial_screen(self):
        self.clear_frame()
        
        if self.storage.exists():
            self.show_login_screen()
        else:
            self.show_setup_screen()

    def show_setup_screen(self):
        ttk.Label(self.main_frame, text="Create New Vault", font=("Consolas", 20, "bold")).pack(pady=20)
        ttk.Label(self.main_frame, text="Set a Master Password. Do not lose this!").pack(pady=5)
        
        pass_entry = ttk.Entry(self.main_frame, show="*", font=("Consolas", 12))
        pass_entry.pack(pady=10, ipadx=5, ipady=5)
        
        def on_create():
            password = pass_entry.get()
            if not password:
                messagebox.showerror("Error", "Password cannot be empty")
                return
                
            try:
                self.storage.create_vault(password, self.security)
                messagebox.showinfo("Success", "Vault created successfully!")
                self.show_dashboard()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create vault: {e}")

        ttk.Button(self.main_frame, text="Create Vault", command=on_create).pack(pady=20)

    def show_login_screen(self):
        ttk.Label(self.main_frame, text="Unlock Vault", font=("Consolas", 20, "bold")).pack(pady=20)
        
        pass_entry = ttk.Entry(self.main_frame, show="*", font=("Consolas", 12))
        pass_entry.pack(pady=10, ipadx=5, ipady=5)
        pass_entry.focus()
        
        def on_unlock(event=None):
            password = pass_entry.get()
            if self.storage.unlock_vault(password, self.security):
                self.show_dashboard()
            else:
                messagebox.showerror("Access Denied", "Incorrect Master Password")
                pass_entry.delete(0, tk.END)

        ttk.Button(self.main_frame, text="Unlock", command=on_unlock).pack(pady=20)
        self.root.bind('<Return>', on_unlock)

    def show_dashboard(self):
        self.clear_frame()
        self.root.unbind('<Return>') # Unbind enter key
        
        # Header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        ttk.Label(header_frame, text="SECURE VAULT", font=("Consolas", 18, "bold")).pack(side=tk.LEFT)
        ttk.Button(header_frame, text="Lock Vault", command=self.lock_vault).pack(side=tk.RIGHT)

        # Treeview (Table)
        columns = ("site", "username", "password_hidden")
        self.tree = ttk.Treeview(self.main_frame, columns=columns, show="headings", selectmode="browse")
        
        self.tree.heading("site", text="Site/Service")
        self.tree.heading("username", text="Username")
        self.tree.heading("password_hidden", text="Password")
        
        self.tree.column("site", width=200)
        self.tree.column("username", width=200)
        self.tree.column("password_hidden", width=150)
        
        self.tree.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.tree, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Buttons Frame
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Add Entry", command=self.add_entry_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_selected).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Show Password", command=self.show_password).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Copy Password", command=self.copy_password).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Copy Username", command=self.copy_username).pack(side=tk.RIGHT, padx=5)

        self.refresh_entries()

    def refresh_entries(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        entries = self.storage.get_entries(self.security)
        self.current_entries_map = {}
        for entry in entries:
            # Mask password; capture the iid returned by insert for reliable lookup
            iid = self.tree.insert("", tk.END, values=(entry['site'], entry['username'], "********"), tags=(str(entry['id']),))
            self.current_entries_map[iid] = entry

    def add_entry_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Entry")
        dialog.geometry("400x300")
        dialog.configure(bg="#2d2d2d")
        
        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Site/Service:").pack(anchor=tk.W)
        site_entry = ttk.Entry(frame, width=40)
        site_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(frame, text="Username:").pack(anchor=tk.W)
        user_entry = ttk.Entry(frame, width=40)
        user_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(frame, text="Password:").pack(anchor=tk.W)
        pass_frame = ttk.Frame(frame)
        pass_frame.pack(fill=tk.X, pady=(0, 20))
        
        pass_entry = ttk.Entry(pass_frame, width=30, show="*")
        pass_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        show_btn = ttk.Button(pass_frame, text="Show")
        show_btn.pack(side=tk.RIGHT, padx=(5, 0))

        def toggle_password():
            if pass_entry.cget("show") == "":
                pass_entry.config(show="*")
                show_btn.config(text="Show")
            else:
                master_pass = simpledialog.askstring("Master Password", "Enter Master Password to view:", show="*", parent=dialog)
                if not master_pass:
                    return
                temp_security = VaultSecurity()
                if self.storage.unlock_vault(master_pass, temp_security):
                    pass_entry.config(show="")
                    show_btn.config(text="Hide")
                else:
                    messagebox.showerror("Access Denied", "Incorrect Master Password", parent=dialog)

        show_btn.config(command=toggle_password)
        
        def on_save():
            if not site_entry.get() or not pass_entry.get():
                messagebox.showerror("Error", "Site and Password are required", parent=dialog)
                return
                
            data = {
                "site": site_entry.get(),
                "username": user_entry.get(),
                "password": pass_entry.get()
            }
            self.storage.add_entry(data, self.security)
            self.refresh_entries()
            dialog.destroy()
            
        ttk.Button(frame, text="Save", command=on_save).pack()

    def delete_selected(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        if messagebox.askyesno("Confirm", "Are you sure you want to delete this entry?"):
            item_id = selected[0]
            entry = self.current_entries_map[item_id]
            # We need to delete by index efficiently. 
            # Since get_entries returned them in order, the 'id' field matches the list index *at that time*.
            # However, file might have changed? No, local single user.
            # But deletion shifts indices. Safe way: rebuild list minus deleted, save all.
            # Wait, 'id' in entry logic from get_entries might be stale if we deleted something before?
            # Let's just rely on the stored ID which I added to get_entries.
            
            # Simple approach: Delete by index from raw file directly.
            self.storage.delete_entry(entry['id'])
            self.refresh_entries()

    def show_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Entry", "Please select an entry first.")
            return
            
        master_pass = simpledialog.askstring("Master Password", "Enter Master Password to view:", show="*")
        if not master_pass:
            return
            
        temp_security = VaultSecurity()
        if not self.storage.unlock_vault(master_pass, temp_security):
            messagebox.showerror("Access Denied", "Incorrect Master Password")
            return
            
        item_id = selected[0]
        entry = self.current_entries_map[item_id]
        
        # Display password in a selectable read-only entry dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("View Password")
        dialog.geometry("350x150")
        dialog.configure(bg="#2d2d2d")
        
        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Password for " + str(entry['site']) + ":").pack(pady=(0, 5))
        
        pass_disp = ttk.Entry(frame, font=("Consolas", 12))
        pass_disp.insert(0, str(entry['password']))
        pass_disp.config(state="readonly")
        pass_disp.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Button(frame, text="Close", command=dialog.destroy).pack()

    def copy_username(self):
        selected = self.tree.selection()
        if not selected:
            return
        item_id = selected[0]
        entry = self.current_entries_map[item_id]
        self.root.clipboard_clear()
        self.root.clipboard_append(str(entry['username']))
        self.root.update()  # Flush so the clipboard is available immediately
        messagebox.showinfo("Copied", "Username copied to clipboard")

    def copy_password(self):
        selected = self.tree.selection()
        if not selected:
            return
        item_id = selected[0]
        entry = self.current_entries_map[item_id]
        password = str(entry['password'])

        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.root.update()  # Flush so the clipboard is available immediately

        # UI Feedback
        original_title = self.root.title()
        self.root.title(f"{original_title} - Password Copied! Clipboard clears in 10s")

        def clear_clipboard():
            try:
                current = self.root.clipboard_get()
                if current == password:
                    self.root.clipboard_clear()
                    self.root.clipboard_append("")
                    self.root.update()
            except Exception:
                pass  # Clipboard may already be cleared
            self.root.after(0, lambda: self.root.title(original_title))

        # Start timer
        threading.Timer(10.0, clear_clipboard).start()

    def lock_vault(self):
        self.security.key = None # Clear key from memory
        self.show_login_screen()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
