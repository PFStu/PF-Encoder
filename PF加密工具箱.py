import tkinter as tk
from tkinter import ttk, messagebox
from hashlib import md5, sha1, sha256, sha512
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from Crypto.Cipher import AES, DES
import binascii
import os

class EncryptionToolbox:
    def __init__(self, root):
        self.root = root
        self.root.title("PF 加密/编码工具箱")
        self.root.geometry("600x400")
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "favicon.ico")
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)

        self.methods = {
            "MD5": (self.md5_encrypt, None),
            "SHA-1": (self.sha1_encrypt, None),
            "SHA-256": (self.sha256_encrypt, None),
            "SHA-512": (self.sha512_encrypt, None),
            "RSA": (self.rsa_encrypt, self.rsa_decrypt),
            "AES": (self.aes_encrypt, self.aes_decrypt),
            "DES": (self.des_encrypt, self.des_decrypt),
            "ASCII": (self.ascii_encode, self.ascii_decode),
            "Unicode": (self.unicode_encode, self.unicode_decode),
            "Base32": (self.base32_encode, self.base32_decode),
            "Base64": (self.base64_encode, self.base64_decode)
        }

        self.method_var = tk.StringVar()
        self.method_var.set("MD5")

        self.method_label = ttk.Label(root, text="选择加密/解密方法:")
        self.method_label.grid(row=0, column=0, padx=5, pady=5)
        self.method_menu = ttk.OptionMenu(root, self.method_var, *self.methods.keys())
        self.method_menu.grid(row=0, column=1, padx=5, pady=5)

        self.input_label = ttk.Label(root, text="输入文本:")
        self.input_label.grid(row=1, column=0, padx=5, pady=5)
        self.input_entry = ttk.Entry(root, width=50)
        self.input_entry.grid(row=1, column=1, padx=5, pady=5)

        self.password_label = ttk.Label(root, text="密码 (AES/DES/RSA):")
        self.password_label.grid(row=2, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(root, width=50, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        self.encrypt_button = tk.Button(root, text="加密", command=self.encrypt, bg="#4CAF50", fg="white", relief=tk.FLAT, borderwidth=0, highlightthickness=0, padx=20, pady=10, font=("Arial", 12), activebackground="#45a049", activeforeground="white", cursor="hand2")
        self.encrypt_button.grid(row=3, column=0, padx=5, pady=5)
        self.decrypt_button = tk.Button(root, text="解密", command=self.decrypt, bg="#f44336", fg="white", relief=tk.FLAT, borderwidth=0, highlightthickness=0, padx=20, pady=10, font=("Arial", 12), activebackground="#e53935", activeforeground="white", cursor="hand2")
        self.decrypt_button.grid(row=3, column=1, padx=5, pady=5)

        self.output_label = ttk.Label(root, text="输出结果:")
        self.output_label.grid(row=4, column=0, padx=5, pady=5)
        self.output_text = tk.Text(root, width=50, height=10)
        self.output_text.grid(row=4, column=1, padx=5, pady=5)

    def encrypt(self):
        method = self.method_var.get()
        input_text = self.input_entry.get()
        password = self.password_entry.get()

        if not input_text:
            messagebox.showerror("错误", "请输入要加密的文本")
            return

        if method in ["AES", "DES", "RSA"] and not password:
            messagebox.showerror("错误", f"{method}加密需要密码")
            return

        self.output_text.delete(1.0, tk.END)
        result = self.methods[method][0](input_text, password)
        self.output_text.insert(tk.END, result)

    def decrypt(self):
        method = self.method_var.get()
        input_text = self.input_entry.get()
        password = self.password_entry.get()

        if not input_text:
            messagebox.showerror("错误", "请输入要解密的文本")
            return

        if method in ["AES", "DES", "RSA"] and not password:
            messagebox.showerror("错误", f"{method}解密需要密码")
            return

        self.output_text.delete(1.0, tk.END)
        result = self.methods[method][1](input_text, password)
        self.output_text.insert(tk.END, result)

    def md5_encrypt(self, text, *args):
        return md5(text.encode()).hexdigest()

    def sha1_encrypt(self, text, *args):
        return sha1(text.encode()).hexdigest()

    def sha256_encrypt(self, text, *args):
        return sha256(text.encode()).hexdigest()

    def sha512_encrypt(self, text, *args):
        return sha512(text.encode()).hexdigest()

    def rsa_encrypt(self, text, password):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        encrypted = public_key.encrypt(
            text.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()

    def rsa_decrypt(self, text, password):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        encrypted = base64.b64decode(text.encode())
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

    def aes_encrypt(self, text, password):
        key = password.encode()
        iv = key[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(text.encode()) + encryptor.finalize()
        return base64.b64encode(encrypted).decode()

    def aes_decrypt(self, text, password):
        key = password.encode()
        iv = key[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(base64.b64decode(text.encode())) + decryptor.finalize()
        return decrypted.decode()

    def des_encrypt(self, text, password):
        key = password.encode()
        iv = key[:8]
        cipher = DES.new(key, DES.MODE_CFB, iv)
        encrypted = cipher.encrypt(text.encode())
        return base64.b64encode(encrypted).decode()

    def des_decrypt(self, text, password):
        key = password.encode()
        iv = key[:8]
        cipher = DES.new(key, DES.MODE_CFB, iv)
        decrypted = cipher.decrypt(base64.b64decode(text.encode()))
        return decrypted.decode()

    def ascii_encode(self, text, *args):
        return ' '.join(format(ord(char), 'b') for char in text)

    def ascii_decode(self, text, *args):
        return ''.join(chr(int(char, 2)) for char in text.split())

    def unicode_encode(self, text, *args):
        return ' '.join(format(ord(char), 'x') for char in text)

    def unicode_decode(self, text, *args):
        return ''.join(chr(int(char, 16)) for char in text.split())

    def base32_encode(self, text, *args):
        return base64.b32encode(text.encode()).decode()

    def base32_decode(self, text, *args):
        return base64.b32decode(text.encode()).decode()

    def base64_encode(self, text, *args):
        return base64.b64encode(text.encode()).decode()

    def base64_decode(self, text, *args):
        return base64.b64decode(text.encode()).decode()

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionToolbox(root)
    root.mainloop()
