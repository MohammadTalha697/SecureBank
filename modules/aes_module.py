"""
Module 2: AES (Advanced Encryption Standard)
Implements AES-128 encryption and decryption
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

class AESCipher:
    """AES-128 Encryption Implementation"""
    
    @staticmethod
    def encrypt(plaintext, key):
        """
        Encrypt plaintext using AES-128
        Returns: (ciphertext_hex, iv_hex)
        """
        # Ensure key is 16 bytes (128 bits)
        if isinstance(key, str):
            # If hex string
            if len(key) == 32:  # 32 hex chars = 16 bytes
                key_bytes = bytes.fromhex(key)
            else:
                # Pad or truncate to 16 bytes
                key_bytes = key.encode('utf-8')
                if len(key_bytes) < 16:
                    key_bytes = key_bytes.ljust(16, b'\0')
                else:
                    key_bytes = key_bytes[:16]
        else:
            key_bytes = key
        
        # Convert plaintext to bytes
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
        
        # Create cipher object with random IV
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        
        # Pad plaintext to multiple of 16 bytes
        padded_plaintext = pad(plaintext_bytes, AES.block_size)
        
        # Encrypt
        ciphertext = cipher.encrypt(padded_plaintext)
        
        # Return hex strings
        return binascii.hexlify(ciphertext).decode('utf-8'), binascii.hexlify(cipher.iv).decode('utf-8')
    
    @staticmethod
    def decrypt(ciphertext_hex, key, iv_hex):
        """
        Decrypt ciphertext using AES-128
        Returns: plaintext
        """
        # Ensure key is 16 bytes
        if isinstance(key, str):
            if len(key) == 32:  # 32 hex chars = 16 bytes
                key_bytes = bytes.fromhex(key)
            else:
                key_bytes = key.encode('utf-8')
                if len(key_bytes) < 16:
                    key_bytes = key_bytes.ljust(16, b'\0')
                else:
                    key_bytes = key_bytes[:16]
        else:
            key_bytes = key
        
        # Convert hex to bytes
        ciphertext = bytes.fromhex(ciphertext_hex)
        iv = bytes.fromhex(iv_hex)
        
        # Create cipher object with same IV
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        
        # Decrypt
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Unpad
        plaintext = unpad(padded_plaintext, AES.block_size)
        
        return plaintext.decode('utf-8')
    
    @staticmethod
    def generate_key():
        """Generate a random 128-bit (16 byte) key"""
        return binascii.hexlify(get_random_bytes(16)).decode('utf-8')
    
    @staticmethod
    def show_round_info(plaintext, key):
        """
        Show one round of AES encryption (simplified)
        Shows SubBytes, ShiftRows operations conceptually
        """
        info = "AES-128 Encryption Process:\n\n"
        info += "Key Size: 128 bits (16 bytes)\n"
        info += "Block Size: 128 bits (16 bytes)\n"
        info += "Number of Rounds: 10\n\n"
        
        # Key info
        if isinstance(key, str):
            if len(key) == 32:
                key_bytes = bytes.fromhex(key)
            else:
                key_bytes = key.encode('utf-8')
                if len(key_bytes) < 16:
                    key_bytes = key_bytes.ljust(16, b'\0')
                else:
                    key_bytes = key_bytes[:16]
        else:
            key_bytes = key
        
        info += f"Key (hex): {binascii.hexlify(key_bytes).decode('utf-8')}\n\n"
        
        # Plaintext info
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
        
        # Pad plaintext
        padded = pad(plaintext_bytes, AES.block_size)
        info += f"Plaintext: {plaintext}\n"
        info += f"Plaintext (hex): {binascii.hexlify(plaintext_bytes).decode('utf-8')}\n"
        info += f"Padded Plaintext (hex): {binascii.hexlify(padded).decode('utf-8')}\n\n"
        
        info += "AES Round Operations:\n"
        info += "1. SubBytes - Substitution of bytes using S-box\n"
        info += "2. ShiftRows - Circular shift of rows\n"
        info += "3. MixColumns - Mixing of columns (not in final round)\n"
        info += "4. AddRoundKey - XOR with round key\n\n"
        
        # Show first block as 4x4 matrix
        if len(padded) >= 16:
            block = padded[:16]
            info += "First block arranged in 4x4 state matrix:\n"
            for i in range(4):
                row = []
                for j in range(4):
                    idx = j * 4 + i  # Column-major order
                    row.append(f"{block[idx]:02x}")
                info += "  ".join(row) + "\n"
        
        return info


class AESModuleGUI:
    """GUI for AES Module"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Encryption Standard - AES Toolkit")
        self.root.geometry("1100x750")
        self.root.configure(bg='#1a1a2e')
        
        # Configure dark modern style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#16213e')
        style.configure('TLabelframe', background='#16213e', borderwidth=3, relief='ridge')
        style.configure('TLabelframe.Label', background='#16213e', 
                   font=('Consolas', 12, 'bold'), foreground='#00d9ff')
        style.configure('TLabel', background='#16213e', font=('Arial', 10), foreground='#e8e8e8')
        style.configure('TButton', font=('Arial', 10, 'bold'), padding=10, borderwidth=2)
        
        # Primary action button style
        style.configure('Primary.TButton', background='#e94560', foreground='#ffffff', 
                       font=('Arial', 10, 'bold'), padding=12, borderwidth=0)
        style.map('Primary.TButton', 
                 background=[('active', '#c7344d'), ('!active', '#e94560')],
                 foreground=[('disabled', '#888888'), ('!disabled', '#ffffff')])
        
        # Secondary button style
        style.configure('Secondary.TButton', background='#00d9ff', foreground='#0f1419', 
                       font=('Arial', 10, 'bold'), padding=10, borderwidth=0)
        style.map('Secondary.TButton', 
                 background=[('active', '#00b8d4'), ('!active', '#00d9ff')],
                 foreground=[('disabled', '#666666'), ('!disabled', '#0f1419')])
        
        # Entry field colors
        style.configure('TEntry', fieldbackground='#0f3460', background='#0f3460', 
                       foreground='#ffffff', insertcolor='#00d9ff', borderwidth=2)
        
        # Top banner
        banner_frame = tk.Frame(root, bg='#e94560', height=90)
        banner_frame.pack(fill='x')
        banner_frame.pack_propagate(False)
        
        banner_title = tk.Label(banner_frame, text="⚡ AES ENCRYPTION SYSTEM", 
                font=('Consolas', 26, 'bold'), fg='#ffffff', bg='#e94560')
        banner_title.pack(pady=(15, 2))
        
        banner_sub = tk.Label(banner_frame, text="128-bit CBC Mode | Military-Grade Security",
                    font=('Arial', 11, 'italic'), fg='#ffe0e6', bg='#e94560')
        banner_sub.pack(pady=(0, 15))
        
        # Container for left and right panels
        container = tk.Frame(root, bg='#1a1a2e')
        container.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Left panel
        left_panel = tk.Frame(container, bg='#1a1a2e', width=550)
        left_panel.pack(side='left', fill='both', expand=True, padx=(0, 8))
        
        # Encryption Key Section
        key_section = ttk.LabelFrame(left_panel, text="⚿ ENCRYPTION KEY", padding=15)
        key_section.pack(fill='x', pady=(0, 12))
        
        key_label = tk.Label(key_section, text="Secret Key (32 hex chars or passphrase):", 
                            bg='#16213e', fg='#d4d4d4', font=('Arial', 9, 'bold'))
        key_label.pack(anchor='w', pady=(0, 5))
        
        key_input_frame = tk.Frame(key_section, bg='#16213e')
        key_input_frame.pack(fill='x', pady=(0, 8))
        
        self.key_entry = ttk.Entry(key_input_frame, width=40, font=('Courier', 10))
        self.key_entry.pack(side='left', fill='x', expand=True, padx=(0, 8))
        
        ttk.Button(key_input_frame, text="Generate", command=self.generate_key, 
                  style='Secondary.TButton', width=12).pack(side='left')
        
        # IV Section
        iv_label = tk.Label(key_section, text="Initialization Vector (IV):", 
                           bg='#16213e', fg='#d4d4d4', font=('Arial', 9, 'bold'))
        iv_label.pack(anchor='w', pady=(8, 5))
        
        self.iv_entry = ttk.Entry(key_section, width=50, font=('Courier', 10))
        self.iv_entry.pack(fill='x')
        
        iv_hint = tk.Label(key_section, text="Auto-generated during encryption | Required for decryption",
                          font=('Arial', 8, 'italic'), fg='#888888', bg='#16213e')
        iv_hint.pack(anchor='w', pady=(3, 0))
        
        # Message Input Section
        input_section = ttk.LabelFrame(left_panel, text="◈ INPUT DATA", padding=15)
        input_section.pack(fill='both', expand=True, pady=(0, 12))
        
        input_label = tk.Label(input_section, text="Enter plaintext or ciphertext below:", 
                              bg='#16213e', fg='#d4d4d4', font=('Arial', 9, 'bold'))
        input_label.pack(anchor='w', pady=(0, 6))
        
        self.plaintext_entry = scrolledtext.ScrolledText(input_section, height=8, width=50, 
                                                         bg='#0f3460', fg='#ffffff', 
                                                         insertbackground='#00d9ff',
                                                         font=('Consolas', 10), wrap='word', 
                                                         relief='flat', borderwidth=3)
        self.plaintext_entry.pack(fill='both', expand=True)
        
        # Control Buttons
        control_frame = tk.Frame(left_panel, bg='#1a1a2e')
        control_frame.pack(fill='x', pady=(0, 0))
        
        btn_row1 = tk.Frame(control_frame, bg='#1a1a2e')
        btn_row1.pack(fill='x', pady=(0, 8))
        
        ttk.Button(btn_row1, text="🔒 ENCRYPT", command=self.encrypt_text, 
                  style='Primary.TButton', width=18).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row1, text="🔓 DECRYPT", command=self.decrypt_text, 
                  style='Primary.TButton', width=18).pack(side='left')
        
        btn_row2 = tk.Frame(control_frame, bg='#1a1a2e')
        btn_row2.pack(fill='x')
        
        ttk.Button(btn_row2, text="📊 Inspect Details", command=self.show_round, 
                  style='Secondary.TButton', width=18).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row2, text="Clear All", command=self.clear_all, 
                  width=18).pack(side='left')
        
        # Right panel - Results
        right_panel = tk.Frame(container, bg='#1a1a2e', width=500)
        right_panel.pack(side='right', fill='both', expand=True, padx=(8, 0))
        
        results_section = ttk.LabelFrame(right_panel, text="◉ RESULTS & OUTPUT", padding=15)
        results_section.pack(fill='both', expand=True)
        
        results_label = tk.Label(results_section, text="Encryption/Decryption Results:", 
                                bg='#16213e', fg='#d4d4d4', font=('Arial', 9, 'bold'))
        results_label.pack(anchor='w', pady=(0, 6))
        
        self.output_text = scrolledtext.ScrolledText(results_section, height=28, width=50,
                                                     bg='#0a1828', fg='#00ff88',
                                                     insertbackground='#00d9ff',
                                                     font=('Courier New', 9), wrap='word',
                                                     relief='groove', borderwidth=3)
        self.output_text.pack(fill='both', expand=True)
        
        # Footer status bar
        footer = tk.Frame(root, bg='#0f3460', height=40)
        footer.pack(fill='x', side='bottom')
        footer.pack_propagate(False)
        
        status_text = tk.Label(footer, 
                     text="⚠ Security Notice: Store keys securely | Never share encryption keys publicly",
                     font=('Arial', 9, 'bold'), fg='#ffd93d', bg='#0f3460')
        status_text.pack(pady=10)
        
        # Store IV for decryption
        self.last_iv = None
    
    def generate_key(self):
        """Generate a random AES key"""
        key = AESCipher.generate_key()
        self.key_entry.delete(0, 'end')
        self.key_entry.insert(0, key)
    
    def encrypt_text(self):
        """Encrypt plaintext"""
        try:
            plaintext = self.plaintext_entry.get('1.0', 'end-1c')
            key = self.key_entry.get()
            
            if not plaintext:
                messagebox.showwarning("Warning", "Please enter message/data")
                return
            
            if not key:
                messagebox.showwarning("Warning", "Please enter or create a key")
                return
            
            # Encrypt
            ciphertext_hex, iv_hex = AESCipher.encrypt(plaintext, key)
            self.last_iv = iv_hex
            
            # Display results
            self.output_text.delete('1.0', 'end')
            self.output_text.insert('1.0', "✓ ENCRYPTION SUCCESSFUL\n")
            self.output_text.insert('end', "="*50 + "\n\n")
            self.output_text.insert('end', f"Secret Key:\n{key}\n\n")
            self.output_text.insert('end', f"Initialization Vector (IV):\n{iv_hex}\n\n")
            self.output_text.insert('end', f"Original Message:\n{plaintext}\n\n")
            self.output_text.insert('end', f"Encrypted Ciphertext:\n{ciphertext_hex}\n\n")
            self.output_text.insert('end', "="*50 + "\n")
            self.output_text.insert('end', "✓ Keep the IV to decrypt this message later")
            
            # Auto-fill IV for decryption
            self.iv_entry.delete(0, 'end')
            self.iv_entry.insert(0, iv_hex)
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_text(self):
        """Decrypt ciphertext"""
        try:
            ciphertext_hex = self.plaintext_entry.get('1.0', 'end-1c').strip()
            key = self.key_entry.get()
            iv_hex = self.iv_entry.get()
            
            if not ciphertext_hex:
                messagebox.showwarning("Warning", "Please enter ciphertext (hex)")
                return
            
            if not key:
                messagebox.showwarning("Warning", "Please enter the key")
                return
            
            if not iv_hex:
                messagebox.showwarning("Warning", "Please enter the IV")
                return
            
            # Decrypt
            plaintext = AESCipher.decrypt(ciphertext_hex, key, iv_hex)
            
            # Display results
            self.output_text.delete('1.0', 'end')
            self.output_text.insert('1.0', "✓ DECRYPTION SUCCESSFUL\n")
            self.output_text.insert('end', "="*50 + "\n\n")
            self.output_text.insert('end', f"Secret Key Used:\n{key}\n\n")
            self.output_text.insert('end', f"IV Used:\n{iv_hex}\n\n")
            self.output_text.insert('end', f"Encrypted Ciphertext:\n{ciphertext_hex}\n\n")
            self.output_text.insert('end', f"Decrypted Message:\n{plaintext}\n\n")
            self.output_text.insert('end', "="*50 + "\n")
            self.output_text.insert('end', "✓ Original message recovered successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def show_round(self):
        """Show AES round information"""
        try:
            plaintext = self.plaintext_entry.get('1.0', 'end-1c')
            key = self.key_entry.get()
            
            if not plaintext:
                messagebox.showwarning("Warning", "Please enter message/data")
                return
            
            if not key:
                messagebox.showwarning("Warning", "Please enter or create a key")
                return
            
            # Get round info
            round_info = AESCipher.show_round_info(plaintext, key)
            
            # Display
            self.output_text.delete('1.0', 'end')
            self.output_text.insert('1.0', round_info)
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def clear_all(self):
        """Clear all fields"""
        self.plaintext_entry.delete('1.0', 'end')
        self.output_text.delete('1.0', 'end')
        self.iv_entry.delete(0, 'end')


def main():
    """Main function to run the AES module"""
    root = tk.Tk()
    app = AESModuleGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()