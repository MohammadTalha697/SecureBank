"""
Module 3: DES (Data Encryption Standard)
Implements DES encryption and decryption with 16 Feistel rounds
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii


class DESCipher:
    """DES Encryption Implementation"""
    
    # Initial Permutation Table (IP)
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]
    
    # Final Permutation Table (FP)
    FP = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]
    
    @staticmethod
    def encrypt(plaintext, key):
        """
        Encrypt plaintext using DES
        Returns: (ciphertext_hex, iv_hex)
        """
        # Ensure key is 8 bytes (64 bits, 56 effective bits)
        if isinstance(key, str):
            # If hex string
            if len(key) == 16:  # 16 hex chars = 8 bytes
                key_bytes = bytes.fromhex(key)
            else:
                # Pad or truncate to 8 bytes
                key_bytes = key.encode('utf-8')
                if len(key_bytes) < 8:
                    key_bytes = key_bytes.ljust(8, b'\0')
                else:
                    key_bytes = key_bytes[:8]
        else:
            key_bytes = key
        
        # Convert plaintext to bytes
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
        
        # Create cipher object with random IV
        cipher = DES.new(key_bytes, DES.MODE_CBC)
        
        # Pad plaintext to multiple of 8 bytes
        padded_plaintext = pad(plaintext_bytes, DES.block_size)
        
        # Encrypt
        ciphertext = cipher.encrypt(padded_plaintext)
        
        # Return hex strings
        return binascii.hexlify(ciphertext).decode('utf-8'), binascii.hexlify(cipher.iv).decode('utf-8')
    
    @staticmethod
    def decrypt(ciphertext_hex, key, iv_hex):
        """
        Decrypt ciphertext using DES
        Returns: plaintext
        """
        # Ensure key is 8 bytes
        if isinstance(key, str):
            if len(key) == 16:  # 16 hex chars = 8 bytes
                key_bytes = bytes.fromhex(key)
            else:
                key_bytes = key.encode('utf-8')
                if len(key_bytes) < 8:
                    key_bytes = key_bytes.ljust(8, b'\0')
                else:
                    key_bytes = key_bytes[:8]
        else:
            key_bytes = key
        
        # Convert hex to bytes
        ciphertext = bytes.fromhex(ciphertext_hex)
        iv = bytes.fromhex(iv_hex)
        
        # Create cipher object with same IV
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        
        # Decrypt
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Unpad
        plaintext = unpad(padded_plaintext, DES.block_size)
        
        return plaintext.decode('utf-8')
    
    @staticmethod
    def generate_key():
        """Generate a random 64-bit (8 byte) key"""
        return binascii.hexlify(get_random_bytes(8)).decode('utf-8')
    
    @staticmethod
    def show_permutation_info(plaintext, key):
        """
        Show DES encryption process with permutation details
        """
        info = "DES Encryption Process:\n\n"
        info += "Key Size: 64 bits (8 bytes, 56 effective bits)\n"
        info += "Block Size: 64 bits (8 bytes)\n"
        info += "Number of Rounds: 16 Feistel rounds\n\n"
        
        # Key info
        if isinstance(key, str):
            if len(key) == 16:
                key_bytes = bytes.fromhex(key)
            else:
                key_bytes = key.encode('utf-8')
                if len(key_bytes) < 8:
                    key_bytes = key_bytes.ljust(8, b'\0')
                else:
                    key_bytes = key_bytes[:8]
        else:
            key_bytes = key
        
        info += f"Key (hex): {binascii.hexlify(key_bytes).decode('utf-8')}\n"
        info += f"Key (binary): {bin(int.from_bytes(key_bytes, 'big'))[2:].zfill(64)}\n\n"
        
        # Plaintext info
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
        
        # Pad plaintext
        padded = pad(plaintext_bytes, DES.block_size)
        info += f"Plaintext: {plaintext}\n"
        info += f"Plaintext (hex): {binascii.hexlify(plaintext_bytes).decode('utf-8')}\n"
        info += f"Padded Plaintext (hex): {binascii.hexlify(padded).decode('utf-8')}\n\n"
        
        # Show first block processing
        if len(padded) >= 8:
            block = padded[:8]
            block_int = int.from_bytes(block, 'big')
            block_bin = bin(block_int)[2:].zfill(64)
            
            info += "First Block (64 bits):\n"
            info += f"Hex: {binascii.hexlify(block).decode('utf-8')}\n"
            info += f"Binary: {block_bin}\n\n"
            
            # Show Initial Permutation
            info += "Initial Permutation (IP):\n"
            info += "The 64-bit block is permuted according to IP table.\n"
            ip_result = DESCipher.apply_permutation(block_bin, DESCipher.IP)
            info += f"After IP: {ip_result[:32]} {ip_result[32:]}\n"
            info += f"Left (L0):  {ip_result[:32]}\n"
            info += f"Right (R0): {ip_result[32:]}\n\n"
            
            info += "16 Feistel Rounds:\n"
            info += "Each round performs:\n"
            info += "  1. Expansion: R(i-1) expanded from 32 to 48 bits\n"
            info += "  2. Key mixing: XOR with 48-bit round key\n"
            info += "  3. S-boxes: 48 bits → 32 bits substitution\n"
            info += "  4. P-box: Permutation of 32 bits\n"
            info += "  5. L(i) = R(i-1), R(i) = L(i-1) ⊕ f(R(i-1), K(i))\n\n"
            
            info += "Final Permutation (FP):\n"
            info += "After 16 rounds, the Final Permutation (FP) is applied.\n"
            info += "FP is the inverse of IP.\n"
        
        return info
    
    @staticmethod
    def apply_permutation(bits, table):
        """Apply a permutation table to a bit string"""
        return ''.join(bits[i-1] for i in table)


class DESModuleGUI:
    """GUI for DES Module"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("DES Encryption Studio")
        self.root.geometry("960x820")
        self.root.configure(bg='#f2fbf7')
        
        # Configure modern style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#f2fbf7')
        style.configure('TLabelframe', background='#f2fbf7', borderwidth=2)
        style.configure('TLabelframe.Label', background='#f2fbf7', 
                   font=('Segoe UI', 11, 'bold'), foreground='#064e3b')
        style.configure('TLabel', background='#f2fbf7', font=('Segoe UI', 10), foreground='#063e30')
        style.configure('TButton', font=('Segoe UI', 9, 'normal'), padding=8)
        style.configure('Accent.TButton', background='#0f766e', foreground='#ffffff')
        style.map('Accent.TButton', background=[('active', '#0e6b62'), ('!active', '#0f766e')])
        style.configure('TEntry', fieldbackground='#ffffff', background='#ffffff', foreground='#062f26')
        
        # Header
        header_frame = tk.Frame(root, bg='#0f766e', height=100)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        title = tk.Label(header_frame, text="🔐 DES — 16 Feistel Rounds", 
                font=('Segoe UI', 22, 'bold'), fg='white', bg='#0f766e')
        title.pack(pady=(18,6))
        subtitle = tk.Label(header_frame, text="Encrypt and decrypt data using DES-CBC (educational)",
                    font=('Segoe UI', 10), fg='#e6fff9', bg='#0f766e')
        subtitle.pack(pady=(0,16))
        
        # Main frame
        main_frame = ttk.Frame(root, padding=10)
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Key frame
        key_frame = ttk.LabelFrame(main_frame, text="Key Settings", padding=10)
        key_frame.pack(fill='x', pady=5)
        
        tk.Label(key_frame, text="Secret Key (8 bytes / 16 hex chars):", bg='#f2fbf7', fg='#063e30').grid(row=0, column=0, sticky='w', pady=5)
        self.key_entry = ttk.Entry(key_frame, width=50)
        self.key_entry.grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Button(key_frame, text="Create Key", command=self.generate_key, style='Accent.TButton').grid(row=0, column=2, padx=5)
        
        # Input frame
        input_frame = ttk.LabelFrame(main_frame, text="Input", padding=10)
        input_frame.pack(fill='x', pady=5)
        
        tk.Label(input_frame, text="Input Data:", bg='#f2fbf7', fg='#063e30').grid(row=0, column=0, sticky='nw', pady=5)
        self.plaintext_entry = scrolledtext.ScrolledText(input_frame, height=4, width=70, bg='#ffffff', fg='#052e25', wrap='word', relief='flat')
        self.plaintext_entry.grid(row=0, column=1, pady=5, padx=5)
        
        tk.Label(input_frame, text="IV (hex, optional):", bg='#f2fbf7', fg='#063e30').grid(row=1, column=0, sticky='w', pady=5)
        self.iv_entry = ttk.Entry(input_frame, width=50)
        self.iv_entry.grid(row=1, column=1, sticky='w', pady=5, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=12)
        
        ttk.Button(button_frame, text="Encrypt Now", command=self.encrypt_text, width=15, style='Accent.TButton').pack(side='left', padx=6)
        ttk.Button(button_frame, text="Decrypt Now", command=self.decrypt_text, width=15, style='Accent.TButton').pack(side='left', padx=6)
        ttk.Button(button_frame, text="View Details", command=self.show_permutation, width=18).pack(side='left', padx=6)
        ttk.Button(button_frame, text="Reset Fields", command=self.clear_all, width=12).pack(side='left', padx=6)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Output & Logs", padding=10)
        output_frame.pack(fill='both', expand=True, pady=5)
        
        tk.Label(output_frame, text="Results:", bg='#f2fbf7', fg='#063e30').pack(anchor='w')
        self.output_text = scrolledtext.ScrolledText(output_frame, height=15, width=80, bg='#f7fffb', fg='#032a22', wrap='word', relief='groove')
        self.output_text.pack(fill='both', expand=True, pady=5)
        
        # Info label
        info_label = tk.Label(main_frame, 
                     text="Tip: Keep your secret key private. IV needed to decrypt when used.",
                     font=('Arial', 9), fg='#055a4e', bg='#f2fbf7')
        info_label.pack(pady=5)
        
        # Store IV for decryption
        self.last_iv = None
    
    def generate_key(self):
        """Generate a random DES key"""
        key = DESCipher.generate_key()
        self.key_entry.delete(0, 'end')
        self.key_entry.insert(0, key)
    
    def encrypt_text(self):
        """Encrypt plaintext"""
        try:
            plaintext = self.plaintext_entry.get('1.0', 'end-1c')
            key = self.key_entry.get()
            
            if not plaintext:
                messagebox.showwarning("Warning", "Please enter plaintext")
                return
            
            if not key:
                messagebox.showwarning("Warning", "Please enter or generate a key")
                return
            
            # Encrypt
            ciphertext_hex, iv_hex = DESCipher.encrypt(plaintext, key)
            self.last_iv = iv_hex
            
            # Display results
            self.output_text.delete('1.0', 'end')
            self.output_text.insert('1.0', "Encryption Successful!\n\n")
            self.output_text.insert('end', f"Key (hex):\n{key}\n\n")
            self.output_text.insert('end', f"IV (hex):\n{iv_hex}\n\n")
            self.output_text.insert('end', f"Plaintext:\n{plaintext}\n\n")
            self.output_text.insert('end', f"Ciphertext (hex):\n{ciphertext_hex}\n\n")
            self.output_text.insert('end', "DES Process:\n")
            self.output_text.insert('end', "- Applied Initial Permutation (IP)\n")
            self.output_text.insert('end', "- Performed 16 Feistel rounds\n")
            self.output_text.insert('end', "- Applied Final Permutation (FP)\n")
            
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
                messagebox.showwarning("Warning", "Please enter ciphertext (in hex format)")
                return
            
            if not key:
                messagebox.showwarning("Warning", "Please enter the key")
                return
            
            if not iv_hex:
                messagebox.showwarning("Warning", "Please enter the IV")
                return
            
            # Decrypt
            plaintext = DESCipher.decrypt(ciphertext_hex, key, iv_hex)
            
            # Display results
            self.output_text.delete('1.0', 'end')
            self.output_text.insert('1.0', "Decryption Successful!\n\n")
            self.output_text.insert('end', f"Key (hex):\n{key}\n\n")
            self.output_text.insert('end', f"IV (hex):\n{iv_hex}\n\n")
            self.output_text.insert('end', f"Ciphertext (hex):\n{ciphertext_hex}\n\n")
            self.output_text.insert('end', f"Decrypted Plaintext:\n{plaintext}\n\n")
            self.output_text.insert('end', "DES Decryption Process:\n")
            self.output_text.insert('end', "- Applied Initial Permutation (IP)\n")
            self.output_text.insert('end', "- Performed 16 Feistel rounds (reverse order)\n")
            self.output_text.insert('end', "- Applied Final Permutation (FP)\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def show_permutation(self):
        """Show DES permutation information"""
        try:
            plaintext = self.plaintext_entry.get('1.0', 'end-1c')
            key = self.key_entry.get()
            
            if not plaintext:
                messagebox.showwarning("Warning", "Please enter plaintext")
                return
            
            if not key:
                messagebox.showwarning("Warning", "Please enter or generate a key")
                return
            
            # Get permutation info
            perm_info = DESCipher.show_permutation_info(plaintext, key)
            
            # Display
            self.output_text.delete('1.0', 'end')
            self.output_text.insert('1.0', perm_info)
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def clear_all(self):
        """Clear all fields"""
        self.plaintext_entry.delete('1.0', 'end')
        self.output_text.delete('1.0', 'end')
        self.iv_entry.delete(0, 'end')


def main():
    """Main function to run the DES module"""
    root = tk.Tk()
    app = DESModuleGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
