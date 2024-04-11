import tkinter as tk
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Function to calculate and display detailed key calculations
def calculate_shared_key():
    try:
        alice_secret = int(alice_secret_entry.get())
        bob_secret = int(bob_secret_entry.get())
        prime = int(prime_combobox.get())
        base = int(base_entry.get())

        # Calculation of public keys
        alice_public = pow(base, alice_secret, prime)
        bob_public = pow(base, bob_secret, prime)

        # Calculation of the shared secret key
        shared_key_alice = pow(bob_public, alice_secret, prime)
        shared_key_bob = pow(alice_public, bob_secret, prime)

        # Update GUI with detailed key information
        alice_details = f"Public Key: ({base}^{alice_secret} mod {prime}) = {alice_public}\nShared Key: ({bob_public}^{alice_secret} mod {prime}) = {shared_key_alice}"
        bob_details = f"Public Key: ({base}^{bob_secret} mod {prime}) = {bob_public}\nShared Key: ({alice_public}^{bob_secret} mod {prime}) = {shared_key_bob}"
        alice_shared_key_label.config(text=alice_details)
        bob_shared_key_label.config(text=bob_details)
        shared_key_entry.delete(0, tk.END)
        shared_key_entry.insert("end", shared_key_bob)
    except ValueError:
        alice_shared_key_label.config(text="Invalid Input")
        bob_shared_key_label.config(text="Invalid Input")

def is_prime(n):
    """Checks if a number is prime."""
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_primes(limit):
    """Generates the first 'limit' number of primes."""
    primes = []
    n = 2
    while len(primes) < limit:
        if is_prime(n):
            primes.append(n)
        n += 1
    return primes

# First 50 prime numbers - change to whatever number of primes you want in the dropdown.
# Note: With a great prime number, comes a great waiting time
primesList = generate_primes(50)

def initialize_aes(key, iv):
    """Initializes AES cipher with given key and IV."""
    return AES.new(key, AES.MODE_CBC, iv)

def get_aes_key(shared_key_str, salt_str):
    """Converts shared key from Diffie-Hellman to a key of suitable size for AES using PBKDF2 with SHA256 hash."""
    salt = salt_str.encode()
    kdf = PBKDF2(shared_key_str, salt, dkLen=32, count=1000, hmac_hash_module=SHA256)
    return kdf

def aes_encrypt():
    """Encrypts the text in aes_input_text and displays the result in aes_output_text."""
    try:
        shared_key_str = shared_key_entry.get()
        salt_str = "some_fixed_salt"
        key = get_aes_key(shared_key_str, salt_str)

        # Convert IV from hex to bytes
        iv_hex = iv_entry.get()
        iv = bytes.fromhex(iv_hex)

        cipher = initialize_aes(key, iv)
        plaintext = pad(aes_input_text.get("1.0", "end").encode(), AES.block_size)
        ciphertext = cipher.encrypt(plaintext)

        aes_output_text.delete("1.0", "end")
        aes_output_text.insert("1.0", ciphertext.hex().strip())  # .strip() removes any extra line breaks

        error_encryptlabel.config(text="")  # Clear error message if encryption is successful
    except Exception as e:
        error_encryptlabel.config(text=f"Error: {str(e)}")  # Display error message

def aes_decrypt():
    """Decrypts the text in aes_input_text and displays the result in aes_output_text."""
    try:
        shared_key_str = shared_key_entry.get()
        salt_str = "some_fixed_salt"
        key = get_aes_key(shared_key_str, salt_str)

        # Convert IV from hex to bytes
        iv_hex = iv_entry.get()
        iv = bytes.fromhex(iv_hex)

        cipher = initialize_aes(key, iv)
        ciphertext = bytes.fromhex(aes_input_text.get("1.0", "end").strip())
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        aes_output_text.delete("1.0", "end")
        aes_output_text.insert("1.0", plaintext.decode().strip())  # .strip() added here as well

        error_decryptlabel.config(text="")  # Clear error message if decryption is successful
    except Exception as e:
        error_decryptlabel.config(text=f"Error: {str(e)}")  # Display error message

def generate_iv():
    """Generates a random IV and inserts it into iv_entry."""
    iv = os.urandom(16)
    iv_entry.delete(0, tk.END)
    iv_entry.insert(0, iv.hex())

def swap_text_fields():
    """Swaps the texts between aes_input_text and aes_output_text."""
    output_text = aes_output_text.get("1.0", "end-1c")

    aes_input_text.delete("1.0", tk.END)
    aes_input_text.insert("1.0", output_text)
    aes_output_text.delete("1.0", tk.END)

    

# GUI setup
root = tk.Tk()
root.title("Diffie-Hellman Key Exchange and AES Demo")

# Main container for vertical organization
main_frame = tk.Frame(root)
main_frame.pack(side=tk.TOP, fill="both", expand=True)

# Horizontal container for Diffie-Hellman sections
dh_frame = tk.Frame(main_frame)
dh_frame.pack(side=tk.TOP, fill="x")

# Diffie-Hellman Sections within the horizontal container
alice_frame = tk.Frame(dh_frame)
alice_frame.pack(side=tk.LEFT, padx=10, pady=10)

public_frame = tk.Frame(dh_frame)
public_frame.pack(side=tk.LEFT, padx=10, pady=10)

tk.Label(public_frame, text="Diffie Hellman").pack()
tk.Label(public_frame, text="").pack()

bob_frame = tk.Frame(dh_frame)
bob_frame.pack(side=tk.LEFT, padx=10, pady=10)

# Alice's section
tk.Label(alice_frame, text="Private - Alice's Place").pack()
tk.Label(alice_frame, text="Secret Number:").pack()
alice_secret_entry = tk.Entry(alice_frame)
alice_secret_entry.pack()
alice_shared_key_label = tk.Label(alice_frame, justify=tk.LEFT)
alice_shared_key_label.pack()

# Public section
tk.Label(public_frame, text="Public").pack()
tk.Label(public_frame, text="Prime Number:").pack()
prime_combobox = ttk.Combobox(public_frame, values=primesList)
prime_combobox.pack()
tk.Label(public_frame, text="Base:").pack()
base_entry = tk.Entry(public_frame)
base_entry.pack()
calculate_button = tk.Button(public_frame, text="Calculate Shared Key", command=calculate_shared_key)
calculate_button.pack()

# Bob's section
tk.Label(bob_frame, text="Private - Bob's Place").pack()
tk.Label(bob_frame, text="Secret Number:").pack()
bob_secret_entry = tk.Entry(bob_frame)
bob_secret_entry.pack()
bob_shared_key_label = tk.Label(bob_frame, justify=tk.LEFT)
bob_shared_key_label.pack()

# Horizontal line
separator = ttk.Separator(main_frame, orient='horizontal')
separator.pack(fill='x', padx=10, pady=5)

# AES Encryption section under the horizontal line
aes_frame = tk.Frame(main_frame)
aes_frame.pack(side=tk.TOP, padx=10, pady=10)

tk.Label(aes_frame, text="AES Encryption/Decryption").pack()
tk.Label(aes_frame, text="").pack()
tk.Label(aes_frame, text="Shared Key (Diffie Hellman):").pack()
shared_key_entry = tk.Entry(aes_frame)
shared_key_entry.pack()

tk.Label(aes_frame, text="").pack()

tk.Label(aes_frame, text="IV:").pack()
iv_entry = tk.Entry(aes_frame)
iv_entry.pack()

# Button to generate IV
iv_button = tk.Button(aes_frame, text="Generate IV", command=generate_iv)
iv_button.pack()

tk.Label(aes_frame, text="").pack()

tk.Label(aes_frame, text="Salt:").pack()
salt_entry = tk.Entry(aes_frame)
salt_entry.pack()

tk.Label(aes_frame, text="").pack()

tk.Label(aes_frame, text="Input Text:").pack()
aes_input_text = tk.Text(aes_frame, height=5, width=40)
aes_input_text.pack()
# Label for encryption error messages
error_encryptlabel = tk.Label(aes_frame, text="", fg="red")
error_encryptlabel.pack()

encrypt_button = tk.Button(aes_frame, text="Encrypt", command=aes_encrypt)
encrypt_button.pack()
decrypt_button = tk.Button(aes_frame, text="Decrypt", command=aes_decrypt)
decrypt_button.pack()

tk.Label(aes_frame, text="").pack()

# Button to swap values between input and output text fields
swap_button = tk.Button(aes_frame, text="--><---", command=swap_text_fields)
swap_button.pack()

tk.Label(aes_frame, text="").pack()

tk.Label(aes_frame, text="Output Text:").pack()
aes_output_text = tk.Text(aes_frame, height=5, width=40)
aes_output_text.pack()
# Label for decryption error messages
error_decryptlabel = tk.Label(aes_frame, text="", fg="red")
error_decryptlabel.pack()


root.mainloop()