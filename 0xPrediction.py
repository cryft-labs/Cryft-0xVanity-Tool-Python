import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
from eth_account import Account
from eth_hash.auto import keccak
import rlp
import json
from tkinter import filedialog
import pyperclip
from web3 import Web3

private_key = None

def is_valid_prefix_suffix(prefix, suffix):
    valid_chars = set('0123456789abcdef')
    if len(prefix) > 10 or len(suffix) > 10:
        return False

    for char in prefix + suffix:
        if char.lower() not in valid_chars:
            return False

    return True

def calculate_total_attempts(start_nonce, max_nonce, max_keys):
    total_attempts = (max_nonce - start_nonce) * max_keys
    return total_attempts

def create_contract_address(account, nonce):
    return '0x' + keccak(rlp.encode([bytes.fromhex(account.address[2:]), nonce]))[-20:].hex()

def search_address(account, wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, start_nonce, max_nonce, max_attempts):
    attempts = 0
    for nonce in range(start_nonce, max_nonce):
        if attempts >= max_attempts:
            break

        address = create_contract_address(account, nonce)
        wallet_address = account.address

        # Convert the addresses to lowercase
        wallet_address_lower = wallet_address.lower()
        address_lower = address.lower()

        if wallet_prefix and not wallet_address_lower.startswith('0x' + wallet_prefix.lower()):
            continue
        if wallet_suffix and not wallet_address_lower.endswith(wallet_suffix.lower()):
            continue
        if contract_prefix and not address_lower.startswith('0x' + contract_prefix.lower()):
            continue
        if contract_suffix and not address_lower.endswith(contract_suffix.lower()):
            continue

        attempts += 1
        return nonce, address, wallet_address, True

    return None, None, None, False

def input_private_key():
    global private_key

    private_key = simpledialog.askstring("Private Key", "Enter a private key (leave empty for random):")
    if private_key:
        try:
            account = Account.from_key(private_key)
        except ValueError:
            messagebox.showerror("Error", "Invalid private key.")
            private_key = None

def start_search():
    global private_key
    wallet_prefix = entry_wallet_prefix.get()
    wallet_suffix = entry_wallet_suffix.get()
    contract_prefix = entry_contract_prefix.get()
    contract_suffix = entry_contract_suffix.get()

    if not is_valid_prefix_suffix(wallet_prefix, wallet_suffix) or not is_valid_prefix_suffix(contract_prefix, contract_suffix):
        messagebox.showerror("Error", "Prefix or suffix must be 7 characters or less and consist of valid hexadecimal characters.")
        return

    start_nonce = int(entry_start_nonce.get())
    max_nonce = int(entry_max_nonce.get())
    max_attempts = int(entry_max_attempts.get())
    max_keys = int(entry_max_keys.get())

    total_attempts = calculate_total_attempts(start_nonce, max_nonce, max_keys)
    messagebox.showinfo("Information", f"Total attempts: {total_attempts}")

    if not max_nonce or not max_attempts or not max_keys or (not wallet_prefix and not wallet_suffix and not contract_prefix and not contract_suffix):
        messagebox.showerror("Error", "Please fill in all the fields.")
        return
 
    found = False  # Initialize the found variable
    keys_checked = 0  # Initialize the keys_checked variable
    private_key = None
    while not found and keys_checked < max_keys:
        if private_key:
            account = Account.from_key(private_key)
        else:
            private_key = Account.create().key.hex()
            account = Account.from_key(private_key)

        nonce, address, wallet_address, found = search_address(account, wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, start_nonce, max_nonce, max_attempts)

        if found:
            pyperclip.copy(private_key)
            messagebox.showinfo("Result", f"Contract Address {address} with nonce {nonce} and Wallet Address {wallet_address} found for private key {private_key}.\n\nPrivate key copied to clipboard.")

            # Save encrypted JSON file
            password = simpledialog.askstring("Encryption Password", "Enter a password to encrypt the JSON file:", show='*')
            encrypted_data = Account.encrypt(private_key, password)
            file_path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"{wallet_address}_Contract-{address}_nonce-{nonce}", title="Save encrypted JSON file")
            if file_path:
                with open(file_path, "w") as file:
                    json.dump(encrypted_data, file)

            break
        else:
            keys_checked += 1
            if keys_checked < max_keys:
                private_key = None
            elif keys_checked == max_keys:  # Add this condition
                private_key = Account.create().key.hex()  # Generate a new private key

    if not found:  # Move this line outside the while loop
        messagebox.showinfo("Result", "No address found with the given wallet and contract prefixes and suffixes in the specified range.")

    nonce, address, wallet_address, found = search_address(account, wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, start_nonce, max_nonce, max_attempts)


root = tk.Tk()
root.title("CRYFT® Vanity Tool")
style = ttk.Style(root)
style.configure('TLabel', font=('Montserrat', 10))

instructions = (
    "1. Enter the Contract and or Wallet Address Prefix or Suffix (if desired).\n"
    "2. Enter the Start Nonce and the Max Nonce for the search.\n"
    "3. Enter the maximum number of attempts per private key.\n"
    "4. Enter the maximum number of private keys to check.\n"
    "5. Click the Search button to start.\n"
    "Valid Characters (0123456789abcdef)"
)

instruction_label = ttk.Label(root, text=instructions)
instruction_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

ttk.Label(root, text="Wallet Address Prefix").grid(row=1, padx=10, pady=10, sticky='w')
ttk.Label(root, text="Wallet Address Suffix").grid(row=2, padx=10, pady=10, sticky='w')
ttk.Label(root, text="Contract Address Prefix").grid(row=3, padx=10, pady=10, sticky='w')
ttk.Label(root, text="Contract Address Suffix").grid(row=4, padx=10, pady=10, sticky='w')
ttk.Label(root, text="Start Nonce").grid(row=5, padx=10, pady=10, sticky='w')
ttk.Label(root, text="Max Nonce").grid(row=6, padx=10, pady=10, sticky='w')
ttk.Label(root, text="Max Attempts per Key").grid(row=7, padx=10, pady=10, sticky='w')
ttk.Label(root, text="Max Keys to Check").grid(row=8, padx=10, pady=10, sticky='w')

entry_wallet_prefix = ttk.Entry(root)
entry_wallet_suffix = ttk.Entry(root)
entry_contract_prefix = ttk.Entry(root)
entry_contract_suffix = ttk.Entry(root)
entry_start_nonce = ttk.Entry(root)
entry_max_nonce = ttk.Entry(root)
entry_max_attempts = ttk.Entry(root)
entry_max_keys = ttk.Entry(root)

entry_wallet_prefix.grid(row=1, column=1, padx=10, pady=10)
entry_wallet_suffix.grid(row=2, column=1, padx=10, pady=10)
entry_contract_prefix.grid(row=3, column=1, padx=10, pady=10)
entry_contract_suffix.grid(row=4, column=1, padx=10, pady=10)
entry_start_nonce.grid(row=5, column=1, padx=10, pady=10)
entry_max_nonce.grid(row=6, column=1, padx=10, pady=10)
entry_max_attempts.grid(row=7, column=1, padx=10, pady=10)
entry_max_keys.grid(row=8, column=1, padx=10, pady=10)

ttk.Button(root, text='Search', command=start_search).grid(row=9, column=0, columnspan=2, padx=10, pady=10)
ttk.Button(root, text='Enter Private Key', command=input_private_key).grid(row=10, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()
