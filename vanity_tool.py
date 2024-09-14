import tkinter as tk
from tkinter import messagebox, ttk, simpledialog, filedialog
from eth_account import Account
from eth_hash.auto import keccak
import rlp
import json
import pyperclip
import concurrent.futures
import os

private_key = None

def is_valid_prefix_suffix(prefix, suffix):
    valid_chars = set('0123456789abcdef')
    if len(prefix) > 10 or len(suffix) > 10:
        return False

    for char in prefix + suffix:
        if char.lower() not in valid_chars:
            return False

    return True

def calculate_max_attempts(start_nonce, max_nonce):
    return max_nonce - start_nonce

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

def search_with_threading(wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, start_nonce, max_nonce, max_keys, thread_count):
    found = False
    results = []
    
    def worker():
        local_private_key = Account.create().key.hex()
        account = Account.from_key(local_private_key)
        max_attempts = calculate_max_attempts(start_nonce, max_nonce)
        nonce, address, wallet_address, found = search_address(account, wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, start_nonce, max_nonce, max_attempts)
        return nonce, address, wallet_address, found, local_private_key
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(worker) for _ in range(max_keys)]
        
        for future in concurrent.futures.as_completed(futures):
            nonce, address, wallet_address, found, local_private_key = future.result()
            if found:
                results.append((nonce, address, wallet_address, local_private_key))
                break

    return results

def input_private_key():
    global private_key

    prompt_text = "Enter a private key (leave empty for a randomly generated one):"
    private_key = simpledialog.askstring("Private Key", prompt_text)
    if private_key:
        try:
            account = Account.from_key(private_key)
            entry_max_keys.delete(0, tk.END)
            entry_max_keys.insert(0, "1")  # Set max keys to 1 since we're using a specific private key
        except ValueError:
            messagebox.showerror("Error", "Invalid private key.")
            private_key = None

def copy_private_key_to_clipboard(key):
    pyperclip.copy(key)
    messagebox.showinfo("Copied", "Private key copied to clipboard.")

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
    max_keys = int(entry_max_keys.get())
    thread_count = thread_slider.get()

    max_attempts = calculate_max_attempts(start_nonce, max_nonce)
    total_attempts = max_attempts * max_keys
    messagebox.showinfo("Information", f"Total attempts: {total_attempts}")

    if not max_nonce or not max_keys or (not wallet_prefix and not wallet_suffix and not contract_prefix and not contract_suffix):
        messagebox.showerror("Error", "Please fill in all the fields.")
        return

    results = search_with_threading(wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, start_nonce, max_nonce, max_keys, thread_count)

    if results:
        nonce, address, wallet_address, local_private_key = results[0]
        
        # Improved search result message with better paragraphing
        result_message = (
            f"Congrats! Search successfully discovered:\n\n"
            f"Contract Address: {address}\n"
            f"Nonce: {nonce}\n"
            f"Wallet Address: {wallet_address}\n\n"
            "Please copy and save the private key."
        )
        # Show a dialog to enter the password and provide an option to copy the private key
        password_dialog = tk.Toplevel(root)
        password_dialog.title("Save Encrypted Private Key")

        tk.Label(password_dialog, text=result_message, justify='left').grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky='w')
        tk.Label(password_dialog, text="Enter a password to encrypt the JSON file:").grid(row=1, column=0, padx=10, pady=10, sticky='w')
        password_entry = tk.Entry(password_dialog, show='*')
        password_entry.grid(row=1, column=1, padx=10, pady=10)

        def save_encrypted_key():
            password = password_entry.get()
            encrypted_data = Account.encrypt(local_private_key, password)
            file_path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"{wallet_address}_Contract-{address}_nonce-{nonce}", title="Save encrypted JSON file")
            if file_path:
                with open(file_path, "w") as file:
                    json.dump(encrypted_data, file)
            password_dialog.destroy()

        def copy_key():
            copy_private_key_to_clipboard(local_private_key)

        ttk.Button(password_dialog, text="Copy Private Key", command=copy_key).grid(row=2, column=0, padx=10, pady=10)
        ttk.Button(password_dialog, text="Save", command=save_encrypted_key).grid(row=2, column=1, padx=10, pady=10)

        # Ensure the dialog stays open after copying the key
        password_dialog.grab_set()

    else:
        messagebox.showinfo("Result", "No address found with the given wallet and contract prefixes and suffixes in the specified range.")

root = tk.Tk()
root.title("CRYFT Vanity Tool")
style = ttk.Style(root)
style.configure('TLabel', font=('Montserrat', 10))

instructions = (
    "1. Enter the Contract and or Wallet Address Prefix or Suffix (if desired).\n"
    "2. Enter the Start Nonce and the Max Nonce for the search.\n"
    "3. Enter the maximum number of private keys to check.\n"
    "4. Select the number of threads to use for parallel processing.\n"
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
ttk.Label(root, text="Max Keys to Check").grid(row=7, padx=10, pady=10, sticky='w')
ttk.Label(root, text="Number of Threads").grid(row=8, padx=10, pady=10, sticky='w')

entry_wallet_prefix = ttk.Entry(root)
entry_wallet_suffix = ttk.Entry(root)
entry_contract_prefix = ttk.Entry(root)
entry_contract_suffix = ttk.Entry(root)
entry_start_nonce = ttk.Entry(root)
entry_max_nonce = ttk.Entry(root)
entry_max_keys = ttk.Entry(root)

entry_wallet_prefix.grid(row=1, column=1, padx=10, pady=10)
entry_wallet_suffix.grid(row=2, column=1, padx=10, pady=10)
entry_contract_prefix.grid(row=3, column=1, padx=10, pady=10)
entry_contract_suffix.grid(row=4, column=1, padx=10, pady=10)
entry_start_nonce.grid(row=5, column=1, padx=10, pady=10)
entry_max_nonce.grid(row=6, column=1, padx=10, pady=10)
entry_max_keys.grid(row=7, column=1, padx=10, pady=10)

# Slider for thread count
max_threads = os.cpu_count()
thread_slider = tk.Scale(root, from_=1, to=max_threads, orient=tk.HORIZONTAL)
thread_slider.set(max_threads)  # Default to maximum threads
thread_slider.grid(row=8, column=1, padx=10, pady=10)

# Centered Optional text above the button
ttk.Label(root, text="Optional", font=('Montserrat', 8)).grid(row=9, column=0, columnspan=2, pady=(0, 0))

ttk.Button(root, text='Enter Private Key', command=input_private_key).grid(row=10, column=0, columnspan=2, padx=10, pady=10)
ttk.Button(root, text='Search', command=start_search).grid(row=11, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()
