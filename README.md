
# CRYFT 0xVanity Tool

CRYFT 0xVanity Tool is a Python-based GUI application that allows users to search for Ethereum contract addresses and wallet addresses with specific prefixes and suffixes. The application leverages multithreading to enhance the performance of the search process and provides options for saving and encrypting private keys.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Installing Python](#installing-python)
    - [Windows](#windows)
    - [macOS](#macos)
    - [Linux](#linux)
  - [Installing Required Python Modules](#installing-required-python-modules)
- [Usage](#usage)
  - [Running the Application](#running-the-application)
  - [Application Features](#application-features)
  - [Search Instructions](#search-instructions)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

Before you begin, ensure you have the following installed on your system:

- Python 3.7 or later
- Pip (Python package manager)

The tool also requires several Python modules:

- `tkinter` (for GUI)
- `eth-account` (for Ethereum account management)
- `eth-hash` (for keccak hashing)
- `rlp` (for encoding Ethereum transactions)
- `pyperclip` (for clipboard management)

## Installation

### Installing Python

#### Windows

1. Download the latest version of Python from the [official Python website](https://www.python.org/downloads/).
2. Run the installer and ensure you check the box that says **Add Python to PATH** before clicking "Install Now".
3. Verify the installation by opening Command Prompt and typing:
   ```sh
   python --version
   pip --version
   ```

#### macOS

1. Open Terminal.
2. Install Python using Homebrew:
   ```sh
   brew install python
   ```
3. Verify the installation:
   ```sh
   python3 --version
   pip3 --version
   ```

#### Linux

For Ubuntu/Debian-based systems:

1. Open Terminal.
2. Update your package list:
   ```sh
   sudo apt update
   ```
3. Install Python:
   ```sh
   sudo apt install python3 python3-pip
   ```
4. Verify the installation:
   ```sh
   python3 --version
   pip3 --version
   ```

For Fedora:

1. Open Terminal.
2. Install Python:
   ```sh
   sudo dnf install python3 python3-pip
   ```
3. Verify the installation:
   ```sh
   python3 --version
   pip3 --version
   ```

### Installing Required Python Modules

Once Python is installed, you need to install the required modules. Open your terminal or command prompt and run:

```sh
pip install eth-account eth-hash rlp web3 pyperclip
```

### Cloning the Repository

To use the CRYFT® Vanity Tool, clone this repository:

```sh
git clone https://github.com/your-username/cryft-vanity-tool.git
cd cryft-vanity-tool
```

## Usage

### Running the Application

To run the CRYFT® Vanity Tool, navigate to the directory where you cloned the repository and execute the following command:

```sh
python3 vanity_tool.py
```

This will launch the GUI of the CRYFT® Vanity Tool.

### Application Features

- **Wallet and Contract Address Prefix/Suffix Search:** Specify the desired prefix and/or suffix for both wallet and contract addresses.
- **Multithreading:** Choose the number of threads to speed up the search process.
- **Optional Private Key Entry:** You can input a specific private key or let the tool generate one randomly.
- **Private Key Management:** Copy the private key to the clipboard and save it in an encrypted JSON format.

### Search Instructions

1. **Enter Address Prefix/Suffix:** You can enter a prefix or suffix for the wallet and contract addresses. These are optional but must be valid hexadecimal strings.
2. **Set Nonce Range:** Specify the start and max nonce values to define the search range.
3. **Max Keys to Check:** Enter the maximum number of private keys to generate and test. If you provide a private key, this will default to 1.
4. **Set Number of Threads:** Use the slider to select the number of threads to utilize for the search.
5. **Click Search:** The tool will start searching for an address that matches the criteria. If found, the result will be displayed, and you can choose to copy the private key and/or save it securely.

## Troubleshooting

If you encounter any issues:

- **Python Not Recognized:** Ensure Python is added to your system's PATH. Refer to the installation instructions.
- **Module Not Found:** Ensure all required Python modules are installed. Use `pip install -r requirements.txt` to install all dependencies at once.
- **Permission Denied Errors:** Run your terminal or command prompt with administrative privileges.

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request with your changes. For major changes, please open an issue first to discuss what you would like to change.

## License

See the `LICENSE` file for details.
