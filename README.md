
# CRYFT 0xVanity Tool

CRYFT 0xVanity Tool is a Python-based GUI application for searching Ethereum wallet and contract addresses with specific prefixes and suffixes. It supports GPU-accelerated search via the **profanity2** backend and OpenCL, multi-GPU selection, multiprocess CPU search, and provides tools for saving and encrypting private keys.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Installing Python](#installing-python)
    - [Windows](#windows)
    - [macOS](#macos)
    - [Linux](#linux)
  - [Installing Required Python Modules](#installing-required-python-modules)
  - [Optional: GPU Acceleration Dependencies](#optional-gpu-acceleration-dependencies)
- [Profanity2 Backend Setup](#profanity2-backend-setup)
  - [Automatic Setup](#automatic-setup)
  - [Manual Setup](#manual-setup)
  - [Environment Variable](#environment-variable)
- [Usage](#usage)
  - [Running the Application](#running-the-application)
  - [Application Features](#application-features)
  - [Search Modes](#search-modes)
  - [Search Instructions](#search-instructions)
  - [GPU Acceleration Controls](#gpu-acceleration-controls)
- [How It Works](#how-it-works)
  - [Profanity2 Integration](#profanity2-integration)
  - [OpenCL Contract Nonce Search](#opencl-contract-nonce-search)
  - [CPU Fallback](#cpu-fallback)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

Before you begin, ensure you have the following installed on your system:

- Python 3.7 or later
- Pip (Python package manager)

### Required Python modules

- `tkinter` — GUI framework (included with most Python installations)
- `eth-account` — Ethereum account management
- `eth-hash` — Keccak-256 hashing
- `rlp` — RLP encoding for contract address derivation
- `pyperclip` — Clipboard integration

### Optional (for GPU acceleration)

- `pyopencl` — OpenCL bindings for GPU contract-nonce search
- `numpy` — Array operations for GPU kernel I/O
- **profanity2** executable — External GPU backend for wallet address search (see [Profanity2 Backend Setup](#profanity2-backend-setup))

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

Once Python is installed, install the required modules:

```sh
pip install eth-account eth-hash rlp pyperclip
```

### Optional: GPU Acceleration Dependencies

To enable GPU-accelerated contract-nonce search via the built-in OpenCL kernel:

```sh
pip install pyopencl numpy
```

> **Note:** You also need an OpenCL-compatible GPU and the appropriate OpenCL drivers installed for your hardware (e.g. NVIDIA, AMD, or Intel GPU drivers).

### Cloning the Repository

```sh
git clone https://github.com/your-username/cryft-vanity-tool.git
cd cryft-vanity-tool
```

## Profanity2 Backend Setup

The **profanity2** backend provides high-speed GPU-accelerated wallet address generation. It is used automatically for wallet-only searches and for the wallet-matching portion of combined wallet+contract searches when a custom private key is not set.

### Automatic Setup

Click the **Set Up Backend** button in the GPU Acceleration panel. The application will:

1. Clone the [profanity2](https://github.com/1inch/profanity2) source from GitHub.
2. Fetch OpenCL headers from Khronos and generate an import library from your system's `OpenCL.dll`.
3. Build the executable using `g++` and `make` (via WinLibs or system toolchain).
4. Place the compiled binary in `backend/profanity2/`.

**Requirements for automatic build:** `git`, `g++`, `make` (or `mingw32-make`). On Windows, these are auto-detected from [WinLibs](https://winlibs.com/) if installed via WinGet.

### Manual Setup

If you already have a profanity2 executable:

1. Click **Set Up Backend** (or **Change Backend...** if one is already configured).
2. Choose **No** when prompted for automatic setup.
3. Browse to your existing `profanity2.exe` or `profanity2.x64` file.

The application also searches these locations automatically on startup:

- `./profanity2.exe` or `./profanity2.x64` (next to `vanity_tool.py`)
- `./backend/profanity2/profanity2.exe` or `./backend/profanity2/profanity2.x64`
- `./tools/profanity2/profanity2.exe` or `./tools/profanity2/profanity2.x64`
- System `PATH`

### Environment Variable

You can also set the `PROFANITY2_PATH` environment variable to the full path of the profanity2 executable. This takes priority over all other detection methods.

## Usage

### Running the Application

```sh
python vanity_tool.py
```

On macOS/Linux:

```sh
python3 vanity_tool.py
```

### Application Features

- **Wallet Address Vanity Search** — Find wallet addresses with a desired hex prefix and/or suffix.
- **Contract Address Vanity Search** — Find contract addresses (derived from wallet + nonce) with a desired hex prefix and/or suffix.
- **Combined Search** — Search for a wallet address AND a contract address that both match specified patterns simultaneously.
- **GPU Acceleration (profanity2)** — Massively parallel wallet address generation on the GPU via the profanity2 backend.
- **GPU Acceleration (OpenCL)** — Contract-nonce search on the GPU using a built-in Keccak-256 OpenCL kernel.
- **Multi-GPU Support** — Select which GPUs to use via per-device checkboxes; unused GPUs are skipped.
- **Multiprocess CPU Search** — Utilizes all CPU cores via `ProcessPoolExecutor` for key generation and nonce scanning.
- **Automatic CPU Fallback** — Falls back to CPU if the GPU backend is unavailable or encounters an error.
- **Probability & ETA Display** — Shows match probability and estimated time to find a match based on live throughput benchmarking.
- **Optional Private Key Input** — Provide a specific private key or let the tool generate keys randomly.
- **Private Key Management** — Copy the private key to the clipboard or save it as a password-encrypted JSON keystore file.
- **Backend Management** — Set up, build, or change the profanity2 GPU backend directly from the GUI.
- **Input Validation** — Prefix and suffix fields accept only valid hexadecimal characters (`0-9`, `a-f`), up to 10 characters each.
- **Cancellation** — Cancel a running search at any time; active GPU processes and CPU workers are terminated cleanly.

### Search Modes

| Scenario | Engine Used |
|---|---|
| Wallet-only search, GPU enabled, no custom private key | **profanity2** GPU backend |
| Wallet + Contract search, GPU enabled, no custom private key | **profanity2** for wallet matching, **OpenCL kernel** for contract nonce search |
| Contract-only search (or any search with custom private key), GPU enabled | **OpenCL kernel** for contract nonces, CPU for key generation |
| Any search, no GPU available | **CPU multiprocess** (all cores) |

### Search Instructions

1. **Enter Address Prefix/Suffix:** Enter a hex prefix and/or suffix for the wallet and/or contract address. At least one must be provided. Valid characters: `0-9`, `a-f` (case-insensitive), max 10 characters each.
2. **Set Nonce Range:** Specify the start and max nonce values for contract address search. Not needed for wallet-only searches.
3. **Max Keys to Check:** Enter the maximum number of private keys to generate and test. Defaults to 1 when a custom private key is provided.
4. **Select GPUs (optional):** Enable or disable individual GPUs in the GPU Acceleration panel.
5. **Tune GPU Settings (optional):** Adjust the batch size (VRAM usage) and compute units sliders.
6. **Click Search:** The tool estimates throughput, displays probability and ETA, then begins searching. If a match is found, you can copy the private key or save it as an encrypted JSON keystore.

### GPU Acceleration Controls

- **GPU Checkboxes** — Enable/disable each detected GPU device. Disabled GPUs are passed to profanity2 as skip arguments.
- **Batch Size (VRAM)** — Controls the number of nonces per OpenCL batch (2^14 to 2^24). Higher values use more VRAM but improve throughput.
- **Compute Units** — Limits the number of GPU compute units used. Reduce this to leave GPU headroom for other tasks.
- **Backend Status** — Shows whether profanity2 is ready, missing, or being set up. Click the button to install or change the backend.

## How It Works

### Profanity2 Integration

For wallet-only GPU searches, the tool:

1. Generates a random **seed private key** and derives its public key.
2. Builds a **matching pattern** from the wallet prefix/suffix (e.g., prefix `dead` + suffix `beef` → `deadXXXX...XXXXbeef`).
3. Launches profanity2 as a subprocess with `--matching <pattern> -z <seed_public_key>`.
4. Profanity2 runs on the GPU and outputs a **delta private key** when it finds a matching address.
5. The tool computes the **final private key** as `(seed + delta) mod n` (secp256k1 curve order) and verifies the derived address matches.

For combined wallet+contract searches, the tool re-launches profanity2 with a fresh seed after each wallet hit whose contract nonces don't match, keeping the GPU searching continuously.

### OpenCL Contract Nonce Search

The tool includes a built-in **Keccak-256 OpenCL kernel** that runs directly on the GPU to search contract nonces. It:

1. RLP-encodes `[sender_address, nonce]` for each nonce in the batch.
2. Computes the Keccak-256 hash on the GPU.
3. Extracts the last 20 bytes as the contract address.
4. Checks prefix/suffix matches in parallel across all work items.

This is used for the contract-address portion of combined searches and for contract-only searches with GPU enabled.

### CPU Fallback

When no GPU is available (or if GPU initialization fails), the tool uses Python's `ProcessPoolExecutor` to distribute key generation and nonce scanning across all CPU cores. The GIL is bypassed by using separate processes rather than threads.

## Troubleshooting

- **Python Not Recognized:** Ensure Python is added to your system's PATH. Refer to the installation instructions.
- **Module Not Found:** Ensure all required Python modules are installed with `pip install eth-account eth-hash rlp pyperclip`.
- **No GPU Detected:** Ensure you have an OpenCL-compatible GPU and that `pyopencl` and `numpy` are installed. Verify your GPU drivers include OpenCL support.
- **Profanity2 Backend Missing:** Click **Set Up Backend** in the GUI to download and build profanity2, or manually provide an existing executable. You can also set the `PROFANITY2_PATH` environment variable.
- **Automatic Build Fails:** The automatic build requires `git`, `g++`, and `make`. On Windows, install [WinLibs](https://winlibs.com/) via WinGet or manually install MinGW-w64. Alternatively, provide a pre-built profanity2 executable.
- **GPU Backend Failed — Fell Back to CPU:** This message appears if profanity2 or OpenCL encounters an error at runtime. The search continues on CPU automatically. Check GPU drivers and OpenCL installation.
- **Permission Denied Errors:** Run your terminal or command prompt with administrative privileges.

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request with your changes. For major changes, please open an issue first to discuss what you would like to change.

## License

See the `LICENSE` file for details.
