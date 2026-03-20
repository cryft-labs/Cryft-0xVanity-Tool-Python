import tkinter as tk
from tkinter import messagebox, ttk, simpledialog, filedialog
from eth_account import Account
from eth_hash.auto import keccak
import rlp
import atexit
import json
import pyperclip
import concurrent.futures
import multiprocessing
import os
import queue
import re
import shutil
import subprocess
import threading
import time

try:
    import pyopencl as cl
    import numpy as np
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

private_key = None
cancel_event = threading.Event()
throughput_cache = {}
backend_status_message = ""
backend_setup_in_progress = False
_active_profanity2_proc = None
_active_executor = None
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ANSI_ESCAPE_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
PROFANITY2_SPEED_RE = re.compile(r'Total:\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?)H/s', re.IGNORECASE)
PROFANITY2_RESULT_RE = re.compile(
    r'Private:\s*0x([0-9a-fA-F]{64}).*?(?:Address|Contract):\s*0x([0-9a-fA-F]{40})',
    re.IGNORECASE | re.DOTALL,
)

# ── OpenCL Keccak-256 kernel for GPU-accelerated contract address search ──────

KECCAK_KERNEL_SRC = """
ulong rotl64(ulong x, uint n) { return (x << n) | (x >> (64u - n)); }

__constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL,
    0x8000000080008000UL, 0x000000000000808BUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008AUL,
    0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL,
    0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800AUL, 0x800000008000000AUL, 0x8000000080008081UL,
    0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

void keccakf(ulong st[25]) {
    ulong t, bc[5];
    for (int r = 0; r < 24; r++) {
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i+4)%5] ^ rotl64(bc[(i+1)%5], 1);
            for (int j = 0; j < 25; j += 5) st[j+i] ^= t;
        }
        t = st[1];
        st[ 1]=rotl64(st[ 6],44); st[ 6]=rotl64(st[ 9],20); st[ 9]=rotl64(st[22],61);
        st[22]=rotl64(st[14],39); st[14]=rotl64(st[20],18); st[20]=rotl64(st[ 2],62);
        st[ 2]=rotl64(st[12],43); st[12]=rotl64(st[13],25); st[13]=rotl64(st[19], 8);
        st[19]=rotl64(st[23],56); st[23]=rotl64(st[15],41); st[15]=rotl64(st[ 4],27);
        st[ 4]=rotl64(st[24],14); st[24]=rotl64(st[21], 2); st[21]=rotl64(st[ 8],55);
        st[ 8]=rotl64(st[16],45); st[16]=rotl64(st[ 5],36); st[ 5]=rotl64(st[ 3],28);
        st[ 3]=rotl64(st[18],21); st[18]=rotl64(st[17],15); st[17]=rotl64(st[11],10);
        st[11]=rotl64(st[ 7], 6); st[ 7]=rotl64(st[10], 3); st[10]=rotl64(t, 1);
        for (int j = 0; j < 25; j += 5) {
            bc[0]=st[j]; bc[1]=st[j+1]; bc[2]=st[j+2]; bc[3]=st[j+3]; bc[4]=st[j+4];
            st[j  ]^=(~bc[1])&bc[2]; st[j+1]^=(~bc[2])&bc[3]; st[j+2]^=(~bc[3])&bc[4];
            st[j+3]^=(~bc[4])&bc[0]; st[j+4]^=(~bc[0])&bc[1];
        }
        st[0] ^= RC[r];
    }
}

__kernel void search_contract_address(
    __global const uchar *address, uint start_nonce,
    __global const uchar *prefix,  uint prefix_len,
    __global const uchar *suffix,  uint suffix_len,
    __global uchar *results)
{
    uint gid = get_global_id(0);
    uint nonce = start_nonce + gid;

    // RLP encode [address, nonce]
    uchar rlp[32]; int rlen;
    uchar nrlp[6]; int nlen;
    if      (nonce == 0u)       { nrlp[0]=0x80; nlen=1; }
    else if (nonce <= 0x7fu)    { nrlp[0]=(uchar)nonce; nlen=1; }
    else if (nonce <= 0xffu)    { nrlp[0]=0x81; nrlp[1]=(uchar)nonce; nlen=2; }
    else if (nonce <= 0xffffu)  { nrlp[0]=0x82; nrlp[1]=(uchar)(nonce>>8);
                                 nrlp[2]=(uchar)(nonce&0xffu); nlen=3; }
    else if (nonce <= 0xffffffu){ nrlp[0]=0x83; nrlp[1]=(uchar)(nonce>>16);
                                 nrlp[2]=(uchar)((nonce>>8)&0xffu);
                                 nrlp[3]=(uchar)(nonce&0xffu); nlen=4; }
    else                       { nrlp[0]=0x84; nrlp[1]=(uchar)(nonce>>24);
                                 nrlp[2]=(uchar)((nonce>>16)&0xffu);
                                 nrlp[3]=(uchar)((nonce>>8)&0xffu);
                                 nrlp[4]=(uchar)(nonce&0xffu); nlen=5; }

    rlp[0] = (uchar)(0xc0 + 21 + nlen);
    rlp[1] = 0x94;
    for (int i = 0; i < 20; i++) rlp[2+i] = address[i];
    for (int i = 0; i < nlen; i++) rlp[22+i] = nrlp[i];
    rlen = 22 + nlen;

    // Keccak-256
    ulong st[25]; for (int i = 0; i < 25; i++) st[i] = 0;
    for (int i = 0; i < rlen; i++)
        st[i/8] ^= ((ulong)rlp[i]) << ((i%8)*8);
    st[rlen/8] ^= ((ulong)0x01) << ((rlen%8)*8);
    st[16] ^= 0x8000000000000000UL;
    keccakf(st);

    // Last 20 bytes of 32-byte hash = contract address
    uchar ca[20];
    for (int i = 0; i < 20; i++) {
        int b = 12 + i;
        ca[i] = (uchar)(st[b/8] >> ((b%8)*8));
    }

    // Convert to hex and match
    uchar hx[40];
    for (int i = 0; i < 20; i++) {
        uchar hi = (ca[i]>>4) & 0x0f, lo = ca[i] & 0x0f;
        hx[i*2]   = hi < 10 ? '0'+hi : 'a'+hi-10;
        hx[i*2+1] = lo < 10 ? '0'+lo : 'a'+lo-10;
    }
    uchar m = 1;
    for (uint i = 0; i < prefix_len; i++)
        if (hx[i] != prefix[i]) { m = 0; break; }
    if (m)
        for (uint i = 0; i < suffix_len; i++)
            if (hx[40 - suffix_len + i] != suffix[i]) { m = 0; break; }
    results[gid] = m;
}
"""


class GPUSearcher:
    """Manages an OpenCL context and runs keccak-256 contract address search on GPU."""

    def __init__(self, platform_idx=None, device_idx=None):
        self.ctx = None
        self.device_name = "Unknown"
        if platform_idx is not None and device_idx is not None:
            platform = cl.get_platforms()[platform_idx]
            devices = platform.get_devices(device_type=cl.device_type.GPU)
            device = devices[device_idx]
            self.ctx = cl.Context(devices=[device])
            self.device_name = device.name.strip()
        else:
            for platform in cl.get_platforms():
                try:
                    devices = platform.get_devices(device_type=cl.device_type.GPU)
                    if devices:
                        self.ctx = cl.Context(devices=[devices[0]])
                        self.device_name = devices[0].name.strip()
                        break
                except cl.Error:
                    continue
        if self.ctx is None:
            raise RuntimeError("No GPU device found")
        self.queue = cl.CommandQueue(self.ctx)
        self.program = cl.Program(self.ctx, KECCAK_KERNEL_SRC).build()

    def search_nonces(self, address_hex, start_nonce, max_nonce, prefix, suffix, batch_size=1 << 20, max_cu=None, stop_event=None):
        """Search nonce range on GPU. Returns first matching nonce or None."""
        addr_np = np.frombuffer(bytes.fromhex(address_hex), dtype=np.uint8)
        prefix_np = np.frombuffer(prefix.lower().encode(), dtype=np.uint8) if prefix else np.zeros(1, dtype=np.uint8)
        suffix_np = np.frombuffer(suffix.lower().encode(), dtype=np.uint8) if suffix else np.zeros(1, dtype=np.uint8)
        plen = len(prefix) if prefix else 0
        slen = len(suffix) if suffix else 0

        mf = cl.mem_flags
        addr_buf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=addr_np)
        prefix_buf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=prefix_np)
        suffix_buf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=suffix_np)

        # Determine local work size based on compute units setting
        local_size = None
        if max_cu and self.ctx:
            dev = self.ctx.devices[0]
            max_wg = dev.max_work_group_size
            if max_cu < dev.max_compute_units:
                local_size = max(1, max_wg // max(1, dev.max_compute_units // max_cu))
                local_size = min(local_size, max_wg)

        current = start_nonce
        while current < max_nonce:
            if cancel_event.is_set() or (stop_event and stop_event.is_set()):
                return None
            batch = min(batch_size, max_nonce - current)
            # Align batch to local_size if set
            if local_size and batch % local_size != 0:
                batch = ((batch // local_size) + 1) * local_size
                batch = min(batch, max_nonce - current + local_size)
            results_host = np.zeros(batch, dtype=np.uint8)
            results_buf = cl.Buffer(self.ctx, mf.WRITE_ONLY, size=int(batch))

            lsize = (local_size,) if local_size else None
            self.program.search_contract_address(
                self.queue, (batch,), lsize,
                addr_buf, np.uint32(current),
                prefix_buf, np.uint32(plen),
                suffix_buf, np.uint32(slen),
                results_buf,
            )
            cl.enqueue_copy(self.queue, results_host, results_buf)
            self.queue.finish()

            actual_count = min(batch, max_nonce - current)
            matches = np.where(results_host[:actual_count] == 1)[0]
            if len(matches) > 0:
                return current + int(matches[0])
            current += actual_count
        return None


def _detect_all_gpus():
    """Return list of dicts with info for every GPU device available."""
    if not GPU_AVAILABLE:
        return []
    gpus = []
    try:
        for pi, platform in enumerate(cl.get_platforms()):
            try:
                devices = platform.get_devices(device_type=cl.device_type.GPU)
                for di, d in enumerate(devices):
                    gpus.append({
                        'platform_idx': pi,
                        'device_idx': di,
                        'name': d.name.strip(),
                        'mem_mb': d.global_mem_size // (1024 * 1024),
                        'compute_units': d.max_compute_units,
                    })
            except cl.Error:
                continue
    except Exception:
        pass
    return gpus


all_gpus = _detect_all_gpus()
gpu_detected = len(all_gpus) > 0
cpu_count = os.cpu_count() or 4

def _find_profanity2_executable():
    env_path = os.environ.get("PROFANITY2_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "profanity2.exe"),
        os.path.join(script_dir, "profanity2.x64"),
        os.path.join(script_dir, "backend", "profanity2", "profanity2.exe"),
        os.path.join(script_dir, "backend", "profanity2", "profanity2.x64"),
        os.path.join(script_dir, "tools", "profanity2", "profanity2.exe"),
        os.path.join(script_dir, "tools", "profanity2", "profanity2.x64"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    return shutil.which("profanity2") or shutil.which("profanity2.exe")


profanity2_path = _find_profanity2_executable()
profanity2_available = profanity2_path is not None


def _set_profanity2_path(path):
    global profanity2_path, profanity2_available
    profanity2_path = path if path and os.path.isfile(path) else None
    profanity2_available = profanity2_path is not None


def _find_winlibs_bin_dir():
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        return None
    packages_dir = os.path.join(local_app_data, "Microsoft", "WinGet", "Packages")
    if not os.path.isdir(packages_dir):
        return None

    prefix = "BrechtSanders.WinLibs.POSIX.UCRT"
    for name in os.listdir(packages_dir):
        if name.startswith(prefix):
            candidate = os.path.join(packages_dir, name, "mingw64", "bin")
            if os.path.isdir(candidate):
                return candidate
    return None


def _detect_backend_tooling():
    git_exe = shutil.which("git")
    make_exe = shutil.which("mingw32-make") or shutil.which("make")
    compiler_exe = shutil.which("g++") or shutil.which("clang++")
    winlibs_bin = _find_winlibs_bin_dir()

    if winlibs_bin:
        if not compiler_exe:
            candidate = os.path.join(winlibs_bin, "g++.exe")
            if os.path.isfile(candidate):
                compiler_exe = candidate
        if not make_exe:
            for filename in ("mingw32-make.exe", "make.exe"):
                candidate = os.path.join(winlibs_bin, filename)
                if os.path.isfile(candidate):
                    make_exe = candidate
                    break

    return {
        "git": git_exe,
        "make": make_exe,
        "compiler": compiler_exe,
        "toolchain_bin": winlibs_bin or (os.path.dirname(compiler_exe) if compiler_exe else None),
    }


def _ensure_opencl_build_deps(backend_root, tools):
    deps_root = os.path.join(backend_root, "deps")
    headers_root = os.path.join(deps_root, "OpenCL-Headers")
    lib_root = os.path.join(deps_root, "OpenCL-lib")
    os.makedirs(deps_root, exist_ok=True)
    os.makedirs(lib_root, exist_ok=True)

    if not tools["git"]:
        raise RuntimeError("git is required to fetch OpenCL headers.")
    if not tools["toolchain_bin"]:
        raise RuntimeError("A GCC toolchain is required to prepare OpenCL build files.")

    cl_header = os.path.join(headers_root, "CL", "cl.h")
    if not os.path.isfile(cl_header):
        subprocess.run(
            [tools["git"], "clone", "--depth", "1", "https://github.com/KhronosGroup/OpenCL-Headers", headers_root],
            check=True,
            **_subprocess_kwargs(deps_root),
        )

    dlltool_exe = os.path.join(tools["toolchain_bin"], "dlltool.exe")
    gendef_exe = os.path.join(tools["toolchain_bin"], "gendef.exe")
    if not os.path.isfile(dlltool_exe) or not os.path.isfile(gendef_exe):
        raise RuntimeError("WinLibs is installed but dlltool/gendef were not found.")

    import_lib = os.path.join(lib_root, "libOpenCL.a")
    if not os.path.isfile(import_lib):
        system_opencl = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "System32", "OpenCL.dll")
        if not os.path.isfile(system_opencl):
            raise RuntimeError("OpenCL.dll was not found in System32.")
        subprocess.run(
            [gendef_exe, system_opencl],
            check=True,
            **_subprocess_kwargs(lib_root),
        )
        subprocess.run(
            [dlltool_exe, "-d", os.path.join(lib_root, "OpenCL.def"), "-D", "OpenCL.dll", "-l", import_lib],
            check=True,
            **_subprocess_kwargs(lib_root),
        )

    return {
        "include_dir": headers_root,
        "lib_dir": lib_root,
    }


def _make_build_env(toolchain_bin):
    env = os.environ.copy()
    if toolchain_bin:
        env["PATH"] = toolchain_bin + os.pathsep + env.get("PATH", "")
    return env


def _backend_status_text():
    if backend_setup_in_progress:
        return backend_status_message or "Wallet GPU backend: setting up...", "blue"
    if profanity2_available:
        backend_name = os.path.basename(profanity2_path)
        return f"Wallet GPU backend: ready ({backend_name})", "green"
    if backend_status_message:
        lowered = backend_status_message.lower()
        if "failed" in lowered:
            return backend_status_message, "red"
        return backend_status_message, "darkorange"
    return "Wallet GPU backend: missing. Click Set Up to install or choose an existing executable.", "darkorange"


def _refresh_backend_status_ui():
    if 'backend_status_label' in globals():
        text, color = _backend_status_text()
        backend_status_label.config(text=text, foreground=color)
    if 'backend_button' in globals():
        if backend_setup_in_progress:
            backend_button.config(text='Setting Up...', state='disabled')
        elif profanity2_available:
            backend_button.config(text='Change Backend...', state='normal')
        else:
            backend_button.config(text='Set Up Backend', state='normal')


def _choose_backend_executable():
    file_path = filedialog.askopenfilename(
        title="Select profanity2 executable",
        filetypes=[("Executables", "*.exe *.x64"), ("All Files", "*.*")],
    )
    if not file_path:
        return False
    _set_profanity2_path(file_path)
    if profanity2_available:
        throughput_cache.clear()
        os.environ["PROFANITY2_PATH"] = file_path
        global backend_status_message
        backend_status_message = ""
        _refresh_backend_status_ui()
        return True
    return False


def _setup_backend_worker():
    global backend_setup_in_progress, backend_status_message
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_root = os.path.join(script_dir, "backend", "profanity2")
    src_dir = os.path.join(backend_root, "src")
    os.makedirs(backend_root, exist_ok=True)

    try:
        tools = _detect_backend_tooling()
        git_exe = tools["git"]
        make_exe = tools["make"]
        compiler_exe = tools["compiler"]

        if not git_exe:
            backend_status_message = "Wallet GPU backend: automatic setup needs git. Choose an existing executable or install git plus build tools."
            return

        if not os.path.isdir(src_dir):
            backend_status_message = "Wallet GPU backend: downloading source..."
            root.after(0, _refresh_backend_status_ui)
            subprocess.run(
                [git_exe, "clone", "https://github.com/1inch/profanity2", src_dir],
                check=True,
                **_subprocess_kwargs(backend_root),
            )
        else:
            backend_status_message = "Wallet GPU backend: refreshing source..."
            root.after(0, _refresh_backend_status_ui)
            subprocess.run(
                [git_exe, "-C", src_dir, "pull", "--ff-only"],
                check=True,
                **_subprocess_kwargs(backend_root),
            )

        built_candidates = [
            os.path.join(src_dir, "profanity2.exe"),
            os.path.join(src_dir, "profanity2.x64"),
        ]

        built_path = next((path for path in built_candidates if os.path.isfile(path)), None)
        if built_path is None:
            if not make_exe or not compiler_exe:
                backend_status_message = (
                    "Wallet GPU backend: source is ready, but auto-build is unavailable on this machine "
                    "because g++/make are missing. Choose an existing executable or install build tools."
                )
                return

            backend_status_message = "Wallet GPU backend: building source..."
            root.after(0, _refresh_backend_status_ui)
            opencl_deps = _ensure_opencl_build_deps(backend_root, tools)
            build_env = _make_build_env(tools["toolchain_bin"])
            subprocess.run(
                [
                    make_exe,
                    "CC=g++",
                    f"CFLAGS=-c -std=c++11 -Wall -mmmx -O2 -mcmodel=large -I{opencl_deps['include_dir']}",
                    f"LDFLAGS=-s -lOpenCL -L{opencl_deps['lib_dir']} -mcmodel=large",
                ],
                check=True,
                env=build_env,
                **_subprocess_kwargs(src_dir),
            )
            built_path = next((path for path in built_candidates if os.path.isfile(path)), None)

        if built_path is None:
            raise RuntimeError("Build completed but no executable was produced.")

        target_name = "profanity2.exe" if built_path.endswith(".exe") else "profanity2.x64"
        target_path = os.path.join(backend_root, target_name)
        shutil.copy2(built_path, target_path)
        _set_profanity2_path(target_path)
        os.environ["PROFANITY2_PATH"] = target_path
        throughput_cache.clear()
        backend_status_message = ""
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        backend_status_message = f"Wallet GPU backend setup failed: {stderr or exc}"
    except Exception as exc:
        backend_status_message = f"Wallet GPU backend setup failed: {exc}"
    finally:
        backend_setup_in_progress = False
        root.after(0, _refresh_backend_status_ui)


def setup_backend():
    global backend_setup_in_progress, backend_status_message
    if backend_setup_in_progress:
        return

    if profanity2_available:
        if _choose_backend_executable():
            return
        backend_status_message = ""
        _refresh_backend_status_ui()
        return

    choice = messagebox.askyesnocancel(
        "Set Up Wallet GPU Backend",
        "Yes: try automatic download/build of profanity2.\n\n"
        "No: choose an existing profanity2 executable.\n\n"
        "Cancel: do nothing.",
    )
    if choice is None:
        return
    if choice is False:
        if _choose_backend_executable():
            return
        backend_status_message = "Wallet GPU backend: no executable selected."
        _refresh_backend_status_ui()
        return

    tools = _detect_backend_tooling()
    if not tools["git"]:
        backend_status_message = "Wallet GPU backend: automatic setup needs git. Choose an existing executable or install git plus build tools."
        _refresh_backend_status_ui()
        if messagebox.askyesno("Choose Existing Backend", "Automatic setup needs git. Do you want to choose an existing profanity2 executable now?"):
            if _choose_backend_executable():
                return
        return

    if not tools["make"] or not tools["compiler"]:
        backend_status_message = (
            "Wallet GPU backend: auto-build is unavailable on this machine because g++/make are missing. "
            "Choose an existing executable or install build tools."
        )
        _refresh_backend_status_ui()
        if messagebox.askyesno("Choose Existing Backend", "This machine does not have g++/make for automatic build. Do you want to choose an existing profanity2 executable now?"):
            if _choose_backend_executable():
                return
        return

    backend_setup_in_progress = True
    backend_status_message = "Wallet GPU backend: preparing setup..."
    _refresh_backend_status_ui()
    threading.Thread(target=_setup_backend_worker, daemon=True).start()


def _normalize_private_key_hex(value):
    normalized = value[2:] if value.startswith("0x") else value
    return normalized.lower().zfill(64)


def _derive_public_key_hex(private_key_hex):
    account = Account.from_key(private_key_hex)
    return account._key_obj.public_key.to_hex()[2:]


def _combine_private_keys(seed_private_key_hex, delta_private_key_hex):
    seed_int = int(_normalize_private_key_hex(seed_private_key_hex), 16)
    delta_int = int(_normalize_private_key_hex(delta_private_key_hex), 16)
    final_int = (seed_int + delta_int) % SECP256K1_ORDER
    return hex(final_int)[2:].zfill(64)


def _build_matching_pattern(prefix, suffix):
    middle_len = 40 - len(prefix) - len(suffix)
    if middle_len < 0:
        raise ValueError("Prefix and suffix are too long for a wallet address pattern.")
    return (prefix + ("X" * middle_len) + suffix).lower()


def _selected_gpu_indices():
    return [index for index, var in enumerate(gpu_vars) if var.get()]


def _profanity2_skip_args(selected_indices):
    skip_args = []
    selected = set(selected_indices)
    for index in range(len(all_gpus)):
        if index not in selected:
            skip_args.extend(["-s", str(index)])
    return skip_args


def _strip_ansi(text):
    return ANSI_ESCAPE_RE.sub("", text).replace("\r", "\n")


def _extract_speed_hps(text):
    matches = PROFANITY2_SPEED_RE.findall(_strip_ansi(text))
    if not matches:
        return None
    value_str, unit = matches[-1]
    multiplier = {
        "": 1.0,
        "K": 1_000.0,
        "M": 1_000_000.0,
        "G": 1_000_000_000.0,
        "T": 1_000_000_000_000.0,
    }
    return float(value_str) * multiplier[unit.upper()]


def _extract_profanity2_result(text):
    # profanity2 outputs progressively better matches; take the last one
    matches = PROFANITY2_RESULT_RE.findall(_strip_ansi(text))
    if not matches:
        return None, None
    delta_key, addr = matches[-1]
    return delta_key.lower(), "0x" + addr.lower()


def _subprocess_kwargs(cwd=None):
    # Default CWD to the profanity2 executable's directory so that
    # the OpenCL kernel source files (keccak.cl, profanity.cl) and
    # the compiled-kernel cache are found/saved in the right place.
    if cwd is None and profanity2_path:
        cwd = os.path.dirname(os.path.abspath(profanity2_path))
    kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "cwd": cwd or os.path.dirname(os.path.abspath(__file__)),
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return kwargs


def _benchmark_profanity2_rate(executable_path, selected_indices):
    cache_key = ("profanity2_hps", executable_path, tuple(selected_indices))
    if cache_key in throughput_cache:
        return throughput_cache[cache_key]

    seed_private_key = Account.create().key.hex()
    seed_public_key = _derive_public_key_hex(seed_private_key)
    cmd = [executable_path, "--benchmark", "-z", seed_public_key, *_profanity2_skip_args(selected_indices)]
    process = subprocess.Popen(cmd, **_subprocess_kwargs())

    try:
        time.sleep(3.0)
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()

    rate = _extract_speed_hps((stdout or "") + "\n" + (stderr or ""))
    if rate is None:
        raise RuntimeError("Unable to determine profanity2 benchmark speed.")
    throughput_cache[cache_key] = rate
    return rate


def is_valid_prefix_suffix(prefix, suffix):
    valid_chars = set('0123456789abcdef')
    if len(prefix) > 10 or len(suffix) > 10:
        return False
    for char in prefix + suffix:
        if char.lower() not in valid_chars:
            return False
    return True

def create_contract_address(account, nonce):
    return '0x' + keccak(rlp.encode([bytes.fromhex(account.address[2:]), nonce]))[-20:].hex()

def _validate_hex(new_value):
    """Tkinter validate callback: allow only hex chars, max 10."""
    if len(new_value) > 10:
        return False
    return all(c in '0123456789abcdefABCDEF' for c in new_value)

def _calc_probability(wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, nonce_range, max_keys):
    """Calculate match probability and expected keys needed."""
    wp_len = len(wallet_prefix)
    ws_len = len(wallet_suffix)
    cp_len = len(contract_prefix)
    cs_len = len(contract_suffix)

    # Probability of wallet address matching prefix+suffix
    p_wallet = (1 / 16) ** (wp_len + ws_len) if (wp_len + ws_len) > 0 else 1.0

    # Probability of a single nonce matching contract prefix+suffix
    p_contract_single = (1 / 16) ** (cp_len + cs_len) if (cp_len + cs_len) > 0 else 1.0

    # Probability of at least one nonce matching across the nonce range
    if cp_len + cs_len > 0 and nonce_range > 0:
        p_contract = 1.0 - (1.0 - p_contract_single) ** nonce_range
    else:
        p_contract = 1.0

    # Per-key probability of full match
    p_per_key = p_wallet * p_contract

    # Overall probability across all keys
    if p_per_key >= 1.0:
        p_overall = 1.0
    else:
        p_overall = 1.0 - (1.0 - p_per_key) ** max_keys

    # Expected keys to find first match
    expected_keys = 1.0 / p_per_key if p_per_key > 0 else float('inf')

    return p_overall, p_per_key, expected_keys

def _benchmark_key_rate(n=20):
    """Measure keys/sec by generating a few test keys."""
    cache_key = ("cpu_keys", n)
    if cache_key in throughput_cache:
        return throughput_cache[cache_key]
    t0 = time.perf_counter()
    for _ in range(n):
        Account.create()
    elapsed = time.perf_counter() - t0
    rate = n / elapsed if elapsed > 0 else 1000.0
    throughput_cache[cache_key] = rate
    return rate

def _benchmark_cpu_contract_nonce_rate(sample_nonces=1024):
    """Measure single-process CPU nonce throughput with a near-impossible match."""
    cache_key = ("cpu_nonces", sample_nonces)
    if cache_key in throughput_cache:
        return throughput_cache[cache_key]
    account = Account.create()
    t0 = time.perf_counter()
    search_address(account, "", "", "ffffffffffff", "", 0, sample_nonces)
    elapsed = time.perf_counter() - t0
    rate = sample_nonces / elapsed if elapsed > 0 else float(sample_nonces)
    throughput_cache[cache_key] = rate
    return rate

def _benchmark_gpu_nonce_rate(gpu_searcher, batch_size, max_cu, sample_batches=1):
    """Measure GPU nonce throughput with a near-impossible match."""
    cache_key = ("gpu_nonces", gpu_searcher.device_name, batch_size, max_cu, sample_batches)
    if cache_key in throughput_cache:
        return throughput_cache[cache_key]
    total_nonces = max(1, batch_size * sample_batches)
    t0 = time.perf_counter()
    gpu_searcher.search_nonces(
        "0000000000000000000000000000000000000000",
        0,
        total_nonces,
        "ffffffffffff",
        "",
        batch_size=batch_size,
        max_cu=max_cu,
    )
    elapsed = time.perf_counter() - t0
    rate = total_nonces / elapsed if elapsed > 0 else float(total_nonces)
    throughput_cache[cache_key] = rate
    return rate

def _estimate_keys_per_second(wallet_only, use_gpu, nonce_range, enabled_gpu_count=0,
                              gpu_searchers=None, gpu_batch_size=1 << 20, gpu_max_cu=None):
    """Estimate end-to-end key throughput for the active search mode."""
    cpu_key_rate = _benchmark_key_rate()

    if wallet_only:
        parallelism = 1 if private_key else cpu_count
        return max(cpu_key_rate * parallelism, 1.0)

    if use_gpu and gpu_searchers:
        gpu_rates = [0.0] * len(gpu_searchers)
        threads = []

        def bench_gpu(idx, searcher):
            try:
                gpu_rates[idx] = _benchmark_gpu_nonce_rate(searcher, gpu_batch_size, gpu_max_cu)
            except Exception:
                gpu_rates[idx] = 0.0

        for idx, searcher in enumerate(gpu_searchers):
            thread = threading.Thread(target=bench_gpu, args=(idx, searcher), daemon=True)
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()

        total_gpu_nonce_rate = sum(gpu_rates)
        gpu_key_rate = total_gpu_nonce_rate / max(nonce_range, 1)
        cpu_parallelism = 1 if private_key else min(cpu_count, max(enabled_gpu_count, 1))
        cpu_cap = cpu_key_rate * cpu_parallelism
        return max(min(gpu_key_rate, cpu_cap), 1.0)

    cpu_nonce_rate = _benchmark_cpu_contract_nonce_rate(min(max(nonce_range, 1), 2048))
    cpu_contract_key_rate = (cpu_nonce_rate * cpu_count) / max(nonce_range, 1)
    return max(cpu_contract_key_rate, 1.0)


def search_with_profanity2(wallet_prefix, wallet_suffix, max_keys, executable_path,
                          selected_indices, on_speed_detected=None):
    """Use the external profanity2 backend for wallet-only GPU search.

    Starts the real search immediately and detects speed from stdout
    dynamically — no separate benchmark launch, so the GPU is never
    initialised twice.
    """
    global _active_profanity2_proc
    if private_key:
        raise RuntimeError("The external GPU backend cannot be used with a fixed private key.")

    cache_key = ("profanity2_hps", executable_path, tuple(selected_indices))

    seed_private_key = Account.create().key.hex()
    seed_public_key = _derive_public_key_hex(seed_private_key)
    matching_pattern = _build_matching_pattern(wallet_prefix, wallet_suffix)

    cmd = [
        executable_path,
        "--matching", matching_pattern,
        "-z", seed_public_key,
        *_profanity2_skip_args(selected_indices),
    ]
    process = subprocess.Popen(cmd, **_subprocess_kwargs())
    _active_profanity2_proc = process

    # Drain pipes in background threads to prevent deadlock on large output
    output_chunks = []
    error_chunks = []

    def _drain(stream, accumulator):
        try:
            for line in stream:
                accumulator.append(line)
        except Exception:
            pass

    stdout_thread = threading.Thread(target=_drain, args=(process.stdout, output_chunks), daemon=True)
    stderr_thread = threading.Thread(target=_drain, args=(process.stderr, error_chunks), daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    # Deadline is set once we detect live GPU speed — not before,
    # because OpenCL init can take several seconds and we must not
    # count that against the search budget.
    deadline = None
    speed_reported = False

    def _terminate():
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()

    try:
        while process.poll() is None:
            if cancel_event.is_set():
                _terminate()
                return []

            combined = "".join(output_chunks) + "\n" + "".join(error_chunks)

            # Check for early match — stop GPU immediately
            delta_key, wallet_addr = _extract_profanity2_result(combined)
            if delta_key:
                final_key = _combine_private_keys(seed_private_key, delta_key)
                derived_addr = Account.from_key(final_key).address
                if _wallet_matches(derived_addr, wallet_prefix, wallet_suffix):
                    _terminate()
                    return [(None, None, derived_addr, final_key)]

            # Detect speed from live output and set deadline from NOW
            # (GPU is actually hashing at this point, init is done)
            if not speed_reported:
                speed = _extract_speed_hps(combined)
                if speed and speed > 0:
                    throughput_cache[cache_key] = speed
                    deadline = time.perf_counter() + max_keys / speed
                    speed_reported = True
                    if on_speed_detected:
                        on_speed_detected(speed)

            if deadline is not None and time.perf_counter() >= deadline:
                _terminate()
                break
            time.sleep(0.1)

        # Collect remaining output after process ends
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        combined = "".join(output_chunks) + "\n" + "".join(error_chunks)
        delta_private_key, wallet_address = _extract_profanity2_result(combined)
        if not delta_private_key:
            return []

        final_private_key = _combine_private_keys(seed_private_key, delta_private_key)
        derived_wallet_address = Account.from_key(final_private_key).address
        if not _wallet_matches(derived_wallet_address, wallet_prefix, wallet_suffix):
            return []
        return [(None, None, derived_wallet_address, final_private_key)]
    finally:
        _active_profanity2_proc = None
        if process.poll() is None:
            process.kill()

def search_combined_with_profanity2(wallet_prefix, wallet_suffix,
                                    contract_prefix, contract_suffix,
                                    start_nonce, max_nonce, max_keys,
                                    executable_path, selected_indices,
                                    gpu_searcher=None,
                                    gpu_batch_size=1 << 20, gpu_max_cu=None,
                                    on_speed_detected=None):
    """Combined wallet+contract search.

    Uses profanity2 (GPU) for wallet address matching, then checks contract
    nonces for each wallet hit via the OpenCL nonce searcher or CPU.
    Re-launches profanity2 with a fresh seed whenever the contract nonces
    don't match, so the GPU does all the heavy key generation.
    """
    global _active_profanity2_proc

    cache_key = ("profanity2_hps", executable_path, tuple(selected_indices))
    # Deadline is set once we detect live GPU speed from the first
    # profanity2 launch — OpenCL init time is not counted.
    deadline = None
    speed_reported = False

    def _check_contract_nonces(final_key):
        """Return (nonce, contract_addr, wallet_addr, key) or None."""
        account = Account.from_key(final_key)
        if gpu_searcher:
            nonce = gpu_searcher.search_nonces(
                account.address[2:], start_nonce, max_nonce,
                contract_prefix, contract_suffix,
                batch_size=gpu_batch_size, max_cu=gpu_max_cu,
            )
        else:
            nonce, _, _, found = search_address(
                account, "", "", contract_prefix, contract_suffix,
                start_nonce, max_nonce,
            )
            if not found:
                nonce = None
        if nonce is not None:
            addr = create_contract_address(account, nonce)
            return [(nonce, addr, account.address, final_key)]
        return None

    while not cancel_event.is_set():
        if deadline and time.perf_counter() >= deadline:
            break

        seed_private_key = Account.create().key.hex()
        seed_public_key = _derive_public_key_hex(seed_private_key)
        matching_pattern = _build_matching_pattern(wallet_prefix, wallet_suffix)

        cmd = [
            executable_path,
            "--matching", matching_pattern,
            "-z", seed_public_key,
            *_profanity2_skip_args(selected_indices),
        ]
        process = subprocess.Popen(cmd, **_subprocess_kwargs())
        _active_profanity2_proc = process

        output_chunks = []
        error_chunks = []

        def _drain(stream, acc):
            try:
                for line in stream:
                    acc.append(line)
            except Exception:
                pass

        stdout_t = threading.Thread(target=_drain, args=(process.stdout, output_chunks), daemon=True)
        stderr_t = threading.Thread(target=_drain, args=(process.stderr, error_chunks), daemon=True)
        stdout_t.start()
        stderr_t.start()

        def _terminate():
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()

        try:
            while process.poll() is None:
                if cancel_event.is_set():
                    _terminate()
                    return []

                combined = "".join(output_chunks) + "\n" + "".join(error_chunks)

                if not speed_reported:
                    speed = _extract_speed_hps(combined)
                    if speed and speed > 0:
                        throughput_cache[cache_key] = speed
                        deadline = time.perf_counter() + max_keys / speed
                        speed_reported = True
                        if on_speed_detected:
                            on_speed_detected(speed)

                delta_key, _ = _extract_profanity2_result(combined)
                if delta_key:
                    _terminate()
                    final_key = _combine_private_keys(seed_private_key, delta_key)
                    derived_addr = Account.from_key(final_key).address
                    if _wallet_matches(derived_addr, wallet_prefix, wallet_suffix):
                        result = _check_contract_nonces(final_key)
                        if result:
                            return result
                    break  # no match or no contract match — re-launch with new seed

                if deadline and time.perf_counter() >= deadline:
                    _terminate()
                    break
                time.sleep(0.1)
            else:
                # Process exited naturally
                stdout_t.join(timeout=2)
                stderr_t.join(timeout=2)
                combined = "".join(output_chunks) + "\n" + "".join(error_chunks)
                delta_key, _ = _extract_profanity2_result(combined)
                if delta_key:
                    final_key = _combine_private_keys(seed_private_key, delta_key)
                    derived_addr = Account.from_key(final_key).address
                    if _wallet_matches(derived_addr, wallet_prefix, wallet_suffix):
                        result = _check_contract_nonces(final_key)
                        if result:
                            return result
        finally:
            _active_profanity2_proc = None
            if process.poll() is None:
                process.kill()

    return []


def _format_duration(seconds):
    """Human-readable duration string."""
    if seconds < 1:
        return "< 1 second"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    if seconds < 86400:
        h, rem = divmod(int(seconds), 3600)
        m = rem // 60
        return f"{h}h {m}m"
    d, rem = divmod(int(seconds), 86400)
    h = rem // 3600
    return f"{d}d {h}h"

def _wallet_matches(wallet_address, wallet_prefix, wallet_suffix):
    wallet_lower = wallet_address.lower()
    if wallet_prefix and not wallet_lower.startswith('0x' + wallet_prefix.lower()):
        return False
    if wallet_suffix and not wallet_lower.endswith(wallet_suffix.lower()):
        return False
    return True

def search_address(account, wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, start_nonce, max_nonce):
    wallet_address = account.address

    # Check wallet prefix/suffix once — they don't change with nonce
    if not _wallet_matches(wallet_address, wallet_prefix, wallet_suffix):
        return None, None, None, False

    for nonce in range(start_nonce, max_nonce):
        if cancel_event.is_set():
            break

        address = create_contract_address(account, nonce)
        address_lower = address.lower()

        if contract_prefix and not address_lower.startswith('0x' + contract_prefix.lower()):
            continue
        if contract_suffix and not address_lower.endswith(contract_suffix.lower()):
            continue

        return nonce, address, wallet_address, True

    return None, None, None, False


def _keygen_worker(args):
    """Generate one key and test wallet match. Runs in a child process."""
    wallet_prefix, wallet_suffix, use_private_key = args
    if use_private_key:
        account = Account.from_key(use_private_key)
        local_key = use_private_key
    else:
        account = Account.create()
        local_key = account.key.hex()
    if _wallet_matches(account.address, wallet_prefix, wallet_suffix):
        return account.address, local_key
    return None


def _cpu_worker(args):
    """Top-level function so ProcessPoolExecutor can pickle it."""
    wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, start_nonce, max_nonce, use_private_key = args
    if use_private_key:
        local_private_key = use_private_key
        account = Account.from_key(local_private_key)
    else:
        account = Account.create()
        local_private_key = account.key.hex()
    wallet_address = account.address

    # Wallet-only mode: no nonce search needed
    if not contract_prefix and not contract_suffix:
        if not _wallet_matches(wallet_address, wallet_prefix, wallet_suffix):
            return None, None, None, False, local_private_key
        return None, None, wallet_address, True, local_private_key

    nonce, address, wallet_address, found = search_address(
        account, wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, start_nonce, max_nonce
    )
    return nonce, address, wallet_address, found, local_private_key


def search_with_processes(wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, start_nonce, max_nonce, max_keys, use_private_key=None):
    global _active_executor
    results = []
    worker_count = min(max_keys, cpu_count)
    args = (wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, start_nonce, max_nonce, use_private_key)

    executor = concurrent.futures.ProcessPoolExecutor(max_workers=worker_count)
    _active_executor = executor
    futures = []
    try:
        futures = [executor.submit(_cpu_worker, args) for _ in range(max_keys)]

        for future in concurrent.futures.as_completed(futures):
            if cancel_event.is_set():
                break
            nonce, address, wallet_address, found, local_private_key = future.result()
            if found:
                results.append((nonce, address, wallet_address, local_private_key))
                break
    finally:
        for f in futures:
            f.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        _active_executor = None

    return results

def search_with_gpu_accel(wallet_prefix, wallet_suffix, contract_prefix, contract_suffix,
                         start_nonce, max_nonce, max_keys, gpu_searchers,
                         use_private_key=None, gpu_batch_size=1 << 20, gpu_max_cu=None):
    """GPU-accelerated search across one or more GPUs.

    Key generation runs in a ProcessPoolExecutor (bypasses GIL) so the
    GPU is kept fed with candidates without a CPU bottleneck.
    """
    global _active_executor
    if not isinstance(gpu_searchers, list):
        gpu_searchers = [gpu_searchers]

    results = []
    result_lock = threading.Lock()
    found_event = threading.Event()
    candidate_queue = queue.Queue(maxsize=max(16, len(gpu_searchers) * 8))
    producers_done = threading.Event()

    # Use multiprocessing for key generation to avoid GIL bottleneck
    keygen_args = (wallet_prefix, wallet_suffix, use_private_key)
    keygen_count = 1 if use_private_key else max_keys
    worker_count = 1 if use_private_key else min(cpu_count, max_keys)
    executor = concurrent.futures.ProcessPoolExecutor(max_workers=worker_count)
    _active_executor = executor

    def feed_candidates():
        """Generate keys via process pool, queue wallet matches for GPU."""
        pending = set()
        max_pending = worker_count * 4
        submitted = 0
        try:
            while submitted < keygen_count and not cancel_event.is_set() and not found_event.is_set():
                # Keep pipeline full
                while len(pending) < max_pending and submitted < keygen_count:
                    if cancel_event.is_set() or found_event.is_set():
                        break
                    pending.add(executor.submit(_keygen_worker, keygen_args))
                    submitted += 1

                if not pending:
                    break

                done, pending = concurrent.futures.wait(
                    pending, timeout=0.1,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for future in done:
                    if cancel_event.is_set() or found_event.is_set():
                        break
                    try:
                        result = future.result()
                    except Exception:
                        continue
                    if result is None:
                        continue
                    wallet_address, local_key = result

                    if not contract_prefix and not contract_suffix:
                        with result_lock:
                            results.append((None, None, wallet_address, local_key))
                        found_event.set()
                        return

                    while not cancel_event.is_set() and not found_event.is_set():
                        try:
                            candidate_queue.put((wallet_address, local_key), timeout=0.1)
                            break
                        except queue.Full:
                            continue
        finally:
            for f in pending:
                f.cancel()
            producers_done.set()

    def gpu_worker(searcher):
        while True:
            if cancel_event.is_set() or found_event.is_set():
                break

            try:
                wallet_address, local_private_key = candidate_queue.get(timeout=0.1)
            except queue.Empty:
                if producers_done.is_set():
                    break
                continue

            try:
                nonce = searcher.search_nonces(
                    wallet_address[2:], start_nonce, max_nonce,
                    contract_prefix, contract_suffix,
                    batch_size=gpu_batch_size, max_cu=gpu_max_cu,
                    stop_event=found_event,
                )
                if found_event.is_set():
                    break
                if nonce is not None:
                    addr = create_contract_address(Account.from_key(local_private_key), nonce)
                    with result_lock:
                        results.append((nonce, addr, wallet_address, local_private_key))
                    found_event.set()
                    break
            finally:
                candidate_queue.task_done()

    # Start feeder thread (dispatches to process pool internally)
    feed_thread = threading.Thread(target=feed_candidates, daemon=True)
    feed_thread.start()

    # Start GPU worker threads
    gpu_threads = []
    for searcher in gpu_searchers:
        t = threading.Thread(target=gpu_worker, args=(searcher,), daemon=True)
        gpu_threads.append(t)
        t.start()

    feed_thread.join()
    for t in gpu_threads:
        t.join()

    try:
        executor.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass
    _active_executor = None

    return results

def input_private_key():
    global private_key

    prompt_text = "Enter a private key (leave empty for a randomly generated one):"
    key = simpledialog.askstring("Private Key", prompt_text)
    if key:
        try:
            Account.from_key(key)
            private_key = key
            entry_max_keys.delete(0, tk.END)
            entry_max_keys.insert(0, "1")
            status_label.config(text="Custom private key set.", foreground="blue")
        except (ValueError, Exception):
            messagebox.showerror("Error", "Invalid private key.")
            private_key = None
    else:
        private_key = None
        status_label.config(text="Using random key generation.", foreground="gray")

def copy_private_key_to_clipboard(key):
    pyperclip.copy(key)
    messagebox.showinfo("Copied", "Private key copied to clipboard.")

def set_ui_searching(searching):
    """Enable/disable controls while a search is running."""
    state = 'disabled' if searching else 'normal'
    search_button.config(state=state)
    pk_button.config(state=state)
    cancel_button.config(state='normal' if searching else 'disabled')
    for entry in (entry_wallet_prefix, entry_wallet_suffix, entry_contract_prefix,
                  entry_contract_suffix, entry_start_nonce, entry_max_nonce, entry_max_keys):
        entry.config(state=state)
    for chk in gpu_checks:
        chk.config(state=state if gpu_detected else 'disabled')
    gpu_batch_slider.config(state=state if gpu_detected else 'disabled')
    gpu_cu_slider.config(state=state if gpu_detected else 'disabled')
    if 'backend_button' in globals() and not backend_setup_in_progress:
        backend_button.config(state=state)
    _refresh_backend_status_ui()

def start_search():
    global private_key
    wallet_prefix = entry_wallet_prefix.get().strip()
    wallet_suffix = entry_wallet_suffix.get().strip()
    contract_prefix = entry_contract_prefix.get().strip()
    contract_suffix = entry_contract_suffix.get().strip()

    if not is_valid_prefix_suffix(wallet_prefix, wallet_suffix) or not is_valid_prefix_suffix(contract_prefix, contract_suffix):
        messagebox.showerror("Error", "Prefix/suffix must be 10 characters or less and valid hexadecimal (0-9, a-f).")
        return

    if not wallet_prefix and not wallet_suffix and not contract_prefix and not contract_suffix:
        messagebox.showerror("Error", "Please enter at least one prefix or suffix to search for.")
        return

    wallet_only = not contract_prefix and not contract_suffix

    try:
        max_keys = int(entry_max_keys.get())
    except ValueError:
        messagebox.showerror("Error", "Max Keys must be a valid integer.")
        return
    if max_keys < 1:
        messagebox.showerror("Error", "Max Keys must be at least 1.")
        return

    if wallet_only:
        start_nonce = 0
        max_nonce = 1
    else:
        try:
            start_nonce = int(entry_start_nonce.get())
            max_nonce = int(entry_max_nonce.get())
        except ValueError:
            messagebox.showerror("Error", "Start Nonce and Max Nonce must be valid integers.")
            return

        if start_nonce < 0 or max_nonce <= start_nonce:
            messagebox.showerror("Error", "Max Nonce must be greater than Start Nonce, and both must be non-negative.")
            return

    nonce_range = max_nonce - start_nonce

    # Calculate probability for the requested search space
    p_overall, p_per_key, expected_keys = _calc_probability(
        wallet_prefix, wallet_suffix, contract_prefix, contract_suffix, nonce_range, max_keys
    )

    cancel_event.clear()
    set_ui_searching(True)
    selected_gpu_indices = _selected_gpu_indices()
    gpu_requested = bool(selected_gpu_indices) and gpu_detected
    has_wallet_pattern = bool(wallet_prefix or wallet_suffix)
    use_backend_gpu = gpu_requested and wallet_only and private_key is None and profanity2_available
    use_combined_gpu = (
        gpu_requested and not wallet_only
        and has_wallet_pattern
        and private_key is None
        and profanity2_available
    )
    use_opencl_gpu = gpu_requested and not wallet_only and not use_combined_gpu
    if wallet_only:
        if use_backend_gpu:
            enabled_names = [all_gpus[i]['name'] for i in selected_gpu_indices]
            mode = f"GPU backend ({', '.join(enabled_names)})"
        else:
            mode = f"{cpu_count} CPU cores (wallet-only)"
    elif use_combined_gpu:
        enabled_names = [all_gpus[i]['name'] for i in selected_gpu_indices]
        mode = f"GPU wallet + nonces ({', '.join(enabled_names)})"
    elif use_opencl_gpu:
        enabled_names = [all_gpus[i]['name'] for i in selected_gpu_indices]
        mode = f"GPU ({', '.join(enabled_names)})"
    else:
        mode = f"{cpu_count} CPU cores"

    prob_pct = p_overall * 100
    if prob_pct >= 99.99:
        prob_str = ">99.99%"
    elif prob_pct < 0.01:
        prob_str = f"{prob_pct:.2e}%"
    else:
        prob_str = f"{prob_pct:.2f}%"

    status_label.config(
        text=f"Preparing... {mode}  |  Prob: {prob_str}  |  Estimating throughput",
        foreground="orange",
    )
    root.update_idletasks()

    def run():
        searchers = None
        if use_backend_gpu:
            try:
                # Use cached rate for initial ETA if available; real speed
                # is detected inline from profanity2's live output —
                # no separate benchmark launch, no double GPU init.
                cache_key = ("profanity2_hps", profanity2_path, tuple(selected_gpu_indices))
                cached_rate = throughput_cache.get(cache_key)
                if cached_rate:
                    est_seconds = max_keys / cached_rate
                    est_full = expected_keys / cached_rate
                    eta_str = (
                        f"ETA if no match: {_format_duration(est_seconds)}  |  "
                        f"Avg to match: {_format_duration(est_full)}"
                    )
                else:
                    eta_str = "Initialising GPU..."

                root.after(0, lambda _es=eta_str: status_label.config(
                    text=f"Searching... {mode}  |  Prob: {prob_str}  |  {_es}",
                    foreground="orange",
                ))

                def _on_speed(speed):
                    es = max_keys / speed
                    ef = expected_keys / speed
                    root.after(0, lambda: status_label.config(
                        text=(
                            f"Searching... {mode}  |  "
                            f"Prob: {prob_str}  |  "
                            f"ETA if no match: {_format_duration(es)}  |  "
                            f"Avg to match: {_format_duration(ef)}"
                        ),
                        foreground="orange",
                    ))

                results = search_with_profanity2(
                    wallet_prefix, wallet_suffix, max_keys,
                    profanity2_path, selected_gpu_indices,
                    on_speed_detected=_on_speed,
                )
            except Exception as e:
                root.after(0, lambda: status_label.config(
                    text=f"GPU backend failed: {e} — fell back to CPU", foreground="red"))
                keys_per_sec = _estimate_keys_per_second(
                    wallet_only=True,
                    use_gpu=False,
                    nonce_range=nonce_range,
                )
                est_seconds = max_keys / keys_per_sec
                est_full = expected_keys / keys_per_sec
                root.after(0, lambda: status_label.config(
                    text=(
                        f"Searching... {cpu_count} CPU cores (wallet-only)  |  "
                        f"Prob: {prob_str}  |  "
                        f"ETA if no match: {_format_duration(est_seconds)}  |  "
                        f"Avg to match: {_format_duration(est_full)}"
                    ),
                    foreground="orange",
                ))
                results = search_with_processes(
                    wallet_prefix, wallet_suffix, contract_prefix, contract_suffix,
                    start_nonce, max_nonce, max_keys,
                    use_private_key=private_key,
                )
        elif use_combined_gpu:
            batch_exp = gpu_batch_slider.get()
            batch_sz = 1 << batch_exp
            max_cu_val = gpu_cu_slider.get()
            try:
                # Create one GPU searcher for nonce checking
                enabled = [all_gpus[i] for i in selected_gpu_indices]
                nonce_searcher = GPUSearcher(enabled[0]['platform_idx'], enabled[0]['device_idx']) if GPU_AVAILABLE else None

                cache_key = ("profanity2_hps", profanity2_path, tuple(selected_gpu_indices))
                cached_rate = throughput_cache.get(cache_key)
                if cached_rate:
                    est_seconds = max_keys / cached_rate
                    est_full = expected_keys / cached_rate
                    eta_str = (
                        f"ETA if no match: {_format_duration(est_seconds)}  |  "
                        f"Avg to match: {_format_duration(est_full)}"
                    )
                else:
                    eta_str = "Initialising GPU..."

                root.after(0, lambda _es=eta_str: status_label.config(
                    text=f"Searching... {mode}  |  Prob: {prob_str}  |  {_es}",
                    foreground="orange",
                ))

                def _on_combined_speed(speed):
                    es = max_keys / speed
                    ef = expected_keys / speed
                    root.after(0, lambda: status_label.config(
                        text=(
                            f"Searching... {mode}  |  "
                            f"Prob: {prob_str}  |  "
                            f"ETA if no match: {_format_duration(es)}  |  "
                            f"Avg to match: {_format_duration(ef)}"
                        ),
                        foreground="orange",
                    ))

                results = search_combined_with_profanity2(
                    wallet_prefix, wallet_suffix,
                    contract_prefix, contract_suffix,
                    start_nonce, max_nonce, max_keys,
                    profanity2_path, selected_gpu_indices,
                    gpu_searcher=nonce_searcher,
                    gpu_batch_size=batch_sz, gpu_max_cu=max_cu_val,
                    on_speed_detected=_on_combined_speed,
                )
            except Exception as e:
                root.after(0, lambda: status_label.config(
                    text=f"Combined GPU failed: {e} — fell back to CPU", foreground="red"))
                keys_per_sec = _estimate_keys_per_second(
                    wallet_only=False, use_gpu=False, nonce_range=nonce_range,
                )
                est_seconds = max_keys / keys_per_sec
                est_full = expected_keys / keys_per_sec
                root.after(0, lambda: status_label.config(
                    text=(
                        f"Searching... {cpu_count} CPU cores  |  "
                        f"Prob: {prob_str}  |  "
                        f"ETA if no match: {_format_duration(est_seconds)}  |  "
                        f"Avg to match: {_format_duration(est_full)}"
                    ),
                    foreground="orange",
                ))
                results = search_with_processes(
                    wallet_prefix, wallet_suffix, contract_prefix, contract_suffix,
                    start_nonce, max_nonce, max_keys,
                    use_private_key=private_key,
                )
        elif use_opencl_gpu:
            batch_exp = gpu_batch_slider.get()
            batch_sz = 1 << batch_exp
            max_cu_val = gpu_cu_slider.get()
            try:
                enabled = [all_gpus[i] for i in selected_gpu_indices]
                searchers = [GPUSearcher(g['platform_idx'], g['device_idx']) for g in enabled]
                keys_per_sec = _estimate_keys_per_second(
                    wallet_only=False,
                    use_gpu=True,
                    nonce_range=nonce_range,
                    enabled_gpu_count=len(enabled),
                    gpu_searchers=searchers,
                    gpu_batch_size=batch_sz,
                    gpu_max_cu=max_cu_val,
                )
                est_seconds = max_keys / keys_per_sec
                est_full = expected_keys / keys_per_sec
                root.after(0, lambda: status_label.config(
                    text=(
                        f"Searching... {mode}  |  "
                        f"Prob: {prob_str}  |  "
                        f"ETA if no match: {_format_duration(est_seconds)}  |  "
                        f"Avg to match: {_format_duration(est_full)}"
                    ),
                    foreground="orange",
                ))
                results = search_with_gpu_accel(
                    wallet_prefix, wallet_suffix, contract_prefix, contract_suffix,
                    start_nonce, max_nonce, max_keys, searchers,
                    use_private_key=private_key,
                    gpu_batch_size=batch_sz, gpu_max_cu=max_cu_val,
                )
            except Exception as e:
                root.after(0, lambda: status_label.config(
                    text=f"GPU failed: {e} — fell back to CPU", foreground="red"))
                keys_per_sec = _estimate_keys_per_second(
                    wallet_only=wallet_only,
                    use_gpu=False,
                    nonce_range=nonce_range,
                )
                est_seconds = max_keys / keys_per_sec
                est_full = expected_keys / keys_per_sec
                root.after(0, lambda: status_label.config(
                    text=(
                        f"Searching... {cpu_count} CPU cores  |  "
                        f"Prob: {prob_str}  |  "
                        f"ETA if no match: {_format_duration(est_seconds)}  |  "
                        f"Avg to match: {_format_duration(est_full)}"
                    ),
                    foreground="orange",
                ))
                results = search_with_processes(
                    wallet_prefix, wallet_suffix, contract_prefix, contract_suffix,
                    start_nonce, max_nonce, max_keys,
                    use_private_key=private_key,
                )
        else:
            keys_per_sec = _estimate_keys_per_second(
                wallet_only=wallet_only,
                use_gpu=False,
                nonce_range=nonce_range,
            )
            est_seconds = max_keys / keys_per_sec
            est_full = expected_keys / keys_per_sec
            root.after(0, lambda: status_label.config(
                text=(
                    f"Searching... {mode}  |  "
                    f"Prob: {prob_str}  |  "
                    f"ETA if no match: {_format_duration(est_seconds)}  |  "
                    f"Avg to match: {_format_duration(est_full)}"
                ),
                foreground="orange",
            ))
            results = search_with_processes(
                wallet_prefix, wallet_suffix, contract_prefix, contract_suffix,
                start_nonce, max_nonce, max_keys,
                use_private_key=private_key,
            )
        root.after(0, lambda: on_search_done(results))

    threading.Thread(target=run, daemon=True).start()

def cancel_search():
    cancel_event.set()
    _cleanup_active_processes()
    status_label.config(text="Cancelling...", foreground="red")


def _cleanup_active_processes():
    """Terminate active profanity2 subprocess and executor, if any."""
    global _active_profanity2_proc, _active_executor
    proc = _active_profanity2_proc
    if proc is not None:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
    executor = _active_executor
    if executor is not None:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass


def _on_close():
    """Clean shutdown: cancel searches, kill subprocesses, destroy window."""
    cancel_event.set()
    _cleanup_active_processes()
    root.destroy()


def on_search_done(results):
    set_ui_searching(False)

    if cancel_event.is_set():
        status_label.config(text="Search cancelled.", foreground="red")
        return

    if results:
        nonce, address, wallet_address, local_private_key = results[0]
        status_label.config(text="Match found!", foreground="green")

        wallet_only = (nonce is None and address is None)
        if wallet_only:
            result_message = (
                f"Congrats! Search successfully discovered:\n\n"
                f"Wallet Address: {wallet_address}\n\n"
                "Please copy and save the private key."
            )
        else:
            result_message = (
                f"Congrats! Search successfully discovered:\n\n"
                f"Contract Address: {address}\n"
                f"Nonce: {nonce}\n"
                f"Wallet Address: {wallet_address}\n\n"
                "Please copy and save the private key."
            )
        password_dialog = tk.Toplevel(root)
        password_dialog.title("Save Encrypted Private Key")
        password_dialog.resizable(False, False)

        tk.Label(password_dialog, text=result_message, justify='left').grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky='w')
        tk.Label(password_dialog, text="Enter a password to encrypt the JSON file:").grid(row=1, column=0, padx=10, pady=10, sticky='w')
        password_entry = tk.Entry(password_dialog, show='*')
        password_entry.grid(row=1, column=1, padx=10, pady=10)

        def save_encrypted_key():
            password = password_entry.get()
            if not password:
                messagebox.showwarning("Warning", "Please enter a password to encrypt the key.", parent=password_dialog)
                return
            encrypted_data = Account.encrypt(local_private_key, password)
            if wallet_only:
                init_file = wallet_address
            else:
                safe_address = address.replace(':', '-')
                init_file = f"{wallet_address}_Contract-{safe_address}_nonce-{nonce}"
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                initialfile=init_file,
                title="Save encrypted JSON file",
                parent=password_dialog,
            )
            if file_path:
                with open(file_path, "w") as file:
                    json.dump(encrypted_data, file)
                messagebox.showinfo("Saved", "Encrypted key saved successfully.", parent=password_dialog)
            password_dialog.destroy()

        def copy_key():
            copy_private_key_to_clipboard(local_private_key)

        ttk.Button(password_dialog, text="Copy Private Key", command=copy_key).grid(row=2, column=0, padx=10, pady=10)
        ttk.Button(password_dialog, text="Save", command=save_encrypted_key).grid(row=2, column=1, padx=10, pady=10)

        password_dialog.grab_set()
    else:
        status_label.config(text="No match found.", foreground="gray")
        messagebox.showinfo("Result", "No address found with the given prefixes/suffixes in the specified range.")

# ── GUI Setup ──────────────────────────────────────────────────────────────────

def main():
    global root, entry_wallet_prefix, entry_wallet_suffix, entry_contract_prefix
    global entry_contract_suffix, entry_start_nonce, entry_max_nonce, entry_max_keys
    global gpu_vars, gpu_checks, pk_button, search_button, cancel_button, status_label
    global gpu_batch_slider, gpu_cu_slider, backend_status_label, backend_button

    root = tk.Tk()
    root.title("CRYFT Vanity Tool")
    root.protocol("WM_DELETE_WINDOW", _on_close)
    atexit.register(lambda: (cancel_event.set(), _cleanup_active_processes()))
    root.columnconfigure(1, weight=1)
    style = ttk.Style(root)
    style.configure('TLabel', font=('Montserrat', 10))

    instructions = (
        "1. Enter the Contract and/or Wallet Address Prefix or Suffix (if desired).\n"
        "2. Enter the Start Nonce and the Max Nonce for the search.\n"
        "3. Enter the maximum number of private keys to check.\n"
        f"4. Click Search to start (uses {cpu_count} CPU cores or GPU if enabled).\n"
        "GPU wallet backend is used automatically for wallet-only searches when available.\n"
        "Valid hex characters: 0-9, a-f"
    )

    instruction_label = ttk.Label(root, text=instructions)
    instruction_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

    # Register hex-only input validator
    hex_vcmd = root.register(_validate_hex)

    ttk.Label(root, text="Wallet Address Prefix").grid(row=1, padx=10, pady=5, sticky='w')
    ttk.Label(root, text="Wallet Address Suffix").grid(row=2, padx=10, pady=5, sticky='w')
    ttk.Label(root, text="Contract Address Prefix").grid(row=3, padx=10, pady=5, sticky='w')
    ttk.Label(root, text="Contract Address Suffix").grid(row=4, padx=10, pady=5, sticky='w')
    ttk.Label(root, text="Start Nonce").grid(row=5, padx=10, pady=5, sticky='w')
    ttk.Label(root, text="Max Nonce").grid(row=6, padx=10, pady=5, sticky='w')
    ttk.Label(root, text="Max Keys to Check").grid(row=7, padx=10, pady=5, sticky='w')

    entry_wallet_prefix = ttk.Entry(root, validate='key', validatecommand=(hex_vcmd, '%P'))
    entry_wallet_suffix = ttk.Entry(root, validate='key', validatecommand=(hex_vcmd, '%P'))
    entry_contract_prefix = ttk.Entry(root, validate='key', validatecommand=(hex_vcmd, '%P'))
    entry_contract_suffix = ttk.Entry(root, validate='key', validatecommand=(hex_vcmd, '%P'))
    entry_start_nonce = ttk.Entry(root)
    entry_max_nonce = ttk.Entry(root)
    entry_max_keys = ttk.Entry(root)

    entry_wallet_prefix.grid(row=1, column=1, padx=10, pady=5, sticky='ew')
    entry_wallet_suffix.grid(row=2, column=1, padx=10, pady=5, sticky='ew')
    entry_contract_prefix.grid(row=3, column=1, padx=10, pady=5, sticky='ew')
    entry_contract_suffix.grid(row=4, column=1, padx=10, pady=5, sticky='ew')
    entry_start_nonce.grid(row=5, column=1, padx=10, pady=5, sticky='ew')
    entry_max_nonce.grid(row=6, column=1, padx=10, pady=5, sticky='ew')
    entry_max_keys.grid(row=7, column=1, padx=10, pady=5, sticky='ew')

    # Sensible defaults
    entry_start_nonce.insert(0, "0")
    entry_max_nonce.insert(0, "1000")
    entry_max_keys.insert(0, "100")

    # GPU Acceleration frame
    gpu_frame = ttk.LabelFrame(root, text="GPU Acceleration")
    gpu_frame.grid(row=8, column=0, columnspan=2, padx=10, pady=5, sticky='ew')
    gpu_frame.columnconfigure(1, weight=1)

    # Define callbacks before widgets that reference them
    def _update_batch_label(exp):
        count = 1 << exp
        mem_bytes = count  # 1 byte per result
        if count >= 1_000_000:
            count_str = f"{count / 1_000_000:.1f}M"
        elif count >= 1_000:
            count_str = f"{count / 1_000:.0f}K"
        else:
            count_str = str(count)
        if mem_bytes >= 1_048_576:
            mem_str = f"{mem_bytes / 1_048_576:.0f} MB"
        elif mem_bytes >= 1024:
            mem_str = f"{mem_bytes / 1024:.0f} KB"
        else:
            mem_str = f"{mem_bytes} B"
        gpu_batch_label.config(text=f"{count_str} nonces/batch (~{mem_str})")

    def _toggle_gpu_sliders():
        any_enabled = any(v.get() for v in gpu_vars) if gpu_vars else False
        if any_enabled:
            gpu_batch_slider.grid()
            gpu_batch_label.grid()
            gpu_cu_slider.grid()
            gpu_cu_label.grid()
            backend_status_label.grid()
            backend_button.grid()
            # Re-show the row labels too
            for w in gpu_frame.grid_slaves():
                info = w.grid_info()
                r = int(info.get('row', -1))
                if r in (slider_start, slider_start + 1) and isinstance(w, ttk.Label) and w not in (gpu_batch_label, gpu_cu_label, backend_status_label):
                    w.grid()
        else:
            gpu_batch_slider.grid_remove()
            gpu_batch_label.grid_remove()
            gpu_cu_slider.grid_remove()
            gpu_cu_label.grid_remove()
            backend_status_label.grid_remove()
            backend_button.grid_remove()
            for w in gpu_frame.grid_slaves():
                info = w.grid_info()
                r = int(info.get('row', -1))
                if r in (slider_start, slider_start + 1) and isinstance(w, ttk.Label) and w not in (gpu_batch_label, gpu_cu_label, backend_status_label):
                    w.grid_remove()

    # Per-GPU checkboxes
    gpu_vars = []
    gpu_checks = []
    if all_gpus:
        for i, gpu_info in enumerate(all_gpus):
            var = tk.BooleanVar(value=True)
            label = f"{gpu_info['name']} ({gpu_info['mem_mb']} MB, {gpu_info['compute_units']} CU)"
            chk = ttk.Checkbutton(gpu_frame, text=label, variable=var, command=_toggle_gpu_sliders)
            chk.grid(row=i, column=0, columnspan=3, padx=5, pady=2, sticky='w')
            gpu_vars.append(var)
            gpu_checks.append(chk)
        slider_start = len(all_gpus)
    else:
        ttk.Label(gpu_frame, text="No GPU available", foreground="gray").grid(
            row=0, column=0, columnspan=3, padx=5, pady=3)
        slider_start = 1

    # Batch size slider (controls VRAM usage): 2^14 (16K) to 2^24 (16M)
    ttk.Label(gpu_frame, text="Batch Size (VRAM)").grid(row=slider_start, column=0, padx=5, pady=3, sticky='w')
    gpu_batch_slider = tk.Scale(gpu_frame, from_=14, to=24, orient=tk.HORIZONTAL,
                                label="", command=lambda v: _update_batch_label(int(v)))
    gpu_batch_slider.set(20)  # Default 1M
    gpu_batch_slider.grid(row=slider_start, column=1, padx=5, pady=3, sticky='ew')
    gpu_batch_label = ttk.Label(gpu_frame, text="1.0M nonces/batch (~1 MB)")
    gpu_batch_label.grid(row=slider_start, column=2, padx=5, pady=3, sticky='w')

    # Compute units slider
    cu_max = max((g['compute_units'] for g in all_gpus), default=1) if all_gpus else 1
    ttk.Label(gpu_frame, text="Compute Units").grid(row=slider_start + 1, column=0, padx=5, pady=3, sticky='w')
    gpu_cu_slider = tk.Scale(gpu_frame, from_=1, to=cu_max, orient=tk.HORIZONTAL)
    gpu_cu_slider.set(cu_max)  # Default: use all
    gpu_cu_slider.grid(row=slider_start + 1, column=1, padx=5, pady=3, sticky='ew')
    gpu_cu_label = ttk.Label(gpu_frame, text=f"of {cu_max} available")
    gpu_cu_label.grid(row=slider_start + 1, column=2, padx=5, pady=3, sticky='w')

    backend_status_label = ttk.Label(gpu_frame, text="", foreground="gray")
    backend_status_label.grid(row=slider_start + 2, column=0, columnspan=3, padx=5, pady=(8, 2), sticky='w')

    backend_button = ttk.Button(gpu_frame, text='Set Up Backend', command=setup_backend)
    backend_button.grid(row=slider_start + 3, column=0, columnspan=3, padx=5, pady=(0, 4), sticky='w')

    _toggle_gpu_sliders()
    _refresh_backend_status_ui()

    # Optional private key
    ttk.Label(root, text="Optional", font=('Montserrat', 8)).grid(row=9, column=0, columnspan=2, pady=(5, 0))

    pk_button = ttk.Button(root, text='Enter Private Key', command=input_private_key)
    pk_button.grid(row=10, column=0, columnspan=2, padx=10, pady=5)

    # Search / Cancel buttons side-by-side
    btn_frame = ttk.Frame(root)
    btn_frame.grid(row=11, column=0, columnspan=2, padx=10, pady=5)
    search_button = ttk.Button(btn_frame, text='Search', command=start_search)
    search_button.pack(side='left', padx=5)
    cancel_button = ttk.Button(btn_frame, text='Cancel', command=cancel_search, state='disabled')
    cancel_button.pack(side='left', padx=5)

    # Status label at the bottom
    gpu_count = len(all_gpus)
    ready_text = f"Ready — {cpu_count} CPU cores"
    if gpu_count:
        ready_text += f", {gpu_count} GPU{'s' if gpu_count > 1 else ''}"
    if profanity2_available:
        ready_text += ", wallet GPU backend available"
    ready_text += " available"
    status_label = ttk.Label(root, text=ready_text, foreground="gray", font=('Montserrat', 9))
    status_label.grid(row=12, column=0, columnspan=2, padx=10, pady=(0, 10))

    root.mainloop()


if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()
