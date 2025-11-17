# ObscuPy – Ultimate Python Obfuscator (Windows-Only)
Created by **Ben281211** — https://github.com/Ben281211/ObscuPy

**ObscuPy** is an advanced, high-security Python obfuscator designed to make reverse-engineering *extremely* difficult. It uses **Cython compilation**, **multi-layer encryption**, **anti-debugging**, and a **memory-only execution loader** to keep your code protected.

> ⚠️ **Windows-only.** The tool relies on Windows-specific compilation and anti-debugging APIs.

---

## Features

- **Native Compilation (Cython)** — Transforms Python source into optimized machine code (`.pyd`).
- **Multi-Stage Encryption Pipeline** — zlib compression → XOR (PBKDF2-derived key) → AES-256-CBC → Base64 packaging.
- **Memory-Only Execution** — Decrypted binary runs from memory and is removed automatically.
- **Anti-Debugging & Anti-VM** — Multiple checks (Python-level and native) with a watchdog thread.
- **Strings & Imports Obfuscation** — Randomized names, obfuscated string literals, and multiple import styles.
- **Junk Code Injection** — Random harmless functions and noise to confuse static analysis.
- **Automatic Cleanup** — Temporary files removed asynchronously after execution.

---

## System Requirements

- **OS:** Windows 10 / 11
- **Python:** 3.8+
- **Dependencies:** `Cython`, `pycryptodome`
- **Build Tools:** Microsoft Visual C++ / Build Tools (for compiling Cython extensions)

---

## Installation

```bash
pip install cython pycryptodome
```

Make sure Microsoft Build Tools are installed and available in your environment.

---

## Usage

```bash
python ObscuPy.py input.py output.py
```

- `input.py` — your original Python script
- `output.py` — the generated obfuscated loader (pure Python loader + encrypted payload)

The loader will: decode the payload, derive keys (PBKDF2), decrypt and decompress the protected `.pyd` binary, write it to a temporary location, import it in-memory, then schedule cleanup.

---

## Notes & Limitations

- Input code must be **valid Python 3** and **Cython-compatible**.
- Highly dynamic or reflection-heavy code may require manual tweaks to work after Cython compilation.
- Large projects increase compilation time and binary size.
- Intended for **Windows-only** deployment (anti-debug/Win32 APIs are Windows-specific).
- This tool focuses on hindering reverse engineering; it is not a replacement for legal protection or secure licensing.

---

## Example

Command-line:

```bash
python ObscuPy.py example_script.py protected_loader.py
```

After successful run, `protected_loader.py` will be the obfuscated loader you can distribute.

---

## Contributing

PRs, issues, and suggestions are welcome. Keep changes focused on portability, usability, and improved protection strategies. Please provide tests for behavior changes.

---

## Disclaimer

Use this tool responsibly. Obfuscation increases the difficulty of reverse engineering but cannot guarantee absolute secrecy. Do not use this project for malicious or unlawful activities.

---

*Maintainer:* Ben281211 — https://github.com/Ben281211