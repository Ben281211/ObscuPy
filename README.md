# ObscuPy – Ultimate Python Obfuscator (Windows-only)

**ObscuPy** is a high-security Python obfuscator designed to make reverse engineering extremely difficult.  
It combines **Cython compilation**, multi-stage encryption, anti-debugging checks, and an in-memory execution loader — specifically for **Windows**.

## Features

- **Cython Compilation** → Converts Python code into native machine code.  
- **AES + XOR + Compression** → Multi-stage encryption pipeline.  
- **Memory-Only Execution** → Protected code never stays permanently on disk.  
- **Anti-Debugging & Integrity Checks** → Program terminates if tampering is detected.  
- **Opaque Control Flow & String Obfuscation** → Prevents reverse engineering and decompiling.  
- **Automatic Cleanup** → Temporary files removed in the background.  

## System Requirements

- **Windows only**  
- Python 3.8+  
- Cython & PyCryptodome  

## Installation

```bash
pip install cython pycryptodome

## Usage

```bash
python ObscuPy.py input.py output.py

- input.py — Your original Python script
- output.py — The encrypted loader that executes the protected binary

## Notes

- Your code must be Cython-compatible.
- Ideal for commercial software, proprietary algorithms, or any Python code that must remain private.
- Windows-only: Does not run on Linux or macOS.