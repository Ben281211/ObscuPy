### Created by Ben281211 - available on github.com/Ben281211/ObscuPy

import os
import sys
import re
import textwrap
import base64
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import subprocess
import shutil
import glob
import uuid
import time
import ast
import random
import string

def gen_name(length):
    alphabet = "Il"
    return ''.join(random.choices(alphabet, k=length))

class UltimateObfuscator:
    def __init__(self):
        self.loader_vars = {
            'data': gen_name(8),
            'key': gen_name(8), 
            'iv': gen_name(8),
            'cipher': gen_name(8),
            'decompressed': gen_name(8),
            'code': gen_name(8),
            'temp_file': gen_name(8),
            'temp_dir': gen_name(8),
            'module': gen_name(8)
        }
        
    def log(self, message):
        print(f"[ObscuPy] {message}")
    
    def unwrap_main_block(self, code: str) -> str:
        tree = ast.parse(code)
        new_body = []

        for node in tree.body:
            if isinstance(node, ast.If):
                if (isinstance(node.test, ast.Compare) and
                    isinstance(node.test.left, ast.Name) and
                    node.test.left.id == "__name__" and
                    len(node.test.ops) == 1 and
                    isinstance(node.test.ops[0], ast.Eq) and
                    len(node.test.comparators) == 1 and
                    isinstance(node.test.comparators[0], ast.Constant) and
                    node.test.comparators[0].value == "__main__"):
                    new_body.extend(node.body)
                    continue
            new_body.append(node)

        new_tree = ast.Module(body=new_body, type_ignores=[])
        return ast.unparse(new_tree)

    def create_highly_obfuscated_cython_extension(self, code, temp_dir):
        self.log("Creating obfuscated Cython extension...")
        anti_re_code = """import sys
import os
import inspect
import ctypes
import threading
import time

def _is_debugging():
    if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
        return True
    if 'pdb' in sys.modules or 'pydevd' in sys.modules or 'wdb' in sys.modules:
        return True
    try:
        sys.settrace(None)
        frame = inspect.currentframe().f_back
        if frame.f_trace is not None:
            return True
    except:
        pass
    try:
        kernel32 = ctypes.windll.kernel32
        if kernel32.IsDebuggerPresent():
            return True
        if kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(ctypes.c_bool())) and ctypes.c_bool().value:
            return True
    except:
        pass
    return False

if _is_debugging():
    print("Sike Nigga")

def _watchdog():
    while True:
        if _is_debugging():
            print("Sike Nigga")
            os._exit(1)

threading.Thread(target=_watchdog, daemon=True).start()
"""
        protected_code = anti_re_code + "\n" + code
        unique_suffix = uuid.uuid4().hex[:8]
        module_name = f"ObscuPy_{unique_suffix}"

        work_dir = os.path.abspath(temp_dir)
        os.makedirs(work_dir, exist_ok=True)

        pyx_file = os.path.join(work_dir, f"{module_name}.pyx")
        with open(pyx_file, 'w', encoding='utf-8') as f:
            f.write(protected_code)

        compile_args = ["/Ox", "/Ob2", "/Ot", "/GS-", "/DNDEBUG"]
        link_args = ["/OPT:REF", "/OPT:ICF", "/LTCG"]

        build_lib = os.path.join(work_dir, "build_lib")
        build_temp = os.path.join(work_dir, "build_temp")
        os.makedirs(build_lib, exist_ok=True)
        os.makedirs(build_temp, exist_ok=True)

        setup_content = textwrap.dedent(f"""
from setuptools import setup, Extension
from Cython.Build import cythonize
extensions = [
    Extension(
        "{module_name}",
        ["{module_name}.pyx"],
        extra_compile_args={compile_args},
        extra_link_args={link_args},
        define_macros=[("NDEBUG", "1")],
    )
]
setup(
    name="{module_name}_pkg",
    ext_modules=cythonize(
        extensions,
        compiler_directives={{
            'language_level': 3,
            'boundscheck': False,
            'wraparound': False,
            'initializedcheck': False,
            'nonecheck': False,
            'overflowcheck': False,
            'cdivision': True,
        }}
    ),
)
""")
        setup_file = os.path.join(work_dir, "setup.py")
        with open(setup_file, 'w', encoding='utf-8') as f:
            f.write(setup_content)

        time.sleep(0.2)

        try:
            result = subprocess.run(
                [sys.executable, "setup.py", "build_ext", "--build-lib", build_lib, "--build-temp", build_temp, "-f"],
                cwd=work_dir, capture_output=True, text=True, timeout=600
            )
            self.log(f"Cython build returncode: {result.returncode}")
            if result.returncode != 0:
                self.log(f"Build stderr: {result.stderr[:1000]}...")
                return None, None
        except Exception as e:
            self.log(f"Cython compilation error: {e}")
            return None, None

        patterns = [os.path.join(build_lib, f"{module_name}.*.pyd"),
                    os.path.join(build_lib, f"{module_name}.pyd")]
        compiled_files = []
        for p in patterns:
            compiled_files.extend(glob.glob(p))

        if not compiled_files:
            self.log("No compiled extension found after build")
            return None, None

        compiled_file = compiled_files[0]
        try:
            with open(compiled_file, 'rb') as f:
                binary_data = f.read()
        except Exception as e:
            self.log(f"Error reading compiled binary: {e}")
            return None, None

        try:
            os.remove(compiled_file)
        except:
            pass
        shutil.rmtree(build_temp)
        shutil.rmtree(build_lib)

        return binary_data, module_name
    
    def encrypt_binary(self, binary_data):
        compressed = zlib.compress(binary_data, level=9)
        xor_key = os.urandom(32)
        xor_encrypted = bytearray()
        for i, byte in enumerate(compressed):
            xor_encrypted.append(byte ^ xor_key[i % len(xor_key)])
        aes_key = os.urandom(32)
        aes_iv = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        aes_encrypted = cipher.encrypt(pad(bytes(xor_encrypted), AES.block_size))
        encoded_payload = base64.b64encode(aes_encrypted).decode('ascii')
        encoded_keys = base64.b64encode(xor_key + aes_key + aes_iv).decode('ascii')
        return encoded_payload, encoded_keys
    
    def create_ultimate_loader(self, encoded_payload, encoded_keys, module_name):
        self.log("Building ObscuPy loader")

        v_B      = gen_name(16)
        v_K      = gen_name(16)
        v_X      = gen_name(16)
        v_K1     = gen_name(16)
        v_K2     = gen_name(16)
        v_C      = gen_name(16)
        v_R      = gen_name(16)
        v_D      = gen_name(16)
        v_T      = gen_name(16)
        v_F      = gen_name(16)
        v_S      = gen_name(16)
        v_M      = gen_name(16)

        imp_sys  = gen_name(16)
        imp_b64  = gen_name(16)
        imp_zlib = gen_name(16)
        imp_os   = gen_name(16)
        imp_tmp  = gen_name(16)
        imp_util = gen_name(16)
        imp_exit = gen_name(16)
        imp_thr  = gen_name(16)
        imp_time = gen_name(16)
        imp_aes  = gen_name(16)

        loader_template = f"""# Obfuscated by ObscuPy - https://github.com/Ben281211/ObscuPy \n\nimport sys as {imp_sys},base64 as {imp_b64},zlib as {imp_zlib},os as {imp_os},tempfile as {imp_tmp},importlib.util as {imp_util},atexit as {imp_exit},threading as {imp_thr},time as {imp_time};from Crypto.Cipher import AES as {imp_aes}\n{v_B}=getattr({imp_b64},''.join(chr(i)for i in[98,54,52,100,101,99,111,100,101]))('{encoded_payload}');{v_K}=getattr({imp_b64},''.join(chr(i)for i in[98,54,52,100,101,99,111,100,101]))('{encoded_keys}');{v_X},{v_K1},{v_K2}={v_K}[:32],{v_K}[32:64],{v_K}[64:80];{v_C}=(lambda k1,iv:getattr({imp_aes},''.join(chr(i)for i in[110,101,119]))(k1,getattr({imp_aes},''.join(chr(i)for i in[77,79,68,69,95,67,66,67])),iv))({v_K1},{v_K2});{v_R}=bytearray(getattr({v_C},''.join(chr(i)for i in[100,101,99,114,121,112,116]))({v_B}));[{v_R}.__setitem__(i,{v_R}[i]^{v_X}[i%len({v_X})])for i in range(len({v_R}))];{v_D}=getattr({imp_zlib},''.join(chr(i)for i in[100,101,99,111,109,112,114,101,115,115]))({v_R});{v_T}=getattr({imp_tmp},''.join(chr(i)for i in[109,107,100,116,101,109,112]))(prefix=str(hash({v_D})%999999)+"_");{v_F}=getattr(getattr({imp_os},''.join(chr(i)for i in[112,97,116,104])),''.join(chr(i)for i in[106,111,105,110]))({v_T},"{module_name}.pyd");getattr(getattr(__builtins__,''.join(chr(i)for i in[111,112,101,110]))({v_F},"wb"),''.join(chr(i)for i in[119,114,105,116,101]))({v_D});{v_S}=getattr({imp_util},''.join(chr(i)for i in[115,112,101,99,95,102,114,111,109,95,102,105,108,101,95,108,111,99,97,116,105,111,110]))("{module_name}",{v_F});{v_M}=getattr({imp_util},''.join(chr(i)for i in[109,111,100,117,108,101,95,102,114,111,109,95,115,112,101,99]))({v_S});getattr({imp_sys},''.join(chr(i)for i in[109,111,100,117,108,101,115]))["{module_name}"]={v_M};(lambda s,m:getattr(getattr(s,''.join(chr(i)for i in[108,111,97,100,101,114])),''.join(chr(i)for i in[101,120,101,99,95,109,111,100,117,108,101]))(m))({v_S},{v_M});getattr({imp_exit},''.join(chr(i)for i in[114,101,103,105,115,116,101,114]))(lambda f={v_F},d={v_T}:getattr(getattr({imp_thr},''.join(chr(i)for i in[84,104,114,101,97,100]))(target=lambda:(getattr({imp_time},''.join(chr(i)for i in[115,108,101,101,112]))(0.25),getattr(getattr({imp_os},''.join(chr(i)for i in[112,97,116,104])),''.join(chr(i)for i in[101,120,105,115,116,115]))(f)and getattr({imp_os},''.join(chr(i)for i in[114,101,109,111,118,101]))(f),getattr(getattr({imp_os},''.join(chr(i)for i in[112,97,116,104])),''.join(chr(i)for i in[101,120,105,115,116,115]))(d)and getattr({imp_os},''.join(chr(i)for i in[114,109,100,105,114]))(d))),''.join(chr(i)for i in[115,116,97,114,116]))())"""

        return loader_template
    
    def add_loader_obfuscation(self, loader_code):
        obfuscated_loader = re.sub(r'[ \t]+', ' ', loader_code)
        return obfuscated_loader.strip()
    
    def verify_obfuscation(self, original_file, obfuscated_file, cython_binary):
        self.log("Verifying obfuscation...")
        original_size = os.path.getsize(original_file)
        obfuscated_size = os.path.getsize(obfuscated_file)
        self.log(f"Original size: {original_size} bytes")
        self.log(f"Obfuscated size: {obfuscated_size} bytes") 
        self.log(f"Cython binary size: {len(cython_binary)} bytes")
        self.log(f"Total protection ratio: {obfuscated_size/original_size*100:.1f}%")
        return True
    
    def obfuscate_file(self, input_file, output_file):
        self.log(f"Reading input file: {input_file}")
        with open(input_file, 'r', encoding='utf-8') as f:
            original_code = f.read()
        original_code = self.unwrap_main_block(original_code)
        temp_dir_name = "ObscuPy_temp"
        os.makedirs(temp_dir_name, exist_ok=True)
        cython_binary, module_name = self.create_highly_obfuscated_cython_extension(original_code, temp_dir_name)
        if cython_binary is None:
            return False
        encoded_payload, encoded_keys = self.encrypt_binary(cython_binary)
        loader_code = self.create_ultimate_loader(encoded_payload, encoded_keys, module_name)
        final_loader = self.add_loader_obfuscation(loader_code)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(final_loader)
        return self.verify_obfuscation(input_file, output_file, cython_binary)

def main():
    if len(sys.argv) != 3:
        print("Usage: python obfuscator.py input.py output.py")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if input_file == output_file:
        print("Error: Input and output cannot be the same")
        sys.exit(1)
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist")
        sys.exit(1)
    
    try:
        import Cython
    except ImportError:
        print("Error: Cython is required")
        sys.exit(1)
    
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("Error: pycryptodome is required")
        sys.exit(1)
    
    obfuscator = UltimateObfuscator()
    
    if obfuscator.obfuscate_file(input_file, output_file):
        obfuscator.log(f"SUCCESS: {input_file} → {output_file}")
    else:
        obfuscator.log("OBFUSCATION FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()