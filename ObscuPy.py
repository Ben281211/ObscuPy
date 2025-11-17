### Created by Ben281211 - available on github.com/Ben281211/ObscuPy

import os
import sys
import re
import textwrap
import base64
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import subprocess
import shutil
import glob
import uuid
import time
import ast
import random
import string

def gen_name(length):
    alphabet = 'lI'
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
            'module': gen_name(8),
            'passw': gen_name(8),
            'xor_salt': gen_name(8),
            'aes_salt': gen_name(8),
            'imp_kdf': gen_name(8),
            'imp_sha': gen_name(8),
            'imp_crypto': gen_name(8),
            'imp_importlib': gen_name(8)
        }
        
    def log(self, message):
        print(f"[ObscuPy] {message}")
    
    def obf_str(self, s):
        return "''.join(chr(i) for i in [%s])" % ','.join(map(str, [ord(c) for c in s]))
    
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

    def generate_junk_code(self):
        junk = []
        for _ in range(random.randint(5, 20)):
            func_name = gen_name(random.randint(5, 15))
            junk.append(f"def {func_name}():\n    a = {random.randint(1, 100)}\n    b = a * {random.randint(1, 10)}\n    if b % 2 == 0:\n        return b\n    else:\n        return a\n")
        return "\n".join(junk) + "\n"

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
        is_remote = ctypes.c_bool()
        kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(is_remote))
        if is_remote.value:
            return True
    except:
        pass
    try:
        if os.path.exists('/proc/self/status'):
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith('TracerPid:'):
                        pid = int(line.split()[1])
                        if pid != 0:
                            return True
    except:
        pass
    return False

def _check_timing():
    start = time.time()
    total = 0
    for i in range(1000000):
        total += i % 10
    end = time.time()
    if end - start > 0.5:
        return True
    return False

def _is_vm():
    try:
        if os.path.exists('/sys/class/dmi/id/product_name'):
            with open('/sys/class/dmi/id/product_name', 'r') as f:
                content = f.read().lower()
                if 'virtualbox' in content or 'vmware' in content or 'qemu' in content:
                    return True
    except:
        pass
    try:
        if 'VIRTUAL' in os.environ.get('COMPUTERNAME', '').upper():
            return True
    except:
        pass
    return False

if _is_debugging() or _check_timing() or _is_vm():
    print("Sike")
    os._exit(1)

def _watchdog():
    while True:
        if _is_debugging() or _check_timing() or _is_vm():
            print("Sike")
            os._exit(1)
        time.sleep(1)

threading.Thread(target=_watchdog, daemon=True).start()
"""
        junk_code = self.generate_junk_code()
        protected_code = anti_re_code + junk_code + "\n" + code
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
                self.log(f"Build stderr: {result.stderr}")
                return None, None
        except Exception as e:
            self.log(f"Cython compilation error: {str(e)}")
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
            self.log(f"Error reading compiled binary: {str(e)}")
            return None, None

        try:
            os.remove(compiled_file)
        except:
            pass
        shutil.rmtree(build_temp, ignore_errors=True)
        shutil.rmtree(build_lib, ignore_errors=True)

        return binary_data, module_name
    
    def encrypt_binary(self, binary_data):
        compressed = zlib.compress(binary_data, level=9)
        xor_salt = os.urandom(16)
        aes_salt = os.urandom(16)
        passw = b'ObscuPy_V2'
        xor_key = PBKDF2(passw, xor_salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
        aes_key = PBKDF2(passw, aes_salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
        aes_iv = os.urandom(16)
        xor_encrypted = bytearray(b ^ xor_key[i % 32] for i, b in enumerate(compressed))
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        aes_encrypted = cipher.encrypt(pad(xor_encrypted, AES.block_size))
        encoded_payload = base64.b64encode(aes_encrypted).decode('ascii')
        encoded_keys = base64.b64encode(xor_salt + aes_salt + aes_iv).decode('ascii')
        return encoded_payload, encoded_keys
    
    def create_ultimate_loader(self, encoded_payload, encoded_keys, module_name):
        self.log("Building ObscuPy loader")

        v_B = self.loader_vars['data']
        v_K = self.loader_vars['key']
        v_XS = self.loader_vars['xor_salt']
        v_AS = self.loader_vars['aes_salt']
        v_IV = self.loader_vars['iv']
        v_X = gen_name(16)
        v_K1 = gen_name(16)
        v_C = self.loader_vars['cipher']
        v_R = gen_name(16)
        v_D = self.loader_vars['decompressed']
        v_T = self.loader_vars['temp_dir']
        v_F = self.loader_vars['temp_file']
        v_S = gen_name(16)
        v_M = self.loader_vars['module']
        v_P = self.loader_vars['passw']

        imp_sys = gen_name(16)
        imp_b64 = gen_name(16)
        imp_zlib = gen_name(16)
        imp_os = gen_name(16)
        imp_tmp = gen_name(16)
        imp_util = gen_name(16)
        imp_exit = gen_name(16)
        imp_thr = gen_name(16)
        imp_time = gen_name(16)
        imp_crypto = self.loader_vars['imp_crypto']
        imp_aes = gen_name(16)
        imp_kdf = self.loader_vars['imp_kdf']
        imp_sha = self.loader_vars['imp_sha']
        imp_importlib = self.loader_vars['imp_importlib']

        modules = {
            'sys': imp_sys,
            'base64': imp_b64,
            'zlib': imp_zlib,
            'os': imp_os,
            'tempfile': imp_tmp,
            'atexit': imp_exit,
            'threading': imp_thr,
            'time': imp_time,
            'importlib.util': imp_util
        }

        import_style = random.choice(['comma', 'import__', 'import_module'])
        import_codes = []
        if import_style == 'comma':
            import_list = ', '.join(f"{mod} as {alias}" for mod, alias in modules.items())
            import_codes.append(f"import {import_list}")
        elif import_style == 'import__':
            import_codes.append(f"{imp_sys}=__import__({self.obf_str('sys')})")
            for mod, alias in modules.items():
                if mod == 'sys': continue
                import_codes.append(f"{alias}=__import__({self.obf_str(mod)})")
        elif import_style == 'import_module':
            import_codes.append(f"{imp_importlib}=__import__({self.obf_str('importlib')})")
            for mod, alias in modules.items():
                import_codes.append(f"{alias}={imp_importlib}.import_module({self.obf_str(mod)})")

        imports = ';'.join(import_codes) + ';'

        setup_codes = [
            f"{imp_crypto}=__import__({self.obf_str('Crypto.Cipher')},fromlist=[{self.obf_str('AES')}])",
            f"{imp_aes}=getattr({imp_crypto},{self.obf_str('AES')})",
            f"{imp_crypto}=__import__({self.obf_str('Crypto.Protocol.KDF')},fromlist=[{self.obf_str('PBKDF2')}])",
            f"{imp_kdf}=getattr({imp_crypto},{self.obf_str('PBKDF2')})",
            f"{imp_crypto}=__import__({self.obf_str('Crypto.Hash')},fromlist=[{self.obf_str('SHA256')}])",
            f"{imp_sha}=getattr({imp_crypto},{self.obf_str('SHA256')})",
        ]
        setups = ';'.join(setup_codes) + ';'

        pass_list = ','.join(str(ord(c)) for c in 'ObscuPy_V2')
        pass_code = f"{v_P}=bytes([{pass_list}]);"

        loader_template = f"""# Obfuscated by ObscuPy - https://github.com/Ben281211/ObscuPy \n\n{imports}{setups}{pass_code}{v_B}=getattr({imp_b64},{self.obf_str('b64decode')})('{encoded_payload}');{v_K}=getattr({imp_b64},{self.obf_str('b64decode')})('{encoded_keys}');{v_XS},{v_AS},{v_IV}={v_K}[:16],{v_K}[16:32],{v_K}[32:];{v_X}={imp_kdf}({v_P},{v_XS},dkLen=32,count=100000,hmac_hash_module={imp_sha});{v_K1}={imp_kdf}({v_P},{v_AS},dkLen=32,count=100000,hmac_hash_module={imp_sha});{v_C}=(lambda k1,iv:getattr({imp_aes},{self.obf_str('new')})(k1,getattr({imp_aes},{self.obf_str('MODE_CBC')}),iv))({v_K1},{v_IV});{v_R}=bytearray(getattr({v_C},{self.obf_str('decrypt')})({v_B}));[{v_R}.__setitem__(i,{v_R}[i]^{v_X}[i%len({v_X})])for i in range(len({v_R}))];{v_D}=getattr({imp_zlib},{self.obf_str('decompress')})({v_R});{v_T}=getattr({imp_tmp},{self.obf_str('mkdtemp')})(prefix=str(hash({v_D})%999999)+"_");{v_F}=getattr(getattr({imp_os},{self.obf_str('path')}),{self.obf_str('join')})({v_T},"{module_name}.pyd");getattr(getattr(__builtins__,{self.obf_str('open')})({v_F},{self.obf_str('wb')}),{self.obf_str('write')})({v_D});{v_S}=getattr({imp_util},{self.obf_str('spec_from_file_location')})("{module_name}",{v_F});{v_M}=getattr({imp_util},{self.obf_str('module_from_spec')})({v_S});getattr({imp_sys},{self.obf_str('modules')})["{module_name}"]={v_M};(lambda s,m:getattr(getattr(s,{self.obf_str('loader')}),{self.obf_str('exec_module')})(m))({v_S},{v_M});getattr({imp_exit},{self.obf_str('register')})(lambda f={v_F},d={v_T}:getattr(getattr({imp_thr},{self.obf_str('Thread')})(target=lambda:(getattr({imp_time},{self.obf_str('sleep')})(0.25),getattr(getattr({imp_os},{self.obf_str('path')}),{self.obf_str('exists')})(f)and getattr({imp_os},{self.obf_str('remove')})(f),getattr(getattr({imp_os},{self.obf_str('path')}),{self.obf_str('exists')})(d)and getattr({imp_os},{self.obf_str('rmdir')})(d))),{self.obf_str('start')})())"""

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
            self.log("Failed to create Cython extension")
            shutil.rmtree(temp_dir_name, ignore_errors=True)
            return False
        encoded_payload, encoded_keys = self.encrypt_binary(cython_binary)
        loader_code = self.create_ultimate_loader(encoded_payload, encoded_keys, module_name)
        final_loader = self.add_loader_obfuscation(loader_code)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(final_loader)
        shutil.rmtree(temp_dir_name, ignore_errors=True)
        return self.verify_obfuscation(input_file, output_file, cython_binary)

def main():
    if len(sys.argv) < 3:
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
        print("Error: Cython is required. Install with 'pip install Cython'")
        sys.exit(1)
    
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("Error: pycryptodome is required. Install with 'pip install pycryptodome'")
        sys.exit(1)
    
    obfuscator = UltimateObfuscator()
    
    if obfuscator.obfuscate_file(input_file, output_file):
        obfuscator.log(f"SUCCESS: {input_file} → {output_file}")
    else:
        obfuscator.log("OBFUSCATION FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()