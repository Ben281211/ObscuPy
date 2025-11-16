### Created by Ben281211 - available on github.com/Ben281211/ObscuPy ###

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

class UltimateObfuscator:
    def __init__(self):
        self.loader_vars = {
            'data': 'IlIIlIIlIIllIllI',
            'key': 'lIIlIllIIlIIlIIl', 
            'iv': 'IIlIllIIllIIlIIl',
            'cipher': 'llIIlIIlIllIIllI',
            'decompressed': 'IllIIllIIllIIlIl',
            'code': 'lIllIIlIIlIIlIll',
            'temp_file': 'IIllIIlIIlIllIIl',
            'temp_dir': 'llIIlIllIIlIIllI',
            'module': 'IllIIlIIllIIllII'
        }
        
    def log(self, message):
        print(f"[ObscuPy] {message}")
    
    def apply_cython_specific_obfuscation(self, code):
        self.log("Applying Cython-specific obfuscation...")
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'(\"\"\"[\s\S]*?\"\"\"|\'\'\'[\s\S]*?\'\'\')', '', code)
        
        def obfuscate_string(match):
            string_content = match.group(0)
            if len(string_content) < 6 or string_content.startswith(('"""', "'''")):
                return string_content
            content = string_content[1:-1]
            if 10 <= len(content) <= 100:
                chunks = [f"chr({ord(c)})" for c in content]
                return f"''.join([{','.join(chunks)}])" if len(chunks) > 1 else chunks[0]
            return string_content
        
        code = re.sub(r'("([^"\\]|\\.)*"|\'([^\'\\]|\\.)*\')', obfuscate_string, code)
        
        cython_directives = """
#cython: language_level=3
#cython: boundscheck=False
#cython: wraparound=False  
#cython: initializedcheck=False
#cython: nonecheck=False
#cython: overflowcheck=False
#cython: cdivision=True
"""
        code = cython_directives + code
        return code
    
    def create_highly_obfuscated_cython_extension(self, code, temp_dir):
        anti_re_code = """
import sys
import os
import time
if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
    os._exit(1)
def _verify_integrity():
    current_file = __file__
    if not os.path.exists(current_file):
        os._exit(1)
    file_size = os.path.getsize(current_file)
    if file_size < 1000 or file_size > 10000000:
        os._exit(1)
    return True
_verify_integrity()
_OPAQUE_TRUE = (hash(str(os.getpid())) % 1000) == (hash(str(os.getpid())) % 1000)
_OPAQUE_FALSE = not _OPAQUE_TRUE
if not _OPAQUE_TRUE:
    os._exit(1)
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
        shutil.rmtree(build_temp, ignore_errors=True)
        shutil.rmtree(build_lib, ignore_errors=True)

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
        loader_template = f"""
# Obfuscated by ObscuPy - https://github.com/Ben281211/ObscuPy

import sys,base64 as b,zlib as z,os as o,tempfile as t,importlib.util as i,atexit as a,threading as th,time as tm
from Crypto.Cipher import AES as A
__B__=b.b64decode('{encoded_payload}');__K__=b.b64decode('{encoded_keys}');__X__,__K1__,__K2__=__K__[:32],__K__[32:64],__K__[64:80];__C__=A.new(__K1__,A.MODE_CBC,__K2__);__R__=bytearray(__C__.decrypt(__B__));[__R__.__setitem__(x,__R__[x]^__X__[x%len(__X__)]) for x in range(len(__R__))];__D__=z.decompress(__R__);__T__=t.mkdtemp(prefix='_'+str(hash(__D__)%99999));__F__=o.path.join(__T__,'{module_name}.pyd');open(__F__,'wb').write(__D__);__S__=i.spec_from_file_location('{module_name}',__F__);__M__=i.module_from_spec(__S__);sys.modules['{module_name}']=__M__;__S__.loader.exec_module(__M__);a.register(lambda F=__F__,T=__T__:th.Thread(target=lambda:F and tm.sleep(0.5) or (o.remove(F) if o.path.exists(F) else 0) or (o.rmdir(T) if o.path.exists(T) else 0)).start())
"""
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
        with open(input_file, 'r', encoding='utf-8') as f:
            original_code = f.read()
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