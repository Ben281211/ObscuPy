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
import traceback
import types
import argparse

# ANSI Colors
R = "\033[31m"
G = "\033[32m"
C = "\033[36m"
Y = "\033[33m"
M = "\033[35m"
W = "\033[0m"
B = "\033[1m"


def print_banner():
    banner = f"""{R}{B}
   ____  ___.                        __________        
  / __ \ \_ |__   ______ ____  __ __ \______   \___.__.
 / /  \ \ | __ \ /  ___// ___\|  |  \ |     ___<   |  |
(  \___> > \_\ \\___ \\  \___|  |  / |    |    \___  |
 \______/|___  /____  >\___  >____/  |____|    / ____|
             \/     \/     \/                  \/      
    {W}{Y}Advanced Python Obfuscation Framework v3.0{W}
    {C}Created by Ben281211{W}
    """
    print(banner)


def gen_name(length=None):
    if length is None:
        length = random.randint(15, 25)
    return random.choice("lI") + "".join(random.choices("lI1", k=length - 1))


class ObscuPyCore:
    def __init__(self):
        self.log("Initializing core engine...", "info")
        time.sleep(0.1)
        self.log("Loading Oblivion Protocol heuristics...", "info")
        time.sleep(0.1)
        self.log("Deployment mode: ACTIVE", "success")

    def log(self, message, level="info"):
        ts = time.strftime("%H:%M:%S")
        if level == "info":
            prefix = f"{C}[*]{W}"
        elif level == "success":
            prefix = f"{G}[+]{W}"
        elif level == "error":
            prefix = f"{R}[-]{W}"
        elif level == "warn":
            prefix = f"{Y}[!]{W}"
        else:
            prefix = f"[*]"
        print(f"{W}[{ts}] {prefix} {message}{W}")

    def obf_str(self, s, strong=False):
        def s1(s):
            return f"bytes.fromhex({repr(s.encode().hex())}).decode()"

        def s2(s):
            k = random.randint(1, 255)
            return f"(lambda: ''.join(chr(i^{k}) for i in [{','.join(map(str, [ord(c) ^ k for c in s]))}]))()"

        def s3(s):
            k = random.randint(1, 100)
            return f"(lambda: ''.join(chr(i-{k}) for i in [{','.join(map(str, [ord(c) + k for c in s]))}]))()"

        return random.choice([s2, s3] if strong else [s1, s2, s3])(s)

    def unwrap(self, code: str) -> str:
        try:
            tree = ast.parse(code)
            new_body = [
                n
                for n in tree.body
                if not (
                    isinstance(n, ast.If)
                    and isinstance(n.test, ast.Compare)
                    and getattr(n.test.left, "id", "") == "__name__"
                )
            ]
            for mn in [
                n
                for n in tree.body
                if (
                    isinstance(n, ast.If)
                    and isinstance(n.test, ast.Compare)
                    and getattr(n.test.left, "id", "") == "__name__"
                )
            ]:
                new_body.extend(mn.body)
            return ast.unparse(ast.Module(body=new_body, type_ignores=[]))
        except Exception as e:
            self.log(
                f"AST unwrap failed, proceeding with original code. (Issue: {e})",
                "warn",
            )
            return code

    def build(self, code, temp_dir):
        self.log("Compiling AST to Cython binary (this may take a moment)...", "info")
        mod_name = f"lI1_{uuid.uuid4().hex[:6]}"
        work_dir = os.path.abspath(temp_dir)
        os.makedirs(work_dir, exist_ok=True)
        anti = textwrap.dedent("""
            import sys,os,ctypes,time
            def _():
             try:
              if getattr(sys,'gettrace',lambda:0)():os._exit(0)
              if os.name == 'nt' and hasattr(ctypes, 'windll') and ctypes.windll.kernel32.IsDebuggerPresent():os._exit(0)
             except:pass
            _()
        """)
        with open(
            os.path.join(work_dir, f"{mod_name}.pyx"), "w", encoding="utf-8"
        ) as f:
            f.write(anti + "\n" + code)
        setup_py = f"from setuptools import setup, Extension;from Cython.Build import cythonize;setup(ext_modules=cythonize([Extension('{mod_name}',['{mod_name}.pyx'],extra_compile_args=['/Ox'])],compiler_directives={{'language_level':3}}))"
        with open(os.path.join(work_dir, "setup.py"), "w") as f:
            f.write(setup_py)
        res = subprocess.run(
            [sys.executable, "setup.py", "build_ext", "--inplace"],
            cwd=work_dir,
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            self.log(f"Subprocess Failure: {res.stderr}", "error")
            return None, None
        pyds = glob.glob(os.path.join(work_dir, f"{mod_name}*.pyd"))
        if not pyds:
            return None, None
        with open(pyds[0], "rb") as f:
            data = f.read()
        return data, mod_name

    def generate(self, payload, keys, mod_name, passw):
        self.log("Synthesizing context mesh and packing layers...", "info")
        v = {
            k: gen_name()
            for k in [
                "sys",
                "os",
                "b64",
                "zlb",
                "aes",
                "kdf",
                "sha",
                "utl",
                "tmp",
                "builtins",
                "h",
                "im",
                "g",
                "sh",
                "lg",
                "res",
                "p",
                "k",
                "pw",
                "mn",
                "mobj",
                "types",
            ]
        }
        disp = gen_name()

        real_logic = textwrap.dedent(f"""
            import types
            {disp}=lambda m,a:getattr(__import__(m,fromlist=['*'])if isinstance(m,str)else m,a)
            {v["sys"]}=__import__({self.obf_str("sys")});{v["os"]}=__import__({self.obf_str("os")});{v["b64"]}=__import__({self.obf_str("base64")});{v["zlb"]}=__import__({self.obf_str("zlib")})
            {v["aes"]}=__import__({self.obf_str("Crypto.Cipher.AES")},fromlist=['new']);{v["kdf"]}=__import__({self.obf_str("Crypto.Protocol.KDF")},fromlist=['PBKDF2']).PBKDF2;{v["sha"]}=__import__({self.obf_str("Crypto.Hash.SHA256")},fromlist=['*'])
            _K={disp}({v["b64"]}, {self.obf_str("b64decode")})({v["k"]});_D={disp}({v["b64"]}, {self.obf_str("b64decode")})({v["p"]})
            _xs,_as,_iv=_K[:16],_K[16:32],_K[32:48];_xk={v["kdf"]}({v["pw"]},_xs,dkLen=32,count=100000,hmac_hash_module={v["sha"]});_ak={v["kdf"]}({v["pw"]},_as,dkLen=32,count=100000,hmac_hash_module={v["sha"]})
            _c={v["aes"]}.new(_ak,{v["aes"]}.MODE_CBC,_iv);_r=bytearray(_c.decrypt(_D))
            for i in range(len(_r)):_r[i]^=_xk[i%32]
            _b={disp}({v["zlb"]},{self.obf_str("decompress")})(_r);_t={disp}({self.obf_str("tempfile")},{self.obf_str("mkdtemp")})(prefix={self.obf_str("lI1_")});_f={disp}({disp}({v["os"]},{self.obf_str("path")}),{self.obf_str("join")})(_t,{v["mn"]}+{self.obf_str(".pyd")})
            {v["h"]}={disp}({self.obf_str("builtins")},{self.obf_str("open")})(_f,{self.obf_str("wb")});{v["h"]}.write(_b);{v["h"]}.close()
            _u=__import__({self.obf_str("importlib.util")},fromlist=['util']);_s={disp}(_u,{self.obf_str("spec_from_file_location")})({v["mn"]},_f);{v["mobj"]}={disp}(_u,{self.obf_str("module_from_spec")})(_s);setattr({v["mobj"]},{self.obf_str("__file__")},__file__);setattr({v["mobj"]},{self.obf_str("__name__")},{self.obf_str("__main__")})
            {disp}({v["sys"]},{self.obf_str("modules")})[{v["mn"]}]={v["mobj"]};{disp}({disp}(_s,{self.obf_str("loader")}),{self.obf_str("exec_module")})({v["mobj"]})
            import atexit;atexit.register(lambda:__import__('subprocess').Popen([{v["sys"]}.executable, '-c', f"import time,os;time.sleep(2);os.remove(r'{{_f}}');os.rmdir(r'{{_t}}')"], **({{'creationflags': 0x08000000}} if {v["os"]}.name == 'nt' else {{}})))
        """).strip()

        def shard(data, size=45):
            return [data[i : i + size] for i in range(0, len(data), size)]

        self.log("Injecting randomized entropy and obfuscating strings...", "info")
        l_sh = shard(real_logic, 250)
        p_sh = shard(payload, 4096)
        k_sh = shard(keys, 32)

        all_shards = []
        p_tag, k_tag, l_tag = [gen_name(10) for _ in range(3)]

        def add_s(shards, tag):
            for i, s in enumerate(shards):
                key = f"{tag}_{str(i).zfill(4)}"
                all_shards.append(
                    f"{gen_name()} = ({random.randint(1, 999)} ^ 0x{random.randint(1, 0xFF):x}) | int(math.cos({random.random()})); (lambda f,k,v: f(k,v))(globals().__setitem__, {repr(key)}, {repr(s)})"
                )

        add_s(l_sh, l_tag)
        add_s(p_sh, p_tag)
        add_s(k_sh, k_tag)
        random.shuffle(all_shards)

        header = f"### Created by Ben281211 - available on github.com/Ben281211/ObscuPy\nimport base64, zlib, math, types\n"
        footer = [
            f"{v['g']} = globals()",
            f"{v['p']} = ''.join([{v['g']}[k] for k in sorted([k for k in {v['g']} if k.startswith({repr(p_tag + '_')})])])",
            f"{v['k']} = ''.join([{v['g']}[k] for k in sorted([k for k in {v['g']} if k.startswith({repr(k_tag + '_')})])])",
            f"{v['pw']} = bytes.fromhex({self.obf_str(passw.hex(), strong=True)}); {v['mn']} = {self.obf_str(mod_name)}",
            f"_code_str = ''.join([{v['g']}[k] for k in sorted([k for k in {v['g']} if k.startswith({repr(l_tag + '_')})])])",
            f"exec(compile(_code_str, '<string>', 'exec'), {v['g']})",
        ]

        body = "\n".join(all_shards) + "\n"
        footer_c = ""
        for i, line in enumerate(footer):
            noise = f"{gen_name()} = ({random.randint(1, 999)} << {random.randint(1, 2)}) ^ 0x{random.randint(1, 0xFF):x} if {random.randint(1, 100)} > 0 else math.pi"
            footer_c += f"{noise}; {line}\n"

        return header + body + footer_c

    def encrypt(self, input_file, output_file):
        try:
            self.log(f"Target selected: {B}{input_file}{W}", "info")
            with open(input_file, "r", encoding="utf-8") as f:
                code = f.read()
            code = self.unwrap(code)
            temp_dir = "ObscuPy_internal_tmp"
            bin_data, mod_name = self.build(code, temp_dir)
            if not bin_data:
                return False
            self.log(f"Applying zlib compression...", "info")
            z_bin = zlib.compress(bin_data, level=9)
            self.log(f"Deriving crypto keys (PBKDF2) & applying AES-256-CBC...", "info")
            passw, xs, as_, iv = [os.urandom(16) for _ in range(4)]
            xk = PBKDF2(passw, xs, dkLen=32, count=100000, hmac_hash_module=SHA256)
            ak = PBKDF2(passw, as_, dkLen=32, count=100000, hmac_hash_module=SHA256)
            aes_data = base64.b64encode(
                AES.new(ak, AES.MODE_CBC, iv).encrypt(
                    pad(bytearray(b ^ xk[i % 32] for i, b in enumerate(z_bin)), 16)
                )
            ).decode()
            keys_data = base64.b64encode(xs + as_ + iv).decode()

            final_loader = self.generate(aes_data, keys_data, mod_name, passw)

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(final_loader)

            shutil.rmtree(temp_dir, ignore_errors=True)
            self.log(
                f"Payload successfully secured. Size: {len(final_loader)} bytes",
                "success",
            )
            return True
        except Exception as e:
            self.log(f"Operational Failure: {e}", "error")
            return False


def main():
    try:
        import colorama

        colorama.just_fix_windows_console()
    except ImportError:
        os.system("")  # Enable ANSI escape codes on Windows command prompt

    parser = argparse.ArgumentParser(
        description="ObscuPy - Ultimate Python Obfuscator",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )
    parser.add_argument("input", nargs="?", help="Input Python script to obfuscate")
    parser.add_argument(
        "-o",
        "--output",
        default="obfuscated.py",
        help="Output file name (default: obfuscated.py)",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="ObscuPy v3.0",
        help="Show program's version number and exit",
    )
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="Show this help message and exit",
    )

    args = parser.parse_args()

    print_banner()

    if not args.input:
        parser.print_help()
        sys.exit(1)

    if not args.input.lower().endswith(".py"):
        print(
            f"[{time.strftime('%H:%M:%S')}] {R}[-]{W} Invalid file extension. Input must be a .py file."
        )
        sys.exit(1)

    if not os.path.exists(args.input):
        print(
            f"[{time.strftime('%H:%M:%S')}] {R}[-]{W} Input file not found: {args.input}"
        )
        sys.exit(1)

    core = ObscuPyCore()
    print(f"{Y}" + "-" * 60 + f"{W}")

    start_time = time.time()
    success = core.encrypt(args.input, args.output)

    print(f"{Y}" + "-" * 60 + f"{W}")
    if success:
        elapsed = time.time() - start_time
        print(
            f"[{time.strftime('%H:%M:%S')}] {G}[+]{W} Operation completed in {B}{elapsed:.2f}s{W}."
        )
        print(
            f"[{time.strftime('%H:%M:%S')}] {G}[+]{W} Output saved to: {B}{args.output}{W}"
        )
    else:
        print(f"[{time.strftime('%H:%M:%S')}] {R}[-]{W} Obfuscation process failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
