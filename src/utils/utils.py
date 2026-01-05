import subprocess
from hashlib import md5

def get_md5_hex(input_str: str):
    obj = md5()
    obj.update(input_str.encode())

    return obj.hexdigest()

def run_ida(idat_path, binary, script):
    cmd = [
        idat_path,
        "-A",
        f"-S{script}",
        binary
    ]
    subprocess.run(
        cmd,
    )
