import os
import sys
import json
import shutil
from collections import defaultdict
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from elftools.elf.elffile import ELFFile
from pwn import *
from binary import Binary, Executable, Library
from utils.logger import get_logger
from utils.utils import get_md5_hex, run_ida
from config.config import config

from ida_domain import Database
from ida_domain.database import IdaCommandOptions
import logging

logger = get_logger(__name__)

class BorderBinaryRecognizor:
    link_num = 0
    exe_num = 0
    lib_num = 0
    binary_list: list[Binary] = []
    exe_list: dict[str, Executable] = {}
    lib_list: dict[str, Library] = {}
    potentital_border_binary_list: dict[str, list[str]] = defaultdict(list)
    signature_func = "socket"
    script_file = os.path.abspath("./src/scripts/socket_call_visitor.py")
    tmp_file = os.path.abspath("./tmp/")
    exclude_libraries = [
        "libc.so.6",
    ]
    lock = threading.Lock()

    def __init__(self, fs_path, max_threads=10):
        self.fs_path = os.path.abspath(fs_path)
        self.max_threads = max_threads

    def process_file(self, file_path):
        logger.debug(f"Processing file: {file_path}")
        binary = Binary(file_path)
        binary.get_filetype()
        if binary.is_link:
            self.link_num += 1
            return
        elif binary.is_exe:
            self.exe_num += 1
            self.exe_list[binary.filename] = Executable(binary.filepath)
        elif binary.is_lib:
            self.lib_num += 1
            self.lib_list[binary.filename] = Library(binary.filepath)
        else:
            return
        with self.lock:
            self.binary_list.append(binary)

    def retrieve_executable_list(self):
        logger.debug(f"fs: {self.fs_path}")

        tasks = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for root, _, files in os.walk(self.fs_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    tasks.append(executor.submit(self.process_file, file_path))

            # 等待所有线程完成
            for _ in as_completed(tasks):
                pass
        logger.info(f"Retrieve all executables done, total num: {len(self.binary_list)}")
        logger.debug(f"executables: {self.exe_num}")
        logger.debug(f"libraries: {self.lib_num}")

    def get_target_file_library(self):
        tmp_ctr = 0
        os.environ["QEMU_LD_PREFIX"] = self.fs_path
        for exe_key in self.exe_list:
            exe = self.exe_list[exe_key]
            logger.debug(f"Target: {exe_key}")
            elf = ELF(exe.filepath, checksec=False)
            self.p = elf.process()
            try:
                libs = self.p.libs()
                tmp_ctr += 1
            except Exception as e:
                logger.error(f"Exception {e} Occurred!")
                logger.warning(f"Failed to get target {exe_key}'s libraries!")

            self.p.close()

            for lib_key in libs:
                key_basename = os.path.basename(lib_key)
                if "lib" in key_basename and ".so" in key_basename:
                    lib = self.lib_list[key_basename]
                    exe.add_lib(lib)
                    lib.add_exe(exe)
                    logger.debug(f"get library {key_basename} for file {exe_key}")
        logger.info(f"Get All Executables' libraries Done, {self.exe_num - tmp_ctr}/{self.exe_num} Failed")

    def recognize_socket_executables(self):
        """ we should use database and ida scripts to implement this function """
        logger.info(f"Precheck if there is border executable in exe or library ...")
        sock_exe_ctr = 0
        sock_lib_ctr = 0
        for exe_key in self.exe_list:
            logger.debug(f"Target executable: {exe_key}")
            exe = self.exe_list[exe_key]
            if exe.check_socket_func():
                logger.debug(f"Found potential border binary: {exe_key}")
                sock_exe_ctr += 1

        for lib_key in self.lib_list:
            logger.debug(f"Target library: {lib_key}")
            if lib_key in self.exclude_libraries:
                logger.debug(f"Skipped library: {lib_key}")
            lib = self.lib_list[lib_key]
            if lib.check_socket_func():
                logger.debug(f"Found potentital border library: {lib_key}")
                sock_lib_ctr += 1

        logger.info(f"Precheck Done! Filtered {sock_exe_ctr}/{self.exe_num} executables, {sock_lib_ctr}/{self.lib_num} libraries, total {sock_exe_ctr+sock_lib_ctr}/ {self.exe_num+self.lib_num} potential border binaries found")

    def _recognize_one_file_socket_feature(self, filename, is_exe) -> bool:
        if is_exe:
            elf = self.exe_list[filename]
        else:
            elf = self.lib_list[filename]
        if elf.has_socket_func:
            logger.debug(f"Checking binary file: {filename} ...")
            # we copy it to tmp directory
            tmp_dir = os.path.abspath(f"{self.tmp_file}/{filename}-{random.randbytes(0x8).hex()}")
            if not os.path.exists(tmp_dir):
                os.mkdir(tmp_dir)
            tmp_elf_path = os.path.abspath(f"{tmp_dir}/{filename}")
            shutil.copy(elf.filepath, tmp_elf_path)
            output_path = os.path.abspath(f"{tmp_dir}/{filename}.json")
            opts = IdaCommandOptions(
                script_file = self.script_file,
                script_args = [output_path]
            )
            logger.debug(f"Launching IDA for {elf.filename}")
            db = Database.open(elf.filepath, args=opts, save_on_close=True)
            db.close()
            logger.debug(f"IDA finished for {elf.filename}")
            with open(output_path, "r") as f:
                data = json.load(f)
            for d in data:
                if "AF_INET" in d["name"]:
                    elf.is_border = True
                    elf.append_border_endpoint(d)
                    logger.debug(f"Found Possibly Border Binary: {filename}")
                    break
        return elf.is_border

    def recognize_socket_features(self):
        """check if there is any socket(AF_INET/AF_INET6) -> bind -> listen -> accept logic"""
        tmp_exe_ctr = 0
        tmp_lib_ctr = 0

        for exe_key in self.exe_list:
            if self._recognize_one_file_socket_feature(exe_key, True):
                tmp_exe_ctr += 1
        for lib_key in self.lib_list:
            if self._recognize_one_file_socket_feature(lib_key, False):
                tmp_lib_ctr += 1
        logger.info(f"Recognized {tmp_exe_ctr}/{self.exe_num} executables, {tmp_lib_ctr}/{self.lib_num} libraries, total {tmp_exe_ctr+tmp_lib_ctr}/{self.lib_num+self.exe_num} binaries")

    def dump_result(self):
        output_path = f"./output/{os.path.basename(self.fs_path)}-{get_md5_hex(self.fs_path)}.json"
        result = []
        for exe_key in self.exe_list:
            elf = self.exe_list[exe_key]
            if elf.is_border == True:
                result.append({
                    "filename": elf.filename,
                    "filepath": elf.filepath,
                    "border_endpoint": elf.border_endpoint,
                })
        for lib_key in self.lib_list:
            elf = self.lib_list[lib_key]
            if elf.is_border == True:
                result.append({
                    "filename": elf.filename,
                    "filepath": elf.filepath,
                    "border_endpoint": elf.border_endpoint,
                    "related_executable": [elf.exes[exe].filename for exe in elf.exes]
                })
        with open(output_path, "w") as f:
            json.dump(result, f, indent=4)
 
    def recognize_border_binary(self):
        logger.info(f"Phrase1: retrieving all executables ...")
        self.retrieve_executable_list()
        logger.info(f"Phrase2: Getting executables' libraries ...")
        self.get_target_file_library()
        # clear qemu core file
        from pathlib import Path

        for core_file in Path(".").glob("qemu_*.core"):
            try:
                core_file.unlink()
            except OSError as e:
                print(f"Failed to remove {core_file}: {e}")

        # debug use
        # logger.debug(f"exe: {self.exe_list["ip"].libs}")
        # logger.debug(f"lib: {self.lib_list["libstrongswan-pkcs1.so"].exes}")
        logger.info(f"Phrase3: Recognizing executables which contain socket-related functions ...")
        self.recognize_socket_executables()

        logger.info(f"Phrase4: Recognizing socket func's features ...")
        self.recognize_socket_features()
        self.dump_result()



if __name__ == "__main__":
    test = BorderBinaryRecognizor("./dataset/squashfs-root/")
    test.recognize_border_binary()
