import os
from pwn import *
from elftools.elf.elffile import ELFFile

class Binary:
    signature_func = ["socket", "bind"]

    def __init__(self, filepath):
        self.filename = os.path.basename(filepath)
        self.filepath = os.path.abspath(filepath)
        self.is_exe = False
        self.is_lib = False
        self.is_link = False

        self.has_socket_func = False
        self.is_border = False
        self.border_endpoint = []

    def get_filetype(self):
        tmp_ctr = 0
        if os.path.islink(self.filepath):
            is_link = True
            tmp_ctr += 1
        with open(self.filepath, "rb") as f:
            magic = f.read(4)
        if magic == b"\x7fELF":
            with open(self.filepath, "rb") as f:
                elf = ELFFile(f)
                if elf.header.e_type == "ET_EXEC":
                    self.is_exe = True
                    tmp_ctr += 1
                elif elf.header.e_type == "ET_DYN":
                    self.is_lib = True
                    tmp_ctr += 1
                else:
                    raise NotImplementedError(f"Unexpected elf header {elf.header.e_type}!")
        assert tmp_ctr == 1

    def check_socket_func(self):
        elf = ELF(self.filepath, checksec=False)
        for sig_func in self.signature_func:
            if sig_func not in elf.symbols:
                return False
        self.has_socket_func = True
        return True

    def append_border_endpoint(self, endpoint):
        self.border_endpoint.append(endpoint)

class Executable(Binary):
    def __init__(self, filepath):
        Binary.__init__(self, filepath)
        self.libs: dict[Library] = {}

    def add_lib(self, lib:"Library"):
        self.libs[lib.filename] = lib

class Library(Binary):
    def __init__(self, filepath):
        Binary.__init__(self, filepath)
        self.exes: dict[Library] = {}

    def add_exe(self, exe:"Executable"):
        self.exes[exe.filename] = exe
