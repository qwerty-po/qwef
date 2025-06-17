from __future__ import annotations

import re
import enum
import json
import math
import os
import string
import sys
import tempfile
from dataclasses import asdict, dataclass

import pykd
from typing import TypeVar, Generic, Optional, Callable, _GenericAlias, Any, get_args, get_origin

## ================================================== Load Module =================================================================

try:
    nt = pykd.module("ntdll")
except:
    pass

## ================================================== Print Manager ================================================================

def p64(value: int) -> bytes:
    return value.to_bytes(8, byteorder="little")

## ================================================== Load Commands =================================================================

class CmdManager:
    def alias(self, cmd, func):
        path = os.path.dirname(sys.argv[0]) + "\\qwef.py"
        pykd.dbgCommand(f"as {cmd} !py -g {path} {func}")

    def register(self, cmd, func):
        self.alias(cmd, func)

## ================================================= Colour Manager =================================================================

class ColourManager:
    def __init__(self):
        self.RED = ("srcpair", "norbg")
        self.BLUE = ("srckw", "norbg")
        self.GRAY = ("subfg", "norbg")
        self.DARK_RED = ("srcstr", "norbg")
        self.GREEN = ("srccmnt", "norbg")
        self.WHITE = ("emphbg", "norbg")
        self.BROWN = ("srcid", "norbg")
        self.PURPLE = ("srcannot", "norbg")

    def colorize(self, col, content):
        return '<col fg="{}" bg="{}">{}</col>'.format(col[0], col[1], content)

    def bold_colorize(self, col, content):
        return f"<b>{self.colorize(col, content)}</b>"

    def red(self, content):
        return self.colorize(self.RED, content)

    def brown(self, content):
        return self.colorize(self.BROWN, content)

    def blue(self, content):
        return self.colorize(self.BLUE, content)

    def gray(self, content):
        return self.colorize(self.GRAY, content)

    def purple(self, content):
        return self.colorize(self.PURPLE, content)

    def dark_red(self, content):
        return self.colorize(self.DARK_RED, content)

    def green(self, content):
        return self.colorize(self.GREEN, content)

    def white(self, content):
        return self.colorize(self.WHITE, content)

    def bold_white(self, content):
        return self.bold_colorize(self.WHITE, content)

    def address_color(self, address: int) -> Callable:
        if address < 0:
            raise ValueError("Invalid address: address must be positive")

        if pykd.isValid(address):
            for section in vmmap.dump_section():
                if section.base_address <= address < section.end_address:
                    if section.usage == "Stack":
                        return self.purple
                    elif PageProtect.is_executable(section.protect):
                        return self.red
                    elif PageProtect.is_writable(section.protect):
                        return self.green
                    else:
                        return self.white
            return self.white
        else:
            return self.white

    def colorize_hex_by_address(self, address: Any, strsz=-1) -> str:
        if type(address) is not int:
            try:
                address = int(address)
            except ValueError:
                raise ValueError("Type can't change to integer")
        target = f"{address:#x}" if strsz == -1 else f"0x{address:0{strsz}x}"
        return self.address_color(address)(target)

    def colorize_string_by_address(self, target: str, address: Any) -> str:
        if type(address) is not int:
            try:
                address = int(address)
            except ValueError:
                raise ValueError("Type can't change to integer")
        return self.address_color(address)(target)


colour: ColourManager = ColourManager()

## ================================================= Registers =================================================================

class EflagsEnum(enum.IntEnum):
    CF = 0
    PF = 2
    AF = 4
    ZF = 6
    SF = 7
    TF = 8
    IF = 9
    DF = 10
    OF = 11
    IOPL = 12
    NT = 14
    RF = 16
    VM = 17
    AC = 18
    VIF = 19
    VIP = 20
    ID = 21

    def __str__(self) -> str:
        if self.name == "CF":
            return "carry"
        elif self.name == "PF":
            return "parity"
        elif self.name == "AF":
            return "auxiliary"
        elif self.name == "ZF":
            return "zero"
        elif self.name == "SF":
            return "sign"
        elif self.name == "TF":
            return "trap"
        elif self.name == "IF":
            return "interrupt"
        elif self.name == "DF":
            return "direction"
        elif self.name == "OF":
            return "overflow"
        elif self.name == "IOPL":
            return "iopl"
        elif self.name == "NT":
            return "nested"
        elif self.name == "RF":
            return "resume"
        elif self.name == "VM":
            return "virtualx86"
        elif self.name == "AC":
            return "alignment"
        elif self.name == "VIF":
            return "vtint"
        elif self.name == "VIP":
            return "vtpend"
        elif self.name == "ID":
            return "id"


@dataclass
class I386Register:
    eax: int
    ebx: int
    ecx: int
    edx: int
    edi: int
    esi: int
    ebp: int
    esp: int
    eip: int

    def __init__(self):
        self.eax: int = -1
        self.ebx: int = -1
        self.ecx: int = -1
        self.edx: int = -1
        self.edi: int = -1
        self.esi: int = -1
        self.ebp: int = -1
        self.esp: int = -1
        self.eip: int = -1

    def assign(self, name, value):
        setattr(self, name, value)


@dataclass
class Amd64Register:
    rax: int
    rbx: int
    rcx: int
    rdx: int
    rdi: int
    rsi: int
    rbp: int
    rsp: int
    r8: int
    r9: int
    r10: int
    r11: int
    r12: int
    r13: int
    r14: int
    r15: int
    rip: int

    def __init__(self):
        self.rax: int = -1
        self.rbx: int = -1
        self.rcx: int = -1
        self.rdx: int = -1
        self.rdi: int = -1
        self.rsi: int = -1
        self.rbp: int = -1
        self.rsp: int = -1
        self.r8: int = -1
        self.r9: int = -1
        self.r10: int = -1
        self.r11: int = -1
        self.r12: int = -1
        self.r13: int = -1
        self.r14: int = -1
        self.r15: int = -1
        self.rip: int = -1

    def assign(self, name, value):
        setattr(self, name, value)


@dataclass
class SegmentRegister:
    cs: int
    ds: int
    es: int
    fs: int
    gs: int
    ss: int

    def __init__(self):
        self.cs: int = -1
        self.ds: int = -1
        self.es: int = -1
        self.fs: int = -1
        self.gs: int = -1
        self.ss: int = -1

    def assign(self, name, value):
        setattr(self, name, value)


@dataclass
class EflagsRegister:
    CF: bool
    PF: bool
    AF: bool
    ZF: bool
    SF: bool
    TF: bool
    IF: bool
    DF: bool
    OF: bool
    IOPL: bool
    NT: bool
    RF: bool
    VM: bool
    AC: bool
    VIF: bool
    VIP: bool
    ID: bool

    def __init__(self):
        self.CF: bool = False
        self.PF: bool = False
        self.AF: bool = False
        self.ZF: bool = False
        self.SF: bool = False
        self.TF: bool = False
        self.IF: bool = False
        self.DF: bool = False
        self.OF: bool = False
        self.IOPL: bool = False
        self.NT: bool = False
        self.RF: bool = False
        self.VM: bool = False
        self.AC: bool = False
        self.VIF: bool = False
        self.VIP: bool = False
        self.ID: bool = False

    def assign(self, name, value):
        setattr(self, name, value)

## ================================================ Memory Access =================================================================

class MemoryAccess:
    def __init__(self):
        self.addr_symbol: dict[int, str] = {}

        self.filename: str = f"{tempfile.gettempdir()}\\{pykd.getProcessSystemID()}.sym"
        if os.path.exists(self.filename):
            self.load_symbol_from_file()

    def __del__(self):
        self.save_symbol_to_file()

    def load_symbol_from_file(self) -> None:
        try:
            with open(self.filename, "r") as fp:
                self.addr_symbol = json.loads(fp.read())
        except:
            pass

    def save_symbol_to_file(self) -> None:
        try:
            with open(self.filename, "w") as fp:
                fp.write(json.dumps(self.addr_symbol))
        except:
            pass

    def deref_ptr(self, ptr: int) -> Optional[int]:
        try:
            return pykd.loadPtrs(ptr, 1)[0] & ContextManager().ptrmask
        except pykd.MemoryException:
            return None

    def get_addr_from_symbol(self, symbol: str) -> Optional[int]:
        try:
            return int(
                f"0x{pykd.dbgCommand(f'x {symbol}').split(' ')[0].replace('`', '')}", 16
            )
        except pykd.MemoryException:
            return None

    def get_string(self, ptr: int) -> Optional[str]:
        try:
            return pykd.loadCStr(ptr)
        except pykd.MemoryException:
            return None
        except UnicodeDecodeError:
            return None

    def get_int(self, ptr: int) -> Optional[int]:
        try:
            return pykd.ptrSignDWord(ptr)
        except pykd.MemoryException:
            return None

    def get_uint(self, ptr: int) -> Optional[int]:
        try:
            return pykd.ptrDWord(ptr)
        except pykd.MemoryException:
            return None

    def get_long(self, ptr: int) -> Optional[int]:
        try:
            return pykd.ptrSignQWord(ptr)
        except pykd.MemoryException:
            return None

    def get_ulong(self, ptr: int) -> Optional[int]:
        try:
            return pykd.ptrQWord(ptr)
        except pykd.MemoryException:
            return None

    def get_bytes(self, ptr: int, size: int) -> Optional[bytes]:
        try:
            return pykd.loadBytes(ptr, size)
        except pykd.MemoryException:
            return None

    def get_symbol(self, ptr: int) -> Optional[str]:
        if ptr in self.addr_symbol:
            return self.addr_symbol[ptr]
        try:
            val = pykd.findSymbol(ptr)
            if val == hex(ptr)[2:]:
                self.addr_symbol[ptr] = None
                return None
            else:
                self.addr_symbol[ptr] = val
                return val
        except pykd.MemoryException:
            return None

    def get_qword_datas(self, ptr: int, size: int = 0x10) -> list[int]:
        retlist: list[int] = []
        for vals in (
            pykd.dbgCommand(f"dq {hex(ptr)} {hex(ptr + size - 1)}")
            .replace("`", "")
            .split("  ")[1]
            .strip()
            .split(" ")
        ):
            for val in vals.split("\n"):
                try:
                    retlist.append(int(val, 16))
                except:
                    raise Exception("Invalid data, please check valid ptr first")
        return retlist

## ================================================================ Page Information =================================================================
class PageState(enum.IntEnum):
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_FREE = 0x10000

    def __str__(self) -> str:
        return self.name

    def is_commit(enum_value: int) -> bool:
        if enum_value & PageState.MEM_COMMIT:
            return True
        else:
            return False

    def is_reserve(enum_value: int) -> bool:
        if enum_value & PageState.MEM_RESERVE:
            return True
        else:
            return False

    def is_free(enum_value: int) -> bool:
        if enum_value & PageState.MEM_FREE:
            return True
        else:
            return False


class PageProtect(enum.IntEnum):
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80

    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_WRITECOMBINE = 0x400

    PAGE_TARGETS_INVALID = 0x40000000

    def __str__(self) -> str:
        return self.name

    def is_executable(enum_val) -> bool:
        if enum_val & (
            PageProtect.PAGE_EXECUTE
            | PageProtect.PAGE_EXECUTE_READ
            | PageProtect.PAGE_EXECUTE_READWRITE
            | PageProtect.PAGE_EXECUTE_WRITECOPY
        ):
            return True
        else:
            return False

    def is_writable(enum_val) -> bool:
        if enum_val & (
            PageProtect.PAGE_READWRITE
            | PageProtect.PAGE_WRITECOPY
            | PageProtect.PAGE_EXECUTE_READWRITE
        ):
            return True
        else:
            return False

    def is_readable(enum_val) -> bool:
        if enum_val & (
            PageProtect.PAGE_READONLY
            | PageProtect.PAGE_READWRITE
            | PageProtect.PAGE_WRITECOPY
            | PageProtect.PAGE_EXECUTE_READ
            | PageProtect.PAGE_EXECUTE_READWRITE
            | PageProtect.PAGE_EXECUTE_WRITECOPY
        ):
            return True
        else:
            return False

    def is_copy_on_write(enum_val) -> bool:
        if enum_val & (PageProtect.PAGE_WRITECOPY | PageProtect.PAGE_EXECUTE_WRITECOPY):
            return True
        else:
            return False

    def is_guard(enum_val) -> bool:
        if enum_val & PageProtect.PAGE_GUARD:
            return True
        else:
            return False

    def is_nocache(enum_val) -> bool:
        if enum_val & PageProtect.PAGE_NOCACHE:
            return True
        else:
            return False

    def is_writecombine(enum_val) -> bool:
        if enum_val & PageProtect.PAGE_WRITECOMBINE:
            return True
        else:
            return False

    def is_targets_invalid(enum_val) -> bool:
        if enum_val & PageProtect.PAGE_TARGETS_INVALID:
            return True
        else:
            return False

    def to_str(enum_value) -> str:
        retstr: str = ""
        if enum_value & PageProtect.PAGE_NOACCESS:
            retstr += "noaccess"
        elif enum_value & PageProtect.PAGE_READONLY:
            retstr += "readonly"
        elif enum_value & PageProtect.PAGE_READWRITE:
            retstr += "readwrite"
        elif enum_value & PageProtect.PAGE_WRITECOPY:
            retstr += "writecopy"
        elif enum_value & PageProtect.PAGE_EXECUTE:
            retstr += "execute"
        elif enum_value & PageProtect.PAGE_EXECUTE_READ:
            retstr += "execute_read"
        elif enum_value & PageProtect.PAGE_EXECUTE_READWRITE:
            retstr += "execute_readwrite"
        elif enum_value & PageProtect.PAGE_EXECUTE_WRITECOPY:
            retstr += "execute_writecopy"

        if enum_value & PageProtect.PAGE_GUARD:
            retstr += " + guard"
        if enum_value & PageProtect.PAGE_NOCACHE:
            retstr += " + nocache"
        if enum_value & PageProtect.PAGE_WRITECOMBINE:
            retstr += " + writecombine"
        if enum_value & PageProtect.PAGE_TARGETS_INVALID:
            retstr += " + targets_invalid"

        return retstr


class PageType(enum.IntEnum):
    MEM_IMAGE = 0x1000000
    MEM_MAPPED = 0x40000
    MEM_PRIVATE = 0x20000

    def __str__(self) -> str:
        return self.name

    def is_image(enum_value) -> bool:
        if enum_value & PageType.MEM_IMAGE:
            return True
        else:
            return False

    def is_mapped(enum_value) -> bool:
        if enum_value & PageType.MEM_MAPPED:
            return True
        else:
            return False

    def is_private(enum_value) -> bool:
        if enum_value & PageType.MEM_PRIVATE:
            return True
        else:
            return False

    def to_str(self, enum_value) -> str:
        retstr: str = ""
        if enum_value & PageType.MEM_IMAGE:
            retstr += "image"
        elif enum_value & PageType.MEM_MAPPED:
            retstr += "mapped"
        elif enum_value & PageType.MEM_PRIVATE:
            retstr += "private"

        return retstr
    

@dataclass
class SectionInfo:
    usage: str
    base_address: int
    end_address: int
    size: int
    image_path: str
    additional: str
    state: PageState
    protect: PageProtect
    type: PageType

    def __init__(self):
        self.usage: str = ""
        self.base_address: int = -1
        self.end_address: int = -1
        self.size: int = -1
        self.image_path: str = ""
        self.additional: str = ""
        self.state: PageState = PageState.MEM_FREE
        self.protect: PageProtect = PageProtect.PAGE_NOACCESS
        self.type: PageType = PageType.MEM_PRIVATE

class Vmmap:
    def __init__(self):
        self.dump_section_info = None
        self.dump_section(True)

    def section_info(self, address: int) -> SectionInfo:
        section_info: SectionInfo = SectionInfo()

        for line in pykd.dbgCommand(f"!address {hex(address)}").split("\n"):
            line = line.replace("`", "")
            if "Allocation Protect:" in line:
                continue

            if "Usage:" in line:
                section_info.usage = line.split(":")[1].strip()
            if "Base Address:" in line:
                section_info.base_address = int(f"0x{line.split(':')[1].strip()}", 16)
            if "End Address:" in line:
                section_info.end_address = int(f"0x{line.split(':')[1].strip()}", 16)
            if "Region Size:" in line:
                section_info.size = int(
                    f"0x{line.split(':')[1].strip().split(' ')[0]}", 16
                )
            if "State:" in line:
                section_info.state = int(
                    f"0x{line.split(':')[1].strip().split(' ')[0]}", 16
                )
            if "Protect:" in line:
                try:
                    section_info.protect = int(
                        f"0x{line.split(':')[1].strip().split(' ')[0]}", 16
                    )
                except:
                    pass
            if "Type:" in line:
                try:
                    section_info.type = int(
                        f"0x{line.split(':')[1].strip().split(' ')[0]}", 16
                    )
                except:
                    pass
            if "Image Path:" in line:
                try:
                    section_info.image_path = line.split(": ")[1].strip()
                except:
                    pass
            if "Mapped file name:" in line:
                section_info.additional = line.split("name:")[1].strip().split(" ")[0]
            if "Additional info:" in line:
                section_info.additional = line.split("info:")[1].strip()

        return section_info

    def dump_section(self, reload=False) -> list[SectionInfo]:
        if self.dump_section_info is not None and reload is False:
            return self.dump_section_info

        dumped_info: list[SectionInfo] = []
        base: int = 0

        while True:
            target_info: SectionInfo = self.section_info(base)

            if target_info.base_address != base:
                break
            else:
                dumped_info.append(target_info)
                base += dumped_info[-1].size
        self.dump_section_info = dumped_info

        return dumped_info

    def print_vmmap(self, level: int = 0):
        for section_info in self.dump_section():
            if pykd.CPUType.AMD64 == pykd.getCPUMode():
                addr_info: str = f"0x{section_info.base_address:016x} - 0x{section_info.end_address:016x} 0x{section_info.size:011x}"
            elif pykd.CPUType.I386 == pykd.getCPUMode():
                addr_info: str = f"0x{section_info.base_address:08x} - 0x{section_info.end_address:08x} 0x{section_info.size:08x}"
            state_info: str = ""
            priv_info: str = ""
            guard_info: str = ""
            type_info: str = ""
            path_info: str = ""

            clr: Callable = colour.white

            if PageState.is_free(section_info.state):
                clr = colour.gray
                state_info += "free"
            elif PageState.is_reserve(section_info.state):
                clr = colour.gray
                state_info += "reserve"
            elif PageState.is_commit(section_info.state):
                state_info += "commit"
                if PageProtect.is_guard(section_info.protect):
                    clr = colour.gray
                    guard_info += "(g)"
                elif PageProtect.is_executable(section_info.protect):
                    clr = colour.red
                elif PageProtect.is_writable(section_info.protect):
                    clr = colour.green
                elif PageProtect.is_readable(section_info.protect):
                    clr = colour.white
                else:
                    clr = colour.gray

                if PageProtect.is_copy_on_write(section_info.protect):
                    priv_info += "c"
                elif PageProtect.is_readable(section_info.protect):
                    priv_info += "r"
                else:
                    priv_info += "-"

                if PageProtect.is_writable(section_info.protect):
                    priv_info += "w"
                else:
                    priv_info += "-"

                if PageProtect.is_executable(section_info.protect):
                    priv_info += "x"
                else:
                    priv_info += "-"

            if PageType.is_mapped(section_info.type):
                type_info += "s"
            elif PageType.is_private(section_info.type):
                type_info += "p"
            elif PageType.is_image(section_info.type):
                type_info += "i"
                if section_info.image_path != "":
                    path_info = section_info.image_path

            if section_info.additional != "" and path_info == "":
                path_info = section_info.additional

            printst: str = ""
            if state_info == "commit":
                printst = (
                    f"{addr_info} {state_info:11} {priv_info}{type_info}{guard_info}"
                )
            elif state_info == "free" or state_info == "reserve":
                printst = f"{addr_info} {state_info:11} {state_info}"

            if level == 0 and clr != colour.gray:
                if section_info.usage == "Stack":
                    clr = colour.purple
                dprint.print(clr(printst), dml=True)
                dprint.print(f" {section_info.usage}")
                if path_info:
                    dprint.println(f" [{path_info}]")
                else:
                    dprint.print_newline()
            elif level == 1:
                if section_info.usage == "Stack":
                    clr = colour.purple
                dprint.print(clr(printst), dml=True)
                dprint.print(f" {section_info.usage}")
                if path_info:
                    dprint.println(f" [{path_info}]")
                else:
                    dprint.print_newline()

class PrintManager:
    def __init__(self):
        self.banner_size = 160
        self.query: list[tuple[str, bool]] = []

    def print(self, context, dml=False):
        self.query.append((context, dml))
        # pykd.dprint(context, dml)

    def println(self, context, dml=False):
        self.query.append((context + "\n", dml))
        # pykd.dprintln(context, dml)

    def clear(self):
        self.query = []

    def flush(self):
        for context, dml in self.query:
            pykd.dprint(context, dml)
        self.query = []

    def banner_print(self, banner_name: str, color: Callable = colour.white):
        leftlen = self.banner_size - len(banner_name) - 2
        llen = leftlen // 2
        rlen = leftlen - llen
        self.println(color(f"{'-' * llen}{banner_name}{'-' * rlen}"), dml=True)

    def success_print(self, content: str, color: Callable = colour.white):
        self.println(color(f"[+] {content}"), dml=True)

    def fail_print(self, content: str, color: Callable = colour.white):
        self.println(color(f"[-] {content}"), dml=True)

    def trying_print(self, content: str, color: Callable = colour.white):
        self.println(color(f"[*] {content}"), dml=True)

    def print_newline(self):
        self.println("")
    
    def remove_last_line(self):
        self.query.pop()

## ================================================================= Context Manager =================================================================

class ContextManager:
    def __init__(self):
        self.arch = pykd.getCPUMode()
        self.regs: Amd64Register | I386Register
        self.segregs: SegmentRegister = SegmentRegister()
        self.eflags: EflagsRegister = EflagsRegister()
        self.ptrmask: int = (
            0xFFFFFFFFFFFFFFFF if self.arch == pykd.CPUType.AMD64 else 0xFFFFFFFF
        )

        self.segments_info: list[SectionInfo] = []

        if self.arch == pykd.CPUType.AMD64:
            self.regs = Amd64Register()
        elif self.arch == pykd.CPUType.I386:
            self.regs = I386Register()
        else:
            raise RuntimeError("Unsupported CPU mode")

    def update_regs(self):
        for reg, _ in asdict(self.regs).items():
            self.regs.assign(reg, pykd.reg(reg))
        for reg, _ in asdict(self.segregs).items():
            self.segregs.assign(reg, pykd.reg(reg))

    def update_eflags(self):
        eflags = pykd.reg("efl")
        for i, flaginfo in enumerate(asdict(self.eflags).items()):
            self.eflags.assign(
                flaginfo[0], (((eflags >> EflagsEnum[flaginfo[0]]) & 1) == 1)
            )

    def update_vmmap(self):
        self.segments_info = vmmap.dump_section()

    def print_context(self):
        self.update_vmmap()
        self.update_regs()
        self.update_eflags()

        dprint.banner_print(" registers ", colour.blue)
        try:
            self.print_regs()
        except:
            pass
        dprint.banner_print(" codes ", colour.blue)
        try:
            self.print_code()
        except:
            pass
        dprint.banner_print(" stack ", colour.blue)
        try:
            self.print_stack()
        except:
            pass
        dprint.banner_print("", colour.blue)

    def arch_base_size(self) -> int:
        if self.arch == pykd.CPUType.AMD64:
            return 8
        elif self.arch == pykd.CPUType.I386:
            return 4
        else:
            raise RuntimeError("Unsupported CPU mode")

    def deep_print(self, value: int, remain: int, xref: int = 0) -> None:
        printst: str = ""
        printsz: int = self.arch_base_size() * 2
        dprint.print(f" {colour.colorize_hex_by_address(value, printsz)}", dml=True)

        if memoryaccess.get_symbol(value) is not None:
            dprint.print(f" <{colour.white(memoryaccess.get_symbol(value))}>", dml=True)

        if pykd.isValid(value):
            if remain == 0:
                dprint.print_newline()
                return
            else:
                dprint.print(" ->", dml=True)
                self.deep_print(memoryaccess.deref_ptr(value), remain - 1, value)
                return
        elif pykd.isValid(xref):
            value: Optional[str] = memoryaccess.get_string(xref)
            if value is None:
                dprint.print_newline()
                return

            if len(value):
                dprint.println(f'("{colour.white(value)}")', dml=True)
                return
            else:
                dprint.print_newline()
                return
        else:
            dprint.print_newline()
            return

    def print_general_regs(self) -> None:
        for reg, vaule in asdict(self.regs).items():
            dprint.print(colour.red(f"{reg:4}"), dml=True)
            dprint.print(": ")
            self.deep_print(vaule, 5)

    def print_seg_regs(self) -> None:
        for reg, vaule in asdict(self.segregs).items():
            dprint.print(f"{reg:2} = 0x{vaule:02x} ")
        dprint.print_newline()

    def print_eflags(self) -> None:
        for reg, vaule in asdict(self.eflags).items():
            if vaule:
                dprint.print(f"{colour.green(str(EflagsEnum[reg]))} ", dml=True)
            else:
                dprint.print(f"{colour.red(str(EflagsEnum[reg]))} ", dml=True)
        dprint.print_newline()

    def disasm(self, addr) -> tuple[str, str]:
        resp = pykd.disasm().disasm(addr).split(" ")
        op_str = resp[1]
        asm_str = " ".join(c for c in resp[2::]).strip()
        return op_str, asm_str

    def print_code_by_address(self, pc: int, tab: str, print_range: int) -> None:
        for _ in range(print_range):
            op_str, asm_str = self.disasm(pc)
            sym: str = memoryaccess.get_symbol(pc)
            debug_info: str = ""
            if sym is not None:
                debug_info: str = f" <{sym}> "
            code_str = f"{pc:#x}: {op_str:25s}{debug_info:20s}{asm_str}"
            dprint.println(colour.white(f"{tab}{code_str}"), dml=True)

            pc += len(op_str) // 2

            if asm_str.startswith("ret"):
                return

    def print_code(self) -> None:
        pc = self.regs.rip if self.arch == pykd.CPUType.AMD64 else self.regs.eip
        for offset in range(-3, 6):
            addr = pykd.disasm().findOffset(offset)
            op_str, asm_str = self.disasm(addr)
            sym: str = memoryaccess.get_symbol(addr)
            debug_info: str = ""
            if sym is not None:
                debug_info: str = f" <{sym}> "
            code_str = f"{addr:#x}: {op_str:25s}{debug_info:20s}{asm_str}"
            if addr == pc:
                dprint.println(colour.bold_white(f"-> {code_str}"), dml=True)

                if asm_str.startswith("ret"):
                    num: int
                    try:
                        if asm_str.split(" ")[1].endswith("h"):
                            num = int(f"0x{asm_str.split(' ')[1][:-1]}", 16)
                        else:
                            num = int(asm_str.split(" ")[1])
                    except:
                        num = 0
                    goto: int = memoryaccess.deref_ptr(
                        self.regs.rsp + num * 8
                        if self.arch == pykd.CPUType.AMD64
                        else self.regs.esp + num * 4
                    )

                    if goto is not None:
                        self.print_code_by_address(goto, " " * 8, 4)
                if asm_str.startswith("jmp"):
                    addr: int = int(
                        f"0x{asm_str.split('(')[-1].split(')')[0].strip().replace('`', '')}",
                        16,
                    )
                    if addr != pykd.disasm().findOffset(offset + 1):
                        self.print_code_by_address(addr, " " * 8, 4)
            else:
                dprint.println(colour.white(f"   {code_str}"), dml=True)

    def print_stack(self) -> None:
        sp = 0
        if self.arch == pykd.CPUType.AMD64:
            sp = self.regs.rsp
        elif self.arch == pykd.CPUType.I386:
            sp = self.regs.esp
        else:
            raise RuntimeError("Unsupported CPU mode")

        if self.arch == pykd.CPUType.I386:
            for offset in range(8):
                dprint.print(f"[sp + {offset * 4:02x}] ")
                addr = sp + offset * 4
                self.deep_print(addr, 2)
        else:
            for offset in range(8):
                dprint.print(f"[sp + {offset * 8:02x}] ")
                addr = sp + offset * 8
                self.deep_print(addr, 2)

    def print_regs(self) -> None:
        self.print_general_regs()
        self.print_seg_regs()
        self.print_eflags()

    def conti(self, cnt: int = 1) -> None:
        for _ in range(cnt):
            pykd.dbgCommand("g")
        self.print_context()
        pykd.dbgCommand("c")

    def ni(self, cnt: int = 1) -> None:
        for _ in range(cnt):
            pykd.dbgCommand("p")
        self.print_context()
        pykd.dbgCommand("ni")

    def si(self, cnt: int = 1) -> None:
        for _ in range(cnt):
            pykd.dbgCommand("t")
        self.print_context()
        pykd.dbgCommand("si")

    def execute(self, params: list[str]):
        cmd, args = params[0], params[1:]
        if len(args) > 0 and args[0] == "help":
            dprint.println(
                colour.white("[*] Usage: c [count], ni [count], si [count], count is optinoal"),
                dml=True,
            )
        elif cmd == "c":
            if args == []:
                context.conti()
            elif len(args) == 1:
                conti_count = int(args[0], 16) if args[0].startswith("0x") else int(args[0])
                self.conti(conti_count)
            else:
                dprint.println(
                    colour.white("[*] Usage: c [count], count is optional"), dml=True
                )
        elif cmd == "ni":
            if args == []:
                context.ni()
            elif len(args) == 1:
                ni_count = int(args[0], 16) if args[0].startswith("0x") else int(args[0])
                self.ni(ni_count)
            else:
                dprint.println(
                    colour.white("[*] Usage: ni [count], count is optional"), dml=True
                )
        elif cmd == "si":
            if args == []:
                context.si()
            elif len(args) == 1:
                si_count = int(args[0], 16) if args[0].startswith("0x") else int(args[0])
                self.si(si_count)
            else:
                dprint.println(
                    colour.white("[*] Usage: si [count], count is optional"), dml=True
                )

## ================================================================= Search Pattern =================================================================

class SearchPattern:
    def __init__(self):
        self.ptrmask: int = (
            0xFFFFFFFFFFFFFFFF
            if pykd.getCPUMode() == pykd.CPUType.AMD64
            else 0xFFFFFFFF
        )

    def help(self):
        dprint.println(
            colour.white("[-] Usage: find [pattern](int, 0x, 0o, 0b, dec, str)"),
            dml=True,
        )

    def find_int(self, start, end, search_value, inputsize) -> list[int]:
        dumped_pattern: str = ""
        retlist: list[int] = []
        search_bytes: str = ""
        for ch in search_value.to_bytes(inputsize, byteorder="little"):
            search_bytes += f" {ch:02x}"

        dumped_pattern = pykd.dbgCommand(f"s {hex(start)} {hex(end)}{search_bytes}")

        if dumped_pattern == None:
            return []

        for line in dumped_pattern.split("\n"):
            if line.strip() == "":
                continue
            line = line.replace("`", "").split("  ")[0]
            retlist.append(int(f"0x{line.strip().split(' ')[0]}", 16))

        return retlist

    def find_str(self, start, end, search_value) -> list[int]:
        dumped_pattern: str = ""
        retlist: list[int] = []

        dumped_pattern = pykd.dbgCommand(
            f's -a {hex(start)} {hex(end)} "{search_value}"'
        )

        if dumped_pattern == None:
            return []

        for line in dumped_pattern.split("\n"):
            if line.strip() == "":
                continue
            line = line.replace("`", "").split("  ")[0]
            retlist.append(int(f"0x{line.strip().split(' ')[0]}", 16))

        return retlist

    def find(
        self,
        pattern: str,
        start: int = 0x0,
        end: int = 0xFFFFFFFFFFFFFFFF,
        level: int = 0,
    ) -> None:
        find_int_mode: bool = False
        search_value: int | str

        if pattern.startswith("0x"):
            find_int_mode = True
            search_value = int(pattern, 16)
        elif pattern.startswith("0b"):
            find_int_mode = True
            search_value = int(pattern, 2)
        elif pattern.startswith("0o"):
            find_int_mode = True
            search_value = int(pattern, 8)
        elif (pattern.startswith("'") and pattern.endswith("'")) or (
            pattern.startswith('"') and pattern.endswith('"')
        ):
            find_int_mode = False
            search_value = pattern[1:-1]
        else:
            try:
                find_int_mode = True
                search_value = int(pattern)
            except:
                find_int_mode = False
                search_value = pattern

        if find_int_mode:
            inputsize: int = 0
            tmp: int = search_value

            while tmp != 0:
                tmp = tmp >> 8
                inputsize += 1
            if inputsize > 8:
                dprint.fail_print("Invalid pattern (too long)")
                self.help()
                return

            dprint.trying_print(
                f"Searching {hex(search_value)} pattern in {'whole memory' if (start == 0 and end == (1 << 64) - 1) else 'given section'}"
            )

            for section in vmmap.dump_section():
                once: bool = True
                offset: int = 0

                if section.base_address < start:
                    continue
                if section.base_address > end:
                    break
                if PageState.is_free(section.state) or PageState.is_reserve(
                    section.state
                ):
                    continue

                dump_result: list[int] = self.find_int(
                    section.base_address, section.end_address, search_value, inputsize
                )

                if dump_result == []:
                    continue

                for addr in dump_result:
                    hex_datas: list[int] = memoryaccess.get_qword_datas(addr)
                    if once:
                        once = False
                        info: str = ""
                        if section.image_path != "":
                            info = section.image_path
                        elif section.additional != "":
                            info = section.additional
                        else:
                            info = section.usage
                        dprint.success_print(
                            f"In {colour.blue(info)} ({hex(section.base_address)}-{hex(section.end_address)} [{PageProtect.to_str(section.protect)}])"
                        )
                    dprint.print(
                        f"{colour.colorize_hex_by_address(addr, 16)}", dml=True
                    )
                    dprint.print(":\t")

                    for data in hex_datas:
                        dprint.print(f"0x{data:016x} ")
                    dprint.print("| ")
                    for data in hex_datas:
                        for ch in p64(data):
                            if chr(ch) in string.whitespace:
                                dprint.print(".")
                            elif chr(ch) in string.printable:
                                dprint.print(chr(ch))
                            else:
                                dprint.print(".")
                    dprint.println(" |")
                dprint.print_newline()

            dprint.success_print("Searching pattern finished")

        else:
            dprint.trying_print(
                f"Searching '{search_value}' pattern in {'whole memory' if (start == 0 and end == (1 << 64) - 1) else 'given section'}"
            )

            for section in vmmap.dump_section():
                once: bool = True

                if section.base_address < start:
                    continue
                if section.base_address > end:
                    break
                if PageState.is_free(section.state) or PageState.is_reserve(
                    section.state
                ):
                    continue

                for addr in self.find_str(
                    section.base_address, section.end_address, search_value
                ):
                    if once:
                        once = False
                        info: str = ""
                        if section.image_path != "":
                            info = section.image_path
                        elif section.additional != "":
                            info = section.additional
                        else:
                            info = section.usage
                        dprint.success_print(
                            f"In '{colour.blue(info)}' ({hex(section.base_address)}-{hex(section.end_address)} [{PageProtect.to_str(section.protect)}])"
                        )
                    dprint.print(colour.white(f"0x{(addr):016x}"), dml=True)
                    dprint.print(":\t")

                    memval: bytes = memoryaccess.get_bytes(addr, 0x10)

                    for ch in memval:
                        dprint.print(f"{ch:02x} ")
                    dprint.print("| ")
                    for ch in memval:
                        ch = chr(ch)
                        if ch in string.whitespace:
                            dprint.print(".")
                        elif ch in string.printable:
                            dprint.print(ch)
                        else:
                            dprint.print(".")
                    dprint.println(" |")

            dprint.success_print("Searching pattern finished")

    def help(self):
        dprint.println(
            colour.white(
                "[*] Usage: find [pattern](int, 0x, 0o, 0b, dec, str) [start] [end], start and end are optional"
            ),
            dml=True,
        )
        dprint.println(
            colour.white(
                "[*] Example: find 0x12345678 0x10000000 0x20000000, find '0x12345678' in range [0x10000000, 0x20000000]"
            ),
            dml=True,
        )

    def execute(self, params: list[str]):
        command, args = params[0], params[1:]
        if len(args) > 0 and args[0] == "help":
            self.help()
        elif command == "find":
            if len(args) == 1:
                self.find(args[0])
            elif len(args) == 2:
                self.find(args[0], int(args[1], 16), 0xFFFFFFFFFFFFFFFF)
            elif len(args) == 3:
                self.find(args[0], int(args[1], 16), int(args[2], 16))
            else:
                self.help()

## ================================================================ Types =================================================================
class Bit(int):
    def __new__(cls, value: int):
        if not isinstance(value, int):
            raise TypeError("Value must be an integer")
        if value < 0 or value > 1:
            raise ValueError("Value must be either 0 or 1")
        return super().__new__(cls, value)

class uint16_t(int):
    def __new__(cls, value: int):
        if not isinstance(value, int):
            raise TypeError("Value must be an integer")
        if value < 0 or value > 0xFFFF:
            raise ValueError("Value must be in the range [0, 65535]")
        return super().__new__(cls, value)
    
    @staticmethod
    def size() -> int:
        return 2

T = TypeVar('T')
    
class Pointer(Generic[T]):
    def __init__(self, address: int, __orig_class__=None):
        self.address = int(address)
        self.__orig_class__ = __orig_class__

    def __int__(self):
        return self.address or 0

    def __eq__(self, other):
        if isinstance(other, Pointer):
            return self.address == other.address
        elif isinstance(other, int):
            return self.address == other
        return False
    
    def __xor__(self, other):
        if isinstance(other, Pointer):
            return Pointer(self.address ^ other.address, self.__orig_class__)
        elif isinstance(other, int):
            return Pointer(self.address ^ other, self.__orig_class__)
        raise TypeError(f"Unsupported type for XOR: {type(other)}")

    def __repr__(self):
        return f"Pointer({self.address:#x})" if self.address is not None else "Pointer(None)"
    
    @property
    def T(self):
        return get_args(self.__orig_class__)[0]
        
    @staticmethod
    def size() -> int:
        if pykd.getCPUMode() == pykd.CPUType.AMD64:
            return 8
        elif pykd.getCPUMode() == pykd.CPUType.I386:
            return 4
        else:
            raise RuntimeError("Unsupported CPU mode")

    def deref(self) -> T:
        if not pykd.isValid(self.address):
            raise pykd.MemoryException(f"Invalid pointer dereference: {self.address:#x}")

        if isinstance(self.T, _GenericAlias):
            return get_origin(self.T)[get_args(self.T)[0]](memoryaccess.deref_ptr(self.address))
        elif self.T == Bit:
            return Bit(memoryaccess.deref_ptr(self.address) & 0x1)
        elif self.T.__name__.startswith("uint") and self.T.__name__.endswith("_t"):
            return uint16_t(memoryaccess.deref_ptr(self.address) & 0xFFFF)

        pykdTypedVar = nt.typedVar(self.T.__name__, self.address)
        if pykdTypedVar is None or not pykd.isValid(pykdTypedVar):
            return None
        return self.T(pykdTypedVar)
    
class Array(Generic[T]):
    def __init__(self, address: int, __orig_class__=None):
        self.address = int(address)
        self.__orig_class__ = __orig_class__

    def __getitem__(self, index: int) -> T:
        if isinstance(self.T, _GenericAlias):
            return get_origin(self.T)[get_args(self.T)[0]](memoryaccess.deref_ptr(self.address + index * self.T.size()))
        elif self.T == Bit:
            return Bit(memoryaccess.deref_ptr(self.address + index * self.T.size()) & 0x1)
        elif self.T.__name__.startswith("uint") and self.T.__name__.endswith("_t"):
            return uint16_t(memoryaccess.deref_ptr(self.address + index * self.T.size()) & 0xFFFF)
        pykdTypedVar = nt.typedVar(self.T.__name__, self.address + index * self.T.size())
        if pykdTypedVar is None or not pykd.isValid(pykdTypedVar):
            return None
        return self.T(pykdTypedVar)

    @property
    def T(self):
        return get_args(self.__orig_class__)[0]

class PykdObject:
    def __init__(self, address: int = 0):
        self.address = int(address)

    def __int__(self):
        return self.address or 0

    def __repr__(self):
        return f"{self.__class__.__name__}({self.address:#x})" if self.address is not None else f"{self.__class__.__name__}(None)"
    
    @classmethod
    def size(cls) -> int:
        return nt.sizeof(cls.__name__)
    
## ================================================================= Data Structure =================================================================
@dataclass
class _SLIST_HEADER(PykdObject):
    Alignment: int
    Region: int
    HeaderX64: int

    def __init__(self, slist_header):
        super().__init__(int(slist_header))
        self.Alignment = slist_header.Alignment
        self.Region = slist_header.Region
        self.HeaderX64 = slist_header.HeaderX64
        
@dataclass
class _LIST_ENTRY(PykdObject):
    Flink: Pointer[_LIST_ENTRY]
    Blink: Pointer[_LIST_ENTRY]

    def __init__(self, list_entry):
        super().__init__(int(list_entry))
        self.Flink = Pointer[_LIST_ENTRY](list_entry.Flink, _LIST_ENTRY)
        self.Blink = Pointer[_LIST_ENTRY](list_entry.Blink, _LIST_ENTRY)
    
    def return_check_list_entry(self, error: list[str]):
        return (True if error == [] else False, error)

    def check_list_entry(self) -> tuple[bool, str]:
        error = []

        if self.Flink.deref() is None:
            error.append(
                f"listentry.Flink({colour.colorize_hex_by_address(self.Flink)}) is Invalid address"
            )
        if self.Blink.deref() is None:
            error.append(
                f"listentry.Blink({colour.colorize_hex_by_address(self.Blink)}) is Invalid address"
            )
        if error != []:
            return self.return_check_list_entry(error)

        if self.Flink.deref().Blink.deref() is None:
            error.append(
                f"listentry.Flink.Blink is Invalid address, {colour.colorize_hex_by_address(self.Flink.deref().Blink)}"
            )
        if self.Blink.deref().Flink.deref() is None:
            error.append(
                f"listentry.Blink.Flink is Invalid address, {colour.colorize_hex_by_address(self.Blink.deref().Flink)}"
            )
        if error != []:
            return self.return_check_list_entry(error)

        if self.Flink.deref().Blink.deref().Flink != self.Flink:
            error.append("chunk->Flink->Blink != chunk")
        if self.Blink.deref().Flink.deref().Blink != self.Blink:
            error.append("chunk->Blink->Flink != chunk")
        if error != []:
            return self.return_check_list_entry(error)

        if self.Flink.deref().Blink.deref().Flink != self.Flink:
            error.append("next_chunk->Blink->Flink != next_chunk")

        return self.return_check_list_entry(error)

    def traverse_list_entry(self, include_self: bool = True) -> tuple[tuple[bool, str], list[_LIST_ENTRY]]:
        success = True
        result = []
        errorstr: str = ""

        if include_self:
            result.append(self)

        curr = self.Blink.deref()

        while curr is not None and curr not in result:
            if int(curr) == int(self):
                break
            result.append(curr)
            check_result = curr.check_list_entry()

            if not check_result[0]:
                success = False
                errorstr += f"Error in list entry {curr}: {check_result[1]}\n"
            curr = curr.Blink.deref()

        if curr is not None and curr in result:
            success = False
            errorstr += f"List entry {curr} is in the list more than once.\n"

        return (success, errorstr), result

@dataclass
class _RTL_BALANCED_NODE(PykdObject):
    Left: Pointer[_RTL_BALANCED_NODE]
    Right: Pointer[_RTL_BALANCED_NODE]
    Red: int
    Balance: int
    ParentValue: Pointer[_RTL_BALANCED_NODE]

    def __init__(self, node):
        super().__init__(int(node))
        self.Left = Pointer[_RTL_BALANCED_NODE](node.Left, _RTL_BALANCED_NODE)
        self.Right = Pointer[_RTL_BALANCED_NODE](node.Right, _RTL_BALANCED_NODE)
        self.Red = node.Red
        self.Balance = node.Balance
        self.ParentValue = Pointer[_RTL_BALANCED_NODE](node.ParentValue & ~(0b11), _RTL_BALANCED_NODE)
    
    def get_parent(self) -> Pointer[_RTL_BALANCED_NODE]:
        if not pykd.isValid(int(self.ParentValue)):
            return Pointer[_RTL_BALANCED_NODE](0, _RTL_BALANCED_NODE)
        return Pointer[_RTL_BALANCED_NODE](self.ParentValue.address & ~(0b11), _RTL_BALANCED_NODE)

    def return_check_rbtree(self, error: list[str]):
        return (True if error == [] else False, error)
    
    def check_node(self, isroot: bool = False) -> tuple[bool, str]:
        error = []

        if not pykd.isValid(int(self)):
            return (
                False,
                f"rbtree node({colour.colorize_hex_by_address(self)}) is Invalid address",
            )

        if not pykd.isValid(int(self.ParentValue)) and isroot is False:
            error.append(
                f"rbtree node.ParentValue({int(self.ParentValue)}) is Invalid address"
            )
        
        if not pykd.isValid(self.Left) and self.Left != 0:
            error.append(f"rbtree node.Left({int(self.Left)}) is Invalid address")

        if not pykd.isValid(self.Right) and self.Right != 0:
            error.append(f"rbtree node.Right({int(self.Right)}) is Invalid address")
        
        if error != []:
            return self.return_check_rbtree(error)
    
        if self.Left != 0 and self.Left.deref().ParentValue != self:
            error.append(
                f"node.Left.ParentValue({int(self.Left.deref().ParentValue):#x}) != node({int(self):#x})"
            )
        if self.Right != 0 and self.Right.deref().ParentValue != self:
            error.append(
                f"node.Right.ParentValue({int(self.Right.deref().ParentValue):#x}) != node({int(self):#x})"
            )
        return self.return_check_rbtree(error)

    def traverse_rbtree_inorder(self) -> list[_RTL_BALANCED_NODE]:
        inorder = []

        if self == 0:
            return []
        if not pykd.isValid(int(self)):
            return []

        if self.Left != 0 and self.Left not in inorder:
            inorder.extend(self.Left.deref().traverse_rbtree_inorder())
        inorder.append(self)
        if self.Right != 0 and self.Right not in inorder:
            inorder.extend(self.Right.deref().traverse_rbtree_inorder())
        if not pykd.isValid(int(self.Left)) and self.Left != 0:
            raise pykd.MemoryException(f"Invalid Left pointer in rbtree node: {int(self.Left):#x}")
        if not pykd.isValid(int(self.Right)) and self.Right != 0:
            raise pykd.MemoryException(f"Invalid Right pointer in rbtree node: {int(self.Right):#x}")

        return inorder

@dataclass
class _RTL_RB_TREE(PykdObject):
    Root: Pointer[_RTL_BALANCED_NODE]
    Min: Pointer[_RTL_BALANCED_NODE]
    Encoded: int

    def __init__(self, rbtree):
        super().__init__(int(rbtree))
        self.Root = Pointer[_RTL_BALANCED_NODE](rbtree.Root, _RTL_BALANCED_NODE)
        self.Min = Pointer[_RTL_BALANCED_NODE](rbtree.Min, _RTL_BALANCED_NODE)
        self.Encoded = rbtree.Encoded
    
    def traverse_rbtree(self) -> list[_RTL_BALANCED_NODE]:
        if not pykd.isValid(int(self.Root)):
            return []
        return self.Root.deref().traverse_rbtree_inorder()

## ================================================================= PEB / TEB =================================================================

class TEB:
    def __init__(self):
        tebaddress: int = self.getTEBAddress()

    # https://github.com/corelan/windbglib/blob/d20b3036547886ff6beb616d24927febfa491e93/windbglib.py#L177
    def getTEBAddress(self) -> Optional[int]:
        try:
            tebinfo = pykd.dbgCommand("!teb")
            tebline = tebinfo.split("\n")[0]
            tebparts = tebline.split(" ")[2]
            return int(f"0x{tebparts}", 16)
        except:
            return None


class PEB:
    def __init__(self):
        self.peb = self.getPEBInfo()

    def getPEBAddress(self) -> Optional[int]:
        try:
            pebinfo = pykd.dbgCommand("!peb")
            pebline = pebinfo.split("\n")[0]
            pebparts = pebline.split(" ")[2]
            return int(f"0x{pebparts}", 16)
        except:
            return None

    def getPEBInfo(self):
        peb = nt.typedVar("_PEB", self.getPEBAddress())

        return peb

## ================================================================= SEH =================================================================

class SEHInfo:
    Curr: int
    Next: int
    Handler: int

    def __init__(self, ptr):
        self.Curr: int = ptr
        self.Next: Optional[int] = None
        self.Handler: Optional[int] = None
        try:
            self.Next = (
                int(nt.typedVar("_EXCEPTION_REGISTRATION_RECORD", ptr).Next)
                & context.ptrmask
            )
            self.Handler = (
                int(nt.typedVar("_EXCEPTION_REGISTRATION_RECORD", ptr).Handler)
                & context.ptrmask
            )
        except pykd.MemoryException:
            pass


class SEH(TEB):
    def __init__(self):
        self.sehchain: list[SEHInfo] = self.getSEHChain()

    def getSEHChain(self) -> list[SEHInfo]:
        self.sehchain = []
        test = []

        tebaddress: int = self.getTEBAddress()

        if tebaddress is None:
            return self.sehchain

        currseh_ptr: int = memoryaccess.deref_ptr(tebaddress)

        if currseh_ptr == 0:
            return self.sehchain
        else:
            self.sehchain.append(SEHInfo(currseh_ptr))

        while True:
            if self.sehchain[-1].Curr in self.sehchain:
                break
            self.sehchain.append(SEHInfo(self.sehchain[-1].Next))
            test.append(self.sehchain[-1])
            if (
                self.sehchain[-1].Next == context.ptrmask
                or self.sehchain[-1].Next is None
            ):
                break

        return self.sehchain

    def get_scopetable(self, sehinfo: int) -> int:
        return int.from_bytes(
            memoryaccess.get_bytes(sehinfo.Curr + 0x8, 4), byteorder="little"
        )

    def get_try_level(self, sehinfo: int) -> int:
        return int.from_bytes(
            memoryaccess.get_bytes(sehinfo.Curr + 0xC, 4), byteorder="little"
        )

    def except_handler3(self, sehinfo: SEHInfo) -> tuple[int, int, int]:
        EnclosingLevel = int.from_bytes(
            memoryaccess.get_bytes(sehinfo.Curr + 0x8, 4), byteorder="little"
        )
        FilterFunc = int.from_bytes(
            memoryaccess.get_bytes(sehinfo.Curr + 0xC, 4), byteorder="little"
        )
        HandlerFunc = int.from_bytes(
            memoryaccess.get_bytes(sehinfo.Curr + 0x10, 4), byteorder="little"
        )
        return (EnclosingLevel, FilterFunc, HandlerFunc)

    def except_handler4(self, sehinfo: SEHInfo) -> tuple[int, int, int]:
        symname = memoryaccess.get_symbol(sehinfo.Handler).split("!")[0]
        security_cookie = int.from_bytes(
            memoryaccess.get_bytes(
                memoryaccess.get_addr_from_symbol(f"{symname}!__security_cookie"), 4
            ),
            byteorder="little",
        )
        scopetable_array = self.get_scopetable(sehinfo) ^ security_cookie

        gs_cookie_offset = memoryaccess.get_int(scopetable_array)
        gs_cookie_xor_offset = memoryaccess.get_int(scopetable_array + 0x4)
        eh_cookie_offset = memoryaccess.get_int(scopetable_array + 0x8)
        eh_cookie_xor_offset = memoryaccess.get_int(scopetable_array + 0xC)

        checker = 0

        if gs_cookie_offset != -2:
            checker = gs_cookie_offset
        else:
            checker = eh_cookie_offset

        EnclosingLevel = int.from_bytes(
            memoryaccess.get_bytes(scopetable_array + 0x10 + 0xC * checker, 4),
            byteorder="little",
        )
        FilterFunc = int.from_bytes(
            memoryaccess.get_bytes(scopetable_array + 0x10 + 0xC * checker + 0x4, 4),
            byteorder="little",
        )
        HandlerFunc = int.from_bytes(
            memoryaccess.get_bytes(scopetable_array + 0x10 + 0xC * checker + 0x8, 4),
            byteorder="little",
        )
        return (EnclosingLevel, FilterFunc, HandlerFunc)

    def get_except_handler_info(
        self, sehinfo: SEHInfo
    ) -> Optional[tuple[int, int, int]]:
        if "_except_handler3" in memoryaccess.get_symbol(sehinfo.Handler):
            return self.except_handler3(sehinfo)
        elif "_except_handler4" in memoryaccess.get_symbol(sehinfo.Handler):
            return self.except_handler4(sehinfo)
        else:
            return None

    def get_esp_and_exc_ptr(self, sehinfo: SEHInfo) -> tuple[int, int]:
        old_esp = int.from_bytes(
            memoryaccess.get_bytes(sehinfo.Curr - 0x8, 4), byteorder="little"
        )
        exc_ptr = int.from_bytes(
            memoryaccess.get_bytes(sehinfo.Curr - 0x4, 4), byteorder="little"
        )
        return (old_esp, exc_ptr)

    def print_sehchain(self) -> None:
        dprint.banner_print(" SEH Chain ")
        self.sehchain = self.getSEHChain()
        self.exceptone: bool = True

        for sehinfo in self.sehchain:
            if self.exceptone:
                self.exceptone = False
            else:
                dprint.println("     ↓")

            if sehinfo.Next is None:
                dprint.println(f"0x{sehinfo.Curr:08x}: (chain is broken)")
                return
            else:
                dprint.print(
                    f"{colour.colorize_hex_by_address(sehinfo.Curr, 8)}: {colour.colorize_hex_by_address(sehinfo.Next, 8)} | {colour.colorize_hex_by_address(sehinfo.Handler, 8)} ",
                    dml=True,
                )
                if memoryaccess.get_symbol(sehinfo.Handler) is not None:
                    dprint.println(f"<{memoryaccess.get_symbol(sehinfo.Handler)}>")
                elif not pykd.isValid(sehinfo.Handler):
                    dprint.println("<invalid address>")
                    continue
                else:
                    dprint.println("")

                if sehinfo.Next == context.ptrmask:
                    dprint.println("     ↓\n(end of chain)")
                else:
                    try_level = self.get_try_level(sehinfo)
                    if try_level == 0xFFFFFFFF or try_level == 0xFFFFFFFE:
                        pykd.println(" " * 12 + "try_level < 0, not in try block")
                    old_esp, exc_ptr = self.get_esp_and_exc_ptr(sehinfo)

                    seh_handler_info = self.get_except_handler_info(sehinfo)
                    if seh_handler_info is not None:
                        EnclosingLevel, FilterFunc, HandlerFunc = seh_handler_info
                        dprint.println(
                            " " * 12
                            + f"old_esp: {colour.colorize_hex_by_address(old_esp, 8)}, exc_ptr: {colour.colorize_hex_by_address(exc_ptr, 8)}, try_level: {try_level}, EnclosingLevel: 0x{EnclosingLevel:08x}, FilterFunc: {colour.colorize_hex_by_address(FilterFunc, 8)}, HandlerFunc: {colour.colorize_hex_by_address(HandlerFunc, 8)}",
                            dml=True,
                        )
                    else:
                        dprint.println(" " * 12 + "unknown exception handler type")

        dprint.banner_print("")

## ================================================================= Heap =================================================================
@dataclass
class _RTLP_HP_HEAP_GLOBALS(PykdObject):
    HeapKey: int
    LfhKey: int
    Flags: int
    RandomSeed: int

    def __init__(self, rtlp_hp_heap_globals):
        super().__init__(int(rtlp_hp_heap_globals))
        self.HeapKey = rtlp_hp_heap_globals.HeapKey
        self.LfhKey = rtlp_hp_heap_globals.LfhKey
        self.Flags = rtlp_hp_heap_globals.Flags
        self.RandomSeed = rtlp_hp_heap_globals.RandomSeed
    
    @staticmethod
    def addr() -> int:
        return memoryaccess.get_addr_from_symbol("ntdll!RtlpHpHeapGlobals")

    @staticmethod
    def get() -> _RTLP_HP_HEAP_GLOBALS:
        return _RTLP_HP_HEAP_GLOBALS(
            nt.typedVar("_RTLP_HP_HEAP_GLOBALS", memoryaccess.get_addr_from_symbol("ntdll!RtlpHpHeapGlobals"))
        )

@dataclass
class _HEAP_LIST_LOOKUP(PykdObject):
    ExtendedLookup: Pointer[_HEAP_LIST_LOOKUP]
    ArraySize: int
    ExtraItem: int
    ItemCount: int
    OutOfRangeItems: int
    BaseIndex: int
    ListHead: Pointer[_LIST_ENTRY]
    ListsInUseUlong: Pointer[int]
    ListHints: Array[Pointer[_LIST_ENTRY]]

    def __init__(self, heap_list_lookup):
        super().__init__(int(heap_list_lookup))
        self.ExtendedLookup = Pointer[_HEAP_LIST_LOOKUP](
            heap_list_lookup.ExtendedLookup
        )
        self.ArraySize = heap_list_lookup.ArraySize
        self.ExtraItem = heap_list_lookup.ExtraItem
        self.ItemCount = heap_list_lookup.ItemCount
        self.OutOfRangeItems = heap_list_lookup.OutOfRangeItems
        self.BaseIndex = heap_list_lookup.BaseIndex
        self.ListHead = Pointer[_LIST_ENTRY](heap_list_lookup.ListHead)
        self.ListsInUseUlong = Pointer[int](heap_list_lookup.ListsInUseUlong)
        self.ListHints = Array[Pointer[_LIST_ENTRY]](heap_list_lookup.ListHints)

    @property
    def size(self) -> int:
        return nt.sizeof("_HEAP_LIST_LOOKUP")

@dataclass
class _INTERLOCK_SEQ(PykdObject):
    Depth: int
    Hint: int
    Lock: int
    Hint16: int
    Exchg: int

    def __init__(self, interlock_seq):
        super().__init__(int(interlock_seq))
        self.Depth = interlock_seq.Depth
        self.Hint = interlock_seq.Hint
        self.Lock = interlock_seq.Lock
        self.Hint16 = interlock_seq.Hint16
        self.Exchg = interlock_seq.Exchg

@dataclass
class _RTL_BITMAP_EX(PykdObject):
    SizeOfBitMap: int
    Buffer: Pointer[int]

    def __init__(self, rtl_bitmap_ex):
        super().__init__(int(rtl_bitmap_ex))
        self.SizeOfBitMap = rtl_bitmap_ex.SizeOfBitMap
        self.Buffer = Pointer[int](rtl_bitmap_ex.Buffer)
    
@dataclass
class _HEAP_USERDATA_HEADER(PykdObject):
    SubSegment: Pointer[_HEAP_SUBSEGMENT]
    SizeIndexAndPadding: int
    SizeIndex: int
    GuardPagePresent: int
    PaddingBytes: int
    Signature: int
    EncodedOffsets: int
    BusyBitmap: _RTL_BITMAP_EX
    BitmapData: Array[Bit]

    def __init__(self, heap_userdata_header):
        super().__init__(int(heap_userdata_header))
        self.SubSegment = Pointer[_HEAP_SUBSEGMENT](heap_userdata_header.SubSegment)
        self.SizeIndexAndPadding = heap_userdata_header.SizeIndexAndPadding
        self.SizeIndex = heap_userdata_header.SizeIndex
        self.GuardPagePresent = heap_userdata_header.GuardPagePresent
        self.PaddingBytes = heap_userdata_header.PaddingBytes
        self.Signature = heap_userdata_header.Signature
        self.EncodedOffsets = heap_userdata_header.EncodedOffsets
        self.BusyBitmap = _RTL_BITMAP_EX(heap_userdata_header.BusyBitmap)
        self.BitmapData = Array[Bit](heap_userdata_header.BitmapData)
    
@dataclass
class _HEAP_LOCAL_DATA(PykdObject):
    def __init__(self, heap_local_data):
        super().__init__(int(heap_local_data))
        # Assuming heap_local_data has no fields for now, can be extended later
        pass

@dataclass
class _HEAP_SUBSEGMENT(PykdObject):
    LocalInfo: Pointer[_HEAP_LOCAL_SEGMENT_INFO]
    UserBlocks: Pointer[_HEAP_USERDATA_HEADER]
    DelayFreeList: Pointer[_SLIST_HEADER]
    AggregateExchg: _INTERLOCK_SEQ
    BlockSize: int
    Flags: int
    BlockCount: int
    SizeIndex: int

    def __init__(self, heap_subsegment):
        super().__init__(int(heap_subsegment))
        self.LocalInfo = Pointer[_HEAP_LOCAL_SEGMENT_INFO](heap_subsegment.LocalInfo)
        self.UserBlocks = Pointer[_HEAP_USERDATA_HEADER](heap_subsegment.UserBlocks)
        self.DelayFreeList = Pointer[_SLIST_HEADER](heap_subsegment.DelayFreeList)
        self.AggregateExchg = _INTERLOCK_SEQ(heap_subsegment.AggregateExchg)
        self.BlockSize = heap_subsegment.BlockSize
        self.Flags = heap_subsegment.Flags
        self.BlockCount = heap_subsegment.BlockCount
        self.SizeIndex = heap_subsegment.SizeIndex

@dataclass
class _HEAP_BUCKET(PykdObject):
    BlockUnits: int
    SizeIndex: int
    UseAffinity: int
    Flags: int

    def __init__(self, heap_bucket):
        super().__init__(int(heap_bucket))
        self.BlockUnits = heap_bucket.BlockUnits
        self.SizeIndex = heap_bucket.SizeIndex
        self.UseAffinity = heap_bucket.UseAffinity
        self.Flags = heap_bucket.Flags
    
    def get_real_size(self) -> int:
        if pykd.getCPUMode() == pykd.CPUType.I386:
            return self.BlockUnits << 3
        elif pykd.getCPUMode() == pykd.CPUType.AMD64:
            return self.BlockUnits << 4
        else:
            raise RuntimeError("Unsupported CPU mode")

@dataclass
class _HEAP_LOCAL_SEGMENT_INFO(PykdObject):
    LocalData: Pointer[_HEAP_LOCAL_DATA]
    ActiveSubsegment: Pointer[_HEAP_SUBSEGMENT]
    CachedItems: Array[Pointer[_HEAP_SUBSEGMENT]]
    SListHeader: Pointer[_SLIST_HEADER]
    BucketIndex: int

    def __init__(self, heap_local_segment_info):
        super().__init__(int(heap_local_segment_info))
        self.LocalData = Pointer[_HEAP_LOCAL_DATA](heap_local_segment_info.LocalData)
        self.ActiveSubsegment = Pointer[_HEAP_SUBSEGMENT](
            heap_local_segment_info.ActiveSubsegment
        )
        self.CachedItems = Array[Pointer[_HEAP_SUBSEGMENT]](
            heap_local_segment_info.CachedItems
        )
        self.SListHeader = Pointer[_SLIST_HEADER](heap_local_segment_info.SListHeader)
        self.BucketIndex = heap_local_segment_info.BucketIndex

@dataclass
class _HEAP_ENTRY(PykdObject):
    PreviousBlockPrivateData: Pointer[int]
    Size: int
    Flags: int
    SmallTagIndex: int
    SubSegmentCode: int
    PreviousSize: int
    SegmentOffset: int
    LFHFlags: int
    UnusedBytes: int

    def __init__(self, heap_entry):
        super().__init__(int(heap_entry))
        self.PreviousBlockPrivateData = Pointer[int](
            heap_entry.PreviousBlockPrivateData, int
        )
        self.Size = heap_entry.Size
        self.Flags = heap_entry.Flags
        self.SmallTagIndex = heap_entry.SmallTagIndex
        self.SubSegmentCode = heap_entry.SubSegmentCode
        self.PreviousSize = heap_entry.PreviousSize
        self.SegmentOffset = heap_entry.SegmentOffset
        self.LFHFlags = heap_entry.LFHFlags
        self.UnusedBytes = heap_entry.UnusedBytes
    
    @staticmethod
    def from_list_entry(list_entry: _LIST_ENTRY) -> _HEAP_ENTRY:
        return _HEAP_ENTRY(nt.typedVar("_HEAP_ENTRY", int(list_entry) - _HEAP_ENTRY.size()))
    
    def decode(self, encoding: _HEAP_ENTRY) -> _HEAP_ENTRY:
        new_heap_entry = _HEAP_ENTRY(self)
        new_heap_entry.PreviousBlockPrivateData ^= encoding.PreviousBlockPrivateData
        new_heap_entry.Size ^= encoding.Size
        new_heap_entry.Flags ^= encoding.Flags
        new_heap_entry.SmallTagIndex ^= encoding.SmallTagIndex
        new_heap_entry.SubSegmentCode ^= encoding.SubSegmentCode
        new_heap_entry.PreviousSize ^= encoding.PreviousSize
        new_heap_entry.SegmentOffset ^= encoding.SegmentOffset
        new_heap_entry.LFHFlags ^= encoding.LFHFlags
        new_heap_entry.UnusedBytes ^= encoding.UnusedBytes

        return new_heap_entry
    
    def get_real_size(self) -> int:
        if pykd.getCPUMode() == pykd.CPUType.I386:
            return self.Size << 3
        elif pykd.getCPUMode() == pykd.CPUType.AMD64:
            return self.Size << 4
        
    @property
    def expected_smalltagindex(self) -> int:
        return (self.Size & 0xff) ^ ((self.Flags & 0xff00) >> 8) ^ (self.Flags)
    
@dataclass
class _LFH_HEAP(PykdObject):
    SubSegmentZones: Pointer[_LIST_ENTRY]
    Heap: Pointer[_HEAP]
    Buckets: Array[_HEAP_BUCKET]
    SegmentInfoArrays: Array[Pointer[_HEAP_LOCAL_SEGMENT_INFO]]

    def __init__(self, lfh_heap):
        super().__init__(int(lfh_heap))
        self.SubSegmentZones = Pointer[_LIST_ENTRY](lfh_heap.SubSegmentZones)
        self.Heap = Pointer[_HEAP](lfh_heap.Heap)
        self.Buckets = Array[_HEAP_BUCKET](lfh_heap.Buckets)
        self.SegmentInfoArrays = Array[Pointer[_HEAP_LOCAL_SEGMENT_INFO]](
            lfh_heap.SegmentInfoArrays
        )

@dataclass
class _HEAP_SEGMENT(PykdObject):
    def __init__(self, heap_segment):
        pass

@dataclass
class _HEAP(PykdObject):
    Segment: _HEAP_SEGMENT
    SegmentSignature: int
    Encoding: _HEAP_ENTRY
    BlocksIndex: Pointer[_HEAP_LIST_LOOKUP]
    FreeLists: _LIST_ENTRY
    FrontEndHeap: Pointer[_LFH_HEAP]

    def __init__(self, heap):
        super().__init__(int(heap))
        self.Segment = _HEAP_SEGMENT(heap.Segment)
        self.SegmentSignature = heap.SegmentSignature
        self.Encoding = _HEAP_ENTRY(heap.Encoding)
        self.BlocksIndex = Pointer[_HEAP_LIST_LOOKUP](heap.BlocksIndex)
        self.FreeLists = _LIST_ENTRY(heap.FreeLists)
        self.FrontEndHeap = Pointer[_LFH_HEAP](heap.FrontEndHeap)
    
class NTHeap():
    def __init__(self):
        pass

    def _HEAP(self, heap_address: int) -> _HEAP:
        return _HEAP(nt.typedVar("_HEAP", heap_address))

    def get_freelist_in_blocksindex(self, BlocksIndex: _HEAP_LIST_LOOKUP) -> list[_LIST_ENTRY]:
        if BlocksIndex == 0:
            return []
        return BlocksIndex.ListHead.deref().traverse_list_entry()[1]

    def get_blocksindexs(self, heap_address: int) -> list[_HEAP_LIST_LOOKUP]:
        heap = self._HEAP(heap_address)
        BlocksIndexs = []
        BlocksIndex = heap.BlocksIndex.deref()
        while BlocksIndex is not None and BlocksIndex != 0:
            BlocksIndexs.append(BlocksIndex)
            if BlocksIndex.ExtendedLookup == 0:
                break
            BlocksIndex = BlocksIndex.ExtendedLookup.deref()
        return BlocksIndexs

    def get_listhint(
        self, heap_address: int
    ) -> list[list[tuple[bool, Pointer[_LIST_ENTRY]]]]:
        listhint_list: list[list[tuple[bool, Pointer[_LIST_ENTRY]]]] = []

        for BlocksIndex in self.get_blocksindexs(heap_address):
            if BlocksIndex is None or BlocksIndex == 0:
                continue
            
            bitlist: list[int] = memoryaccess.get_qword_datas(
                int(BlocksIndex.ListsInUseUlong),
                math.floor(BlocksIndex.ArraySize / (0x8 * 0x8)),
            )
            bitmap: int = 0
            for i, bitnum in enumerate(bitlist):
                bitmap |= bitnum << (i * 64)

            listhint: list[int] = []

            for i in range(BlocksIndex.ArraySize):
                listhint.append(
                    (True if (bitmap >> i) & 1 else False, BlocksIndex.ListHints[i])
                )
            listhint_list.append(listhint)

        return listhint_list

    def get_chunk_size(
        self, heap: _HEAP, chunk: _HEAP_ENTRY, encoding: bool = True
    ) -> int:
        target = chunk.Size
        if encoding:
            target ^= heap.Encoding.Size
        if context.arch == pykd.CPUType.I386:
            return target << 3
        elif context.arch == pykd.CPUType.AMD64:
            return target << 4
        else:
            raise RuntimeError("Unsupported CPU mode")

    def is_valid_smalltagindex(self, chunk: _HEAP_ENTRY, encoding: _HEAP_ENTRY) -> int:
        # if context.arch == pykd.CPUType.I386:
        checker: int = 0
        for ch in (int(chunk.Size) ^ int(encoding.Size)).to_bytes(
            2, byteorder="little"
        ):
            checker ^= ch
        for ch in (int(chunk.Flags) ^ int(encoding.Flags)).to_bytes(
            1, byteorder="little"
        ):
            checker ^= ch
        for ch in (int(chunk.SmallTagIndex) ^ int(encoding.SmallTagIndex)).to_bytes(
            1, byteorder="little"
        ):
            checker ^= ch
        return checker

    def print_freelist(self, heap_address: int) -> None:
        heap = self._HEAP(heap_address)
        listhint_list = self.get_listhint(heap_address)
        blocksindex_list: list[_HEAP_LIST_LOOKUP] = self.get_blocksindexs(heap_address)

        notlfh_idxs: list[int] = []

        for i, blocksindex in enumerate(blocksindex_list):
            if blocksindex.BaseIndex == 0x0:
                notlfh_idxs.append(i)

        for t, listhint in enumerate(listhint_list):
            if t not in notlfh_idxs:
                continue

            freelist = self.get_freelist_in_blocksindex(blocksindex_list[t])

            if freelist == []:
                dprint.banner_print(" [-] Heap freelist is empty ")
                dprint.println(colour.white(" [-] Heap freelist is empty \n"), dml=True)
                return

            dprint.banner_print(
                f" [+] Heap freelist scan ({heap_address:#x}) at blocksindex {t} "
            )
            for i, linked_list in enumerate(freelist):
                chunk = _HEAP_ENTRY.from_list_entry(linked_list).decode(heap.Encoding)

                if not pykd.isValid(int(linked_list)):
                    dprint.print(colour.red(f"0x{int(chunk):08x} "), dml=True)
                    dprint.println(colour.white("| <invalid address> |"), dml=True)
                else:
                    dprint.print(
                        colour.white(
                            f"{colour.colorize_string_by_address(f'0x{int(chunk):08x}', chunk)} | Flink: {colour.colorize_string_by_address(f'0x{int(linked_list.Flink):08x}', linked_list.Flink)} / Blink: {colour.colorize_string_by_address(f'0x{int(linked_list.Blink):08x}', linked_list.Blink)} |"
                        ),
                        dml=True,
                    )
                    if i == 0 or (
                        i == len(freelist) - 1 and freelist[-1] == freelist[0]
                    ):
                        dprint.print(" (head)")
                    else:
                        dprint.print(
                            colour.white(
                                f" Size: {colour.blue(f'0x{chunk.get_real_size():04x}')} , PrevSize: 0x{chunk.get_real_size():04x}"
                            ),
                            dml=True,
                        )

                        if chunk.Size >= len(listhint):
                            dprint.print(colour.white(" (out of list hint)"), dml=True)
                        elif listhint[chunk.Size] == (True, int(linked_list)):
                            dprint.print(
                                colour.white(f" (list hint at [{chunk.Size:#x}])"),
                                dml=True,
                            )
                        elif (
                            listhint[chunk.Size][0]
                            and listhint[chunk.Size][1].deref() != int(linked_list)
                        ):
                            dprint.print(
                                colour.red(
                                    f" (expect 0x{int(linked_list):08x} but 0x{int(listhint[chunk.Size][1].deref()):08x}, based on list hint)"
                                ),
                                dml=True,
                            )

                        if chunk.SmallTagIndex != chunk.expected_smalltagindex:
                            dprint.print(
                                colour.red(
                                    f" (encoding error, {chunk.SmallTagIndex:#x} != {chunk.expected_smalltagindex:#x})"
                                ),
                                dml=True,
                            )

                    dprint.print_newline()

                if i != len(freelist) - 1:
                    sanity_result = linked_list.check_list_entry()
                    if sanity_result[0]:
                        dprint.println("     ↕️")
                    else:
                        dprint.println(
                            colour.red(f"     ↕️     ({', '.join(sanity_result[1])})"),
                            True,
                        )
            dprint.banner_print("")

    def print_lfh(self, heap_address: int) -> None:
        heap = self._HEAP(heap_address)
        lfh_heap = heap.FrontEndHeap.deref()

        if lfh_heap.Buckets.address == 0:
            dprint.banner_print(" [-] LFH Heap is not enabled ")
            return

        dprint.banner_print(f" [+] LFH Heap ({heap_address:#x}) at frontend heap ")
        for i in range(129):
            if int(lfh_heap.SegmentInfoArrays[i]) == 0:
                continue
            bucket, segment_info = lfh_heap.Buckets[i], lfh_heap.SegmentInfoArrays[i].deref()
            if segment_info.ActiveSubsegment == 0:
                dprint.println(
                    colour.white(
                        f"segment {i:#x} is empty ({colour.colorize_hex_by_address(0)}, size: {colour.blue(f'{bucket.get_real_size():#x}')})"
                    ),
                    dml=True,
                )
                dprint.println(
                    f"heap entry start: {colour.colorize_hex_by_address(0)}",
                    dml=True,
                )
                dprint.print_newline()
                continue
            _, active_subsegment = bucket.BlockUnits, segment_info.ActiveSubsegment.deref()
            userdata = active_subsegment.UserBlocks.deref()

            if active_subsegment.AggregateExchg.Depth == 0:
                dprint.println(
                    colour.white(
                        f"segment {i:#x} is full ({colour.colorize_hex_by_address(userdata)}, size: {colour.blue(f'{bucket.get_real_size():#x}')})"
                    ),
                    dml=True,
                )
                dprint.println(
                    f"heap entry start: {colour.colorize_hex_by_address(int(userdata))}",
                )
            else:
                dprint.println(
                    colour.white(
                        f"segment {i:#x} is not full, {int(active_subsegment.AggregateExchg.Depth):#x} ({colour.colorize_hex_by_address(int(userdata))}, size: {colour.blue(f'{bucket.get_real_size():#x}')})"
                    ),
                    dml=True,
                )
                dprint.println(
                    f"heap entry start: {colour.colorize_hex_by_address(userdata)}",
                    dml=True,
                )
                dprint.print("busybitmap: ")
                bitvalue: int = memoryaccess.get_qword_datas(int(userdata.BusyBitmap.Buffer), 1)[
                    0
                ]
                for j in range(int(userdata.BusyBitmap.SizeOfBitMap)):
                    if (bitvalue >> j) & 1 == 0:
                        dprint.print(colour.red(0), dml=True)
                    else:
                        dprint.print(colour.green(1), dml=True)
                dprint.print_newline()

            for i in range(16):
                if segment_info.CachedItems[i] == 0:
                    continue
                cacheditem = segment_info.CachedItems[i].deref()
                if cacheditem != 0:
                    try:
                        dprint.println(
                            colour.white(
                                f"cacheditems[{j}] (_HEAP_SUBSEGMENT *): {colour.colorize_hex_by_address(cacheditem)}"
                            ),
                            dml=True,
                        )
                    except pykd.MemoryException:
                        dprint.println(
                            colour.white(
                                f"cacheditems[{j}] (_HEAP_SUBSEGMENT *): {colour.colorize_hex_by_address(cacheditem)} {colour.red('( invalid chunk address )')}"
                            ),
                            dml=True,
                        )
            dprint.print_newline()

        dprint.banner_print("")

@dataclass
class _HEAP_DESCRIPTOR_KEY(PykdObject):
    Key: int
    EncodedCommittedPageCount: int
    LargePageCost: int
    UnitCount: int

    def __init__(self, heap_descriptor_key):
        super().__init__(int(heap_descriptor_key))
        self.Key = heap_descriptor_key.Key
        self.EncodedCommittedPageCount = heap_descriptor_key.EncodedCommittedPageCount
        self.LargePageCost = heap_descriptor_key.LargePageCost
        self.UnitCount = heap_descriptor_key.UnitCount

@dataclass
class _HEAP_PAGE_RANGE_DESCRIPTOR(PykdObject):
    TreeNode: _RTL_BALANCED_NODE
    TreeSignature: int
    UnusedBytes: int
    ExtraPresent: int
    Spare0: int
    RangeFlags: int
    CommittedPageCount: int
    UnitOffset: int
    Spare: int
    Key: _HEAP_DESCRIPTOR_KEY
    Align: int
    UnitSize: int

    def __init__(self, heap_page_range_descriptor):
        super().__init__(int(heap_page_range_descriptor))
        self.TreeNode = _RTL_BALANCED_NODE(heap_page_range_descriptor.TreeNode)
        self.TreeSignature = heap_page_range_descriptor.TreeSignature
        self.UnusedBytes = heap_page_range_descriptor.UnusedBytes
        self.ExtraPresent = heap_page_range_descriptor.ExtraPresent
        self.Spare0 = heap_page_range_descriptor.Spare0
        self.RangeFlags = heap_page_range_descriptor.RangeFlags
        self.CommittedPageCount = heap_page_range_descriptor.CommittedPageCount
        self.UnitOffset = heap_page_range_descriptor.UnitOffset
        self.Spare = heap_page_range_descriptor.Spare
        self.Key = _HEAP_DESCRIPTOR_KEY(heap_page_range_descriptor.Key)
        self.Align = heap_page_range_descriptor.Align
        self.UnitSize = heap_page_range_descriptor.UnitSize
    
    @staticmethod
    def from_rbtree_node(node: _RTL_BALANCED_NODE) -> _HEAP_PAGE_RANGE_DESCRIPTOR:
        return _HEAP_PAGE_RANGE_DESCRIPTOR(nt.typedVar("_HEAP_PAGE_RANGE_DESCRIPTOR", int(node)))


@dataclass
class _HEAP_PAGE_SEGMENT(PykdObject):
    ListEntry: _LIST_ENTRY
    Signature: int
    DescArray: Array[_HEAP_PAGE_RANGE_DESCRIPTOR]

    def __init__(self, heap_page_segment):
        super().__init__(int(heap_page_segment))
        self.ListEntry = _LIST_ENTRY(heap_page_segment.ListEntry)
        self.Signature = heap_page_segment.Signature
        self.DescArray = Array[_HEAP_PAGE_RANGE_DESCRIPTOR](heap_page_segment.DescArray)

    @staticmethod
    def page_start_align(header_size: int, align: int) -> int:
        return (header_size + align - 1) & ~(align - 1)

    @staticmethod
    def from_page_range_descriptor(
        page_range_descriptor: _HEAP_PAGE_RANGE_DESCRIPTOR
    ) -> _HEAP_PAGE_SEGMENT:
        return _HEAP_PAGE_SEGMENT(nt.typedVar("_HEAP_PAGE_SEGMENT", int(page_range_descriptor) & ~0x1fff))
    
    @staticmethod
    def from_list_entry(list_entry: _LIST_ENTRY) -> _HEAP_PAGE_SEGMENT:
        return _HEAP_PAGE_SEGMENT(nt.typedVar("_HEAP_PAGE_SEGMENT", int(list_entry)))

    def get_page_addr(self, seg_context: _HEAP_SEG_CONTEXT, page_range_descriptor: _HEAP_PAGE_RANGE_DESCRIPTOR) -> int:
        return (
            int(self) + 
            self.page_start_align(0x2000, seg_context.align) +
            (int(page_range_descriptor) - int(self)) // _HEAP_PAGE_RANGE_DESCRIPTOR.size() * seg_context.align
        )
    
    def page_range_descriptor(self) -> list[_HEAP_PAGE_RANGE_DESCRIPTOR]:
        idx = 2
        descs: list[_HEAP_PAGE_RANGE_DESCRIPTOR] = []
        while idx < 0x100:
            descs.append(self.DescArray[idx])
            if self.DescArray[idx].UnitSize == 0:
                break
            idx += self.DescArray[idx].UnitSize
        return descs
    
class _HEAP_VS_CHUNK_HEADER_SIZE(PykdObject):
    MemoryCost: int
    UnsafeSize: int
    UnsafePrevSize: int
    Allocated: int
    
    def __init__(self, heap_vs_chunk_header_size):
        super().__init__(int(heap_vs_chunk_header_size))
        self.MemoryCost = heap_vs_chunk_header_size.MemoryCost
        self.UnsafeSize = heap_vs_chunk_header_size.UnsafeSize
        self.UnsafePrevSize = heap_vs_chunk_header_size.UnsafePrevSize
        self.Allocated = heap_vs_chunk_header_size.Allocated
        self.KeyUShort = heap_vs_chunk_header_size.KeyUShort
        self.KeyULong = heap_vs_chunk_header_size.KeyULong
        self.HeaderBits = heap_vs_chunk_header_size.HeaderBits
    
    def decode(self) -> _HEAP_VS_CHUNK_HEADER_SIZE:
        new_header = _HEAP_VS_CHUNK_HEADER_SIZE(nt.typedVar("_HEAP_VS_CHUNK_HEADER_SIZE", _RTLP_HP_HEAP_GLOBALS.addr()))
        new_header.MemoryCost ^= self.MemoryCost ^ (int(self) & 0xffff)
        new_header.UnsafeSize ^= self.UnsafeSize ^ ((int(self) >> 16) & 0xffff)
        new_header.UnsafePrevSize ^= self.UnsafePrevSize ^ ((int(self) >> 32) & 0xffff)
        new_header.Allocated ^= self.Allocated ^ ((int(self) >> 48) & 0xffff)

        return new_header
    
@dataclass
class _HEAP_VS_CHUNK_HEADER(PykdObject):
    Sizes: _HEAP_VS_CHUNK_HEADER_SIZE
    AllocatedChunkBits: int
    
    @property
    def EncodedSegmentPageOffset(self) -> int:
        return self.AllocatedChunkBits & 0xff
    
    @property
    def UnusedBytes(self) -> int:
        return (self.AllocatedChunkBits >> 8) & 0x1
    
    @property
    def SkipDuringWalk(self) -> int:
        return (self.AllocatedChunkBits >> 9) & 0x1

    def __init__(self, heap_vs_chunk_header):
        super().__init__(int(heap_vs_chunk_header))
        self.Sizes = _HEAP_VS_CHUNK_HEADER_SIZE(heap_vs_chunk_header.Sizes)
        self.AllocatedChunkBits = heap_vs_chunk_header.AllocatedChunkBits
    
    def decode(self) -> _HEAP_VS_CHUNK_HEADER:
        new_header = _HEAP_VS_CHUNK_HEADER(nt.typedVar("_HEAP_VS_CHUNK_HEADER", _RTLP_HP_HEAP_GLOBALS.addr() - 8))
        new_header.Sizes = self.Sizes.decode()
        new_header.AllocatedChunkBits = (new_header.AllocatedChunkBits & ~(0xff)) | (new_header.EncodedSegmentPageOffset ^ self.EncodedSegmentPageOffset ^ (int(self) & 0xff))
        return new_header

    def print_chunk_info(self) -> None:
        decoded_header = self.decode()
        dprint.println(
            f"MemoryCost: {decoded_header.Sizes.MemoryCost:#x}, Size: {colour.blue(f'{(decoded_header.Sizes.UnsafeSize << 4):#x}')}, PrevSize: {colour.blue(f'{(decoded_header.Sizes.UnsafePrevSize << 4):#x}')}, Allocated: {colour.green(f'{decoded_header.Sizes.Allocated:#x}')}",
            dml=True,
        )
        dprint.println(
            f"EncodedSegmentPageOffset: {decoded_header.EncodedSegmentPageOffset:#x}, UnusedBytes: {decoded_header.UnusedBytes:#x}, SkipDuringWalk: {decoded_header.SkipDuringWalk:#x}",
            dml=True,
        )

@dataclass
class _HEAP_VS_CHUNK_FREE_HEADER(PykdObject):
    Header: _HEAP_VS_CHUNK_HEADER
    Node: _RTL_BALANCED_NODE

    def __init__(self, heap_vs_chunk_free_header):
        super().__init__(int(heap_vs_chunk_free_header))
        self.Header = _HEAP_VS_CHUNK_HEADER(heap_vs_chunk_free_header.Header)
        self.Node = _RTL_BALANCED_NODE(heap_vs_chunk_free_header.Node)

    def from_rbtree_node(node: _RTL_BALANCED_NODE) -> _HEAP_VS_CHUNK_FREE_HEADER:
        return _HEAP_VS_CHUNK_FREE_HEADER(nt.typedVar("_HEAP_VS_CHUNK_FREE_HEADER", int(node) - _HEAP_VS_CHUNK_HEADER_SIZE.size()))

    def print_chunk_info(self) -> None:
        decoded_header = self.Header.Sizes.decode()
        dprint.println(
            f"MemoryCost: {decoded_header.MemoryCost:#x}, Size: {colour.blue(f'{(decoded_header.UnsafeSize << 4):#x}')}, PrevSize: {colour.blue(f'{(decoded_header.UnsafePrevSize << 4):#x}')}, Allocated: {colour.red(f'{decoded_header.Allocated:#x}')}",
            dml=True,
        )
        dprint.println(
            f"Parent: {colour.colorize_hex_by_address(int(self.Node.get_parent()), 8)}, Left: {colour.colorize_hex_by_address(int(self.Node.Left), 8)}, Right: {colour.colorize_hex_by_address(int(self.Node.Right), 8)}",
            dml=True,
        )


@dataclass
class _HEAP_SEG_CONTEXT(PykdObject):
    SegmentMask: int
    UnitShift: int
    Heap: Pointer[_SEGMENT_HEAP]
    SegmentListHead: _LIST_ENTRY
    FreePageRanges: _RTL_RB_TREE

    def __init__(self, heap_seg_context):
        super().__init__(int(heap_seg_context))
        self.SegmentMask = heap_seg_context.SegmentMask
        self.UnitShift = heap_seg_context.UnitShift
        self.Heap = Pointer[_SEGMENT_HEAP](heap_seg_context.Heap)
        self.SegmentListHead = _LIST_ENTRY(heap_seg_context.SegmentListHead)
        self.FreePageRanges = _RTL_RB_TREE(heap_seg_context.FreePageRanges)

    @property
    def align(self) -> int:
        return 1 << self.UnitShift
    
    def get_segments(self) -> list[_HEAP_PAGE_SEGMENT]:
        segments: list[_HEAP_PAGE_SEGMENT] = []
        for entry in self.SegmentListHead.traverse_list_entry(False)[1]:
            segment = _HEAP_PAGE_SEGMENT.from_list_entry(entry)
            if not pykd.isValid(int(segment)):
                dprint.println(colour.red(f"Invalid segment address: {int(segment)}"))
                continue
            segments.append(segment)
        return segments
    
@dataclass
class _SINGLE_LIST_ENTRY(PykdObject):
    Next: Pointer[_SINGLE_LIST_ENTRY]

    def __init__(self, single_list_entry):
        super().__init__(int(single_list_entry))
        self.Next = Pointer[_SINGLE_LIST_ENTRY](single_list_entry.Next)
    
    def traverse_single_list_entry(self, include_head: bool = True) -> list[Pointer[_SINGLE_LIST_ENTRY]]:
        entries: list[Pointer[_SINGLE_LIST_ENTRY]] = []
        if include_head:
            entries.append(self)
        current = self.Next
        while pykd.isValid(int(current)):
            entries.append(current)
            current = current.Next
        return entries
    
@dataclass
class _HEAP_LFH_BLOCK_SLIST(_SINGLE_LIST_ENTRY):
    def __init__(self, heap_lfh_block_slist):
        super().__init__(heap_lfh_block_slist)
        # Assuming heap_lfh_block_slist has no additional fields for now, can be extended later
    
@dataclass
class _HEAP_LFH_PTRREF_LIST(_LIST_ENTRY):
    def __init__(self, heap_lfh_ptrref_list):
        super().__init__(heap_lfh_ptrref_list)

@dataclass
class _HEAP_LFH_BLOCK_LIST(PykdObject):
    Next: int
    Count: int
    SList: _HEAP_LFH_BLOCK_SLIST
    ListFields: int

    def __init__(self, heap_lfh_block_list):
        super().__init__(int(heap_lfh_block_list))
        self.Next = heap_lfh_block_list.Next
        self.Count = heap_lfh_block_list.Count
        self.SList = _HEAP_LFH_BLOCK_SLIST(heap_lfh_block_list.SList)
        self.ListFields = heap_lfh_block_list.ListFields
    
@dataclass
class _HEAP_LFH_SUBSEGMENT_OWNER(PykdObject):
    IsBucket: int
    BucketIndex: int
    SlotCount: int
    BucketRef: int
    PrivateSlotMapRef: int
    HeatMapRef: int
    OwnerFreeList: _SINGLE_LIST_ENTRY
    PrivSlotListEntry: _HEAP_LFH_PTRREF_LIST
    AvailableSubsegmentList: _LIST_ENTRY
    FullSubsegmentList: _LIST_ENTRY

    def __init__(self, heap_lfh_segment_owner):
        super().__init__(int(heap_lfh_segment_owner))
        self.IsBucket = heap_lfh_segment_owner.IsBucket
        self.BucketIndex = heap_lfh_segment_owner.BucketIndex
        self.SlotCount = heap_lfh_segment_owner.SlotCount
        self.BucketRef = heap_lfh_segment_owner.BucketRef
        self.PrivateSlotMapRef = heap_lfh_segment_owner.PrivateSlotMapRef
        self.HeatMapRef = heap_lfh_segment_owner.HeatMapRef
        self.OwnerFreeList = _SINGLE_LIST_ENTRY(heap_lfh_segment_owner.OwnerFreeList)
        self.PrivSlotListEntry = _HEAP_LFH_PTRREF_LIST(heap_lfh_segment_owner.PrivSlotListEntry)
        self.AvailableSubsegmentList = _LIST_ENTRY(heap_lfh_segment_owner.AvailableSubsegmentList)
        self.FullSubsegmentList = _LIST_ENTRY(heap_lfh_segment_owner.FullSubsegmentList)

@dataclass
class _HEAP_LFH_SUBSEGMENT_STATE(PykdObject):
    DelayFreeList: int
    DelayFreeCount: int
    Owner: int
    Location: int
    DelayFreeFields: int
    OwnerLocation: int
    FreeList: _HEAP_LFH_BLOCK_LIST

    def __init__(self, heap_lfh_subsegment_state):
        super().__init__(int(heap_lfh_subsegment_state))
        self.DelayFreeList = heap_lfh_subsegment_state.DelayFreeList
        self.DelayFreeCount = heap_lfh_subsegment_state.DelayFreeCount
        self.Owner = heap_lfh_subsegment_state.Owner
        self.Location = heap_lfh_subsegment_state.Location
        self.DelayFreeFields = heap_lfh_subsegment_state.DelayFreeFields
        self.OwnerLocation = heap_lfh_subsegment_state.OwnerLocation
        self.FreeList = _HEAP_LFH_BLOCK_LIST(heap_lfh_subsegment_state.FreeList)

@dataclass
class _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS(PykdObject):
    BlockSize: int # short
    FirstBlockOffset: int # short
    EncodedData: int # union of upper values

    def __init__(self, heap_lfh_subsegment_encoded_offsets):
        super().__init__(int(heap_lfh_subsegment_encoded_offsets))
        self.BlockSize = heap_lfh_subsegment_encoded_offsets.BlockSize
        self.FirstBlockOffset = heap_lfh_subsegment_encoded_offsets.FirstBlockOffset
        self.EncodedData = heap_lfh_subsegment_encoded_offsets.EncodedData
    
    def decode(self, subsegment: _HEAP_LFH_SUBSEGMENT) -> _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS:
        new_offsets = _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS(self)
        LfhKey = _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS(
            nt.typedVar("_HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS", _RTLP_HP_HEAP_GLOBALS.addr() + 0x8)
        )
        shifted_addr = int(subsegment) >> 12
        
        new_offsets.BlockSize ^= LfhKey.BlockSize ^ (shifted_addr & 0xffff)
        new_offsets.FirstBlockOffset ^= LfhKey.FirstBlockOffset ^ ((shifted_addr >> 16) & 0xffff)
        new_offsets.EncodedData ^= LfhKey.EncodedData ^ shifted_addr
        print(f"Decoded offsets: BlockSize={new_offsets.BlockSize:#x}, FirstBlockOffset={new_offsets.FirstBlockOffset:#x}, EncodedData={new_offsets.EncodedData:#x}")
        return new_offsets
    
@dataclass
class _HEAP_VS_SUBSEGMENT(PykdObject):
    ListEntry: _HEAP_VS_SUBSEGMENT_LIST_ENTRY
    CommitBitmap: int
    CommitLock: int
    Size: int
    OwnerSlotRef: int
    Signature: int
    FullCommit: int

    def __init__(self, heap_vs_subsegment):
        super().__init__(int(heap_vs_subsegment))
        self.ListEntry = _HEAP_VS_SUBSEGMENT_LIST_ENTRY(heap_vs_subsegment.ListEntry)
        self.CommitBitmap = heap_vs_subsegment.CommitBitmap
        self.CommitLock = heap_vs_subsegment.CommitLock
        self.Size = heap_vs_subsegment.Size
        self.OwnerSlotRef = heap_vs_subsegment.OwnerSlotRef
        self.Signature = heap_vs_subsegment.Signature
        self.FullCommit = heap_vs_subsegment.FullCommit

    def from_list_entry(
        list_entry: _HEAP_VS_SUBSEGMENT_LIST_ENTRY
    ) -> _HEAP_VS_SUBSEGMENT:
        return _HEAP_VS_SUBSEGMENT(nt.typedVar("_HEAP_VS_SUBSEGMENT", int(list_entry)))

    def dump_all_chunks(self) -> list[_HEAP_VS_CHUNK_HEADER]:
        chunks: list[_HEAP_VS_CHUNK_HEADER] = []
        curr = _HEAP_VS_CHUNK_HEADER(nt.typedVar("_HEAP_VS_CHUNK_HEADER", int(self) + 0x30))

        while int(curr) < int(self) + (self.Size << 4):
            if not pykd.isValid(int(curr)):
                dprint.println(colour.red(f"Invalid chunk header address: {int(curr)}"))
                break
            chunks.append(curr)
            curr = _HEAP_VS_CHUNK_HEADER(nt.typedVar("_HEAP_VS_CHUNK_HEADER", int(curr) + (curr.Sizes.decode().UnsafeSize << 4)))
    
        return chunks

@dataclass
class _HEAP_LFH_SUBSEGMENT(PykdObject):
    ListEntry: _LIST_ENTRY
    State: _HEAP_LFH_SUBSEGMENT_STATE
    OwnerFreeListEntry: _SINGLE_LIST_ENTRY
    CommitStateOffset: int
    FreeCount: int
    BlockCount: int
    FreeHint: int
    CommitUnitShift: int
    CommitUnitCount: int
    CommitUnitInfo: int
    BlockOffsets: _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS
    BucketRef: int
    PrivateSlotMapRef: int
    HighWatermarkBlockIndex: int
    BitmapSearchWidth: int
    BlockBitmap: Array[int]

    def __init__(self, heap_lfh_subsegment):
        super().__init__(int(heap_lfh_subsegment))
        self.ListEntry = _LIST_ENTRY(heap_lfh_subsegment.ListEntry)
        self.State = _HEAP_LFH_SUBSEGMENT_STATE(heap_lfh_subsegment.State)
        self.OwnerFreeListEntry = _SINGLE_LIST_ENTRY(heap_lfh_subsegment.OwnerFreeListEntry)
        self.CommitStateOffset = heap_lfh_subsegment.CommitStateOffset
        self.FreeCount = heap_lfh_subsegment.FreeCount
        self.BlockCount = heap_lfh_subsegment.BlockCount
        self.FreeHint = heap_lfh_subsegment.FreeHint
        self.CommitUnitShift = heap_lfh_subsegment.CommitUnitShift
        self.CommitUnitCount = heap_lfh_subsegment.CommitUnitCount
        self.CommitUnitInfo = heap_lfh_subsegment.CommitUnitInfo
        self.BlockOffsets = _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS(heap_lfh_subsegment.BlockOffsets)
        self.BucketRef = heap_lfh_subsegment.BucketRef
        self.PrivateSlotMapRef = heap_lfh_subsegment.PrivateSlotMapRef
        self.HighWatermarkBlockIndex = heap_lfh_subsegment.HighWatermarkBlockIndex
        self.BitmapSearchWidth = heap_lfh_subsegment.BitmapSearchWidth
        self.BlockBitmap = Array[int](heap_lfh_subsegment.BlockBitmap)

    def from_list_entry(
        list_entry: _LIST_ENTRY
    ) -> _HEAP_LFH_SUBSEGMENT:
        return _HEAP_LFH_SUBSEGMENT(nt.typedVar("_HEAP_LFH_SUBSEGMENT", int(list_entry)))
        
@dataclass
class _HEAP_LFH_FAST_REF(PykdObject):
    Target: int
    RefCount: int
    Value: int

    @property
    def subsegment(self) -> Pointer[_HEAP_LFH_SUBSEGMENT]:
        if self.Target == 0:
            return None
        return Pointer[_HEAP_LFH_SUBSEGMENT](nt.typedVar("_HEAP_LFH_SUBSEGMENT", self.Target & ~0xfff))

    def __init__(self, heap_lfh_fast_ref):
        super().__init__(int(heap_lfh_fast_ref))
        self.Target = heap_lfh_fast_ref.Target
        self.RefCount = heap_lfh_fast_ref.RefCount
        self.Value = heap_lfh_fast_ref.Value
    
@dataclass
class _HEAP_SUBALLOCATOR_CALLBACKS(PykdObject):
    Allocate: int
    Free: int
    Commit: int
    Decommit: int
    ExtendContext: int
    TlsCleanup: int

    def __init__(self, heap_suballocator_callbacks):
        super().__init__(int(heap_suballocator_callbacks))
        self.Allocate = heap_suballocator_callbacks.Allocate
        self.Free = heap_suballocator_callbacks.Free
        self.Commit = heap_suballocator_callbacks.Commit
        self.Decommit = heap_suballocator_callbacks.Decommit
        self.ExtendContext = heap_suballocator_callbacks.ExtendContext
        self.TlsCleanup = heap_suballocator_callbacks.TlsCleanup

@dataclass
class _HEAP_LFH_CONFIG(PykdObject):
    def __init__(self, heap_lfh_config):
        super().__init__(int(heap_lfh_config))
        # Assuming heap_lfh_config has no fields for now, can be extended later
    pass

@dataclass
class _HEAP_LFH_BUCKET(PykdObject):
    State: _HEAP_LFH_SUBSEGMENT_OWNER
    TotalBlockCount: int
    TotalSubsegmentCount: int
    PrivSlotList: _HEAP_LFH_PTRREF_LIST

    def __init__(self, heap_lfh_bucket):
        super().__init__(int(heap_lfh_bucket))
        self.State = _HEAP_LFH_SUBSEGMENT_OWNER(heap_lfh_bucket.State)
        self.TotalBlockCount = heap_lfh_bucket.TotalBlockCount
        self.TotalSubsegmentCount = heap_lfh_bucket.TotalSubsegmentCount
        self.PrivSlotList = _HEAP_LFH_PTRREF_LIST(heap_lfh_bucket.PrivSlotList)
    
    @staticmethod
    def index_from_size(size: int) -> int:
        def align(size: int) -> int:
            return (size + 0xf) & ~0xf
    
        index_map_idx = ((align(size) + 0xf) >> 4) - 1
        return int(memoryaccess.get_bytes(
            memoryaccess.get_addr_from_symbol("ntdll!RtlpLfhBucketIndexMap") + index_map_idx, 
            1
        )[0])

@dataclass
class _HEAP_LFH_SLOT_MAP(PykdObject):
    Map: Array[uint16_t]
    def __init__(self, heap_lfh_slot_map):
        super().__init__(int(heap_lfh_slot_map))
        self.Map = Array[uint16_t](heap_lfh_slot_map.Map)

@dataclass
class _HEAP_VS_CONTEXT(PykdObject):
    SlotMapRef: uint16_t
    AffinityMask: int
    Callbacks: _HEAP_SUBALLOCATOR_CALLBACKS
    
    def __init__(self, heap_vs_context):
        super().__init__(int(heap_vs_context))
        self.SlotMapRef = heap_vs_context.SlotMapRef
        self.AffinityMask = heap_vs_context.AffinityMask
        self.Callbacks = _HEAP_SUBALLOCATOR_CALLBACKS(heap_vs_context.Callbacks)
    
    def get_affinity_slot(self) -> _HEAP_VS_AFFINITY_SLOT:
        index = memoryaccess.get_int(int(self) + self.SlotMapRef * 0x40) & 0xffff
        return _HEAP_VS_AFFINITY_SLOT(
            nt.typedVar(
                "_HEAP_VS_AFFINITY_SLOT",
                int(self) + 0x40 * index
            )
        )

@dataclass
class _HEAP_VS_DELAY_FREE_CONTEXT(PykdObject):
    ListHead: _SLIST_HEADER
    
    def __init__(self, heap_vs_delay_free_context):
        super().__init__(int(heap_vs_delay_free_context))
        self.ListHead = _SLIST_HEADER(heap_vs_delay_free_context.ListHead)

@dataclass
class _HEAP_LFH_CONTEXT(PykdObject):
    BackendCtx: int
    Callbacks: _HEAP_SUBALLOCATOR_CALLBACKS
    Config: _HEAP_LFH_CONFIG
    EncodeKey: int
    Buckets: Array[Pointer[_HEAP_LFH_BUCKET]]
    SlotMaps: Array[_HEAP_LFH_SLOT_MAP]

    def __init__(self, heap_lfh_context):
        super().__init__(int(heap_lfh_context))
        self.BackendCtx = heap_lfh_context.BackendCtx
        self.Callbacks = _HEAP_SUBALLOCATOR_CALLBACKS(heap_lfh_context.Callbacks)
        self.Config = _HEAP_LFH_CONFIG(heap_lfh_context.Config)
        self.EncodeKey = heap_lfh_context.EncodeKey
        self.Buckets = Array[Pointer[_HEAP_LFH_BUCKET]](heap_lfh_context.Buckets)
        self.SlotMaps = Array[_HEAP_LFH_SLOT_MAP](heap_lfh_context.SlotMaps)

@dataclass
class _HEAP_VS_SUBSEGMENT_LIST_ENTRY(_LIST_ENTRY):
    def __init__(self, heap_vs_subsegment_list_entry):
        super().__init__(heap_vs_subsegment_list_entry)
    
    def traverse_list_entry(self, include_head: bool = True) -> tuple[tuple[bool, str], list[_HEAP_VS_SUBSEGMENT_LIST_ENTRY]]:
        success = True
        result = []
        errorstr: str = ""

        if include_head:
            result.append(self)

        curr = _HEAP_VS_SUBSEGMENT_LIST_ENTRY(
            nt.typedVar(
                "_LIST_ENTRY", 
                int(self.Flink) ^ int(self)
            )
        )

        while curr is not None and curr not in result:
            if int(curr) == int(self):
                break
            result.append(curr)
            
            curr = _HEAP_VS_SUBSEGMENT_LIST_ENTRY(
                nt.typedVar(
                    "_LIST_ENTRY", 
                    int(curr.Flink) ^ int(curr)
                )
            )

        if curr is not None and curr in result:
            success = False
            errorstr += f"List entry {curr} is in the list more than once.\n"

        return (success, errorstr), result


@dataclass
class _HEAP_VS_AFFINITY_SLOT(PykdObject):
    VsContext: Pointer[_HEAP_VS_CONTEXT]
    Lock: int
    FreeChunkTree: _RTL_RB_TREE
    SubsegmentList: _HEAP_VS_SUBSEGMENT_LIST_ENTRY
    DelayFreeContext: _HEAP_VS_DELAY_FREE_CONTEXT

    def __init__(self, heap_vs_affinity_slot):
        super().__init__(int(heap_vs_affinity_slot))
        self.VsContext = Pointer[_HEAP_VS_CONTEXT](heap_vs_affinity_slot.VsContext)
        self.Lock = heap_vs_affinity_slot.Lock
        self.FreeChunkTree = _RTL_RB_TREE(heap_vs_affinity_slot.FreeChunkTree)
        self.SubsegmentList = _HEAP_VS_SUBSEGMENT_LIST_ENTRY(heap_vs_affinity_slot.SubsegmentList)
        self.DelayFreeContext = _HEAP_VS_DELAY_FREE_CONTEXT(heap_vs_affinity_slot.DelayFreeContext)

@dataclass
class _HEAP_LFH_AFFINITY_SLOT(PykdObject):
    State: _HEAP_LFH_SUBSEGMENT_OWNER
    ActiveSubsegment: _HEAP_LFH_FAST_REF
    
    def __init__(self, heap_lfh_affinity_slot):
        super().__init__(int(heap_lfh_affinity_slot))
        self.State = _HEAP_LFH_SUBSEGMENT_OWNER(heap_lfh_affinity_slot.State)
        self.ActiveSubsegment = _HEAP_LFH_FAST_REF(heap_lfh_affinity_slot.ActiveSubsegment)
    
    @staticmethod
    def from_map_index(
        lfh_context: _HEAP_LFH_CONTEXT, map_index: int
    ) -> _HEAP_LFH_AFFINITY_SLOT:
        return _HEAP_LFH_AFFINITY_SLOT(
            nt.typedVar(
                "_HEAP_LFH_AFFINITY_SLOT", 
                int(lfh_context) + map_index * _HEAP_LFH_AFFINITY_SLOT.size()
            )
        )

@dataclass
class _SEGMENT_HEAP(PykdObject):
    Signature: int
    SegContexts: Array[_HEAP_SEG_CONTEXT]
    VsContext: _HEAP_VS_CONTEXT
    LfhContext: _HEAP_LFH_CONTEXT

    def __init__(self, segment_heap):
        super().__init__(int(segment_heap))
        self.Signature = segment_heap.Signature
        self.SegContexts = Array[_HEAP_SEG_CONTEXT](segment_heap.SegContexts)
        self.VsContext = _HEAP_VS_CONTEXT(segment_heap.VsContext)
        self.LfhContext = _HEAP_LFH_CONTEXT(segment_heap.LfhContext)

class SegmentHeap():
    def __init__(self):
        self.buckets_cnt = 128
        pass

    def _SEGMENT_HEAP(self, heap_address: int) -> _SEGMENT_HEAP:
        return _SEGMENT_HEAP(nt.typedVar("_SEGMENT_HEAP", heap_address))

    def print_bucket(
        self, lfh_context: _HEAP_LFH_CONTEXT, bucket: _HEAP_LFH_BUCKET, index: int, banner=True
    ) -> None:
        def print_lfh_subsegment(lfh_subsegment: _HEAP_LFH_SUBSEGMENT, once: bool, bucket_index: int, ignore_bitmap: bool = False) -> bool:
            BlockOffsets = lfh_subsegment.BlockOffsets.decode(lfh_subsegment)
            BlockCnt = lfh_subsegment.CommitStateOffset - 0x8

            if once:
                dprint.println(f"BucketIndex: {int(bucket_index):#x}")
                once = False

            BlockBitmap: list[int] = [] 
            for i in range(BlockCnt):
                BlockBitmap.append(
                    memoryaccess.get_ulong(lfh_subsegment.BlockBitmap.address + i * 8)
                )

            dprint.println(
                f"    Subsegment: {colour.colorize_hex_by_address(int(lfh_subsegment))}",
                dml=True,
            )
            dprint.print(
                f"    Flink: {colour.colorize_hex_by_address(int(lfh_subsegment.ListEntry.Flink))}, Blink: {colour.colorize_hex_by_address(int(lfh_subsegment.ListEntry.Blink))}",
                dml=True,
            )
            sanity_result = lfh_subsegment.ListEntry.traverse_list_entry()
            if sanity_result[0]:
                pass
            else:
                dprint.print(colour.red(f" ({', '.join(sanity_result[1])})"), dml=True)
            dprint.print_newline()

            dprint.println(
                f"    BlockSize : {colour.blue(f'{int(BlockOffsets.BlockSize):#x}')}", dml=True
            )

            remain = 0
            for i, block in enumerate(BlockBitmap):
                for j in range(32):
                    if i * 32 + j >= lfh_subsegment.BlockCount:
                        break
                    if not ((block >> j) & 1):
                        remain += 1

            dprint.print(
                f"    Total: {int(lfh_subsegment.BlockCount):#x}, Remain: {remain:#x} ",
                dml=True,
            )
            
            locations = ["AvaliableSubsegment", "FullSubsegment", "WillBeReturnBackToBackend"]
            dprint.println(f"Location: {locations[lfh_subsegment.State.Location]}", dml=True)

            if not ignore_bitmap:
                dprint.print("    ")
                if lfh_subsegment.BlockCount > 0x800:
                    dprint.println(
                        f"    BlockBitmap: {colour.red('(too large to print)')}", dml=True
                    )
                    dprint.print_newline()
                    return once

                for i, block in enumerate(BlockBitmap):
                    for j in range(32):
                        if i * 32 + j >= lfh_subsegment.BlockCount:
                            break
                        if (block >> j) & 1:
                            dprint.print(colour.green("1"), dml=True)
                        else:
                            dprint.print(colour.red("0"), dml=True)
                    dprint.print_newline()
                    dprint.print("    ")
            else:
                dprint.print_newline()
        
        if banner:
            dprint.banner_print(f" [+] LFH Bucket ({int(bucket):#x}) ")

        once = True
        map_index = lfh_context.SlotMaps[0].Map[bucket.State.BucketIndex]
        affinity_slot = _HEAP_LFH_AFFINITY_SLOT.from_map_index(lfh_context, map_index)
        
        if affinity_slot.ActiveSubsegment.subsegment is None:
            if once:
                dprint.println(f"BucketIndex: {int(bucket.State.BucketIndex):#x}")
                once = False
            dprint.println(
                colour.red("    Active subsegment is not set"),
                dml=True,
            )
        else:
            once = print_lfh_subsegment(affinity_slot.ActiveSubsegment.subsegment.deref(), once, bucket.State.BucketIndex)
        dprint.print_newline()

        for subsegment_node in affinity_slot.State.AvailableSubsegmentList.traverse_list_entry(False)[1]:
            subsegment = _HEAP_LFH_SUBSEGMENT.from_list_entry(subsegment_node)
            if affinity_slot.ActiveSubsegment.subsegment is not None and int(subsegment) == int(affinity_slot.ActiveSubsegment.subsegment):
                continue
            if not pykd.isValid(int(subsegment)):
                dprint.println(
                    colour.red(f"Invalid subsegment address: {int(subsegment)}"), dml=True
                )
                continue   
            once = print_lfh_subsegment(subsegment, once, bucket.State.BucketIndex)

        dprint.print_newline() 
        for subsegment_node in affinity_slot.State.FullSubsegmentList.traverse_list_entry(False)[1]:
            subsegment = _HEAP_LFH_SUBSEGMENT.from_list_entry(subsegment_node)
            if not pykd.isValid(int(subsegment)):
                dprint.println(
                    colour.red(f"Invalid subsegment address: {int(subsegment)}"), dml=True
                )
                continue   
            once = print_lfh_subsegment(subsegment, once, bucket.State.BucketIndex, ignore_bitmap=True)

        if banner:
            dprint.banner_print("")
        dprint.print_newline()

    def print_lfh(self, heap_address: int, size: int = -1) -> None:
        segment_heap = self._SEGMENT_HEAP(heap_address)
        lfh_context = segment_heap.LfhContext

        dprint.banner_print(f" [+] LFH Heap ({heap_address:#x}) ")
        avaliable_segments_idx = []
        for i in range(self.buckets_cnt):
            bucket_ptr = segment_heap.LfhContext.Buckets[i]
            if pykd.isValid(int(bucket_ptr)):
                bucket = bucket_ptr.deref()
                if bucket.TotalSubsegmentCount > 0:
                    avaliable_segments_idx.append(bucket.State.BucketIndex)
        dprint.print(colour.white("avaliable segments: "), dml=True)

        for i, idx in enumerate(avaliable_segments_idx):
            if i % 10 == 0 and i != 0:
                dprint.print_newline()
                dprint.print(colour.white("                    "), dml=True)
            dprint.print(colour.white(f"{idx * 0x10:#x} "), dml=True)
        dprint.println("\n")

        for i in range(self.buckets_cnt):
            bucket_ptr = segment_heap.LfhContext.Buckets[i]
            if not pykd.isValid(int(bucket_ptr)):
                continue
            bucket = bucket_ptr.deref()
            if bucket.TotalSubsegmentCount > 0:
                self.print_bucket(lfh_context, bucket, size, banner=False)

            if bucket.TotalBlockCount > bucket.TotalSubsegmentCount:
                avaliable_segments_idx.append(bucket.State.BucketIndex)

        dprint.banner_print("")

    def print_vs(self, heap_address: int) -> None:
        segment_heap = self._SEGMENT_HEAP(heap_address)
        vs_context = segment_heap.VsContext
        dprint.banner_print(f" [+] VS Heap ({heap_address:#x}) ")

        affinity_slot = vs_context.get_affinity_slot()
        dprint.println(
            colour.white(
                f"VsContext: {colour.colorize_string_by_address(f'0x{int(vs_context):08x}', vs_context)}"
            ),
            dml=True,
        )
        dprint.print_newline()

        dprint.println(
            colour.white(
                f"AffinitySlot: {colour.colorize_string_by_address(f'0x{int(affinity_slot):08x}', affinity_slot)}"
            ),
            dml=True,
        )

        dprint.print_newline()

        for subsegment_node in affinity_slot.SubsegmentList.traverse_list_entry(False)[1]:
            dprint.println(
                "-"* 158, dml=True
            )
            subsegment: _HEAP_VS_SUBSEGMENT = _HEAP_VS_SUBSEGMENT.from_list_entry(subsegment_node)

            if not pykd.isValid(int(subsegment)):
                dprint.println(
                    colour.red(f"Invalid subsegment address: {int(subsegment)}"), dml=True
                )
                continue

            dprint.println(
                colour.white(
                    f"Subsegment: {colour.colorize_string_by_address(f'0x{int(subsegment):08x}', subsegment)}, Size: {colour.blue(hex(subsegment.Size << 4))}", 
                ),
                dml=True,
            )
            dprint.print_newline()

            for chunk in subsegment.dump_all_chunks():
                if chunk.Sizes.decode().Allocated == 0:
                    chunk = _HEAP_VS_CHUNK_FREE_HEADER(
                        nt.typedVar(
                            "_HEAP_VS_CHUNK_FREE_HEADER", int(chunk)
                        )
                    )
                else:
                    chunk = _HEAP_VS_CHUNK_HEADER(
                        nt.typedVar(
                            "_HEAP_VS_CHUNK_HEADER", int(chunk)
                        )
                    )
                dprint.println(
                    colour.white(
                        f"Chunk: {colour.colorize_string_by_address(f'0x{int(chunk):08x}', chunk)}"
                    ),
                    dml=True,
                )
                chunk.print_chunk_info()
                dprint.print_newline()

            dprint.remove_last_line()
            dprint.println(
                "-"* 158, dml=True
            )

            dprint.print_newline() 

    def print_freed_vs(self, heap_address: int) -> None:
        segment_heap = self._SEGMENT_HEAP(heap_address)
        vs_context = segment_heap.VsContext
        dprint.banner_print(f" [+] VS Heap ({heap_address:#x}) ")

        affinity_slot = vs_context.get_affinity_slot()
        dprint.println(
            colour.white(
                f"VsContext: {colour.colorize_string_by_address(f'0x{int(vs_context):08x}', vs_context)}"
            ),
            dml=True,
        )

        dprint.print_newline()

        dprint.println(
            colour.white(
                f"AffinitySlot: {colour.colorize_string_by_address(f'0x{int(affinity_slot):08x}', affinity_slot)}"
            ),
            dml=True,
        )

        dprint.print_newline()

        for free_chunk in affinity_slot.FreeChunkTree.traverse_rbtree():
            chunk: _HEAP_VS_CHUNK_FREE_HEADER = _HEAP_VS_CHUNK_FREE_HEADER.from_rbtree_node(free_chunk)

            dprint.println(
                colour.white(
                    f"Chunk: {colour.colorize_string_by_address(f'0x{int(chunk):08x}', chunk)}"
                ),
                dml=True,
            )
            chunk.print_chunk_info()
            dprint.print_newline()

        dprint.remove_last_line()
        dprint.println(
            "-"* 158, dml=True
        )

    def print_segment(self, heap_address: int) -> None:
        dprint.banner_print(f" [+] Segment ({heap_address:#x}) ")
        segment_heap = self._SEGMENT_HEAP(heap_address)

        for idx in range(2):
            if idx == 0:
                dprint.banner_print(" [+] Small Segment ")
            else:
                dprint.banner_print(" [+] Large Segment ")

            seg_context = segment_heap.SegContexts[idx]

            dprint.println(
                colour.white(
                    f"Segcontext: {colour.colorize_string_by_address(f'0x{int(seg_context):08x}', seg_context)}"
                ),
                dml=True,
            )

            for page_segment in seg_context.get_segments():
                dprint.println(
                    colour.white(
                        f"    PageSegment: {colour.colorize_string_by_address(f'0x{int(page_segment):08x}', int(page_segment))}"
                    ),
                    dml=True,
                )
                dprint.print_newline()

                for page_range_descriptor in page_segment.page_range_descriptor():
                    page_addr = page_segment.get_page_addr(seg_context, page_range_descriptor)
                    
                    dprint.println(
                        colour.white(
                            f"        Chunk Metadata: {colour.colorize_string_by_address(f'0x{int(page_range_descriptor):08x}', page_range_descriptor)}"
                        ),
                        dml=True,
                    )
                    dprint.println(
                        colour.white(
                            f"            StartAddr: {colour.colorize_string_by_address(f'0x{page_addr:08x}', page_addr)}, Size: {colour.blue(hex(page_range_descriptor.UnitSize * seg_context.align))}"
                        ),
                        dml=True,
                    )
                    dprint.print_newline()

                    if page_range_descriptor.UnitSize == 0:
                        dprint.println(
                            colour.red(
                                "            UnitSize is 0 or segment is not initialized, can't dump more"
                            ),
                            dml=True,
                        )
                        break

    def print_freed_segment(self, heap_address: int) -> None:
        dprint.banner_print(f" [+] Segment ({heap_address:#x}) ")
        segment_heap = self._SEGMENT_HEAP(heap_address)

        for idx in range(2):
            if idx == 0:
                dprint.banner_print(" [+] Small Segment ")
            else:
                dprint.banner_print(" [+] Large Segment ")

            seg_context = segment_heap.SegContexts[idx]
            free_page_ranges = seg_context.FreePageRanges

            first_print = True
            for node in free_page_ranges.traverse_rbtree():
                page_range_descriptor = _HEAP_PAGE_RANGE_DESCRIPTOR.from_rbtree_node(node)
                page_segment = _HEAP_PAGE_SEGMENT.from_page_range_descriptor(page_range_descriptor)
                page_addr = page_segment.get_page_addr(seg_context, page_range_descriptor)

                if first_print:
                    first_print = False
                    dprint.println(
                        colour.white(
                            f"Segcontext: {colour.colorize_string_by_address(f'0x{int(seg_context):08x}', seg_context)}"
                        ),
                        dml=True,
                    )

                dprint.println(
                    colour.white(
                        f"    Chunk Metadata: {colour.colorize_string_by_address(f'0x{int(page_range_descriptor):08x}', int(page_range_descriptor))}"
                    ),
                    dml=True,
                )
                dprint.println(
                    colour.white(
                        f"        StartAddr: {colour.colorize_string_by_address(f'0x{int(page_addr):08x}', page_addr)}, Size: {colour.blue(hex(page_range_descriptor.UnitSize * seg_context.align))}"
                    ),
                    dml=True,
                )
                dprint.println(
                    colour.white(
                        f"        Left: {colour.colorize_string_by_address(f'{int(page_range_descriptor.TreeNode.Left):#x}', page_range_descriptor.TreeNode.Left)}, Right: {colour.colorize_string_by_address(f'{int(page_range_descriptor.TreeNode.Right):#x}', page_range_descriptor.TreeNode.Right)}"
                    ),
                    dml=True,
                )
                dprint.print_newline()

            dprint.banner_print("")

        dprint.banner_print("")

    def print_block(self, heap_address: int) -> None:
        pass


class Heap(PEB):
    def __init__(self):
        self.heaps: list[int] = self.get_heaps_address()
        self.NtHeap: NTHeap = NTHeap()
        self.SegmentHeap: SegmentHeap = SegmentHeap()
        pass

    def is_NTHeap(self, heap_address: int) -> bool:
        return (
            True
            if nt.typedVar("_HEAP", heap_address).Signature == 0xEEFFEEFF
            else False
        )

    def is_SegmentHeap(self, heap_address: int) -> bool:
        return (
            True
            if nt.typedVar("_SEGMENT_HEAP", heap_address).Signature == 0xDDEEDDEE
            else False
        )

    def get_heaps_address(self) -> list[int]:
        peb = self.getPEBInfo()
        self.heaps = []

        for i in range(peb.NumberOfHeaps):
            self.heaps.append(
                memoryaccess.deref_ptr(
                    peb.ProcessHeaps
                    + i * (4 if context.arch == pykd.CPUType.I386 else 8)
                )
            )
        return self.heaps

    def print_freelist(self, heap_address: int) -> None:
        if self.is_NTHeap(heap_address):
            self.NtHeap.print_freelist(heap_address)
        else:
            dprint.fail_print("Heap type is not supported")

    def print_lfh(self, heap_address: int, size: int = -1) -> None:
        if self.is_NTHeap(heap_address):
            self.NtHeap.print_lfh(heap_address)
        elif self.is_SegmentHeap(heap_address):
            if size != -1:
                self.SegmentHeap.print_lfh(heap_address, size)
            else:
                self.SegmentHeap.print_lfh(heap_address)
        else:
            dprint.fail_print("Heap type is not supported")

    def print_vs(self, heap_address: int) -> None:
        if self.is_SegmentHeap(heap_address):
            self.SegmentHeap.print_vs(heap_address)
        else:
            dprint.fail_print("Heap type is not supported")

    def print_segment(self, heap_address: int, idx: int = -1) -> None:
        if self.is_SegmentHeap(heap_address):
            self.SegmentHeap.print_segment(heap_address)
        else:
            dprint.fail_print("Heap type is not supported")

    def print_freed_vs(self, heap_address: int) -> None:
        if self.is_SegmentHeap(heap_address):
            self.SegmentHeap.print_freed_vs(heap_address)
        else:
            dprint.fail_print("Heap type is not supported")

    def print_freed_segment(self, heap_address: int) -> None:
        if self.is_SegmentHeap(heap_address):
            self.SegmentHeap.print_freed_segment(heap_address)
        else:
            dprint.fail_print("Heap type is not supported")

    def print_block(self, heap_address: int) -> None:
        if self.is_SegmentHeap(heap_address):
            self.SegmentHeap.print_block(heap_address)
        else:
            dprint.fail_print("Heap type is not supported")

    def print_all(self, heap_address: int) -> None:
        if self.is_NTHeap(heap_address):
            self.NtHeap.print_freelist(heap_address)
            self.NtHeap.print_lfh(heap_address)
        elif self.is_SegmentHeap(heap_address):
            self.SegmentHeap.print_lfh(heap_address)
            self.SegmentHeap.print_vs(heap_address)
            self.SegmentHeap.print_segment(heap_address)
        else:
            dprint.fail_print("Heap type is not supported")

    
    def execute(self, args: list[str]) -> None:
        command, args = args[1], args[2:]
        heap_addresses = self.get_heaps_address()
        if command == "help":
            dprint.println(
                "Usage: heap [command] [index]\n"
                "Commands:\n"
                "    indexes: Print heap index\n"
                "    freelist: Print free list\n"
                "    lfh: Print LFH heap\n"
                "    vs: Print VS heap\n"
                "    segment: Print segment heap\n"
            )

        elif command == "indexes":
            for i, heap_address in enumerate(heap_addresses):
                if self.is_NTHeap(heap_address):
                    dprint.println(
                        f"Heap {i}: {colour.colorize_hex_by_address(heap_address)} (NTHeap)",
                        dml=True
                    )
                elif self.is_SegmentHeap(heap_address):
                    dprint.println(
                        f"Heap {i}: {colour.colorize_hex_by_address(heap_address)} (SegmentHeap)",
                        dml=True
                    )
                else:
                    dprint.println(
                        f"Heap {i}: {colour.colorize_hex_by_address(heap_address)} (Unknown Heap Type)",
                        dml=True
                    )
                
        elif command == "freelist":
            if len(args) < 1:
                dprint.println("[-] Usage: heap freelist [heap_index]")
                return
            try:
                heap_index = int(args[0])
                if heap_index < 0 or heap_index >= len(heap_addresses):
                    dprint.println(f"[-] Invalid heap index: {heap_index}")
                    return
                self.print_freelist(heap_addresses[heap_index])
            except ValueError:
                dprint.println("[-] Invalid heap index format")
        
        elif command == "lfh":
            if len(args) < 1:
                dprint.println("[-] Usage: heap lfh [heap_index] [size]")
                return
            try:
                heap_index = int(args[0])
                if heap_index < 0 or heap_index >= len(heap_addresses):
                    dprint.println(f"[-] Invalid heap index: {heap_index}")
                    return
                size = -1
                if len(args) > 1:
                    size = stoi.str2int(args[1])
                self.print_lfh(heap_addresses[heap_index], size)
            except ValueError:
                dprint.println("[-] Invalid heap index or size format")

        elif command == "vs":
            if len(args) < 1:
                dprint.println("[-] Usage: heap vs [heap_index] [option]")
                dprint.println("Options: --freed")
                return
            try:
                heap_index = int(args[0])
                if heap_index < 0 or heap_index >= len(heap_addresses):
                    dprint.println(f"[-] Invalid heap index: {heap_index}")
                    return
                if "--freed" in args:
                    self.print_freed_vs(heap_addresses[heap_index])
                else:
                    self.print_vs(heap_addresses[heap_index])
            except ValueError:
                dprint.println("[-] Invalid heap index format")
        
        elif command == "segment":
            if len(args) < 1:
                dprint.println("[-] Usage: heap segment [heap_index] [option]")
                dprint.println("Options: --freed")
                return
            try:
                heap_index = int(args[0])
                if heap_index < 0 or heap_index >= len(heap_addresses):
                    dprint.println(f"[-] Invalid heap index: {heap_index}")
                    return
                if "--freed" in args:
                    self.print_freed_segment(heap_addresses[heap_index])
                else:
                    self.print_segment(heap_addresses[heap_index])
            except ValueError:
                dprint.println("[-] Invalid heap index format")
        
        elif command == "all":
            if len(args) < 1:
                dprint.println("[-] Usage: heap all [heap_index]")
                return
            try:
                heap_index = int(args[0])
                if heap_index < 0 or heap_index >= len(heap_addresses):
                    dprint.println(f"[-] Invalid heap index: {heap_index}")
                    return
                self.print_all(heap_addresses[heap_index])
            except ValueError:
                dprint.println("[-] Invalid heap index format")

class Utils:
    def __init__(self):
        pass

    def exittable_viewer(self) -> None:
        dprint.banner_print(" [+] _acrt_atexit_table ")
        exit_table_addr = memoryaccess.get_addr_from_symbol(
            "ucrtbase!_acrt_atexit_table"
        )
        security_cookie = memoryaccess.deref_ptr(
            memoryaccess.get_addr_from_symbol("ucrtbase!__security_cookie")
        )
        first = ror(
            memoryaccess.deref_ptr(exit_table_addr) ^ security_cookie,
            security_cookie & 0x3F,
            64,
        )
        last = ror(
            memoryaccess.deref_ptr(
                exit_table_addr + (4 if context.arch == pykd.CPUType.I386 else 8)
            )
            ^ security_cookie,
            security_cookie & 0x3F,
            64,
        )

        dprint.println("_acrt_atexit_table")
        dprint.println(
            f"Range: [{colour.colorize_hex_by_address(first)}, {colour.colorize_hex_by_address(last)})",
            dml=True,
        )
        for i, value_ptr in enumerate(range(first, last, 8)):
            value = memoryaccess.deref_ptr(value_ptr)
            if value != security_cookie:
                value = ror(value ^ security_cookie, security_cookie & 0x3F, 64)
            else:
                value = 0
            if value != 0:
                dprint.println(
                    f"{i:02}: {colour.colorize_hex_by_address(value_ptr)} -> {colour.colorize_hex_by_address(value)}",
                    dml=True,
                )

        dprint.banner_print("")


class StrToInt:
    def __init__(self):
        pass

    def str2int(self, string: str) -> int:
        if "`" in string:
            string = "0x" + string.replace("`", "")
        return eval(string)


## register commands
cmd: CmdManager = CmdManager()

memoryaccess: MemoryAccess = MemoryAccess()
context: ContextManager = ContextManager()
dprint: PrintManager = PrintManager()

vmmap: Vmmap = Vmmap()
search: SearchPattern = SearchPattern()
seh: SEH = SEH()
heap: Heap = Heap()
utils: Utils = Utils()

stoi: StrToInt = StrToInt()


# Rotate left: 0b1001 --> 0b0011
def rol(val, r_bits, max_bits):
    return (val << r_bits % max_bits) & (2**max_bits - 1) | (
        (val & (2**max_bits - 1)) >> (max_bits - (r_bits % max_bits))
    )


# Rotate right: 0b1001 --> 0b1100
def ror(val, r_bits, max_bits):
    return ((val & (2**max_bits - 1)) >> r_bits % max_bits) | (
        val << (max_bits - (r_bits % max_bits)) & (2**max_bits - 1)
    )


if __name__ == "__main__":
    ## register commands
    cmd.alias("vmmap", "vmmap")

    cmd.alias("c", "c")
    cmd.alias("ni", "ni")
    cmd.alias("si", "si")
    cmd.alias("find", "find")
    cmd.alias("view", "view")
    cmd.alias("seh", "seh")
    cmd.alias("heap", "heap")
    cmd.alias("exittable", "exittable")

    dprint.clear()

    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "vmmap":
            vmmap.print_vmmap()

        elif command == "c" or command == "ni" or command == "si":
            context.execute(sys.argv[1:])

        elif command == "exittable":
            if len(sys.argv) == 2:
                utils.exittable_viewer()

        elif command == "view":
            context.print_context()

        elif command == "find":
            search.execute(sys.argv[1:])

        elif command == "seh":
            if len(sys.argv) == 2:
                dprint.println("[-] Usage: seh [view, ...]")
            if len(sys.argv) == 6:
                if sys.argv[5] == "view":
                    seh.print_sehchain()
                elif sys.argv[5] == "?":
                    dprint.println("[-] Usage: seh [view, ...]")
                    
        elif command == "heap":
            heap.execute(sys.argv[1:])

    dprint.flush()
