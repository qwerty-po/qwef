import enum
import json
import math
import os
import re
import string
import sys
import tempfile
import typing
from dataclasses import asdict, dataclass, fields

import pykd

try:
    nt = pykd.module("ntdll")
except:
    pass


def p64(value: int) -> bytes:
    return value.to_bytes(8, byteorder="little")


class CmdManager:
    def alias(self, cmd, func):
        path = os.path.dirname(sys.argv[0]) + "\\qwef.py"
        pykd.dbgCommand(f"as {cmd} !py -g {path} {func}")

    def register(self, cmd, func):
        self.alias(cmd, func)


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

    def address_color(self, address: int) -> typing.Callable:
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

    def colorize_hex_by_address(self, address: any, strsz=-1) -> str:
        if type(address) is not int:
            try:
                address = int(address)
            except:
                raise ValueError("Type can't change to integer")
        target = f"{address:#x}" if strsz == -1 else f"0x{address:0{strsz}x}"
        return self.address_color(address)(target)

    def colorize_string_by_address(self, target: str, address: int) -> str:
        return self.address_color(address)(target)


colour: ColourManager = ColourManager()

# class I386RegisterEnum(enum.IntEnum):
#     eax = 0; ebx = 1; ecx = 2; edx = 3
#     edi = 4; esi = 5; ebp = 6; esp = 7
#     eip = 8

#     def __str__(self) -> str:
#         return self.name

# class Amd64RegisterEnum(enum.IntEnum):
#     rax = 0; rbx = 1; rcx = 2; rdx = 3
#     rdi = 4; rsi = 5; rbp = 6; rsp = 7
#     r8 = 8; r9 = 9; r10 = 10; r11 = 11
#     r12 = 12; r13 = 13; r14 = 14; r15 = 15
#     rip = 16

#     def __str__(self) -> str:
#         return self.name

# class SegmentRegisterEnum(enum.IntEnum):
#     cs = 0; ds = 1; es = 2; fs = 3
#     gs = 4; ss = 5

#     def __str__(self) -> str:
#         return self.name


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


class MemoryAccess:
    def __init__(self):
        self.addr_symbol: typing.Dict[int, str] = {}

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

    def deref_ptr(self, ptr: int) -> typing.Union[int, None]:
        try:
            return pykd.loadPtrs(ptr, 1)[0] & ContextManager().ptrmask
        except pykd.MemoryException:
            return None

    def get_addr_from_symbol(self, symbol: str) -> typing.Union[int, None]:
        try:
            return int(
                f"0x{pykd.dbgCommand(f'x {symbol}').split(' ')[0].replace('`', '')}", 16
            )
        except pykd.MemoryException:
            return None

    def get_string(self, ptr: int) -> typing.Union[str, None]:
        try:
            return pykd.loadCStr(ptr)
        except pykd.MemoryException:
            return None
        except UnicodeDecodeError:
            return None

    def get_int(self, ptr: int) -> typing.Union[int, None]:
        try:
            return pykd.ptrSignDWord(ptr)
        except pykd.MemoryException:
            return None

    def get_uint(self, ptr: int) -> typing.Union[int, None]:
        try:
            return pykd.ptrDWord(ptr)
        except pykd.MemoryException:
            return None

    def get_long(self, ptr: int) -> typing.Union[int, None]:
        try:
            return pykd.ptrSignQWord(ptr)
        except pykd.MemoryException:
            return None

    def get_ulong(self, ptr: int) -> typing.Union[int, None]:
        try:
            return pykd.ptrQWord(ptr)
        except pykd.MemoryException:
            return None

    def get_bytes(self, ptr: int, size: int) -> typing.Union[bytes, None]:
        try:
            return pykd.loadBytes(ptr, size)
        except pykd.MemoryException:
            return None

    def get_symbol(self, ptr: int) -> typing.Union[str, None]:
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

    def get_qword_datas(self, ptr: int, size: int = 0x10) -> typing.List[int]:
        retlist: typing.List[int] = []
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

    def dump_section(self, reload=False) -> typing.List[SectionInfo]:
        if self.dump_section_info is not None and reload is False:
            return self.dump_section_info

        dumped_info: typing.List[SectionInfo] = []
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
                addr_info: str = (
                    f"0x{section_info.base_address:016x} - 0x{section_info.end_address:016x} 0x{section_info.size:011x}"
                )
            elif pykd.CPUType.I386 == pykd.getCPUMode():
                addr_info: str = (
                    f"0x{section_info.base_address:08x} - 0x{section_info.end_address:08x} 0x{section_info.size:08x}"
                )
            state_info: str = ""
            priv_info: str = ""
            guard_info: str = ""
            type_info: str = ""
            path_info: str = ""

            clr: function = colour.white

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
        self.query: typing.List[typing.Tuple[str, bool]] = []

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

    def banner_print(self, banner_name: str, color: typing.Callable = colour.white):
        leftlen = self.banner_size - len(banner_name) - 2
        llen = leftlen // 2
        rlen = leftlen - llen
        self.println(color(f"{'-' * llen}{banner_name}{'-' * rlen}"), dml=True)

    def success_print(self, content: str, color: typing.Callable = colour.white):
        self.println(color(f"[+] {content}"), dml=True)

    def fail_print(self, content: str, color: typing.Callable = colour.white):
        self.println(color(f"[-] {content}"), dml=True)

    def trying_print(self, content: str, color: typing.Callable = colour.white):
        self.println(color(f"[*] {content}"), dml=True)

    def print_newline(self):
        self.println("")


class ContextManager:

    def __init__(self):
        self.arch = pykd.getCPUMode()
        self.regs: typing.Union[Amd64Register, I386Register]
        self.segregs: SegmentRegister = SegmentRegister()
        self.eflags: EflagsRegister = EflagsRegister()
        self.ptrmask: int = (
            0xFFFFFFFFFFFFFFFF if self.arch == pykd.CPUType.AMD64 else 0xFFFFFFFF
        )

        self.segments_info: typing.List[SectionInfo] = []

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
            value: typing.Union[str, None] = memoryaccess.get_string(xref)
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
            dprint.print(f": ")
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

    def disasm(self, addr) -> typing.Tuple[str, str]:
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
                dprint.print(f"[sp + {offset*4:02x}] ")
                addr = sp + offset * 4
                self.deep_print(addr, 2)
        else:
            for offset in range(8):
                dprint.print(f"[sp + {offset*8:02x}] ")
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

    def find_int(self, start, end, search_value, inputsize) -> typing.List[int]:
        dumped_pattern: str = ""
        retlist: typing.List[int] = []
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

    def find_str(self, start, end, search_value) -> typing.List[int]:
        dumped_pattern: str = ""
        retlist: typing.List[int] = []

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
        search_value: typing.Union[int, str]

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
                f"Searching {hex(search_value)} pattern in {'whole memory' if (start == 0 and end == (1<<64)-1) else 'given section'}"
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

                dump_result: typing.List[int] = self.find_int(
                    section.base_address, section.end_address, search_value, inputsize
                )

                if dump_result == []:
                    continue

                for addr in dump_result:
                    hex_datas: typing.List[int] = memoryaccess.get_qword_datas(addr)
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
                    dprint.print(f":\t")

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

            dprint.success_print(f"Searching pattern finished")

        else:
            dprint.trying_print(
                f"Searching '{search_value}' pattern in {'whole memory' if (start == 0 and end == (1<<64)-1) else 'given section'}"
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
                    dprint.print(f":\t")

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


class ListEntry:
    def __init__(self):
        pass

    def return_check_listentry(self, error: typing.List[str]):
        return (True if error == [] else False, error)

    def check_listentry(
        self, listentry: nt.typedVar("_LIST_ENTRY", int)
    ) -> typing.Tuple[bool, str]:
        error = []

        if not pykd.isValid(listentry):
            return (
                False,
                f"listentry({colour.colorize_hex_by_address(listentry)}) is Invalid address",
            )

        if not pykd.isValid(listentry.Flink):
            error.append(
                f"listentry.Flink({colour.colorize_hex_by_address(listentry.Flink)}) is Invalid address"
            )
        if not pykd.isValid(listentry.Blink):
            error.append(
                f"listentry.Blink({colour.colorize_hex_by_address(listentry.Blink)}) is Invalid address"
            )
        if error != []:
            return self.return_check_listentry(error)

        if not pykd.isValid(listentry.Flink.Blink):
            error.append(
                f"listentry.Flink.Blink({colour.colorize_hex_by_address(listentry.Flink.Blink)}) is Invalid address"
            )
        if not pykd.isValid(listentry.Blink.Flink):
            error.append(
                f"listentry.Blink.Flink({colour.colorize_hex_by_address(listentry.Blink.Flink)}) is Invalid address"
            )
        if error != []:
            return self.return_check_listentry(error)

        if listentry.Flink.Blink != listentry:
            error.append("chunk->Flink->Blink != chunk")
        if listentry.Blink.Flink != listentry:
            error.append("chunk->Blink->Flink != chunk")
        if error != []:
            return self.return_check_listentry(error)

        if listentry.Flink.Blink.Flink != listentry.Flink:
            error.append("next_chunk->Blink->Flink != next_chunk")

        return self.return_check_listentry(error)

    def traverse_list_entry(
        self, list_entry: nt.typedVar("_LIST_ENTRY", int)
    ) -> typing.Tuple[typing.Tuple[bool, str], typing.List[any]]:
        curr = list_entry
        success = True
        result = []
        errorstr: str = ""

        while True:
            if not pykd.isValid(curr):
                success = False
                errorstr = f"listentry({colour.colorize_hex_by_address(curr)}) is Invalid address"
                break
            if curr in result:
                if curr != list_entry:
                    success = False
                    errorstr = f"listentry({colour.colorize_hex_by_address(curr)}) is already in list"
                else:
                    result.append(curr)
                break
            result.append(curr)
            curr = curr.Flink
        return (success, errorstr), result


class RBTree:
    def __init__(self):
        pass

    def return_check_rbtree(self, error: typing.List[str]):
        return (True if error == [] else False, error)

    def check_rbtree(
        self, rbtree: nt.typedVar("_RTL_RB_TREE", int)
    ) -> typing.Tuple[bool, str]:
        error = []

        if not pykd.isValid(rbtree):
            return (
                False,
                f"rbtree({colour.colorize_hex_by_address(rbtree)}) is Invalid address",
            )

        if not pykd.isValid(rbtree.Root):
            error.append(
                f"rbtree.Root({colour.colorize_hex_by_address(rbtree.Root)}) is Invalid address"
            )
        if error != []:
            return self.return_check_rbtree(error)

    def check_rbtree_node(
        self, node: nt.typedVar("_RTL_BALANCED_NODE", int), isroot: bool = False
    ) -> typing.Tuple[bool, str]:
        error = []

        if not pykd.isValid(node):
            return (
                False,
                f"rbtree node({colour.colorize_hex_by_address(node)}) is Invalid address",
            )

        if not pykd.isValid(node.ParentValue) and isroot is False:
            error.append(
                f"rbtree node.ParentValue({int(node.ParentValue)}) is Invalid address"
            )
        if not pykd.isValid(node.Left) and node.Left != 0:
            error.append(f"rbtree node.Left({int(node.Left)}) is Invalid address")
        if not pykd.isValid(node.Right) and node.Right != 0:
            error.append(f"rbtree node.Right({int(node.Right)}) is Invalid address")
        if error != []:
            return self.return_check_rbtree(error)

        if node.Left != 0 and node.Left.ParentValue & ~(0b11) != node:
            error.append(
                f"node.Left.ParentValue({int(node.Left.ParentValue&~(0b11)):#x}) != node({int(node):#x})"
            )
        if node.Right != 0 and node.Right.ParentValue & ~(0b11) != node:
            error.append(
                f"node.Right.ParentValue({int(node.Right.ParentValue&~(0b11)):#x}) != node({int(node):#x})"
            )
        return self.return_check_rbtree(error)

    def rbtree_inorder_traversal(
        self, node: nt.typedVar("_RTL_BALANCED_NODE", int)
    ) -> typing.List[any]:
        inorder = []

        if node == 0:
            return []
        if not pykd.isValid(node):
            return []

        left = node.Left
        right = node.Right
        if left != 0 and left not in inorder:
            inorder += self.rbtree_inorder_traversal(left)
        if node not in inorder:
            inorder.append(node)
        if right != 0 and right not in inorder:
            inorder += self.rbtree_inorder_traversal(right)

        return inorder

    def traversal_rbtree(
        self, root: nt.typedVar("_RTL_BALANCED_NODE", int)
    ) -> typing.List[any]:
        return self.rbtree_inorder_traversal(root)


class TEB:
    def __init__(self):
        tebaddress: int = self.getTEBAddress()

    # https://github.com/corelan/windbglib/blob/d20b3036547886ff6beb616d24927febfa491e93/windbglib.py#L177
    def getTEBAddress(self) -> typing.Union[int, None]:
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

    def getPEBAddress(self) -> typing.Union[int, None]:
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


class SEHInfo:
    Curr: int
    Next: int
    Handler: int

    def __init__(self, ptr):
        self.Curr: int = ptr
        self.Next: typing.Union[int, None] = None
        self.Handler: typing.Union[int, None] = None
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
        self.sehchain: typing.List[SEHInfo] = self.getSEHChain()

    def getSEHChain(self) -> typing.List[SEHInfo]:
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
                or self.sehchain[-1].Next == None
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

    def except_handler3(self, sehinfo: SEHInfo) -> typing.Tuple[int, int, int]:
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

    def except_handler4(self, sehinfo: SEHInfo) -> typing.Tuple[int, int, int]:
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
    ) -> typing.Union[typing.Tuple[int, int, int], None]:
        if "_except_handler3" in memoryaccess.get_symbol(sehinfo.Handler):
            return self.except_handler3(sehinfo)
        elif "_except_handler4" in memoryaccess.get_symbol(sehinfo.Handler):
            return self.except_handler4(sehinfo)
        else:
            return None

    def get_esp_and_exc_ptr(self, sehinfo: SEHInfo) -> typing.Tuple[int, int]:
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
                dprint.println(f"     ↓")

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
                    dprint.println(f"<invalid address>")
                    continue
                else:
                    dprint.println(f"")

                if sehinfo.Next == context.ptrmask:
                    dprint.println(f"     ↓\n(end of chain)")
                else:
                    try_level = self.get_try_level(sehinfo)
                    if try_level == 0xFFFFFFFF or try_level == 0xFFFFFFFE:
                        pykd.println(f" " * 12 + f"try_level < 0, not in try block")
                    old_esp, exc_ptr = self.get_esp_and_exc_ptr(sehinfo)

                    seh_handler_info = self.get_except_handler_info(sehinfo)
                    if seh_handler_info is not None:
                        EnclosingLevel, FilterFunc, HandlerFunc = seh_handler_info
                        dprint.println(
                            f" " * 12
                            + f"old_esp: {colour.colorize_hex_by_address(old_esp, 8)}, exc_ptr: {colour.colorize_hex_by_address(exc_ptr, 8)}, try_level: {try_level}, EnclosingLevel: 0x{EnclosingLevel:08x}, FilterFunc: {colour.colorize_hex_by_address(FilterFunc, 8)}, HandlerFunc: {colour.colorize_hex_by_address(HandlerFunc, 8)}",
                            dml=True,
                        )
                    else:
                        dprint.println(f" " * 12 + f"unknown exception handler type")

        dprint.banner_print("")


class NTHeap(ListEntry):
    def __init__(self):
        pass

    def _HEAPInfo(self, heap_address: int) -> nt.typedVar("_HEAP", int):
        return nt.typedVar("_HEAP", heap_address)

    def get_freelist(self, heap_address: int) -> typing.List[int]:
        heap: nt.typedVar("_HEAP", heap_address) = self._HEAPInfo(heap_address)
        return self.traverse_list_entry(heap.FreeLists)[1]

    def get_freelist_in_blocksindex(self, blockindex_address: int) -> typing.List[int]:
        freelist: typing.List[int] = []
        blockindex = nt.typedVar("_HEAP_LIST_LOOKUP", blockindex_address)
        if blockindex == 0:
            return []
        return self.traverse_list_entry(blockindex.ListHead)[1]

    def get_blockindex_list(self, heap_address: int):
        heap: nt.typedVar("_HEAP", heap_address) = self._HEAPInfo(heap_address)
        blockindex_list = []
        current_blockindex = nt.typedVar("_HEAP_LIST_LOOKUP", int(heap.BlocksIndex))
        while True:
            blockindex_list.append(current_blockindex)
            if not pykd.isValid(current_blockindex):
                break
            elif current_blockindex == 0:
                break
            current_blockindex = nt.typedVar(
                "_HEAP_LIST_LOOKUP", int(current_blockindex.ExtendedLookup)
            )

        return blockindex_list

    def get_listhint(
        self, heap_address: int
    ) -> typing.List[typing.List[typing.Tuple[bool, int]]]:
        blockindex_list: typing.List[nt.typedVar("_HEAP_LIST_LOOKUP")] = (
            self.get_blockindex_list(heap_address)
        )
        listhint_list: typing.List[typing.List[typing.Tuple[bool, int]]] = []

        for blockindex in blockindex_list:
            if int(blockindex) == 0:
                listhint_list.append([])
                continue
            tempbitlist: typing.List[int] = memoryaccess.get_qword_datas(
                blockindex.ListsInUseUlong,
                math.floor(blockindex.ArraySize / (0x8 * 0x8)),
            )
            bitmap: int = 0
            for i, bitnum in enumerate(tempbitlist):
                bitmap |= bitnum << (i * 64)

            listhint: typing.List[int] = []

            for i in range(blockindex.ArraySize):
                listhint.append(
                    (True if (bitmap >> i) & 1 else False, int(blockindex.ListHints[i]))
                )
            listhint_list.append(listhint)

        return listhint_list

    def get_frontendheap(self, heap_address: int) -> nt.typedVar("_LFH_HEAP", int):
        heap: nt.typedVar("_HEAP", heap_address) = self._HEAPInfo(heap_address)
        return nt.typedVar("_LFH_HEAP", int(heap.FrontEndHeap))

    def get_buckets_ptr(self, heap_address: int) -> typing.List[int]:
        heap: nt.typedVar("_HEAP", heap_address) = self._HEAPInfo(heap_address)
        lfh_heap: nt.typedVar("_LFH_HEAP", int) = self.get_frontendheap(heap_address)
        buckets: typing.List[nt.typedVar("_HEAP_BUCKET", int)] = []

        for i in range(0, 128 + 1):
            buckets.append(nt.typedVar("_HEAP_BUCKET", int(lfh_heap.Buckets[i])))

        return buckets

    def get_segmentinfoarray_ptr(self, heap_address: int) -> typing.List[int]:
        heap: nt.typedVar("_HEAP", heap_address) = self._HEAPInfo(heap_address)
        lfh_heap: nt.typedVar("_LFH_HEAP", int) = self.get_frontendheap(heap_address)

        if int(lfh_heap) == 0:
            return []

        segmentinfoarray: typing.List[nt.typedVar("_HEAP_LOCAL_SEGMENT_INFO", int)] = []

        for i in range(0, 128 + 1):
            segmentinfoarray.append(
                nt.typedVar(
                    "_HEAP_LOCAL_SEGMENT_INFO", int(lfh_heap.SegmentInfoArrays[i])
                )
            )

        return segmentinfoarray

    def get_cacheditems(self, segmentinfo_address: int) -> typing.List[int]:
        segmentinfo: nt.typedVar("_HEAP_LOCAL_SEGMENT_INFO", int) = nt.typedVar(
            "_HEAP_LOCAL_SEGMENT_INFO", segmentinfo_address
        )
        cacheditems: typing.List[int] = []

        for i in range(0, 16):
            cacheditems.append(int(segmentinfo.CachedItems[i]))

        return cacheditems

    def get_chunk_size(
        self, chunk_ptr: int, heap_address: int = 0, encoding: bool = True
    ) -> int:
        heap = self._HEAPInfo(heap_address)
        chunk = nt.typedVar("_HEAP_ENTRY", chunk_ptr)

        target = chunk.Size
        if encoding:
            target ^= heap.Encoding.Size
        if context.arch == pykd.CPUType.I386:
            return target << 3
        elif context.arch == pykd.CPUType.AMD64:
            return target << 4
        else:
            raise RuntimeError("Unsupported CPU mode")

    def is_valid_smalltagindex(self, chunk, encoding) -> int:
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
        heap = self._HEAPInfo(heap_address)
        listhint_list: typing.List[typing.List[typing.Tuple[bool, int]]] = (
            self.get_listhint(heap_address)
        )
        blockindex_list: typing.List[nt.typedVar("_HEAP_LIST_LOOKUP", int)] = (
            self.get_blockindex_list(heap_address)
        )

        notlfh_idxs: typing.List[int] = []

        for i, blockindex in enumerate(blockindex_list):
            if blockindex.BaseIndex == 0x0:
                notlfh_idxs.append(i)

        for t, listhint in enumerate(listhint_list):
            if t not in notlfh_idxs:
                continue

            freelist = self.get_freelist_in_blocksindex(blockindex_list[t])

            if freelist == []:
                dprint.banner_print(" [-] Heap freelist is empty ")
                dprint.println(colour.white(" [-] Heap freelist is empty \n"), dml=True)
                return

            dprint.banner_print(
                f" [+] Heap freelist scan ({heap_address:#x}) at blocksindex {t} "
            )
            for i, addr in enumerate(freelist):
                linked_list = nt.typedVar("_LIST_ENTRY", addr)
                linked_list_addr = addr

                addr -= nt.sizeof("_HEAP_ENTRY")
                chunk = nt.typedVar("_HEAP_ENTRY", addr)
                encoding = heap.Encoding

                chunk_idx = chunk.Size ^ encoding.Size
                real_chunk_size = self.get_chunk_size(addr, heap_address)
                real_chunk_prevsize = self.get_chunk_size(addr, heap_address)

                if not pykd.isValid(linked_list):
                    dprint.print(colour.red(f"0x{addr:08x} "), dml=True)
                    dprint.println(colour.white(f"| <invalid address> |"), dml=True)
                else:
                    dprint.print(
                        colour.white(
                            f"{colour.colorize_string_by_address(f'0x{addr:08x}', addr)} | Flink: {colour.colorize_string_by_address(f'0x{int(linked_list.Flink):08x}', linked_list.Flink)} / Blink: {colour.colorize_string_by_address(f'0x{int(linked_list.Blink):08x}', linked_list.Blink)} |"
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
                                f" Size: {colour.blue(f'0x{real_chunk_size:04x}')} , PrevSize: 0x{real_chunk_prevsize:04x}"
                            ),
                            dml=True,
                        )

                        if chunk_idx >= len(listhint):
                            dprint.print(colour.white(f" (out of list hint)"), dml=True)
                        elif listhint[chunk_idx] == (True, linked_list_addr):
                            dprint.print(
                                colour.white(f" (list hint at [{chunk_idx:#x}])"),
                                dml=True,
                            )
                        elif (
                            listhint[chunk_idx][0] == True
                            and listhint[chunk_idx][1] != linked_list_addr
                        ):
                            dprint.print(
                                colour.red(
                                    f" (expect 0x{linked_list_addr:08x} but 0x{listhint[chunk_idx][1]:08x}, based on list hint)"
                                ),
                                dml=True,
                            )

                        checker = self.is_valid_smalltagindex(chunk, encoding)
                        if checker != 0:
                            dprint.print(
                                colour.red(
                                    f" (encoding error, 0x0 != 0x{checker:02x})"
                                ),
                                dml=True,
                            )

                    dprint.print_newline()

                if i != len(freelist) - 1:
                    sanity_result = self.check_listentry(linked_list)
                    if sanity_result[0]:
                        dprint.println(f"     ↕️")
                    else:
                        dprint.println(
                            colour.red(f"     ↕️     ({', '.join(sanity_result[1])})"),
                            True,
                        )
            dprint.banner_print("")

    def print_lfh(self, heap_address: int) -> None:
        heap: nt.typedVar("_HEAP", heap_address) = self._HEAPInfo(heap_address)
        lfh_heap: nt.typedVar("_LFH_HEAP", int) = self.get_frontendheap(heap_address)
        buckets: typing.List[nt.typedVar("_HEAP_BUCKET", int)] = self.get_buckets_ptr(
            heap_address
        )
        segmentinfoarray: typing.List[nt.typedVar("_HEAP_LOCAL_SEGMENT_INFO", int)] = (
            self.get_segmentinfoarray_ptr(heap_address)
        )

        if segmentinfoarray == []:
            dprint.banner_print(" [-] LFH Heap is not enabled ")
            return

        dprint.banner_print(f" [+] LFH Heap ({heap_address:#x}) at frontend heap ")
        for i, lfh_info in enumerate(zip(buckets, segmentinfoarray)):
            bucket, segmentptr = lfh_info

            try:
                segmentinfo: nt.typedVar("_HEAP_LOCAL_SEGMENT_INFO", int) = nt.typedVar(
                    "_HEAP_LOCAL_SEGMENT_INFO", segmentptr
                )
                active_subseg: nt.typedVar("_HEAP_SUBSEGMENT", int) = nt.typedVar(
                    "_HEAP_SUBSEGMENT", int(segmentinfo.ActiveSubsegment)
                )
                user_block: nt.typedVar("_HEAP_USERDATA_HEADER", int) = nt.typedVar(
                    "_HEAP_USERDATA_HEADER", int(active_subseg.UserBlocks)
                )
                aggregate_exchg: nt.typedVar("_INTERLOCK_SEQ", int) = nt.typedVar(
                    "_INTERLOCK_SEQ", int(active_subseg.AggregateExchg)
                )
            except pykd.MemoryException:
                continue

            chunk_size: int = 0
            if context.arch == pykd.CPUType.I386:
                chunk_size = active_subseg.BlockSize << 3
            elif context.arch == pykd.CPUType.AMD64:
                chunk_size = active_subseg.BlockSize << 4
            else:
                raise RuntimeError("Unsupported CPU mode")

            heap_entry_start: int = (
                int(user_block) + nt.sizeof("_HEAP_USERDATA_HEADER") + 0x8
            )

            if aggregate_exchg.Depth == 0:
                dprint.println(
                    colour.white(
                        f"segment {i:#x} is full ({colour.colorize_hex_by_address(user_block)}, size: {colour.blue(f'{chunk_size:#x}')})"
                    ),
                    dml=True,
                )
                dprint.println(
                    f"heap entry start: {colour.colorize_hex_by_address(heap_entry_start)}"
                )
            else:
                dprint.println(
                    colour.white(
                        f"segment {i:#x} is not full, {int(aggregate_exchg.Depth):#x} ({colour.colorize_hex_by_address(user_block)}, size: {colour.blue(f'{chunk_size   :#x}')})"
                    ),
                    dml=True,
                )
                dprint.println(
                    f"heap entry start: {colour.colorize_hex_by_address(heap_entry_start)}",
                    dml=True,
                )
                dprint.print("busybitmap: ")
                busybitmap: nt.typedVar("_RTL_BITMAP", int) = nt.typedVar(
                    "_RTL_BITMAP", int(user_block.BusyBitmap)
                )
                bitvalue: int = memoryaccess.get_qword_datas(int(busybitmap.Buffer), 1)[
                    0
                ]
                for j in range(int(busybitmap.SizeOfBitMap)):
                    if (bitvalue >> j) & 1 == 0:
                        dprint.print(colour.red(0), dml=True)
                    else:
                        dprint.print(colour.green(1), dml=True)
                dprint.print_newline()

            cacheditems: typing.List[int] = self.get_cacheditems(segmentptr)
            for j, cacheditem in enumerate(cacheditems):
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
                                f"cacheditems[{j}] (_HEAP_SUBSEGMENT *): {colour.colorize_hex_by_address(cacheditem)} {colour.red(f'( invalid chunk address )')}"
                            ),
                            dml=True,
                        )
            dprint.print_newline()

        dprint.banner_print("")


class SegmentHeap(ListEntry, RBTree):
    def __init__(self):
        self._RTLP_HP_HEAP_GLOBALS = nt.typedVar(
            "_RTLP_HP_HEAP_GLOBALS",
            memoryaccess.get_addr_from_symbol("ntdll!RtlpHpHeapGlobals"),
        )
        self.buckets_cnt = 130
        pass

    def _SEGMENT_HEAP(self, heap_address: int) -> nt.typedVar("_SEGMENT_HEAP", int):
        return nt.typedVar("_SEGMENT_HEAP", heap_address)

    def VSContext(self, heap_address: int) -> nt.typedVar("_HEAP_VS_CONTEXT", int):
        return nt.typedVar(
            "_HEAP_VS_CONTEXT", self._SEGMENT_HEAP(heap_address).VsContext
        )

    def LFHContext(self, heap_address: int) -> nt.typedVar("_HEAP_LFH_CONTEXT", int):
        return nt.typedVar(
            "_HEAP_LFH_CONTEXT", self._SEGMENT_HEAP(heap_address).LfhContext
        )

    def SegContexts(
        self, heap_address: int
    ) -> nt.typedVar("_HEAP_SEG_CONTEXT[2]", int):
        return self._SEGMENT_HEAP(heap_address).SegContexts

    def LFH_Callback(
        self, heap_address: int
    ) -> nt.typedVar("_HEAP_SUBALLOCATOR_CALLBACKS", int):
        return self.LFHContext(heap_address).Callbacks

    def LFH_Buckets(self, heap_address: int) -> typing.List[any]:
        lfhcontext: nt.typedVar("_HEAP_LFH_CONTEXT", int) = self.LFHContext(
            heap_address
        )
        buckets: typing.List[nt.typedVar("_HEAP_LFH_BUCKET", int)] = []

        for i in range(0, self.buckets_cnt):
            buckets.append(nt.typedVar("_HEAP_LFH_BUCKET", lfhcontext.Buckets[i]))

        return buckets

    def LFH_Bucket(
        self, heap_address: int, idx: int
    ) -> nt.typedVar("_HEAP_LFH_BUCKET", int):
        return nt.typedVar(
            "_HEAP_LFH_BUCKET", self.LFHContext(heap_address).Buckets[idx]
        )

    def is_Bucket(self, bucket: nt.typedVar("_HEAP_LFH_BUCKET", int)) -> bool:
        return True if bucket.State.IsBucket else False

    def BucketIndex(self, bucket: nt.typedVar("_HEAP_LFH_BUCKET", int)) -> int:
        return int(bucket.State.BucketIndex)

    def Bucket_SlotCount(self, bucket: nt.typedVar("_HEAP_LFH_BUCKET", int)) -> int:
        return int(bucket.State.SlotCount)

    def Bucket_AffinitySlots(
        self, bucket: nt.typedVar("_HEAP_LFH_BUCKET", int)
    ) -> nt.typedVar("_HEAP_LFH_AFFINITY_SLOT**", int):
        return nt.typedVar("_HEAP_LFH_AFFINITY_SLOT**", bucket.AffinitySlots)

    def Bucket_AffinitySlot(
        self, bucket: nt.typedVar("_HEAP_LFH_BUCKET", int), idx: int = 0
    ) -> nt.typedVar("_HEAP_LFH_AFFINITY_SLOT", int):
        return nt.typedVar("_HEAP_LFH_AFFINITY_SLOT", bucket.AffinitySlots[idx])

    def Bucket_Affinity_ActiveSubSegment(
        self, bucket: nt.typedVar("_HEAP_LFH_BUCKET", int), idx: int = 0
    ) -> nt.typedVar("_HEAP_LFH_FAST_REF", int):
        return nt.typedVar(
            "_HEAP_LFH_FAST_REF", self.Bucket_AffinitySlot(bucket, idx).ActiveSubsegment
        )

    def Bucket_ActiveSubsegment(
        self, bucket: nt.typedVar("_HEAP_LFH_BUCKET", int), idx: int = 0
    ) -> nt.typedVar("_HEAP_LFH_SUBSEGMENT", int):
        return nt.typedVar(
            "_HEAP_LFH_SUBSEGMENT",
            self.Bucket_Affinity_ActiveSubSegment(bucket, idx).Target & (~0xFFF),
        )

    def Bucket_Affinity_AvailableSubsegmentCount(
        self, bucket: nt.typedVar("_HEAP_LFH_BUCKET", int), idx: int = 0
    ) -> int:
        return int(self.Bucket_AffinitySlot(bucket, idx).State.AvailableSubsegmentCount)

    def Bucket_Affinity_AvailableSubsegmentList(
        self, bucket: nt.typedVar("_HEAP_LFH_BUCKET", int), idx: int = 0
    ) -> nt.typedVar("_LIST_ENTRY", int):
        return self.Bucket_AffinitySlot(bucket, idx).State.AvailableSubsegmentList

    def Bucket_Affinity_FullSubsegmentList(
        self, bucket: nt.typedVar("_HEAP_LFH_BUCKET", int), idx: int = 0
    ) -> nt.typedVar("_LIST_ENTRY", int):
        return self.Bucket_AffinitySlot(bucket, idx).State.FullSubsegmentList

    def _HEAP_LFH_SUBSEGMENT(
        self, subsegment_address: int
    ) -> nt.typedVar("_HEAP_LFH_SUBSEGMENT", int):
        return nt.typedVar("_HEAP_LFH_SUBSEGMENT", subsegment_address)

    def print_bucket(
        self, bucket: nt.typedVar("_HEAP_LFH_BUCKET", int), size: int, banner=True
    ) -> None:

        def print_lfh_subsegment(self, curr: int, size: int, once: bool) -> bool:
            subsegment: nt.typedVar("_HEAP_LFH_SUBSEGMENT", int) = (
                self._HEAP_LFH_SUBSEGMENT(curr)
            )
            BlockCount: int = subsegment.BlockCount
            FreeHint: int = subsegment.FreeHint
            FreeCount: int = subsegment.FreeCount
            Location: int = subsegment.Location

            BlockOffsets: int = (
                subsegment.BlockOffsets.EncodedData
                ^ (int(subsegment) >> 12)
                ^ self._RTLP_HP_HEAP_GLOBALS.LfhKey
            )
            BlockSize: int = BlockOffsets & 0xFFFF
            # FirstBlock: int = int(subsegment) + ((BlockOffsets >> 16) & 0xffff)

            if BlockSize != size and size != -1:
                return once

            if once:
                dprint.println(f"BucketIndex: {self.BucketIndex(bucket)}")
                once = False

            BlockBitmap: bytes = memoryaccess.get_bytes(
                subsegment.BlockBitmap,
                BlockCount / 4 if BlockCount % 4 == 0 else BlockCount / 4 + 1,
            )

            dprint.println(
                f"    Subsegment: {colour.colorize_hex_by_address(int(subsegment))}",
                dml=True,
            )
            dprint.print(
                f"    Flink: {colour.colorize_hex_by_address(int(subsegment.ListEntry.Flink))}, Blink: {colour.colorize_hex_by_address(int(subsegment.ListEntry.Blink))}",
                dml=True,
            )
            sanity_result = self.check_listentry(subsegment.ListEntry)
            if sanity_result[0]:
                pass
            else:
                dprint.print(colour.red(f" ({', '.join(sanity_result[1])})"), dml=True)
            dprint.print_newline()

            dprint.println(
                f"    BlockSize : {colour.blue(f'{BlockSize:#x}')}", dml=True
            )
            dprint.print(
                f"    BlockCount: {int(BlockCount):#x}, FreeHint: {int(FreeHint):#x}, FreeCount: {int(FreeCount):#x}, ",
                dml=True,
            )

            LocationEnum = ["AvailableSegment", "FullSegment", "WillRevertToBackend"]

            dprint.println(
                f"Location: {colour.white(f'{LocationEnum[Location]}')}", dml=True
            )
            dprint.print(f"    ")

            if BlockCount > 0x800:
                dprint.println(
                    f"    BlockBitmap: {colour.red(f'(too large to print)')}", dml=True
                )
                dprint.print_newline()
                return once

            for i in range(
                BlockCount / 4 if BlockCount % 4 == 0 else BlockCount / 4 + 1
            ):
                for j in range(0, 8, 2):
                    if i * 4 + j // 2 >= BlockCount:
                        break

                    if (BlockBitmap[i] >> j) & 1:
                        dprint.print(colour.green("1"), dml=True)
                    else:
                        dprint.print(colour.red("0"), dml=True)

                if (i + 1) % 16 == 0:
                    dprint.print_newline()
                    dprint.print(f"    ")

            dprint.print_newline()
            dprint.print_newline()

            return once

        if banner:
            dprint.banner_print(f" [+] LFH Bucket ({int(bucket):#x}) ")

        once = True
        already_visited = []
        curr = self.Bucket_Affinity_AvailableSubsegmentList(bucket).Flink
        while curr != self.Bucket_Affinity_AvailableSubsegmentList(bucket):
            if not pykd.isValid(curr):
                dprint.print("    Subsegment: ")
                dprint.println(
                    colour.red(f"{int(curr):#x} is invalid address"), dml=True
                )
                break
            if curr in already_visited:
                dprint.print("    Subsegment: ")
                dprint.println(
                    colour.red(f"{int(curr):#x} is already visited"), dml=True
                )
                break
            already_visited.append(curr)
            once = print_lfh_subsegment(self, curr, size, once)
            curr = curr.Flink

        curr = self.Bucket_Affinity_FullSubsegmentList(bucket).Flink
        while curr != self.Bucket_Affinity_FullSubsegmentList(bucket):
            if not pykd.isValid(curr):
                dprint.print("    Subsegment: ")
                dprint.println(
                    colour.red(f"{int(curr):#x} is invalid address"), dml=True
                )
                break
            if curr in already_visited:
                dprint.print("    Subsegment: ")
                dprint.println(
                    colour.red(f"{int(curr):#x} is already visited"), dml=True
                )
                break
            already_visited.append(curr)
            once = print_lfh_subsegment(self, curr, size, once)
            curr = curr.Flink

        if banner:
            dprint.banner_print("")

    def print_lfh(self, heap_address: int, size: int = -1) -> None:
        dprint.banner_print(f" [+] LFH Heap ({heap_address:#x}) ")
        avaliable_segments_idx = []
        for bucket in self.LFH_Buckets(heap_address):
            if pykd.isValid(bucket) and self.Bucket_Affinity_AvailableSubsegmentCount(
                bucket, 0
            ):
                avaliable_segments_idx.append(self.BucketIndex(bucket))
        dprint.print(colour.white(f"avaliable segments: "), dml=True)

        for i, idx in enumerate(avaliable_segments_idx):
            if i % 10 == 0 and i != 0:
                dprint.print_newline()
                dprint.print(colour.white(f"                    "), dml=True)
            dprint.print(colour.white(f"{idx * 0x10:#x} "), dml=True)
        dprint.println("\n")

        for bucket in self.LFH_Buckets(heap_address):
            if pykd.isValid(bucket) and self.Bucket_Affinity_AvailableSubsegmentCount(
                bucket, 0
            ):
                self.print_bucket(bucket, size, False)
            if pykd.isValid(bucket) and self.Bucket_Affinity_FullSubsegmentList(
                bucket, 0
            ):
                avaliable_segments_idx.append(self.BucketIndex(bucket))
        dprint.banner_print("")

    def VS_Callback(
        self, heap_address: int
    ) -> nt.typedVar("_HEAP_SUBALLOCATOR_CALLBACKS", int):
        return self.VSContext(heap_address).Callbacks

    def VS_FreeChunkTree_Root(
        self, heap_address: int
    ) -> nt.typedVar("_RTL_BALANCED_NODE", int):
        if self.VSContext(heap_address).FreeChunkTree.Encoded == 0:
            return nt.typedVar(
                "_RTL_BALANCED_NODE", self.VSContext(heap_address).FreeChunkTree.Root
            )
        else:
            return nt.typedVar(
                "_RTL_BALANCED_NODE",
                self.VSContext(heap_address).FreeChunkTree.Root
                ^ int(self.VSContext(heap_address).FreeChunkTree),
            )

    def VS_inuse_chunk_header(
        self, chunk_address: int
    ) -> nt.typedVar("_HEAP_VS_CHUNK_HEADER", int):
        return nt.typedVar("_HEAP_VS_CHUNK_HEADER", chunk_address)

    def VS_freed_chunk_header(
        self, chunk_address: int
    ) -> nt.typedVar("_HEAP_VS_CHUNK_FREE_HEADER", int):
        return nt.typedVar("_HEAP_VS_CHUNK_FREE_HEADER", chunk_address)

    @dataclass
    class VS_Sizes:
        MemoryCost: int
        UnsafeSize: int
        ActualSize: int
        UnsafePrevSize: int
        ActualPrevSize: int
        Allocated: bool = int

    def VS_decode_chunk_Sizes(self, chunk_address: int) -> VS_Sizes:
        Sizes = int(self.VS_inuse_chunk_header(chunk_address).Sizes.HeaderBits)
        Sizes ^= chunk_address ^ self._RTLP_HP_HEAP_GLOBALS.HeapKey

        return self.VS_Sizes(
            MemoryCost=Sizes & 0xFFFF,
            UnsafeSize=(Sizes >> 16) & 0xFFFF,
            ActualSize=(((Sizes >> 16) & 0xFFFF) << 4),
            UnsafePrevSize=(Sizes >> 32) & 0xFFFF,
            ActualPrevSize=(((Sizes >> 32) & 0xFFFF) << 4),
            Allocated=(Sizes >> 48) & 0xFF,
        )

    def VS_FreeChunkTree_Inorder(self, heap_address: int) -> list:
        return self.traversal_rbtree(self.VS_FreeChunkTree_Root(heap_address))

    def print_vs(self, heap_address: int) -> None:
        freed_chunks = self.VS_FreeChunkTree_Inorder(heap_address)

        dprint.banner_print(f" [+] VS Heap ({heap_address:#x}) ")
        for rbtree_node in freed_chunks:
            chunk = nt.typedVar("_HEAP_VS_CHUNK_FREE_HEADER", rbtree_node - 8)

            if not pykd.isValid(chunk):
                dprint.println(
                    colour.red(f"0x{chunk:08x} is invalid address"), dml=True
                )
                continue
            chunk_Sizes = self.VS_decode_chunk_Sizes(chunk)
            isroot = chunk == self.VS_FreeChunkTree_Root(heap_address) - 8

            if isroot:
                dprint.println(colour.brown("Root"), dml=True)
            dprint.print(
                f"addr: {colour.colorize_hex_by_address(int(chunk))}", dml=True
            )
            check_rbtree = self.check_rbtree_node(rbtree_node, isroot)
            if check_rbtree[0]:
                dprint.print_newline()
            else:
                dprint.println(
                    colour.red(" " * 30 + f"({', '.join(check_rbtree[1])})"), dml=True
                )
            dprint.println(
                f"Size: {colour.blue(f'0x{chunk_Sizes.ActualSize:04x}')}, PrevChunkAddr: {colour.colorize_hex_by_address(int(chunk - chunk_Sizes.ActualSize))}",
                dml=True,
            )
            dprint.println(
                f"Parent: {colour.colorize_hex_by_address(rbtree_node.ParentValue)}, Left: {colour.colorize_hex_by_address(rbtree_node.Left)}, Right: {colour.colorize_hex_by_address(rbtree_node.Right)}",
                dml=True,
            )

            dprint.print_newline()
        dprint.banner_print("")

    def _HEAP_SEG_CONTEXT(
        self, segment_address: int
    ) -> nt.typedVar("_HEAP_SEG_CONTEXT", int):
        return nt.typedVar("_HEAP_SEG_CONTEXT", segment_address)

    def Seg_SegmentListHead(
        self, segment_address: int
    ) -> nt.typedVar("_LIST_ENTRY", int):
        return self._HEAP_SEG_CONTEXT(segment_address).SegmentListHead

    def _HEAP_PAGE_SEGMENT(
        self, segment_address: int
    ) -> nt.typedVar("_HEAP_PAGE_SEGMENT", int):
        return nt.typedVar("_HEAP_PAGE_SEGMENT", segment_address)

    def Seg_PageStart(self, segment_page_address: int, idx: int) -> int:
        return (
            int(segment_page_address + 0x2000)
            if idx == 0
            else int(segment_page_address + 0x10000)
        )

    def Seg_DescArray(
        self, segment_address: int, offset: int
    ) -> nt.typedVar("_HEAP_PAGE_RANGE_DESCRIPTOR", int):
        return nt.typedVar(
            "_HEAP_PAGE_RANGE_DESCRIPTOR",
            self._HEAP_PAGE_SEGMENT(segment_address).DescArray[offset],
        )

    def Seg_DescArrayOffset(self, descarray_address: int) -> int:
        assert descarray_address % 0x20 == 0
        start = (descarray_address & (~0xFFFFF)) + 0x40
        return (descarray_address - start) // 0x20

    def Seg_FreePageRanges(
        self, segment_address: int
    ) -> nt.typedVar("_RTL_RB_TREE", int):
        return nt.typedVar(
            "_RTL_RB_TREE", self._HEAP_SEG_CONTEXT(segment_address).FreePageRanges
        )

    def Seg_FreePageRanges_Root(
        self, segment_address: int
    ) -> nt.typedVar("_RTL_BALANCED_NODE", int):
        if self.Seg_FreePageRanges(segment_address).Encoded == 0:
            return nt.typedVar(
                "_RTL_BALANCED_NODE", self.Seg_FreePageRanges(segment_address).Root
            )
        else:
            return nt.typedVar(
                "_RTL_BALANCED_NODE",
                self.Seg_FreePageRanges(segment_address).Root
                ^ int(self.Seg_FreePageRanges(segment_address)),
            )

    def Seg_FreePageRanges_Inorder(self, segment_address: int) -> typing.List[any]:
        return self.traversal_rbtree(self.Seg_FreePageRanges_Root(segment_address))

    def _HEAP_PAGE_RANGE_DESCRIPTOR(
        self, page_range_descriptor_address: int
    ) -> nt.typedVar("_HEAP_PAGE_RANGE_DESCRIPTOR", int):
        return nt.typedVar("_HEAP_PAGE_RANGE_DESCRIPTOR", page_range_descriptor_address)

    def print_segment(self, heap_address: int) -> None:
        dprint.banner_print(f" [+] Segment ({heap_address:#x}) ")

        for idx in range(2):
            pgoffset = 0x1000 if idx == 0 else 0x10000
            if idx == 0:
                dprint.banner_print(" [+] Small Segment ")
            else:
                dprint.banner_print(" [+] Large Segment ")

            segcontext = self.SegContexts(heap_address)[idx]
            pagesegment = self._HEAP_PAGE_SEGMENT(
                self.Seg_SegmentListHead(segcontext).Flink
            )
            startaddr = self.Seg_PageStart(pagesegment, idx)
            dprint.println(
                colour.white(
                    f"Segcontext: {colour.colorize_string_by_address(f'0x{int(segcontext):08x}', int(segcontext))}"
                ),
                dml=True,
            )
            dprint.println(
                colour.white(
                    f"    PageSegment: {colour.colorize_string_by_address(f'0x{int(pagesegment):08x}', int(pagesegment))}"
                ),
                dml=True,
            )
            dprint.print_newline()

            offset: int = 2
            while offset < 0x100:
                chunk: int = pagesegment + pgoffset * offset
                chunk_meta = self._HEAP_PAGE_RANGE_DESCRIPTOR(
                    self.Seg_DescArray(pagesegment, offset)
                )
                dprint.println(
                    colour.white(
                        f"        Chunk Metadata: {colour.colorize_string_by_address(f'0x{int(chunk_meta):08x}', int(chunk_meta))}"
                    ),
                    dml=True,
                )
                dprint.println(
                    colour.white(
                        f"            StartAddr: {colour.colorize_string_by_address(f'0x{chunk:08x}', chunk)}, Size: {colour.blue(hex(chunk_meta.UnitSize * pgoffset))}"
                    ),
                    dml=True,
                )
                dprint.print_newline()

                if chunk_meta.UnitSize == 0:

                    dprint.println(
                        colour.red(
                            f"            UnitSize is 0 or segment is not initialized, can't dump more"
                        ),
                        dml=True,
                    )
                    break
                else:
                    offset += chunk_meta.UnitSize

    def print_freed_segment(self, heap_address: int) -> None:
        dprint.banner_print(f" [+] Segment ({heap_address:#x}) ")

        for idx in range(2):
            pgoffset = 0x1000 if idx == 0 else 0x10000
            if idx == 0:
                dprint.banner_print(" [+] Small Segment ")
            else:
                dprint.banner_print(" [+] Large Segment ")

            segcontext = self.SegContexts(heap_address)[idx]
            pagesegment = self._HEAP_PAGE_SEGMENT(
                self.Seg_SegmentListHead(segcontext).Flink
            )
            startaddr = self.Seg_PageStart(pagesegment, idx)
            FreePageRanges = self.Seg_FreePageRanges_Inorder(segcontext)
            if FreePageRanges != []:
                dprint.println(
                    colour.white(
                        f"Segcontext: {colour.colorize_string_by_address(f'0x{int(segcontext):08x}', int(segcontext))}"
                    ),
                    dml=True,
                )

            for freed_chunk_meta in FreePageRanges:
                offset: int = self.Seg_DescArrayOffset(int(freed_chunk_meta))
                chunk: int = startaddr + pgoffset * offset
                chunk_meta = self._HEAP_PAGE_RANGE_DESCRIPTOR(freed_chunk_meta)
                dprint.println(
                    colour.white(
                        f"    Chunk Metadata: {colour.colorize_string_by_address(f'0x{int(chunk_meta):08x}', int(chunk_meta))}"
                    ),
                    dml=True,
                )
                dprint.println(
                    colour.white(
                        f"        StartAddr: {colour.colorize_string_by_address(f'0x{chunk:08x}', chunk)}, Size: {colour.blue(hex(chunk_meta.UnitSize * pgoffset))}"
                    ),
                    dml=True,
                )

            dprint.banner_print("")

        dprint.banner_print("")

    def print_block(self, heap_address: int) -> None:
        pass


class Heap(PEB):
    def __init__(self):
        self.heaps: typing.List[int] = self.get_heaps_address()
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

    def analysis_chunk(self, chunk_address: int):
        info = pykd.dbgCommand(f"!heap -x {hex(chunk_address)}")
        if info == None:
            dprint.fail_print("Invalid chunk address")
            return

        info = info.split("\n")[3:]
        info_dict = {}
        chunk_info = {}

        for line in info:
            if ":" not in line:
                continue
            key, value = line.split(":")[0].strip(), line.split(":")[1].strip()
            info_dict[key] = value

        if "Chunk header address" not in info_dict or "Heap Address" not in info_dict:
            dprint.fail_print(
                f"Analysis failed, please check the chunk address ({colour.colorize_hex_by_address(chunk_address)})"
            )
            return

        if "Variable size allocated chunk" in info_dict["Allocation status"]:
            chunk_info["status"] = "VS"
            chunk_info["chunk_address"] = int(info_dict["Chunk header address"], 16)
            chunk_info["size"] = int(info_dict["Chunk size (bytes)"].split(" ")[0])
        elif "Backend" in info_dict["Allocation status"]:
            chunk_info["status"] = "Backend"
            chunk_info["chunk_address"] = int(info_dict["Block Address"], 16)
            chunk_info["size"] = int(info_dict["Block Size"].split(" ")[0])
        elif "LFH" in info_dict["Allocation status"]:
            chunk_info["status"] = "LFH"
            chunk_info["chunk_address"] = int(info_dict["Block Address"], 16)
            chunk_info["size"] = int(info_dict["Block Size"].split(" ")[0])

        if self.is_NTHeap(int(info_dict["Heap Address"], 16)):
            chunk_info["type"] = "NTHeap"
            # self.NtHeap.analysis_chunk(chunk_info, info_dict, chunk_info)
        elif self.is_SegmentHeap(int(info_dict["Heap Address"], 16)):
            chunk_info["type"] = "SegmentHeap"
            # self.SegmentHeap.analysis_chunk(chunk_address, info_dict, chunk_info)

        for key, value in chunk_info.items():
            if type(value) == int:
                dprint.println(f"{key}: {value:#x}")
            else:
                dprint.println(f"{key}: {value}")

        if chunk_info["type"] == "SegmentHeap":
            if chunk_info["status"] == "VS":
                self.SegmentHeap.print_vs(int(info_dict["Heap Address"], 16))
            elif chunk_info["status"] == "LFH":
                self.SegmentHeap.print_lfh(
                    int(info_dict["Heap Address"], 16), chunk_info["size"]
                )
            elif chunk_info["status"] == "Backend":
                self.SegmentHeap.print_block(int(info_dict["Heap Address"], 16))

    def get_heaps_address(self) -> typing.List[int]:
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
            # self.SegmentHeap.print_lfh(heap_address)
            self.SegmentHeap.print_vs(heap_address)
            self.SegmentHeap.print_segment(heap_address)
            self.SegmentHeap.print_block(heap_address)
        else:
            dprint.fail_print("Heap type is not supported")


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
rol = lambda val, r_bits, max_bits: (val << r_bits % max_bits) & (2**max_bits - 1) | (
    (val & (2**max_bits - 1)) >> (max_bits - (r_bits % max_bits))
)

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: (
    (val & (2**max_bits - 1)) >> r_bits % max_bits
) | (val << (max_bits - (r_bits % max_bits)) & (2**max_bits - 1))

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
        elif command == "c":
            if len(sys.argv) == 2:
                context.conti()
            elif len(sys.argv) == 3:
                if sys.argv[2].startswith("0x"):
                    context.conti(int(sys.argv[2], 16))
                else:
                    context.conti(int(sys.argv[2]))
        elif command == "ni":
            if len(sys.argv) == 2:
                context.ni()
            elif len(sys.argv) == 3:
                if sys.argv[2].startswith("0x"):
                    context.ni(int(sys.argv[2], 16))
                else:
                    context.ni(int(sys.argv[2]))
        elif command == "si":
            if len(sys.argv) == 2:
                context.si()
            elif len(sys.argv) == 3:
                if sys.argv[2].startswith("0x"):
                    context.si(int(sys.argv[2], 16))
                else:
                    context.si(int(sys.argv[2]))
        elif command == "exittable":
            if len(sys.argv) == 2:
                utils.exittable_viewer()
        elif command == "view":
            context.print_context()
        elif command == "find":
            if len(sys.argv) == 3:
                search.find(sys.argv[2])
            elif len(sys.argv) == 5:
                search.find(sys.argv[2], int(sys.argv[3], 16), int(sys.argv[4], 16))
            else:
                search.help()
        elif command == "seh":
            if len(sys.argv) == 2:
                dprint.println("[-] Usage: seh [view, ...]")
            if len(sys.argv) == 6:
                if sys.argv[5] == "view":
                    seh.print_sehchain()
                elif sys.argv[5] == "?":
                    dprint.println("[-] Usage: seh [view, ...]")
        elif command == "heap":
            if len(sys.argv) == 2:
                dprint.println(
                    "[-] Usage: heap [freelist, lfh, vs, segment, block, all] <heap_index>"
                )

            elif len(sys.argv) == 3:
                val = stoi.str2int(sys.argv[2])
                heap.analysis_chunk(val)

            elif len(sys.argv) == 4:
                if sys.argv[2] == "freelist":
                    heap.print_freelist(
                        heap.get_heaps_address()[stoi.str2int(sys.argv[3])]
                    )
                elif sys.argv[2] == "lfh":
                    heap.print_lfh(heap.get_heaps_address()[stoi.str2int(sys.argv[3])])
                elif sys.argv[2] == "vs":
                    heap.print_vs(heap.get_heaps_address()[stoi.str2int(sys.argv[3])])
                elif sys.argv[2] == "segment":
                    heap.print_segment(
                        heap.get_heaps_address()[stoi.str2int(sys.argv[3])]
                    )
                elif sys.argv[2] == "block":
                    heap.print_block(
                        heap.get_heaps_address()[stoi.str2int(sys.argv[3])]
                    )
                elif sys.argv[2] == "all":
                    heap.print_all(heap.get_heaps_address()[stoi.str2int(sys.argv[3])])
                elif sys.argv[2] == "?":
                    dprint.println(
                        "[-] Usage: heap [freelist, lfh, vs, segment, block, all] <heap_index>"
                    )

            elif len(sys.argv) == 5:
                if sys.argv[2] == "lfh":
                    heap.print_lfh(
                        heap.get_heaps_address()[stoi.str2int(sys.argv[3])],
                        stoi.str2int(sys.argv[4]),
                    )
                if sys.argv[2] == "segment":
                    if sys.argv[3] == "freed":
                        heap.print_freed_segment(
                            heap.get_heaps_address()[stoi.str2int(sys.argv[4])]
                        )
                    else:
                        heap.print_segment(
                            heap.get_heaps_address()[stoi.str2int(sys.argv[3])],
                            stoi.str2int(sys.argv[4]),
                        )

            else:
                dprint.println(
                    "[-] Usage: heap [freelist, lfh, vs, segment, block, all] <heap_index>"
                )

    dprint.flush()
