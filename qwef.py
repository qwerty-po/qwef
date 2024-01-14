import re
import os
import sys
import pykd
import enum
import typing
import string

from dataclasses import dataclass, fields, asdict

def p64(value: int) -> bytes:
    return value.to_bytes(8, byteorder="little")

class CmdManager():
        
    def alias(self, cmd, func):
        path = os.path.dirname(sys.argv[0])+'\\qwef.py'
        pykd.dbgCommand(f"as {cmd} !py -g {path} {func}")
    
    def register(self, cmd, func):
        self.alias(cmd, func)


class ColourManager():
    
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
        return "<col fg=\"{}\" bg=\"{}\">{}</col>".format(col[0], col[1], content)

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
    CF = 0; PF = 2; AF = 4; ZF = 6
    SF = 7; TF = 8; IF = 9; DF = 10
    OF = 11; IOPL = 12; NT = 14; RF = 16
    VM = 17; AC = 18; VIF = 19; VIP = 20
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
class I386Register():
    eax: int; ebx: int; ecx: int; edx: int
    edi: int; esi: int; ebp: int; esp: int
    eip: int
    
    def __init__(self):
        self.eax: int = -1; self.ebx: int = -1; self.ecx: int = -1; self.edx: int = -1
        self.edi: int = -1; self.esi: int = -1; self.ebp: int = -1; self.esp: int = -1
        self.eip: int = -1
    
    def assign(self, name, value):
        setattr(self, name, value)

@dataclass
class Amd64Register():
    rax: int; rbx: int; rcx: int; rdx: int
    rdi: int; rsi: int; rbp: int; rsp: int
    r8: int; r9: int; r10: int; r11: int
    r12: int; r13: int; r14: int; r15: int
    rip: int
    
    def __init__(self):
        self.rax: int = -1; self.rbx: int = -1; self.rcx: int = -1; self.rdx: int = -1
        self.rdi: int = -1; self.rsi: int = -1; self.rbp: int = -1; self.rsp: int = -1
        self.r8: int = -1; self.r9: int = -1; self.r10: int = -1; self.r11: int = -1
        self.r12: int = -1; self.r13: int = -1; self.r14: int = -1; self.r15: int = -1
        self.rip: int = -1
    
    def assign(self, name, value):
        setattr(self, name, value)

@dataclass
class SegmentRegister():
    cs: int; ds: int; es: int; fs: int
    gs: int; ss: int
    
    def __init__(self):
        self.cs: int = -1; self.ds: int = -1; self.es: int = -1; self.fs: int = -1
        self.gs: int = -1; self.ss: int = -1
    
    def assign(self, name, value):
        setattr(self, name, value)

@dataclass
class EflagsRegister():
    CF: bool; PF: bool; AF: bool; ZF: bool
    SF: bool; TF: bool; IF: bool; DF: bool
    OF: bool; IOPL: bool; NT: bool; RF: bool
    VM: bool; AC: bool; VIF: bool; VIP: bool
    ID: bool
    
    def __init__(self):
        self.CF: bool = False; self.PF: bool = False; self.AF: bool = False; self.ZF: bool = False
        self.SF: bool = False; self.TF: bool = False; self.IF: bool = False; self.DF: bool = False
        self.OF: bool = False; self.IOPL: bool = False; self.NT: bool = False; self.RF: bool = False
        self.VM: bool = False; self.AC: bool = False; self.VIF: bool = False; self.VIP: bool = False
        self.ID: bool = False
    
    def assign(self, name, value):
        setattr(self, name, value)
    
class MemoryAccess():
    def __init__(self):
        self.addr_symbol: typing.Dict[int, str] = {}
    
    def deref_ptr(self, ptr: int, mask: int) -> typing.Union[int, None]:
        """dereference pointer

        Args:
            ptr (int): pointer address
            mask (int): masking based on pointer size

        Returns:
            typing.Union[int, None]: dereferenced pointer or None
        """
        try:
            return pykd.loadPtrs(ptr, 1)[0] & mask
        except pykd.MemoryException:
            return None
        
    def get_string(self, ptr: int) -> typing.Union[str, None]:
        """load ASCII string (if not return error)

        Args:
            ptr (int): pointer address

        Returns:
            typing.Union[str, None]: string or None
        """
        try:
            return pykd.loadCStr(ptr)
        except pykd.MemoryException:
            return None
        except UnicodeDecodeError:
            return None
    
    def get_bytes(self, ptr: int, size: int) -> typing.Union[bytes, None]:
        """load bytes given size

        Args:
            ptr (int): pointer address
            size (int): size of bytes

        Returns:
            typing.Union[bytes, None]: bytes or None
        """
        try:
            return pykd.loadBytes(ptr, size)
        except pykd.MemoryException:
            return None
        
    def get_symbol(self, ptr: int) -> typing.Union[str, None]:
        """get symbol name if exist

        Args:
            ptr (int): pointer address

        Returns:
            typing.Union[str, None]: symbol name or None (it would be saved in self.addr_symbol)
        """
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
        """get data(qword) from ptr (if not return error)

        Args:
            ptr (int): pointer address
            size (int, optional): get size. Defaults to 0x10.

        Raises:
            Exception: _description_

        Returns:
            typing.List[int]: _description_
        """
        retlist: typing.List[int] = []
        for val in pykd.dbgCommand(f"dq {hex(ptr)} {hex(ptr + size - 1)}").replace("`", "").split("  ")[1].strip().split(" "):
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
                PageProtect.PAGE_EXECUTE \
                | PageProtect.PAGE_EXECUTE_READ \
                | PageProtect.PAGE_EXECUTE_READWRITE \
                | PageProtect.PAGE_EXECUTE_WRITECOPY
            ):
            return True
        else:
            return False
    
    def is_writable(enum_val) -> bool:
        if enum_val & (
                PageProtect.PAGE_READWRITE \
                | PageProtect.PAGE_WRITECOPY
            ):
            return True
        else:
            return False
    
    def is_readable(enum_val) -> bool:
        if enum_val & (
                PageProtect.PAGE_READONLY \
                | PageProtect.PAGE_READWRITE \
                | PageProtect.PAGE_WRITECOPY
            ):
            return True
        else:
            return False
    
    def is_copy_on_write(enum_val) -> bool:
        if enum_val & (
                PageProtect.PAGE_WRITECOPY \
                | PageProtect.PAGE_EXECUTE_WRITECOPY
            ):
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
class Vmmap():
    
    def __init__(self):
        pass

    def section_info(self, address: int) -> SectionInfo:
        section_info: SectionInfo = SectionInfo()
        
        for line in pykd.dbgCommand(f"!address {hex(address)}").split("\n"):
            line = line.replace('`', '')
            if "Allocation Protect:" in line:
                continue
            
            if "Usage:" in line:
                section_info.usage = line.split(":")[1].strip()
            if "Base Address:" in line:
                section_info.base_address = int(f"0x{line.split(':')[1].strip()}", 16)
            if "End Address:" in line:
                section_info.end_address = int(f"0x{line.split(':')[1].strip()}", 16)
            if "Region Size:" in line:
                section_info.size = int(f"0x{line.split(':')[1].strip().split(' ')[0]}", 16)
            if "State:" in line:
                section_info.state = int(f"0x{line.split(':')[1].strip().split(' ')[0]}", 16)
            if "Protect:" in line:
                try:
                    section_info.protect = int(f"0x{line.split(':')[1].strip().split(' ')[0]}", 16)
                except:
                    pass
            if "Type:" in line:
                try:
                    section_info.type = int(f"0x{line.split(':')[1].strip().split(' ')[0]}", 16)
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
    
    def dump_section(self) -> typing.List[SectionInfo]:
        dumped_info: typing.List[SectionInfo] = []
        base: int = 0
        
        while True:
            target_info: SectionInfo = self.section_info(base)
            
            if target_info.base_address != base:
                break
            else:
                dumped_info.append(target_info)
                base += dumped_info[-1].size
            
        return dumped_info

    def print_vmmap(self, level: int = 0):
        for section_info in self.dump_section():
            addr_info: str = f"0x{section_info.base_address:016x} - 0x{section_info.end_address:016x} 0x{section_info.size:011x}"
            state_info: str = ""
            priv_info: str = ""
            guard_info: str = ""
            type_info: str = ""
            path_info: str = ""
            
            clr: function = colour.white
            
            if PageState.is_free(section_info.state):
                clr = colour.gray
                state_info += 'free'
            elif PageState.is_reserve(section_info.state):
                clr = colour.gray
                state_info += 'reserve'
            elif PageState.is_commit(section_info.state):
                state_info += 'commit'
                if PageProtect.is_guard(section_info.protect):
                    clr = colour.gray
                    guard_info += '(g)'
                elif PageProtect.is_executable(section_info.protect):
                    clr = colour.red
                elif PageProtect.is_writable(section_info.protect):
                    clr = colour.green
                elif PageProtect.is_readable(section_info.protect):
                    clr = colour.white
                else:
                    clr = colour.gray
                
                if PageProtect.is_copy_on_write(section_info.protect):
                    priv_info += 'c'
                elif PageProtect.is_readable(section_info.protect):
                    priv_info += 'r'
                else:
                    priv_info += '-'
                    
                if PageProtect.is_writable(section_info.protect):
                    priv_info += 'w'
                else:
                    priv_info += '-'
                
                if PageProtect.is_executable(section_info.protect):
                    priv_info += 'x'
                else:
                    priv_info += '-'

            if PageType.is_mapped(section_info.type):
                type_info += 's'
            elif PageType.is_private(section_info.type):
                type_info += 'p'
            elif PageType.is_image(section_info.type):
                type_info += 'i'
                if section_info.image_path != "":
                    path_info = section_info.image_path
            
            if section_info.additional != "" and path_info == "":
                path_info = section_info.additional

            printst: str = ""
            if state_info == "commit":
                printst = f"{addr_info} {state_info:11} {priv_info}{type_info}{guard_info}"
            elif state_info == "free" or state_info == "reserve":
                printst = f"{addr_info} {state_info:11} {state_info}"
            
            if level == 0 and clr != colour.gray:
                pykd.dprint(clr(printst), dml=True)
                pykd.dprint(f" {section_info.usage}")
                if path_info:
                    pykd.dprintln(f" [{path_info}]")
                else:
                    pykd.dprintln("")
            elif level == 1:
                pykd.dprint(clr(printst), dml=True)
                pykd.dprint(f" {section_info.usage}")
                if path_info:
                    pykd.dprintln(f" [{path_info}]")
                else:
                    pykd.dprintln("")
class ContextManager():
    
    def __init__(self):
        self.arch = pykd.getCPUMode()
        self.regs : typing.Union[Amd64Register, I386Register]
        self.segregs : SegmentRegister = SegmentRegister()
        self.eflags : EflagsRegister = EflagsRegister()
        self.ptrmask: int = 0xffffffffffffffff if self.arch == pykd.CPUType.AMD64 else 0xffffffff
        
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
            self.eflags.assign(flaginfo[0], (((eflags >> EflagsEnum[flaginfo[0]]) & 1) == 1))
            
    def update_vmmap(self):
        self.segments_info = vmmap.dump_section()
        
    def print_context(self):
        self.update_vmmap()
        self.update_regs()
        self.update_eflags()
        self.update_vmmap()
        
        pykd.dprintln(colour.blue("--------------------------------------------------------- registers ---------------------------------------------------------"), dml=True)
        self.print_regs()
        pykd.dprintln(colour.blue("---------------------------------------------------------   codes   ---------------------------------------------------------"), dml=True)
        self.print_code()
        pykd.dprintln(colour.blue("---------------------------------------------------------   stack   ---------------------------------------------------------"), dml=True)
        self.print_stack()
    
    def colorize_print_by_priv(self, value) -> None:
        for section in self.segments_info:
            if section.base_address <= value <= section.end_address:
                if section.usage == "Stack":
                    pykd.dprint(colour.purple(f" 0x{value:016x}"), dml=True)
                elif PageProtect.is_executable(section.protect):
                    pykd.dprint(colour.red(f" 0x{value:016x}"), dml=True)
                elif PageProtect.is_writable(section.protect):
                    pykd.dprint(colour.green(f" 0x{value:016x}"), dml=True)
                else:
                    pykd.dprint(colour.white(f" 0x{value:016x}"), dml=True)
                return
        pykd.dprint(colour.white(f" 0x{value:016x}"), dml=True)
    
    def deep_print(self, value: int, remain: int, xref: int = 0) -> None:
        printst: str = ""
        self.colorize_print_by_priv(value)
        if memoryaccess.get_symbol(value) is not None:
            pykd.dprint(f" <{colour.white(memoryaccess.get_symbol(value))}>", dml=True)
            
        if pykd.isValid(value):
            if remain == 0:
                pykd.dprintln("")
                return
            else:
                pykd.dprint(" ->", dml=True)
                self.deep_print(memoryaccess.deref_ptr(value, self.ptrmask), remain - 1, value)
                return
        elif pykd.isValid(xref):
            value: typing.Union[str, None] = memoryaccess.get_string(xref)
            if value is None:
                pykd.dprintln("")
                return

            if len(value):
                pykd.dprintln(f'("{colour.white(value)}")', dml=True)
                return
            else:
                pykd.dprintln("")
                return
        else:
            pykd.dprintln("")
            return
    
    def print_general_regs(self) -> None:
        for reg, vaule in asdict(self.regs).items():
            pykd.dprint(colour.red(f"{reg:4}"), dml=True)
            pykd.dprint(f": ")
            self.deep_print(vaule, 5)
            
    def print_seg_regs(self) -> None:
        for reg, vaule in asdict(self.segregs).items():
            pykd.dprint(f"{reg:2} = 0x{vaule:02x} ")
        pykd.dprintln("")
    
    def print_eflags(self) -> None:
        
        for reg, vaule in asdict(self.eflags).items():
            if vaule:
                pykd.dprint(f"{colour.green(str(EflagsEnum[reg]))} ", dml=True)
            else:
                pykd.dprint(f"{colour.red(str(EflagsEnum[reg]))} ", dml=True)
        pykd.dprintln("")
        
    def disasm(self, addr) -> typing.Tuple[str, str]:
        resp = pykd.disasm().disasm(addr).split(" ")
        op_str = resp[1]
        asm_str = ' '.join(c for c in resp[2::]).strip()
        return op_str, asm_str

    def print_code_by_address(self, pc: int, tab: str, print_range: int) -> None:

        for _ in range(print_range):
            op_str, asm_str = self.disasm(pc)
            sym: str = memoryaccess.get_symbol(pc)
            debug_info: str = ""
            if sym is not None:
                debug_info: str = f" <{sym}> "
            code_str = f"{pc:#x}: {op_str:25s}{debug_info:20s}{asm_str}"
            pykd.dprintln(colour.white(f"{tab}{code_str}"), dml=True)
            
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
                pykd.dprintln(colour.bold_white(f"-> {code_str}"), dml=True)
                
                if asm_str.startswith("ret"):
                    num: int 
                    try:
                        if asm_str.split(" ")[1].endswith("h"):
                            num = int(f"0x{asm_str.split(' ')[1][:-1]}", 16)
                        else:
                            num = int(asm_str.split(" ")[1])
                    except:
                        num = 0
                    goto: int = memoryaccess.deref_ptr(self.regs.rsp + num * 8 if self.arch == pykd.CPUType.AMD64 else self.regs.esp + num * 4, self.ptrmask)
                    
                    if goto is not None:
                        self.print_code_by_address(goto, " "*8, 4)
            else:
                pykd.dprintln(colour.white(f"   {code_str}"), dml=True)
                
    def print_stack(self) -> None:
        sp = self.regs.rsp if self.arch == pykd.CPUType.AMD64 else self.regs.esp
        
        if self.arch == pykd.CPUType.I386:
            for offset in range(8):
                pykd.dprint(f"[sp + {offset*4:02x}] ")
                addr = sp + offset * 4
                self.deep_print(addr, 2)
        else:
            for offset in range(8):
                pykd.dprint(f"[sp + {offset*8:02x}] ")
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

class SearchPattern():
    def __init__(self):
        self.ptrmask: int = 0xffffffffffffffff if pykd.getCPUMode() == pykd.CPUType.AMD64 else 0xffffffff
    
    def help(self):
        pykd.dprintln(colour.white("[-] Usage: find [pattern](int, 0x, 0o, 0b, dec, str)"), dml=True)
        
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
            line = line.replace('`', '').split("  ")[0]
            retlist.append(int(f"0x{line.strip().split(' ')[0]}", 16))
    
        return retlist

    def find_str(self, start, end, search_value) -> typing.List[int]:
        dumped_pattern: str = ""
        retlist: typing.List[int] = []
        
        dumped_pattern = pykd.dbgCommand(f"s -a {hex(start)} {hex(end)} \"{search_value}\"")
        
        if dumped_pattern == None:
            return []
        
        for line in dumped_pattern.split("\n"):
            if line.strip() == "":
                continue
            line = line.replace('`', '').split("  ")[0]
            retlist.append(int(f"0x{line.strip().split(' ')[0]}", 16))

        return retlist
    
    def find(self, pattern: str, start: int = 0x0, end: int = 0xffffffffffffffff, level: int = 0) -> None:
        
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
        elif (pattern.startswith("'") and pattern.endswith("'")) \
            or (pattern.startswith("\"") and pattern.endswith("\"")):
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
                pykd.dprintln(colour.white("[-] Invalid pattern (too long)"), dml=True)
                self.help()
                return

            pykd.dprintln(colour.white(f"[+] Searching {hex(search_value)} pattern in {'whole memory' if (start == 0 and end == (1<<64)-1) else 'given section'}"), dml=True)
            
            for section in vmmap.dump_section():
                once: bool = True
                offset: int = 0
                
                if section.base_address < start:
                    continue
                if section.base_address > end:
                    break
                if PageState.is_free(section.state) or PageState.is_reserve(section.state):
                    continue
                
                dump_result: typing.List[int] = self.find_int(section.base_address, section.end_address, search_value, inputsize)
                
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
                        print(type(section.protect))
                        pykd.dprintln(f"[+] In '{colour.blue(info)}' ({hex(section.base_address)}-{hex(section.end_address)} [{PageProtect.to_str(section.protect)}])", dml=True)
                    pykd.dprint(colour.white(f"0x{(section.base_address + offset):016x}"), dml=True)
                    pykd.dprint(f":\t")
                
                    for data in hex_datas:
                        pykd.dprint(f"0x{data:016x} ")
                    pykd.dprint("| ")
                    for data in hex_datas:
                        for ch in p64(data):
                            if chr(ch) in string.whitespace:
                                pykd.dprint(".")
                            elif chr(ch) in string.printable:
                                pykd.dprint(chr(ch))
                            else:
                                pykd.dprint(".")
                    pykd.dprintln(" |")
                            
            pykd.dprintln(colour.white(f"[+] Searching pattern finished"), dml=True)
        
        else:
            pykd.dprintln(colour.white(f"[+] Searching '{search_value}' pattern in {'whole memory' if (start == 0 and end == (1<<64)-1) else 'given section'}"), dml=True)
            
            for section in vmmap.dump_section():
                once: bool = True
                
                if section.base_address < start:
                    continue
                if section.base_address > end:
                    break
                if PageState.is_free(section.state) or PageState.is_reserve(section.state):
                    continue
                
                for addr in self.find_str(section.base_address, section.end_address, search_value):
                    if once:
                        once = False
                        info: str = ""
                        if section.image_path != "":
                            info = section.image_path
                        elif section.additional != "":
                            info = section.additional
                        else:
                            info = section.usage
                        pykd.dprintln(f"[+] In '{colour.blue(info)}' ({hex(section.base_address)}-{hex(section.end_address)} [{PageProtect.to_str(section.protect)}])", dml=True)
                    pykd.dprint(colour.white(f"0x{(addr):016x}"), dml=True)
                    pykd.dprint(f":\t")
                    
                    memval: bytes = memoryaccess.get_bytes(addr, 0x10)
                    
                    for ch in memval:
                        pykd.dprint(f"{ch:02x} ")
                    pykd.dprint("| ")
                    for ch in memval:
                        ch = chr(ch)
                        if ch in string.whitespace:
                            pykd.dprint(".")
                        elif ch in string.printable:
                            pykd.dprint(ch)
                        else:
                            pykd.dprint(".")
                    pykd.dprintln(" |")
                    
            pykd.dprintln(colour.white(f"[+] Searching pattern finished"), dml=True)

@dataclass
class ListEntry():
    Flink: int
    Blink: int
    
    def __init__(self, Flink: int, Blink: int) -> None:
        self.Flink: int = Flink
        self.Blink: int = Blink

class TEB():
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
class PEB():
    @dataclass
    class PEBInfo():
        InheritedAddressSpace: int
        ReadImageFileExecOptions: int
        BeingDebugged: int
        
        BitField: int # contain ImageUsesLargePages to IsLongPathAwareProcess
        ImageUsesLargePages: int
        IsProtectedProcess: int
        IsImageDynamicallyRelocated: int
        SkipPatchingUser32Forwarders: int
        IsPackagedProcess: int
        IsAppContainer: int
        IsProtectedProcessLight: int
        IsLongPathAwareProcess: int
        
        Mutant: int
        ImageBaseAddress: int
        Ldr: int
        ProcessParameters: int
        SubSystemData: int
        ProcessHeap: int
        FastPebLock: int
        AtlThunkSListPtr: int
        IFEOKey: int
        
        CrossProcessFlags: int # contain ProcessInJob to ReservedBits0
        ProcessInJob: int
        ProcessInitializing: int
        ProcessUsingVEH: int
        ProcessUsingVCH: int
        ProcessUsingFTH: int
        ProcessPreviouslyThrottled: int
        ProcessCurrentlyThrottled: int
        ProcessImagesHotPatched: int
        ReservedBits0: int
        
        KernelCallbackTable: int # union with UserSharedInfoPtr
        UserSharedInfoPtr: int
        
        SystemReserved: int
        AtlThunkSListPtr32: int
        ApiSetMap: int
        TlsExpansionCounter: int
        TlsBitmap: int
        TlsBitmapBits: typing.List[int]
        ReadOnlySharedMemoryBase: int
        SharedData: int
        ReadOnlyStaticServerData: int
        AnsiCodePageData: int
        OemCodePageData: int
        UnicodeCaseTableData: int
        NumberOfProcessors: int
        NtGlobalFlag: int
        CriticalSectionTimeout: int
        HeapSegmentReserve: int
        HeapSegmentCommit: int
        HeapDeCommitTotalFreeThreshold: int
        HeapDeCommitFreeBlockThreshold: int
        NumberOfHeaps: int
        MaximumNumberOfHeaps: int
        ProcessHeaps: int
        GdiSharedHandleTable: int
        ProcessStarterHelper: int
        GdiDCAttributeList: typing.List[int]
        LoaderLock: int
        OSMajorVersion: int
        OSMinorVersion: int
        OSBuildNumber: int
        OSCSDVersion: int
        OSPlatformId: int
        ImageSubsystem: int
        ImageSubsystemMajorVersion: int
        ImageSubsystemMinorVersion: int
        ActiveProcessAffinityMask: int
        GdiHandleBuffer: int
        PostProcessInitRoutine: int
        TlsExpansionBitmap: int
        TlsExpansionBitmapBits: typing.List[int]
        
        SessionId: int
        AppCompatFlags: int
        AppCompatFlagsUser: int
        pShimData: int
        AppCompatInfo: int
        CSDVersion: typing.List[int] # Length, Maxlength, string ptr
        
        ActivationContextData: int
        ProcessAssemblyStorageMap: int
        SystemDefaultActivationContextData: int
        SystemAssemblyStorageMap: int
        MinimumStackCommit: int
        SparePointers: typing.List[int]
        
        PatchLoaderData: int
        ChpeV2ProcessInfo: int
        AppModelFeatureState: int
        SpareUlongs: typing.List[int]
        
        ActiveCodePage: int
        OemCodePage: int
        UseCaseMapping: int
        UnusedNlsField: int
        WerRegistrationData: int
        WerShipAssertPtr: int
        Spare: int
        pImageHeaderHash: int
        
        TracingFlags: int # contain HeapTracingEnabled to SpareTracingBits
        HeapTracingEnabled: int
        CritSecTracingEnabled: int
        LibLoaderTracingEnabled: int
        SpareTracingBits: int
        
        CsrServerReadOnlySharedMemoryBase: int
        TppWorkerpListLock: int
        TppWorkerpList: ListEntry
        
        WaitOnAddressHashTable: typing.List[int]
        
        TelemetryCoverageHeader: int
        CloudFileFlags: int
        CloudFileDiagFlags: int
        PlaceholderCompatibilityMode: int
        PlaceholderCompatibilityModeReserved: typing.List[int]
        
        LeapSecondData: int # contain LeapSecondFlags to Reserved
        LeapSecondFlags: int
        SixtySecondEnabled: int
        Reserved: int
        
        NtGlobalFlag2: int
        ExtendedFeatureDisableMask: int
        
        def __init__(self, peb_address):
            if context.arch == pykd.CPUType.I386:
                bytes_data: bytes = memoryaccess.get_bytes(peb_address, 0x484)
                
                self.InheritedAddressSpace = int.from_bytes(bytes_data[0x000:0x001], byteorder="little")
                self.ReadImageFileExecOptions = int.from_bytes(bytes_data[0x001:0x002], byteorder="little")
                self.BeingDebugged = int.from_bytes(bytes_data[0x002:0x003], byteorder="little")
                
                self.BitField = int.from_bytes(bytes_data[0x003:0x004], byteorder="little")
                self.ImageUsesLargePages = int.from_bytes(bytes_data[0x003:0x004], byteorder="little") & 0x1
                self.IsProtectedProcess = (int.from_bytes(bytes_data[0x003:0x004], byteorder="little") >> 1) & 0x1
                self.IsImageDynamicallyRelocated = (int.from_bytes(bytes_data[0x003:0x004], byteorder="little") >> 2) & 0x1
                self.SkipPatchingUser32Forwarders = (int.from_bytes(bytes_data[0x003:0x004], byteorder="little") >> 3) & 0x1
                self.IsPackagedProcess = (int.from_bytes(bytes_data[0x003:0x004], byteorder="little") >> 4) & 0x1
                self.IsAppContainer = (int.from_bytes(bytes_data[0x003:0x004], byteorder="little") >> 5) & 0x1
                self.IsProtectedProcessLight = (int.from_bytes(bytes_data[0x003:0x004], byteorder="little") >> 6) & 0x1
                self.IsLongPathAwareProcess = (int.from_bytes(bytes_data[0x003:0x004], byteorder="little") >> 7) & 0x1
                
                self.Mutant = int.from_bytes(bytes_data[0x004:0x008], byteorder="little")
                self.ImageBaseAddress = int.from_bytes(bytes_data[0x008:0x00c], byteorder="little")
                self.Ldr = int.from_bytes(bytes_data[0x00c:0x010], byteorder="little")
                self.ProcessParameters = int.from_bytes(bytes_data[0x010:0x0014], byteorder="little")
                self.SubSystemData = int.from_bytes(bytes_data[0x014:0x018], byteorder="little")
                self.ProcessHeap = int.from_bytes(bytes_data[0x018:0x01c], byteorder="little")
                self.FastPebLock = int.from_bytes(bytes_data[0x01c:0x020], byteorder="little")
                self.AtlThunkSListPtr = int.from_bytes(bytes_data[0x020:0x024], byteorder="little")
                self.IFEOKey = int.from_bytes(bytes_data[0x024:0x028], byteorder="little")
                self.CrossProcessFlags = int.from_bytes(bytes_data[0x028:0x02c], byteorder="little")
                self.ProcessInJob = (int.from_bytes(bytes_data[0x028:0x02c], byteorder="little")) & 0x1
                self.ProcessInitializing = (int.from_bytes(bytes_data[0x028:0x02c], byteorder="little") >> 1) & 0x1
                self.ProcessUsingVEH = (int.from_bytes(bytes_data[0x028:0x02c], byteorder="little") >> 2) & 0x1
                self.ProcessUsingVCH = (int.from_bytes(bytes_data[0x028:0x02c], byteorder="little") >> 3) & 0x1
                self.ProcessUsingFTH = (int.from_bytes(bytes_data[0x028:0x02c], byteorder="little") >> 4) & 0x1
                self.ProcessPreviouslyThrottled = (int.from_bytes(bytes_data[0x028:0x02c], byteorder="little") >> 5) & 0x1
                self.ProcessCurrentlyThrottled = (int.from_bytes(bytes_data[0x028:0x02c], byteorder="little") >> 6) & 0x1
                self.ProcessImagesHotPatched = (int.from_bytes(bytes_data[0x028:0x02c], byteorder="little") >> 7) & 0x1
                self.ReservedBits0 = (int.from_bytes(bytes_data[0x028:0x02c], byteorder="little") >> 8) & 0xffffff
                
                self.KernelCallbackTable = int.from_bytes(bytes_data[0x02c:0x030], byteorder="little")
                self.UserSharedInfoPtr = int.from_bytes(bytes_data[0x02c:0x030], byteorder="little")
                
                self.SystemReserved = int.from_bytes(bytes_data[0x030:0x034], byteorder="little")
                self.AtlThunkSListPtr32 = int.from_bytes(bytes_data[0x034:0x038], byteorder="little")
                self.ApiSetMap = int.from_bytes(bytes_data[0x038:0x03c], byteorder="little")
                self.TlsExpansionCounter = int.from_bytes(bytes_data[0x03c:0x040], byteorder="little")
                self.TlsBitmap = int.from_bytes(bytes_data[0x040:0x044], byteorder="little")
                
                self.TlsBitmapBits = []
                for i in range(0x044, 0x04c, 0x4):
                    self.TlsBitmapBits.append(int.from_bytes(bytes_data[i:i+4], byteorder="little"))
                
                self.ReadOnlySharedMemoryBase = int.from_bytes(bytes_data[0x04c:0x050], byteorder="little")
                self.SharedData = int.from_bytes(bytes_data[0x050:0x054], byteorder="little")
                self.ReadOnlyStaticServerData = int.from_bytes(bytes_data[0x054:0x058], byteorder="little")
                self.AnsiCodePageData = int.from_bytes(bytes_data[0x058:0x05c], byteorder="little")
                self.OemCodePageData = int.from_bytes(bytes_data[0x05c:0x060], byteorder="little")
                self.UnicodeCaseTableData = int.from_bytes(bytes_data[0x060:0x064], byteorder="little")
                self.NumberOfProcessors = int.from_bytes(bytes_data[0x064:0x068], byteorder="little")
                self.NtGlobalFlag = int.from_bytes(bytes_data[0x068:0x070], byteorder="little")
                self.CriticalSectionTimeout = int.from_bytes(bytes_data[0x070:0x078], byteorder="little")
                self.HeapSegmentReserve = int.from_bytes(bytes_data[0x078:0x07c], byteorder="little")
                
                self.HeapSegmentCommit = int.from_bytes(bytes_data[0x07c:0x080], byteorder="little")
                self.HeapDeCommitTotalFreeThreshold = int.from_bytes(bytes_data[0x080:0x084], byteorder="little")
                self.HeapDeCommitFreeBlockThreshold = int.from_bytes(bytes_data[0x084:0x088], byteorder="little")
                self.NumberOfHeaps = int.from_bytes(bytes_data[0x088:0x08c], byteorder="little")
                self.MaximumNumberOfHeaps = int.from_bytes(bytes_data[0x08c:0x090], byteorder="little")
                self.ProcessHeaps = int.from_bytes(bytes_data[0x090:0x094], byteorder="little")
                self.GdiSharedHandleTable = int.from_bytes(bytes_data[0x094:0x098], byteorder="little")
                self.ProcessStarterHelper = int.from_bytes(bytes_data[0x098:0x09c], byteorder="little")
                self.GdiDCAttributeList = int.from_bytes(bytes_data[0x09c:0x0a0], byteorder="little")
                self.LoaderLock = int.from_bytes(bytes_data[0x0a0:0x0a4], byteorder="little")
                self.OSMajorVersion = int.from_bytes(bytes_data[0x0a4:0x0a8], byteorder="little")
                self.OSMinorVersion = int.from_bytes(bytes_data[0x0a8:0x0ac], byteorder="little")
                self.OSBuildNumber = int.from_bytes(bytes_data[0x0ac:0x0ae], byteorder="little")
                self.OSCSDVersion = int.from_bytes(bytes_data[0x0ae:0x0b0], byteorder="little")
                self.OSPlatformId = int.from_bytes(bytes_data[0x0b0:0x0b4], byteorder="little")
                self.ImageSubsystem = int.from_bytes(bytes_data[0x0b4:0x0b8], byteorder="little")
                self.ImageSubsystemMajorVersion = int.from_bytes(bytes_data[0x0b8:0x0bc], byteorder="little")
                self.ImageSubsystemMinorVersion = int.from_bytes(bytes_data[0x0bc:0x0c0], byteorder="little")
                self.ActiveProcessAffinityMask = int.from_bytes(bytes_data[0x0c0:0x0c4], byteorder="little")
                
                self.GdiHandleBuffer = []
                for i in range(0x0c4, 0x14c, 0x4):
                    self.GdiHandleBuffer.append(int.from_bytes(bytes_data[i:i+4], byteorder="little"))
                
                self.PostProcessInitRoutine = int.from_bytes(bytes_data[0x14c:0x150], byteorder="little")
                self.TlsExpansionBitmap = int.from_bytes(bytes_data[0x150:0x154], byteorder="little")
                
                self.TlsExpansionBitmapBits = []
                for i in range(0x154, 0x1d4, 0x4):
                    self.TlsExpansionBitmapBits.append(int.from_bytes(bytes_data[i:i+4], byteorder="little"))
                    
                self.SessionId = int.from_bytes(bytes_data[0x1d4:0x1d8], byteorder="little")
                
                self.AppCompatFlags = int.from_bytes(bytes_data[0x1d8:0x1e0], byteorder="little")
                self.AppCompatFlagsUser = int.from_bytes(bytes_data[0x1e0:0x1e8], byteorder="little")
                
                self.pShimData = int.from_bytes(bytes_data[0x1e8:0x1ec], byteorder="little")
                self.AppCompatInfo = int.from_bytes(bytes_data[0x1ec:0x1f0], byteorder="little")
                
                self.CSDVersion = [ 
                                    int.from_bytes(bytes_data[0x1f0:0x1f2], byteorder="little"), \
                                    int.from_bytes(bytes_data[0x1f2:0x1f4], byteorder="little"), \
                                    int.from_bytes(bytes_data[0x1f4:0x1f8], byteorder="little")
                                  ]
                
                self.ActivationContextData = int.from_bytes(bytes_data[0x1f8:0x1fc], byteorder="little")
                self.ProcessAssemblyStorageMap = int.from_bytes(bytes_data[0x1fc:0x200], byteorder="little")
                self.SystemDefaultActivationContextData = int.from_bytes(bytes_data[0x200:0x204], byteorder="little")
                self.SystemAssemblyStorageMap = int.from_bytes(bytes_data[0x204:0x208], byteorder="little")
                self.MinimumStackCommit = int.from_bytes(bytes_data[0x208:0x20c], byteorder="little")
                
                self.SparePointers = []
                for i in range(0x20c, 0x214, 0x4):
                    self.SparePointers.append(int.from_bytes(bytes_data[i:i+4], byteorder="little"))

                self.PatchLoaderData = int.from_bytes(bytes_data[0x214:0x218], byteorder="little")
                self.ChpeV2ProcessInfo = int.from_bytes(bytes_data[0x218:0x21c], byteorder="little")
                self.AppModelFeatureState = int.from_bytes(bytes_data[0x21c:0x220], byteorder="little")
                
                self.SpareUlongs = []
                for i in range(0x220, 0x228, 0x4):
                    self.SpareUlongs.append(int.from_bytes(bytes_data[i:i+4], byteorder="little"))
                    
                self.ActiveCodePage = int.from_bytes(bytes_data[0x228:0x22a], byteorder="little")
                self.OemCodePage = int.from_bytes(bytes_data[0x22a:0x22c], byteorder="little")
                self.UseCaseMapping = int.from_bytes(bytes_data[0x22c:0x22e], byteorder="little")
                self.UnusedNlsField = int.from_bytes(bytes_data[0x22e:0x230], byteorder="little")
                self.WerRegistrationData = int.from_bytes(bytes_data[0x230:0x234], byteorder="little")
                self.WerShipAssertPtr = int.from_bytes(bytes_data[0x234:0x238], byteorder="little")
                self.Spare = int.from_bytes(bytes_data[0x238:0x23c], byteorder="little")
                self.pImageHeaderHash = int.from_bytes(bytes_data[0x23c:0x240], byteorder="little")
                
                self.TracingFlags = int.from_bytes(bytes_data[0x240:0x248], byteorder="little")
                self.HeapTracingEnabled = (int.from_bytes(bytes_data[0x240:0x248], byteorder="little")) & 0x1
                self.CritSecTracingEnabled = (int.from_bytes(bytes_data[0x240:0x248], byteorder="little") >> 1) & 0x1
                self.LibLoaderTracingEnabled = (int.from_bytes(bytes_data[0x240:0x248], byteorder="little") >> 2) & 0x1
                self.SpareTracingBits = (int.from_bytes(bytes_data[0x240:0x248], byteorder="little") >> 3)
                
                self.CsrServerReadOnlySharedMemoryBase = int.from_bytes(bytes_data[0x248:0x250], byteorder="little")
                self.TppWorkerpListLock = int.from_bytes(bytes_data[0x250:0x254], byteorder="little")
                self.TppWorkerpList = ListEntry(int.from_bytes(bytes_data[0x254:0x258], byteorder="little"), int.from_bytes(bytes_data[0x258:0x25c], byteorder="little"))
                
                self.WaitOnAddressHashTable = []
                for i in range(0x25c, 0x45c, 0x4):
                    self.WaitOnAddressHashTable.append(int.from_bytes(bytes_data[i:i+4], byteorder="little"))
                
                self.TelemetryCoverageHeader = int.from_bytes(bytes_data[0x45c:0x460], byteorder="little")
                self.CloudFileFlags = int.from_bytes(bytes_data[0x460:0x464], byteorder="little")
                self.CloudFileDiagFlags = int.from_bytes(bytes_data[0x464:0x468], byteorder="little")
                self.PlaceholderCompatibilityMode = int.from_bytes(bytes_data[0x468:0x469], byteorder="little")
                self.PlaceholderCompatibilityModeReserved = int.from_bytes(bytes_data[0x469:0x470], byteorder="little")
                self.LeapSecondData = int.from_bytes(bytes_data[0x470:0x474], byteorder="little")
                
                self.LeapSecondFlags = int.from_bytes(bytes_data[0x474:0x478], byteorder="little")
                self.SixtySecondEnabled = (int.from_bytes(bytes_data[0x474:0x478], byteorder="little")) & 0x1
                self.Reserved = (int.from_bytes(bytes_data[0x474:0x478], byteorder="little") >> 1)
                
                self.NtGlobalFlag2 = int.from_bytes(bytes_data[0x478:0x480], byteorder="little")
                self.ExtendedFeatureDisableMask = int.from_bytes(bytes_data[0x480:0x484], byteorder="little")
        
    def __init__(self):
        self.peb: self.PEBInfo
        
        self.getPEBInfo()
    
    def getPEBAddress(self) -> typing.Union[int, None]:
        try:
            pebinfo = pykd.dbgCommand("!peb")
            pebline = pebinfo.split("\n")[0]
            pebparts = pebline.split(" ")[2]
            return int(f"0x{pebparts}", 16)
        except:
            return None
    
    def getPEBInfo(self) -> None:
        self.peb: int = self.PEBInfo(self.getPEBAddress())
        
        return self.peb
        

class SEHInfo():
    Curr: int
    Next: int
    Handler: int
    
    def __init__(self, ptr):
        self.Curr: int = ptr
        self.Next: typing.Union[int, None] = None 
        self.Handler: typing.Union[int, None] = None
        
        self.Next = memoryaccess.deref_ptr(ptr, context.ptrmask)
        self.Handler = memoryaccess.deref_ptr(ptr + 4, context.ptrmask)

class SEH(TEB):
    def __init__(self):
        self.sehchain: typing.List[SEHInfo] = self.getSEHChain()
    
    def getSEHChain(self) -> typing.List[SEHInfo]:
        self.sehchain = []
        
        if context.arch != pykd.CPUType.I386:
            return self.sehchain
        
        tebaddress: int = self.getTEBAddress()
        if tebaddress is None:
            return self.sehchain
        
        currseh_ptr: int = memoryaccess.deref_ptr(tebaddress, context.ptrmask)
        if currseh_ptr == 0:
            return self.sehchain
        else:
            self.sehchain.append(SEHInfo(currseh_ptr))
        
        while True:
            self.sehchain.append(SEHInfo(self.sehchain[-1].Next))
            if self.sehchain[-1].Next == context.ptrmask or self.sehchain[-1].Next == None:
                break
        
        return self.sehchain
    
    def print_sehchain(self) -> None:
        self.sehchain = self.getSEHChain()
        self.exceptone: bool = True
        
        for sehinfo in self.sehchain:
            if self.exceptone:
                self.exceptone = False
            else:
                pykd.dprintln(f"     ↓")
                
            if sehinfo.Next is None:
                pykd.dprintln(f"0x{sehinfo.Curr:08x}: (chain is broken)")
                return
            else:
                if memoryaccess.get_symbol(sehinfo.Handler) is not None:
                    pykd.dprintln(f"0x{sehinfo.Curr:08x}: 0x{sehinfo.Next:08x} | 0x{sehinfo.Handler:08x} <{memoryaccess.get_symbol(sehinfo.Handler)}>")
                elif not pykd.isValid(sehinfo.Handler):
                    pykd.dprintln(f"0x{sehinfo.Curr:08x}: 0x{sehinfo.Next:08x} | 0x{sehinfo.Handler:08x} <invalid address>")
                else:
                    pykd.dprintln(f"0x{sehinfo.Curr:08x}: 0x{sehinfo.Next:08x} | 0x{sehinfo.Handler:08x}")
                if sehinfo.Next == context.ptrmask:
                    pykd.dprintln(f"     ↓\n(end of chain)")

class Heap(PEB):
    def __init__(self):
        self.heaps: typing.List[int] = self.get_heaps_address()
        pass

    def get_heaps_address(self) -> typing.List[int]:
        peb: PEB.PEBInfo = self.getPEBInfo()
        self.heaps = []
        
        for i in range(peb.NumberOfHeaps):
            self.heaps.append(memoryaccess.deref_ptr(peb.ProcessHeaps + i*4, context.ptrmask))
        return self.heaps
                

## register commands
cmd: CmdManager = CmdManager()

memoryaccess: MemoryAccess = MemoryAccess()
colour: ColourManager = ColourManager()
context: ContextManager = ContextManager()    

vmmap: Vmmap = Vmmap()
search: SearchPattern = SearchPattern()
seh: SEH = SEH()
heap: Heap = Heap()

if __name__ == "__main__":
    
    ## register commands
    cmd.alias("vmmap", "vmmap")
    
    cmd.alias("c", "c")
    cmd.alias("ni", "ni")
    cmd.alias("si", "si")
    cmd.alias("find", "find")
    cmd.alias("view", "view")
    cmd.alias("seh", "seh")
    
    if len(sys.argv) > 1:
        command=sys.argv[1]
        if command == 'vmmap':
            vmmap.print_vmmap()
        elif command == 'c':
            if len(sys.argv) == 2:
                context.conti()
            elif len(sys.argv) == 3:
                if sys.argv[2].startswith("0x"):
                    context.conti(int(sys.argv[2], 16))
                else:
                    context.conti(int(sys.argv[2]))
        elif command == 'ni':
            if len(sys.argv) == 2:
                context.ni()
            elif len(sys.argv) == 3:
                if sys.argv[2].startswith("0x"):
                    context.ni(int(sys.argv[2], 16))
                else:
                    context.ni(int(sys.argv[2]))
        elif command == 'si':
            if len(sys.argv) == 2:
                context.si()
            elif len(sys.argv) == 3:
                if sys.argv[2].startswith("0x"):
                    context.si(int(sys.argv[2], 16))
                else:
                    context.si(int(sys.argv[2]))
        elif command == 'view':
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
                pykd.dprintln("[-] Usage: seh [view, ...]")
            if len(sys.argv) == 6:
                if sys.argv[5] == "view":
                    seh.print_sehchain()
                elif sys.argv[5] == "?":
                    pykd.dprintln("[-] Usage: seh [view, ...]")