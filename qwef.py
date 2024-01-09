import os
import sys
import pykd
import enum
import typing

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
    
    
class ContextManager():
    
    def __init__(self):
        self.arch = pykd.getCPUMode()
        self.regs : typing.Union[Amd64Register, I386Register]
        self.segregs : SegmentRegister = SegmentRegister()
        self.eflags : EflagsRegister = EflagsRegister()
        self.ptrmask: int = 0xffffffffffffffff if self.arch == pykd.CPUType.AMD64 else 0xffffffff
        
        self.color = ColourManager()
        self.vmmap = Vmmap()
        
        self.segments_info: typing.List[SectionInfo] = self.vmmap.dump_section()
        
        if self.arch == pykd.CPUType.AMD64:
            self.regs = Amd64Register()
        elif self.arch == pykd.CPUType.I386:
            self.regs = I386Register()
        else:
            raise Exception("Unsupported CPU mode")
        
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
        self.segments_info = self.vmmap.dump_section()
        
    def print_context(self):
        self.update_regs()
        self.update_eflags()
        self.update_vmmap()
        
        pykd.dprintln(self.color.blue("--------------------------------------------------------- registers ---------------------------------------------------------"), dml=True)
        self.print_regs()
        pykd.dprintln(self.color.blue("---------------------------------------------------------   codes   ---------------------------------------------------------"), dml=True)
        self.print_code()
        pykd.dprintln(self.color.blue("---------------------------------------------------------   stack   ---------------------------------------------------------"), dml=True)
        self.print_stack()
        
    def deref_ptr(self, ptr) -> typing.Union[int, None]:
        try:
            return pykd.loadPtrs(ptr, 1)[0] & self.ptrmask
        except pykd.MemoryException:
            return None
        
    def get_string(self, ptr) -> typing.Union[str, None]:
        try:
            return pykd.loadCStr(ptr)
        except pykd.MemoryException:
            return None
        except UnicodeDecodeError:
            return None
        
    def get_symbol(self, ptr) -> typing.Union[str, None]:
        try:
            val = pykd.findSymbol(ptr)
            if val == hex(ptr)[2:]:
                return None
            else:
                return val
        except pykd.MemoryException:
            return None
    
    def colorize_print_by_priv(self, value) -> None:
        for section in self.segments_info:
            if section.base_address <= value <= section.end_address:
                if section.usage == "Stack":
                    pykd.dprint(self.color.purple(f" 0x{value:016x}"), dml=True)
                elif section.protect & (
                        PageProtect.PAGE_EXECUTE \
                        | PageProtect.PAGE_EXECUTE_READ \
                        | PageProtect.PAGE_EXECUTE_READWRITE \
                        | PageProtect.PAGE_EXECUTE_WRITECOPY
                    ):
                    pykd.dprint(self.color.red(f" 0x{value:016x}"), dml=True)
                elif section.protect & (
                        PageProtect.PAGE_READWRITE \
                        | PageProtect.PAGE_WRITECOPY
                    ):
                    pykd.dprint(self.color.green(f" 0x{value:016x}"), dml=True)
                else:
                    pykd.dprint(self.color.white(f" 0x{value:016x}"), dml=True)
                return
        pykd.dprint(self.color.white(f" 0x{value:016x}"), dml=True)
    
    def deep_print(self, value: int, remain: int, xref: int = 0) -> None:
        printst: str = ""
        self.colorize_print_by_priv(value)
        if pykd.findSymbol(value) != hex(value)[2:]:
            pykd.dprint(f" <{self.color.white(pykd.findSymbol(value))}>", dml=True)
            
        if pykd.isValid(value):
            if remain == 0:
                pykd.dprintln("")
                return
            else:
                pykd.dprint(" ->", dml=True)
                self.deep_print(self.deref_ptr(value), remain - 1, value)
                return
        elif pykd.isValid(xref):
            value: typing.Union[str, None] = self.get_string(xref)
            if value is None:
                pykd.dprintln("")
                return

            if len(value):
                pykd.dprintln(f'("{self.color.white(value)}")', dml=True)
                return
            else:
                pykd.dprintln("")
                return
        else:
            pykd.dprintln("")
            return
    
    def print_general_regs(self) -> None:
        for reg, vaule in asdict(self.regs).items():
            pykd.dprint(self.color.red(f"{reg:4}"), dml=True)
            pykd.dprint(f": ")
            self.deep_print(vaule, 5)
            
    def print_seg_regs(self) -> None:
        for reg, vaule in asdict(self.segregs).items():
            pykd.dprint(f"{reg:2} = 0x{vaule:02x} ")
        pykd.dprintln("")
    
    def print_eflags(self) -> None:
        
        for reg, vaule in asdict(self.eflags).items():
            if vaule:
                pykd.dprint(f"{self.color.green(str(EflagsEnum[reg]))} ", dml=True)
            else:
                pykd.dprint(f"{self.color.red(str(EflagsEnum[reg]))} ", dml=True)
        pykd.dprintln("")
        
    def disasm(self, addr) -> typing.Tuple[str, str]:
        """ disassemble, return opcodes and assembly string """
        resp = pykd.disasm().disasm(addr).split(" ")
        op_str = resp[1]
        asm_str = ' '.join(c for c in resp[2::]).strip()
        return op_str, asm_str

    def print_code_by_address(self, pc: int, tab: str, print_range: int) -> None:

        for _ in range(print_range):
            op_str, asm_str = self.disasm(pc)
            sym: str = self.get_symbol(pc)
            debug_info: str = ""
            if sym is not None:
                debug_info: str = f" <{sym}> "
            code_str = f"{pc:#x}: {op_str:25s}{debug_info:20s}{asm_str}"
            pykd.dprintln(self.color.white(f"{tab}{code_str}"), dml=True)
            
            pc += len(op_str) // 2
            
            if asm_str.startswith("ret"):
                return
            
    def print_code(self) -> None:
        pc = self.regs.rip if self.arch == pykd.CPUType.AMD64 else self.regs.eip
        for offset in range(-3, 6):
            addr = pykd.disasm().findOffset(offset)
            op_str, asm_str = self.disasm(addr)
            sym: str = self.get_symbol(addr)
            debug_info: str = ""
            if sym is not None:
                debug_info: str = f" <{sym}> "
            code_str = f"{addr:#x}: {op_str:25s}{debug_info:20s}{asm_str}"
            if addr == pc:
                pykd.dprintln(self.color.bold_white(f"-> {code_str}"), dml=True)
                
                if asm_str.startswith("ret"):
                    num: int 
                    try:
                        if asm_str.split(" ")[1].endswith("h"):
                            num = int(f"0x{asm_str.split(' ')[1][:-1]}", 16)
                        else:
                            num = int(asm_str.split(" ")[1])
                    except:
                        num = 0
                    goto: int = self.deref_ptr(self.regs.rsp + num * (8 if self.arch == pykd.CPUType.AMD64 else 4))
                    
                    if goto is not None:
                        self.print_code_by_address(goto, " "*8, 4)
            else:
                pykd.dprintln(self.color.white(f"   {code_str}"), dml=True)
                
    def print_stack(self) -> None:
        sp = self.regs.rsp if self.arch == pykd.CPUType.AMD64 else self.regs.esp
        
        if self.arch == pykd.CPUType.I386:
            for offset in range(4):
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
    
    def conti(self) -> None:
        pykd.dbgCommand("g")
        self.print_context()
    
    def ni(self) -> None:
        pykd.dbgCommand("p")
        self.print_context()
        pykd.dbgCommand("ni")
    
    def si(self) -> None:
        pykd.dbgCommand("t")
        self.print_context()
        
class PageState(enum.IntEnum):
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_FREE = 0x10000
    
    def __str__(self) -> str:
        return self.name
    
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

class PageType(enum.IntEnum):
    MEM_IMAGE = 0x1000000
    MEM_MAPPED = 0x40000
    MEM_PRIVATE = 0x20000
    
    def __str__(self) -> str:
        return self.name
    
@dataclass
class SectionInfo:
    usage: str
    base_address: int
    end_address: int
    size: int
    image_path: str
    mapped_file_name: str
    state: PageState
    protect: PageProtect
    type: PageType
    
    def __init__(self):
        self.usage: str = ""
        self.base_address: int = -1
        self.end_address: int = -1
        self.size: int = -1
        self.image_path: str = ""
        self.mapped_file_name: str = ""
        self.state: PageState = PageState.MEM_FREE
        self.protect: PageProtect = PageProtect.PAGE_NOACCESS
        self.type: PageType = PageType.MEM_PRIVATE

class Vmmap():
    
    def __init__(self):
        self.color = ColourManager()
    
    def vmmap(self):
        section_info: list = []
        for section in pykd.dbgCommand("!vadump").split("\n\n"):
            base_address: int = -1
            end_address: int = -1
            for line_info in section.split("\n"):
                if line_info.startswith("BaseAddress"):
                    base_address = int(f"0x{line_info.split(':')[1].strip()}", 16)
                elif line_info.startswith("RegionSize"):
                    end_address = base_address + int(f"0x{line_info.split(':')[1].strip()}", 16)
            if base_address == -1 or end_address == -1:
                continue
            else:
                section_info.append({
                    "base_address": base_address,
                    "end_address": end_address,
                    "size": end_address - base_address,
                })

        return section_info
    
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
                section_info.mapped_file_name = line.split("name:")[1].strip().split(" ")[0]
            
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
            
            color: function = self.color.white
            
            if section_info.state & PageState.MEM_FREE:
                color = self.color.gray
                state_info += 'free'
            elif section_info.state & PageState.MEM_RESERVE:
                color = self.color.gray
                state_info += 'reserve'
            elif section_info.state & PageState.MEM_COMMIT:
                state_info += 'commit'
                if section_info.protect & (
                        PageProtect.PAGE_EXECUTE \
                        | PageProtect.PAGE_EXECUTE_READ \
                        | PageProtect.PAGE_EXECUTE_READWRITE \
                        | PageProtect.PAGE_EXECUTE_WRITECOPY
                    ):
                    color = self.color.red
                    
                    if section_info.protect & PageProtect.PAGE_EXECUTE_READWRITE:
                        priv_info = 'rwx'
                    
                    elif section_info.protect & PageProtect.PAGE_EXECUTE_WRITECOPY:
                        priv_info = 'cwx'
                        
                    elif section_info.protect & PageProtect.PAGE_EXECUTE_READ:
                        priv_info = 'r-x'
                    
                    elif section_info.protect & PageProtect.PAGE_EXECUTE:
                        priv_info = 'r--'
                    
                elif section_info.protect & (
                        PageProtect.PAGE_READWRITE \
                        | PageProtect.PAGE_WRITECOPY
                    ):
                    color = self.color.green
                    
                    if section_info.protect & PageProtect.PAGE_READWRITE:
                        priv_info = 'rw-'
                    
                    elif section_info.protect & PageProtect.PAGE_WRITECOPY:
                        priv_info = 'cw-'
                    
                elif section_info.protect & PageProtect.PAGE_READONLY:
                    color = self.color.white
                    
                    priv_info = 'r--'
                    
                else:
                    color = self.color.gray
                    
                    priv_info = '---'
            
                if section_info.protect & PageProtect.PAGE_GUARD:
                    color = self.color.gray
                    guard_info += '(g)'
            
            if section_info.type & PageType.MEM_MAPPED:
                type_info += 's'
            elif section_info.type & PageType.MEM_PRIVATE:
                type_info += 'p'
            elif section_info.type & PageType.MEM_IMAGE:
                type_info += 'i'
                if section_info.image_path != "":
                    path_info = section_info.image_path
            
            if section_info.mapped_file_name == "MappedFile":
                path_info = section_info.mapped_file_name
            elif path_info == "":
                path_info = section_info.usage

            printst: str = ""
            if state_info == "commit":
                printst = f"{addr_info} {state_info:11} {priv_info}{type_info}{guard_info}"
            elif state_info == "free" or state_info == "reserve":
                printst = f"{addr_info} {state_info:11} {state_info}"
            
            if level == 0 and color != self.color.gray:
                pykd.dprint(color(printst), dml=True)
                pykd.dprintln(f" {path_info}")
            elif level == 1:
                pykd.dprint(color(printst), dml=True)
                pykd.dprintln(f" {path_info}")

## register commands
# cmd.register("vmmap", "vmmap.print_vmmap")  
if __name__ == "__main__":
    
    cmd = CmdManager()
    context = ContextManager()       
    vmmap = Vmmap() 
    
    ## register commands
    cmd.alias("vmmap", "vmmap")
    
    cmd.alias("c", "c")
    cmd.alias("ni", "ni")
    cmd.alias("si", "si")
    
    if len(sys.argv) == 2:
        command=sys.argv[1]
        if command == 'vmmap':
            vmmap.print_vmmap()
        elif command == 'c':
            context.conti()
        elif command == 'ni':
            context.ni()
        elif command == 'si':
            context.si()
            