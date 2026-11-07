"""Process memory scanner/editor for single-player games (Cheat Engine style, interactive).

Backends
  darwin : mach_vm_* via ctypes (macOS, Apple Silicon or Intel). Run with sudo. The target must
           not be SIP/hardened-runtime protected (Apple apps and most App Store builds refuse
           task_for_pid; unsigned or get-task-allow builds, Unity/Godot dev builds, and games
           run under Whisky/CrossOver's wine processes generally work).
  linux  : /proc/<pid>/mem (used for testing this tool; also handy on Linux/Proton).

Use it on single-player games. Editing memory of online games can get your account banned.
"""
import ctypes
import os
import platform
import shlex
import struct
import subprocess
import sys
import threading
from typing import Dict, Iterator, Optional, Tuple

from .common import ToolError

TYPES = {"i8": "b", "u8": "B", "i16": "h", "u16": "H", "i32": "i", "u32": "I",
         "i64": "q", "u64": "Q", "f32": "f", "f64": "d"}
CHUNK = 4 * 1024 * 1024
PAGE = 16384


def parse_value(vtype, text):
    fmt = "<" + TYPES[vtype]
    try:
        value = float(text) if vtype.startswith("f") else int(text, 0)
        return struct.unpack(fmt, struct.pack(fmt, value))[0]  # normalise (f32 rounding etc.)
    except (ValueError, struct.error, OverflowError) as e:
        raise ToolError(f"{text!r} is not a valid {vtype}: {e}")


# ------------------------------------------------------------------------ backends
class LinuxBackend:
    def __init__(self, pid):
        self.pid = pid
        try:
            self.fd = os.open(f"/proc/{pid}/mem", os.O_RDWR)
        except OSError as e:
            raise ToolError(f"cannot open process {pid}: {e} (run as root / adjust ptrace_scope)")

    def regions(self) -> Iterator[Tuple[int, int]]:
        with open(f"/proc/{self.pid}/maps") as f:
            for line in f:
                rng, perms = line.split(None, 2)[:2]
                if perms[0] == "r" and perms[1] == "w":
                    a, b = rng.split("-")
                    yield int(a, 16), int(b, 16)

    def read(self, addr: int, size: int) -> Optional[bytes]:
        try:
            data = os.pread(self.fd, size, addr)
        except OSError:
            return None
        return data if len(data) == size else (data or None)

    def write(self, addr: int, data: bytes) -> None:
        try:
            os.pwrite(self.fd, data, addr)
        except OSError as e:
            raise ToolError(f"write to {addr:#x} failed: {e}")


class DarwinBackend:
    VM_REGION_BASIC_INFO_64 = 9
    PROT_R, PROT_W, PROT_COPY = 1, 2, 16

    class _RegionInfo(ctypes.Structure):
        _pack_ = 4  # vm_region_basic_info_data_64_t is declared under #pragma pack(4)
        _fields_ = [("protection", ctypes.c_int), ("max_protection", ctypes.c_int),
                    ("inheritance", ctypes.c_uint), ("shared", ctypes.c_uint),
                    ("reserved", ctypes.c_uint), ("offset", ctypes.c_uint64),
                    ("behavior", ctypes.c_int), ("user_wired_count", ctypes.c_ushort)]

    def __init__(self, pid):
        if platform.system() != "Darwin":
            raise ToolError("the darwin backend only works on macOS")
        c = ctypes
        lib = self.lib = c.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        lib.task_for_pid.argtypes = [c.c_uint32, c.c_int, c.POINTER(c.c_uint32)]
        lib.mach_vm_region.argtypes = [c.c_uint32, c.POINTER(c.c_uint64), c.POINTER(c.c_uint64),
                                       c.c_int, c.c_void_p, c.POINTER(c.c_uint32),
                                       c.POINTER(c.c_uint32)]
        lib.mach_vm_read_overwrite.argtypes = [c.c_uint32, c.c_uint64, c.c_uint64, c.c_void_p,
                                               c.POINTER(c.c_uint64)]
        lib.mach_vm_write.argtypes = [c.c_uint32, c.c_uint64, c.c_void_p, c.c_uint32]
        lib.mach_vm_protect.argtypes = [c.c_uint32, c.c_uint64, c.c_uint64, c.c_int, c.c_int]
        for fn in (lib.task_for_pid, lib.mach_vm_region, lib.mach_vm_read_overwrite,
                   lib.mach_vm_write, lib.mach_vm_protect):
            fn.restype = c.c_int
        me = c.c_uint32.in_dll(lib, "mach_task_self_").value
        self.task = c.c_uint32(0)
        kr = lib.task_for_pid(me, pid, c.byref(self.task))
        if kr != 0:
            raise ToolError(
                f"task_for_pid({pid}) failed (kern_return {kr}). Run with sudo, and note that "
                "SIP/hardened-runtime apps cannot be attached."
            )

    def regions(self) -> Iterator[Tuple[int, int]]:
        c = ctypes
        addr = c.c_uint64(0)
        while True:
            size = c.c_uint64(0)
            info = self._RegionInfo()
            count = c.c_uint32(c.sizeof(info) // 4)
            obj = c.c_uint32(0)
            kr = self.lib.mach_vm_region(self.task, c.byref(addr), c.byref(size),
                                         self.VM_REGION_BASIC_INFO_64, c.byref(info),
                                         c.byref(count), c.byref(obj))
            if kr != 0:
                return
            if info.protection & self.PROT_R and info.protection & self.PROT_W:
                yield addr.value, addr.value + size.value
            addr = c.c_uint64(addr.value + size.value)

    def read(self, addr: int, size: int) -> Optional[bytes]:
        buf = ctypes.create_string_buffer(size)
        out = ctypes.c_uint64(0)
        kr = self.lib.mach_vm_read_overwrite(self.task, addr, size, buf, ctypes.byref(out))
        return buf.raw[:out.value] if kr == 0 else None

    def write(self, addr: int, data: bytes) -> None:
        buf = ctypes.create_string_buffer(data, len(data))
        if self.lib.mach_vm_write(self.task, addr, buf, len(data)) == 0:
            return
        # page may be copy-on-write / read-only: widen protection once and retry
        self.lib.mach_vm_protect(self.task, addr, len(data), 0,
                                 self.PROT_R | self.PROT_W | self.PROT_COPY)
        kr = self.lib.mach_vm_write(self.task, addr, buf, len(data))
        if kr != 0:
            raise ToolError(f"mach_vm_write at {addr:#x} failed (kern_return {kr})")


def make_backend(pid, name="auto"):
    if name == "auto":
        name = "darwin" if platform.system() == "Darwin" else "linux"
    return (DarwinBackend if name == "darwin" else LinuxBackend)(pid)


# ------------------------------------------------------------------------- session
class Session:
    def __init__(self, backend):
        self.backend = backend
        self.vtype = "i32"
        self.candidates: Dict[int, float] = {}
        self._freezers: Dict[int, threading.Event] = {}

    # reading ---------------------------------------------------------------
    def _read_range(self, start, length):
        data = self.backend.read(start, length)
        if data is not None and len(data) == length:
            return data
        # a hole inside the region: fall back to page-sized reads
        out = bytearray()
        for off in range(0, length, PAGE):
            part = self.backend.read(start + off, min(PAGE, length - off))
            out += part if part and len(part) == min(PAGE, length - off) else b"\0" * min(PAGE, length - off)
        return bytes(out)

    def read_value(self, addr, vtype=None):
        vtype = vtype or self.vtype
        fmt = "<" + TYPES[vtype]
        data = self.backend.read(addr, struct.calcsize(fmt))
        if data is None or len(data) != struct.calcsize(fmt):
            return None
        return struct.unpack(fmt, data)[0]

    # scanning --------------------------------------------------------------
    def first_scan(self, vtype, value):
        self.vtype = vtype
        fmt = "<" + TYPES[vtype]
        size = struct.calcsize(fmt)
        needle = struct.pack(fmt, value)
        found: Dict[int, float] = {}
        for start, end in self.backend.regions():
            pos = start
            while pos < end:
                n = min(CHUNK + size - 1, end - pos)
                data = self._read_range(pos, n)
                i = data.find(needle)
                while i != -1:
                    addr = pos + i
                    if addr % size == 0:
                        found[addr] = value
                    i = data.find(needle, i + 1)
                pos += CHUNK
        self.candidates = found
        return len(found)

    def next_scan(self, mode, value=None):
        if not self.candidates:
            raise ToolError("no candidates; run `scan <type> <value>` first")
        keep: Dict[int, float] = {}
        for addr, old in self.candidates.items():
            cur = self.read_value(addr)
            if cur is None:
                continue
            ok = {
                "eq": cur == value,
                "changed": cur != old,
                "unchanged": cur == old,
                "inc": cur > old,
                "dec": cur < old,
            }[mode]
            if ok:
                keep[addr] = cur
        self.candidates = keep
        return len(keep)

    # writing / freezing ----------------------------------------------------
    def write_value(self, addr, value, vtype=None):
        self.backend.write(addr, struct.pack("<" + TYPES[vtype or self.vtype], value))

    def freeze(self, addr, value, interval=0.05):
        self.unfreeze(addr)
        stop = threading.Event()
        data = struct.pack("<" + TYPES[self.vtype], value)

        def loop():
            while not stop.wait(interval):
                try:
                    self.backend.write(addr, data)
                except ToolError:
                    return

        threading.Thread(target=loop, daemon=True).start()
        self._freezers[addr] = stop

    def unfreeze(self, addr=None):
        for a in ([addr] if addr is not None else list(self._freezers)):
            ev = self._freezers.pop(a, None)
            if ev:
                ev.set()


# ---------------------------------------------------------------------------- CLI
def list_processes(filter_text=None):
    out = subprocess.run(["ps", "-axo", "pid=,comm="], capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        pid, _, comm = line.strip().partition(" ")
        if pid.isdigit() and (not filter_text or filter_text.lower() in comm.lower()):
            rows.append((int(pid), comm.strip()))
    return rows


def resolve_pid(target):
    if target.isdigit():
        return int(target)
    matches = list_processes(target)
    if len(matches) != 1:
        listing = "\n".join(f"  {p}  {n}" for p, n in matches[:10]) or "  (none)"
        more = f"\n  ... and {len(matches) - 10} more" if len(matches) > 10 else ""
        raise ToolError(f"{len(matches)} processes match {target!r}; use a PID:\n{listing}{more}")
    return matches[0][0]


HELP = """\
scan <type> <value>     first scan (types: i8 u8 i16 u16 i32 u32 i64 u64 f32 f64)
next <value>            keep addresses that now equal <value>
next changed|unchanged|inc|dec
list [n]                show first n candidates (default 20)
read <addr|#i> [type]   read a value
write <addr|#i> <value> write a value (#i = index shown by `list`)
freeze <addr|#i> <value> keep writing a value (50 ms); `unfreeze [addr|#i]`
reset                   forget candidates
quit"""


def _addr(session, token):
    if token.startswith("#"):
        keys = sorted(session.candidates)
        try:
            return keys[int(token[1:])]
        except (ValueError, IndexError):
            raise ToolError(f"no candidate {token}")
    try:
        return int(token, 0)
    except ValueError:
        raise ToolError(f"bad address {token!r}")


def run_command(session, line):
    """Execute one REPL line. Returns False to quit."""
    parts = shlex.split(line)
    if not parts:
        return True
    cmd, rest = parts[0].lower(), parts[1:]
    if cmd in ("quit", "exit", "q"):
        return False
    if cmd == "help":
        print(HELP)
    elif cmd == "scan":
        if len(rest) != 2 or rest[0] not in TYPES:
            raise ToolError("usage: scan <type> <value>")
        n = session.first_scan(rest[0], parse_value(rest[0], rest[1]))
        print(f"{n} candidate(s)")
    elif cmd == "next":
        if len(rest) != 1:
            raise ToolError("usage: next <value|changed|unchanged|inc|dec>")
        if rest[0] in ("changed", "unchanged", "inc", "dec"):
            n = session.next_scan(rest[0])
        else:
            n = session.next_scan("eq", parse_value(session.vtype, rest[0]))
        print(f"{n} candidate(s)")
    elif cmd == "list":
        limit = int(rest[0]) if rest else 20
        for i, addr in enumerate(sorted(session.candidates)[:limit]):
            print(f"#{i:<4} {addr:#016x}  {session.candidates[addr]}")
    elif cmd == "read":
        addr = _addr(session, rest[0])
        value = session.read_value(addr, rest[1] if len(rest) > 1 else None)
        print("unreadable" if value is None else value)
    elif cmd == "write":
        if len(rest) != 2:
            raise ToolError("usage: write <addr|#i> <value>")
        session.write_value(_addr(session, rest[0]), parse_value(session.vtype, rest[1]))
        print("ok")
    elif cmd == "freeze":
        if len(rest) != 2:
            raise ToolError("usage: freeze <addr|#i> <value>")
        session.freeze(_addr(session, rest[0]), parse_value(session.vtype, rest[1]))
        print("frozen")
    elif cmd == "unfreeze":
        session.unfreeze(_addr(session, rest[0]) if rest else None)
        print("ok")
    elif cmd == "reset":
        session.candidates = {}
        print("cleared")
    else:
        raise ToolError(f"unknown command {cmd!r}; type `help`")
    return True


def cmd_ps(args):
    for pid, name in list_processes(args.filter):
        print(f"{pid:>7}  {name}")


def cmd_attach(args):
    pid = resolve_pid(args.target)
    session = Session(make_backend(pid, args.backend))
    print(f"attached to pid {pid}. type `help` for commands.")
    while True:
        try:
            line = input("mem> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        try:
            if not run_command(session, line):
                break
        except ToolError as e:
            print(f"error: {e}")
    session.unfreeze()


def register(sub):
    mem = sub.add_parser("mem", help="process memory scanner/editor (single-player games)")
    msub = mem.add_subparsers(dest="mem_cmd", metavar="<action>", required=True)
    p = msub.add_parser("ps", help="list running processes")
    p.add_argument("filter", nargs="?")
    p.set_defaults(func=cmd_ps)
    p = msub.add_parser("attach", help="interactive scan/edit session on a PID or unique name")
    p.add_argument("target", help="PID or process-name substring")
    p.add_argument("--backend", choices=["auto", "darwin", "linux"], default="auto")
    p.set_defaults(func=cmd_attach)
