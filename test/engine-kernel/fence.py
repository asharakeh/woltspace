"""Landlock (ABI >= 6) + no_new_privs + seccomp socket fence, applied before exec."""
import ctypes as C
import errno
import os
from pathlib import Path
import platform
import sys

LIB = C.CDLL(None, use_errno=True)
CREATE, ADD, RESTRICT = 444, 445, 446  # x86_64 and aarch64
EXECUTE, WRITE, READ_FILE, READ_DIR = 1, 2, 4, 8
READ = EXECUTE | READ_FILE | READ_DIR
FILE_ONLY = EXECUTE | WRITE | READ_FILE | (1 << 14) | (1 << 15)  # + truncate, ioctl_dev
CONNECT_TCP, SCOPES = 2, 3  # net: bind 1 | connect 2; scopes: abstract unix 1 | signal 2


class Ruleset(C.Structure):
    _fields_ = [("fs", C.c_uint64), ("net", C.c_uint64), ("scoped", C.c_uint64)]


class Beneath(C.Structure):
    _pack_ = 1
    _fields_ = [("access", C.c_uint64), ("fd", C.c_int32)]


class Port(C.Structure):
    _pack_ = 1
    _fields_ = [("access", C.c_uint64), ("port", C.c_uint64)]


class Filter(C.Structure):
    _fields_ = [("code", C.c_uint16), ("jt", C.c_uint8), ("jf", C.c_uint8), ("k", C.c_uint32)]


class Program(C.Structure):
    _fields_ = [("len", C.c_uint16), ("filter", C.POINTER(Filter))]


def checked(value):
    if value < 0:
        number = C.get_errno()
        raise OSError(number, os.strerror(number))
    return value


def abi():
    assert platform.machine() == "x86_64", "seccomp table is x86_64 only"
    return checked(LIB.syscall(CREATE, None, 0, 1))


# socket() only for AF_INET/AF_INET6, SOCK_STREAM, protocol 0 or IPPROTO_TCP;
# io_uring_setup, foreign arch, x32 -> EPERM.
SECCOMP = [(0x20, 0, 0, 4), (0x15, 0, 14, 0xC000003E), (0x20, 0, 0, 0),
           (0x35, 12, 0, 0x40000000), (0x15, 11, 0, 425), (0x15, 0, 9, 41),
           (0x20, 0, 0, 16), (0x15, 1, 0, 2), (0x15, 0, 7, 10),
           (0x20, 0, 0, 24), (0x54, 0, 0, 0xF), (0x15, 0, 4, 1),
           (0x20, 0, 0, 32), (0x15, 1, 0, 0), (0x15, 0, 1, 6),
           (0x06, 0, 0, 0x7FFF0000), (0x06, 0, 0, 0x00050000 | errno.EPERM)]


def fence(own, port, reads=()):
    """Own dir read/write (no exec), system and `reads` read/exec, TCP connect to `port` only."""
    version = abi()
    assert version >= 6, "landlock abi below 6"
    rights = (1 << 16) - 1
    attrs = Ruleset(rights, 3, SCOPES)
    rules = checked(LIB.syscall(CREATE, C.byref(attrs), C.sizeof(attrs), 0))
    try:
        grants = [(Path(own), rights & ~EXECUTE), (Path("/dev/null"), READ_FILE | WRITE),
                  (Path("/proc"), READ), (Path(sys.base_prefix), READ)]
        grants += [(Path(p), READ) for p in ("/usr", "/bin", "/lib", "/lib64", "/etc/ssl/openssl.cnf")
                   if Path(p).exists()]
        grants += [(Path(p), READ) for p in reads]
        for path, access in grants:
            if not path.is_dir():
                access &= FILE_ONLY
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                checked(LIB.syscall(ADD, rules, 1, C.byref(Beneath(access, fd)), 0))
            finally:
                os.close(fd)
        checked(LIB.syscall(ADD, rules, 2, C.byref(Port(CONNECT_TCP, port)), 0))
        checked(LIB.prctl(38, 1, 0, 0, 0))  # PR_SET_NO_NEW_PRIVS
        checked(LIB.syscall(RESTRICT, rules, 0))
    finally:
        os.close(rules)
    table = (Filter * len(SECCOMP))(*[Filter(*row) for row in SECCOMP])
    checked(LIB.prctl(22, 2, C.byref(Program(len(SECCOMP), table)), 0, 0))
    return version
