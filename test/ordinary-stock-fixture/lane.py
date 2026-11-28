"""Exact process identity and pidfd signalling from the hosted kernel fixture."""
import os
import signal


def ident(pid):
    """(ppid, start time) of a live process (any task not a zombie), else None."""
    try:
        with open(f"/proc/{pid}/stat") as stat:
            fields = stat.read().rsplit(")", 1)[1].split()
    except OSError:
        return None
    if fields[0] == "Z":  # an exited leader: the process lives while any of its tasks does
        try:
            tasks = os.listdir(f"/proc/{pid}/task")
        except OSError:
            return None
        if not any(_state(f"/proc/{pid}/task/{task}/stat") not in (None, "Z", "X") for task in tasks):
            return None
    return int(fields[1]), fields[19]


def _state(path):
    try:
        with open(path) as stat:
            return stat.read().rsplit(")", 1)[1].split()[0]
    except OSError:
        return None


def born(pid):
    return (ident(pid) or (0, None))[1]


def tree(root):
    """{pid: start} of live descendants of root, by a full /proc parent walk."""
    rows = {int(entry): row for entry in filter(str.isdigit, os.listdir("/proc")) if (row := ident(entry))}
    found, frontier = {}, {root}
    while frontier:
        frontier = {pid for pid, (ppid, _) in rows.items() if ppid in frontier and pid not in found}
        found.update({pid: rows[pid][1] for pid in frontier})
    return found


def owned_signal(pid, start, sig):
    """Signal only through a pidfd whose process still has the recorded start time."""
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return False
    try:
        if start is None or born(pid) != start:
            return False
        signal.pidfd_send_signal(fd, sig)
        return True
    except ProcessLookupError:
        return False
    finally:
        os.close(fd)
