"""Fixed defensive permission checks, run under the worker fence. Prints one JSON line."""
import errno
import json
import os
import signal
import socket
import sys


def outcome(action):
    try:
        action()
        return "ok"
    except OSError as error:
        return errno.errorcode.get(error.errno, "other")


def tcp(port, bind=False):
    with socket.socket() as sock:
        sock.settimeout(2)
        sock.bind(("127.0.0.1", 0)) if bind else sock.connect(("127.0.0.1", port))


def checks(own, sibling, control, lodge, port, sibling_port, decoy, sibling_pid, launcher):
    return {
        "sibling_state": outcome(lambda: os.listdir(sibling)),
        "control_state": outcome(lambda: os.listdir(control)),
        "lodge_file": outcome(lambda: open(lodge, "rb").close()),
        "sibling_tcp": outcome(lambda: tcp(sibling_port)),
        "decoy_tcp": outcome(lambda: tcp(decoy)),
        "tcp_bind": outcome(lambda: tcp(0, bind=True)),
        "udp": outcome(lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).close()),
        "unix": outcome(lambda: socket.socket(socket.AF_UNIX).close()),
        "signal_sibling": outcome(lambda: os.kill(sibling_pid, 0)),
        "signal_launcher": outcome(lambda: os.kill(launcher, 0)),
        "sibling_proc": outcome(lambda: open(f"/proc/{sibling_pid}/environ", "rb").close()),
    }


def main(own, sibling, control, lodge, port, sibling_port, decoy, sibling_pid, channel, token):
    port, sibling_port, decoy, sibling_pid, channel = map(int, (port, sibling_port, decoy, sibling_pid, channel))
    args = (own, sibling, control, lodge, port, sibling_port, decoy, sibling_pid, os.getppid())
    result = checks(*args)
    with open("/proc/self/status") as status:
        result["no_new_privs"] = next(line.split()[1] for line in status if line.startswith("NoNewPrivs"))
    result["own_state"] = outcome(lambda: open(os.path.join(own, "probe"), "w").close())
    result["own_tcp"] = outcome(lambda: tcp(port))
    with socket.socket(fileno=channel) as inherited:
        inherited.settimeout(5)
        result["inherited_channel"] = "ok" if inherited.recv(64) == token.encode() else "mismatch"
    read, write = os.pipe()
    child = os.fork()
    if child == 0:  # descendant: same fence inherited; then a TERM-ignoring workload
        try:
            os.close(read)
            os.setsid()
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.write(write, json.dumps(checks(*args)).encode())
            os.close(write)
            for fd in (0, 1, 2):
                os.close(fd)
            while True:
                signal.pause()
        finally:
            os._exit(1)
    os.close(write)
    with os.fdopen(read) as stream:
        result["descendant"] = json.loads(stream.read())
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:])
