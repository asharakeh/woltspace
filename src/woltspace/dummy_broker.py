"""Protected dummy action core. No provider, credential migration or public API."""
import json
import threading
from pathlib import Path


def action(store: Path) -> dict:
    if not store.read_text():
        raise ValueError("dummy store unavailable")
    return {"result": "accepted"}


if __name__ == "__main__":
    import sys

    try:
        print(json.dumps(action(Path(sys.argv[1]))), flush=True)
        threading.Event().wait()
    except (OSError, ValueError):
        sys.exit(1)  # never print the store or exception text
