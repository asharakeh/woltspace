"""The image installs woltspace on a uv-managed CPython, never on Debian's.

Debian's python3 (3.11.2) lacks tarfile's `filter=` (3.11.4+), so `woltspace
restore` crashed inside a container lodge. Nobody builds the image in CI, so
these read the Dockerfile.
"""

import re
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[1] / "container" / "Dockerfile"


def _text():
    """The Dockerfile, comments dropped and continuations joined."""
    lines = DOCKERFILE.read_text().splitlines()
    return "\n".join(l for l in lines if not l.lstrip().startswith("#")).replace("\\\n", " ")


def test_both_tool_installs_take_only_the_managed_pin():
    text = _text()
    assert re.search(r"^ARG WOLTSPACE_PYTHON_VERSION=3\.13(\.\d+)?$", text, re.M)
    installs = re.findall(r"uv tool install ([^;]*)", text)
    # The dev wheel and the PyPI release both.
    assert [i for i in installs if "/tmp/local-src" in i] and [i for i in installs if "woltspace==" in i]
    for args in installs:
        # A bare pin takes a system 3.13 if the base image ships one, and a
        # download would land in root's own data dir, which node cannot read.
        assert args.startswith('--managed-python --no-python-downloads --python "$WOLTSPACE_PYTHON_VERSION" '), args
    assert not re.search(r"UV_PYTHON_(PREFERENCE|DOWNLOADS)", text)


def test_the_pin_is_installed_first_into_a_build_arg_dir_under_opt():
    text = _text()
    # A stage ARG reaches the tool-install RUN; an ENV would follow node to
    # runtime, where uv could then not install any other Python.
    arg = re.search(r"^ARG UV_PYTHON_INSTALL_DIR=/opt/\S+$", text, re.M)
    install = text.index('uv python install --no-bin "$WOLTSPACE_PYTHON_VERSION"')
    assert arg and arg.start() < install < text.index("uv tool install")
    assert not re.search(r"^ENV .*UV_PYTHON_INSTALL_DIR", text, re.M)


def test_debian_python3_stays_for_direct_callers():
    assert re.search(r"apt-get install [^;]*\bpython3\b", _text())
