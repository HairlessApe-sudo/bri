"""Private strict XLSX subprocess entry point (not a generic sandbox)."""

import os
import resource
import signal
import sys


def _lower_limit(kind: int, soft: int, hard: int) -> None:
    previous_soft, previous_hard = resource.getrlimit(kind)
    if previous_hard != resource.RLIM_INFINITY:
        hard = min(hard, previous_hard)
    if previous_soft != resource.RLIM_INFINITY:
        soft = min(soft, previous_soft)
    resource.setrlimit(kind, (min(soft, hard), hard))


def _main() -> int:
    cpu, address_space, max_input, max_canonical = map(int, sys.argv[1:5])
    purelib = sys.argv[5]
    signal.signal(signal.SIGXCPU, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGXCPU})
    _lower_limit(resource.RLIMIT_CORE, 0, 0)
    _lower_limit(resource.RLIMIT_CPU, cpu, cpu + 1)
    _lower_limit(resource.RLIMIT_AS, address_space, address_space)

    # -I -S excludes ambient module paths and site hooks. Add only our source
    # root and the interpreter's configured dependency directory (defusedxml).
    source_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.extend((source_root, purelib))

    from bri.ingestion._xlsx_strict_archive import StrictArchiveError, read_package

    content = sys.stdin.buffer.read(max_input + 1)
    if len(content) > max_input:
        return 1  # Parent protocol violation.
    try:
        parts = read_package(content)
    except StrictArchiveError:
        return 2
    del content

    from bri.ingestion._xlsx_strict_parser import StrictParseError, parse_package

    try:
        canonical = parse_package(parts)
    except StrictParseError:
        return 3
    del parts
    if len(canonical) > max_canonical:
        return 5
    sys.stdout.buffer.write(b"\x00" + len(canonical).to_bytes(4, "big"))
    sys.stdout.buffer.write(canonical)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        code = _main()
    except MemoryError:
        code = 4
    except Exception:
        code = 1
    raise SystemExit(code)
