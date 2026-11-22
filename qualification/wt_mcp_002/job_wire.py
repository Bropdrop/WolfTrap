"""Private, bounded broker/supervisor channel. All destinations and file counts are constants."""
import struct

NAMES = ("geotrace.json", "geotrace.md", "geotrace.sarif", "manifest.json")
ARTIFACT = 1 << 20
SCAN_INPUT = (262144, 16384, 10, 64)
INPUTS = {b"F": (65536,), b"S": SCAN_INPUT, b"V": SCAN_INPUT + (ARTIFACT,) * len(NAMES)}
OUTPUT_LIMIT = 4 * (ARTIFACT + 4) + 1024


def exact(stream, count):
    data = bytearray()
    while len(data) < count:
        part = stream.read(count - len(data))
        if not part:
            raise EOFError("incomplete job")
        data.extend(part)
    return bytes(data)


def get(stream, limit):
    size, = struct.unpack("!I", exact(stream, 4))
    if size > limit:
        raise ValueError("job exceeds profile")
    return exact(stream, size)


def put(stream, data, limit):
    if len(data) > limit:
        raise ValueError("job exceeds profile")
    stream.write(struct.pack("!I", len(data)))
    stream.write(data)
