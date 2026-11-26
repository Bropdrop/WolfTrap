"""Broker endpoint for the private supervisor pipes. The wire carries bytes, never paths."""
import io
import os
import stat

from job_wire import ARTIFACT, INPUTS, NAMES, OUTPUT_LIMIT, exact, get, put

_channel = None


def connect(request, response):
    global _channel
    if _channel is not None or min(request, response) < 3 or request == response:
        raise ValueError("invalid channel")
    if not all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (request, response)):
        raise ValueError("private pipes required")
    keep = sorted((request, response))
    for first, end in zip((3, keep[0]+1, keep[1]+1), (*keep, os.sysconf("SC_OPEN_MAX"))):
        os.closerange(first, end)
    _channel = os.fdopen(request, "wb"), os.fdopen(response, "rb")


def call(role, parts):
    writer, reader = _channel
    frame = io.BytesIO()
    frame.write(role)
    for part, limit in zip(parts, INPUTS[role], strict=True):
        put(frame, part, limit)
    writer.write(frame.getvalue())
    writer.flush()
    try:
        return exact(reader, 1)[0], get(reader, OUTPUT_LIMIT)
    except EOFError as exc:
        raise ValueError("supervisor reply incomplete") from exc


def worker(payload):
    return call(b"F", (payload,))


def engine(scan, inputs, output, policy):
    parts = [(inputs/"sample.json").read_bytes(), (inputs/"geo.json").read_bytes(),
             policy["as_of"].encode("ascii"), policy["geo_digest"].encode("ascii")]
    bundle = output/"bundle"
    if not scan:
        return call(b"V", parts + [(bundle/name).read_bytes() for name in NAMES])
    code, data = call(b"S", parts)
    if code in (0, 1):
        stream = io.BytesIO(data)
        bundle.mkdir(mode=0o700)
        try:
            for name in NAMES:
                with (bundle/name).open("xb") as destination:
                    destination.write(get(stream, ARTIFACT))
            if stream.read(1):
                raise ValueError("unexpected scan output")
        except EOFError as exc:
            raise ValueError("incomplete scan output") from exc
    return code, b""
