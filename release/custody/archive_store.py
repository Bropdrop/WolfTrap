"""Local, bounded, evaluation-only release history. The subscriber pins the head externally."""

from contextlib import contextmanager
import fcntl
import os
import re
import secrets
import stat

from release_client import private_directory, publish_new
from release_core import verify
from release_io import BUNDLE_LIMIT, DOC_LIMIT, OPEN_DIR, Verdict, encode, parse, path, require, sha, stamp
from release_policy import PROFILE, hexval, wheel_name

GENESIS = sha(b"awooo.local-evaluation-custody/v1:empty\n")
SCHEMA = "awooo.local-evaluation-custody/v1"
MAX_SLOTS = 16
MAX_PENDING = 4
FIELDS = (
    "version",
    "commit",
    "tree",
    "archive_sha256",
    "wheel_sha256",
    "sbom_sha256",
    "manifest_sha256",
    "policy_sha256",
)


def slot_name(sequence):
    return f"release-{sequence:08d}"


def distinct(*locations):
    paths = list(map(path, locations))
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            require(not left.is_relative_to(right) and not right.is_relative_to(left), "custody-path-overlap")


@contextmanager
def locked(vault, *, writing=False):
    fd = private_directory(vault)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if writing else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Verdict("INCONCLUSIVE", "custody-busy-retry") from None
        yield fd
        check = private_directory(vault)
        try:
            require(os.path.samestat(os.fstat(check), os.fstat(fd)), "custody-directory-changed")
        finally:
            os.close(check)
    finally:
        os.close(fd)


def entries(fd, limit):
    names = set()
    with os.scandir(fd) as listing:
        for item in listing:
            require(len(names) < limit, "custody-directory-bound")
            names.add(item.name)
    return names


def layout(fd):
    names = entries(fd, MAX_SLOTS + MAX_PENDING)
    slots = set()
    pending = 0
    for name in names:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            "unsafe-custody-directory",
        )
        if re.fullmatch(r"pending-[0-9a-f]{32}", name):
            pending += 1
        else:
            require(re.fullmatch(r"release-[0-9]{8}", name), "unexpected-custody-entry")
            slots.add(int(name[8:]))
    require(pending <= MAX_PENDING and len(slots) <= MAX_SLOTS, "custody-directory-bound")
    require(slots == set(range(1, len(slots) + 1)), "incomplete-custody-history")
    return len(slots), pending


def read_member(fd, name, limit):
    file_fd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=fd)
    try:
        info = os.fstat(file_fd)
        require(
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit,
            "unsafe-custody-member",
        )
        with open(f"/proc/self/fd/{file_fd}", "rb") as stream:
            data = stream.read(limit + 1)
        require(
            len(data) == info.st_size
            and stamp(info) == stamp(os.fstat(file_fd))
            and stamp(info) == stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)),
            "custody-member-changed",
        )
        return data
    finally:
        os.close(file_fd)


def read_slot(fd, sequence, previous):
    name = slot_name(sequence)
    slot = os.open(name, OPEN_DIR, dir_fd=fd)
    try:
        before = stamp(os.fstat(slot))
        require(entries(slot, 2) == {"index.json", "capsule.zip"}, "incomplete-custody-slot")
        index = read_member(slot, "index.json", DOC_LIMIT)
        record = parse(index)
        require(
            isinstance(record, dict)
            and set(record)
            == set(FIELDS) | {"schema", "scope", "sequence", "previous_index_sha256", "archive_bytes"},
            "custody-index-schema",
        )
        require(
            record["schema"] == SCHEMA
            and record["scope"] == PROFILE
            and type(record["sequence"]) is int
            and record["sequence"] == sequence
            and record["previous_index_sha256"] == previous,
            "custody-history-diverged",
        )
        wheel_name(record["version"])
        require(
            all(hexval(record[key], 40) for key in ("commit", "tree"))
            and all(hexval(record[key], 64) for key in FIELDS if key.endswith("_sha256")),
            "custody-index-digests",
        )
        raw = read_member(slot, "capsule.zip", BUNDLE_LIMIT)
        require(
            type(record["archive_bytes"]) is int
            and record["archive_bytes"] == len(raw)
            and record["archive_sha256"] == sha(raw),
            "custody-artifact-mismatch",
        )
        require(
            before == stamp(os.fstat(slot)) == stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)),
            "custody-slot-changed",
        )
        return index, raw
    finally:
        os.close(slot)


def snapshot(fd, count, pin):
    require(type(count) is int and 0 <= count <= MAX_SLOTS and hexval(pin, 64), "custody-checkpoint-format")
    length, pending = layout(fd)
    require(length == count, "custody-head-sequence-mismatch")
    previous = GENESIS
    slots = []
    for sequence in range(1, count + 1):
        index, raw = read_slot(fd, sequence, previous)
        slots.append((index, raw))
        previous = sha(index)
    require(pin == previous, "independent-custody-pin-mismatch")
    require((length, pending) == layout(fd), "custody-layout-changed")
    return slots, pending


def write_slot(fd, sequence, index, raw):
    """Commit both durable members with one same-filesystem directory rename under the vault lock."""
    final = slot_name(sequence)
    stage = "pending-" + secrets.token_hex(16)
    os.mkdir(stage, mode=0o700, dir_fd=fd)
    tmp = os.open(stage, OPEN_DIR, dir_fd=fd)
    try:
        for name, data in (("capsule.zip", raw), ("index.json", index)):
            dest = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=tmp)
            with os.fdopen(dest, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(tmp)
        try:
            os.stat(final, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Verdict("REJECTED", "custody-slot-exists")
        os.rename(stage, final, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        # On interruption leave the uncommitted stage for operator inspection.
        # It never contributes to a checkpoint; never unlink a name supplied by storage.
        os.close(tmp)


def receipt(status, sequence, pin, pending=0):
    return {
        "schema": "awooo.custody-receipt/v1",
        "scope": PROFILE,
        "status": status,
        "sequence": sequence,
        "index_sha256": pin,
        "uncommitted_stages": pending,
    }


def admit(vault, raw, trust, policy_pin, count, pin, now, *, reconcile=False, minimum_generation=None):
    require(type(count) is int and 0 <= count < MAX_SLOTS, "custody-capacity")
    sequence = count + 1
    verified, _wheel = verify(raw, trust, policy_pin, sequence, sequence, "current", now, minimum_generation)
    record = {key: verified[key] for key in FIELDS}
    record.update(
        schema=SCHEMA, scope=PROFILE, sequence=sequence, previous_index_sha256=pin, archive_bytes=len(raw)
    )
    index = encode(record)
    with locked(vault, writing=True) as fd:
        if reconcile:
            # Resolve commit succeeded / receipt lost only against the full independently
            # supplied capsule AND the original still-current policy and prior checkpoint.
            # snapshot checks the entire predecessor chain and bytes against this digest.
            _, pending = snapshot(fd, sequence, sha(index))
            return receipt("RECONCILED_EVALUATION_BYTES", sequence, sha(index), pending)
        _slots, pending = snapshot(fd, count, pin)
        require(pending < MAX_PENDING, "inspect-abandoned-stages", "INCONCLUSIVE")
        write_slot(fd, sequence, index, raw)
        readback = read_slot(fd, sequence, pin)
        require(readback == (index, raw), "custody-admission-readback")
    return receipt("ADMITTED_EVALUATION_BYTES", sequence, sha(index), pending)


def audit(vault, count, pin):
    with locked(vault) as fd:
        _slots, pending = snapshot(fd, count, pin)
    return receipt("VERIFIED_ARCHIVE_BYTES", count, pin, pending)


def replicate(vault, replica, count, pin):
    distinct(vault, replica)
    with locked(vault) as fd:
        source, _ = snapshot(fd, count, pin)
    with locked(replica, writing=True) as dest:
        present, pending = layout(dest)
        require(present <= count, "replica-ahead-of-pinned-source")
        prefix_pin = sha(source[present - 1][0]) if present else GENESIS
        snapshot(dest, present, prefix_pin)
        require(pending < MAX_PENDING or present == count, "inspect-abandoned-stages", "INCONCLUSIVE")
        for sequence in range(present + 1, count + 1):
            index, raw = source[sequence - 1]
            write_slot(dest, sequence, index, raw)
        snapshot(dest, count, pin)
    return receipt("REPLICATED_EVALUATION_BYTES", count, pin, pending)


def restore(vault, count, pin, release_sequence, output):
    dest = path(output)
    distinct(vault, dest.parent)
    require(type(release_sequence) is int and 1 <= release_sequence <= count, "unknown-recovery-sequence")
    with locked(vault) as fd:
        slots, pending = snapshot(fd, count, pin)
        index, raw = slots[release_sequence - 1]
    publish_new(dest.parent, dest.name, raw)
    with locked(dest.parent) as fd:
        require(sha(read_member(fd, dest.name, BUNDLE_LIMIT)) == sha(raw), "recovery-readback-failed")
    report = receipt("RESTORED_BYTES", count, pin, pending)
    report.update(
        restored_sequence=release_sequence, restored_index_sha256=sha(index), archive_sha256=sha(raw)
    )
    return report
