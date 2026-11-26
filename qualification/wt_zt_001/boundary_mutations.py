"""Single-guard experiments on fixture file capture and local artifact verification."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import zipfile

from package import build, ZIP

HERE = Path(__file__).resolve().parent
PLAN = [
    ("path confinement", "guard_profiles", "parts[-1], os.O_NOFOLLOW | os.O_NONBLOCK",
     "parts[-1], os.O_NONBLOCK"),
    ("evidence member content", "evidence", "if stream.read(len(content) + 1) != content:",
     'if stream.read(len(content) + 1) != content and name != "assessment.json":'),
    ("evidence completeness", "evidence", "if set(os.listdir(fd)) != MEMBERS:",
     "if not os.listdir(fd):"),
    ("plugin permissions", "package", "if stream.read(len(data) + 1) != data:",
     "if stream.read(len(data) + 1) != data and name != ZIP:"),
]


def probe(control, module, directory, expected):
    if control == "path confinement":
        target = directory / "fictional-outside"
        target.write_bytes(b"outside-sentinel")
        root = directory / "selected"
        root.mkdir()
        (root / "selected.md").symlink_to(target)
        fd = os.open(root, os.O_DIRECTORY | os.O_RDONLY)
        try:
            result = module.capture_candidate(fd, "selected.md")
            return "HOLD" if result == "HOLD" else "READ_EXTERNAL_FIXTURE"
        finally:
            os.close(fd)
    files = expected.copy()
    if control == "plugin permissions":
        data = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(files[ZIP])) as approved, zipfile.ZipFile(data, "w") as changed:
            for entry in approved.infolist():
                original = approved.read(entry.filename)
                if entry.filename == "plugin.json":
                    assert original.count(b'"Read"') == 1
                    original = original.replace(b'"Read"', b'"Exec"')
                changed.writestr(entry, original)
        files[ZIP] = data.getvalue()
    elif control == "evidence completeness":
        files["unexpected"] = b"unapproved"
    else:
        files["assessment.json"] = b"changed"
    for name, data in files.items():
        (directory / name).write_bytes(data)
    fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY)
    try:
        if control == "plugin permissions":
            module.check(fd, expected)
        else:
            module.verify(fd, expected)
        return "ACCEPTED"
    except (ValueError, OSError):
        return "REJECTED"
    finally:
        os.close(fd)


def run():
    report = []
    for control, name, original, weak in PLAN:
        clean = (HERE / (name + ".py")).read_text()
        expected = build() if control == "plugin permissions" else {
                "assessment.json":b"trusted", "assessment.md":b"fixture", "manifest.json":b"fixture"}
        observations = []
        with tempfile.TemporaryDirectory() as tmp:
            for index, source in enumerate([clean, clean.replace(original, weak, 1), clean]):
                if index == 1 and source == clean:
                    raise ValueError("missing mutation anchor")
                folder = Path(tmp) / str(index)
                folder.mkdir()
                file = folder / (name + ".py")
                file.write_text(source)
                spec = importlib.util.spec_from_file_location("trial_" + name, file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                data = folder / "fixture"
                data.mkdir()
                observations.append(probe(control, module, data, expected))
        baseline, mutant, restored = observations
        desired = "HOLD" if control == "path confinement" else "REJECTED"
        classification = "INCONCLUSIVE"
        if baseline == restored == desired:
            classification = "SURVIVED" if mutant == desired else "DETECTED"
        report.append(dict(control=control, original=original, replacement=weak, expected=desired,
                           baseline=baseline, mutant=mutant, restored=restored, classification=classification))
    return report


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, indent=2))
