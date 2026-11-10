#!/usr/bin/env python3
"""Offline checks for staged backup write/delete helpers."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))
import ops  # noqa: E402


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        data = Path(td)
        (data / "store.json").write_text("{}", encoding="utf-8")
        (data / "secret_key").write_text("x" * 32, encoding="utf-8")
        w = ops.write_backup(data, name="test-backup.zip")
        assert w["ok"], w
        path = Path(w["path"])
        assert path.is_file()
        assert path.parent.name == "backups"
        # staged file must not be nested into next archive
        blob2 = ops.make_backup(data)
        import zipfile, io
        names = zipfile.ZipFile(io.BytesIO(blob2)).namelist()
        assert not any(n.startswith("backups/") for n in names), names
        assert ops.delete_backup_file(path)
        assert not path.exists()
        # write two, cleanup keep 0
        ops.write_backup(data, name="a.zip")
        ops.write_backup(data, name="b.zip")
        n = ops.cleanup_staged_backups(data, keep_newest=0)
        assert n >= 2
        assert list(ops.backups_dir(data).glob("*.zip")) == []
        # pre-restore cleanup
        (data / "pre-restore-1.zip").write_bytes(b"1")
        (data / "pre-restore-2.zip").write_bytes(b"2")
        removed = ops.cleanup_pre_restore(data, keep_newest=1)
        assert removed == 1
        assert len(list(data.glob("pre-restore-*.zip"))) == 1
    print("ok backup stage/delete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
