from __future__ import annotations

import json
import zipfile
from pathlib import Path, PurePosixPath

from scripts import finalize_v111_phase2a_owner_review_delivery as delivery


def test_external_audit_delivery_is_sanitized_and_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "delivery"
    root.mkdir(mode=0o700)
    result = delivery.finalize(
        delivery.DEFAULT_MACHINE_ROOT,
        root,
        delivery.DEFAULT_DOCX,
    )
    manifest = json.loads((root / "DELIVERY-MANIFEST.json").read_bytes())
    zip_path = root / delivery.ZIP_NAME

    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False
    assert manifest["docx"]["all_rendered_pages_visually_inspected"] is True
    assert manifest["docx"]["table_geometry_audit_passed"] is True
    assert manifest["private_paths_included"] is False
    assert manifest["secrets_or_private_keys_included"] is False
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
        assert "EXTERNAL-AUDIT-MANIFEST.json" in names
        assert any(name.startswith("machine/") for name in names)
        assert any(name.startswith("owner-review/") for name in names)
        assert all(not PurePosixPath(name).is_absolute() for name in names)
        assert all(".." not in PurePosixPath(name).parts for name in names)
        combined = b"".join(archive.read(name) for name in names)
        assert b"/Users/" not in combined
        assert b"/private/" not in combined
        assert b"BEGIN PRIVATE KEY" not in combined
