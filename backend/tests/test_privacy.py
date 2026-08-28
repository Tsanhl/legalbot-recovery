from pathlib import Path

from app.privacy import path_fingerprint, safe_source_name, scrub_pii


def test_pii_and_absolute_paths_are_scrubbed() -> None:
    raw = "Email owner@example.com or +852 9123 4567; file /Users/owner/Desktop/Law/private.pdf"
    cleaned = scrub_pii(raw)
    assert "owner@example.com" not in cleaned
    assert "9123" not in cleaned
    assert "/Users/" not in cleaned


def test_phone_scrubber_preserves_legal_citation_coordinates() -> None:
    raw = (
        "Blackstone's Commentaries (1765-1769); Burrows, (2001) 117 LQR 412; "
        "Westpac [2012] WASCA 157; (2012) 270 FLR 1; ER 982-983. 45."
    )

    assert scrub_pii(raw) == raw


def test_phone_scrubber_keeps_eight_digit_local_numbers_supported() -> None:
    cleaned = scrub_pii("Call 9123 4567, 91234567, or +852 9123 4567.")

    assert cleaned == "Call [PHONE], [PHONE], or [PHONE]."


def test_safe_source_alias_never_contains_personal_filename() -> None:
    path = Path("/Users/owner/Desktop/Law/My marked answer.pdf")
    label = safe_source_name(path, "a" * 64)
    assert label == "source-aaaaaaaaaaaa.pdf"
    assert "marked" not in label
    assert len(path_fingerprint(path)) == 64
