"""Offline storage/accounting sanity check; no Docker, agent, or provider needed."""

from pathlib import Path
from tempfile import TemporaryDirectory

from .budget_gateway import BudgetGateway, BudgetRejection, MICRO
from .snapshots import BlobStore, reconstruct


def main() -> None:
    with TemporaryDirectory(prefix="mini-swe-connector-") as temp:
        root = Path(temp)
        blobs = BlobStore(root / "blobs")
        changed = b"answer = 42\n"
        changed_ref = blobs.put(changed)
        assert blobs.put(changed) == changed_ref
        assert blobs.has(changed_ref)
        assert blobs.get(changed_ref) == changed

        base = root / "base"
        base.mkdir()
        (base / "main.py").write_text("answer = 0\n")
        (base / "remove.py").write_text("obsolete = True\n")
        (base / "keep.py").write_text("untouched = True\n")
        manifest = {
            "files": {
                "main.py": changed_ref,
                "remove.py": None,
                "helpers/check.py": blobs.put(b"assert 6 * 7 == 42\n"),
            }
        }
        restored = root / "restored"
        reconstruct(manifest, base, restored, blobs)
        assert (restored / "main.py").read_bytes() == changed
        assert not (restored / "remove.py").exists()
        assert (restored / "keep.py").read_bytes() == (base / "keep.py").read_bytes()
        assert (restored / "helpers/check.py").read_bytes() == b"assert 6 * 7 == 42\n"
        assert (base / "remove.py").exists()

        gateway = BudgetGateway(root / "budget.sqlite", {"demo": MICRO}, MICRO)
        try:
            reservation = gateway.reserve(bucket="demo", bound_microusd=MICRO)
            gateway.mark_ambiguous(reservation.request_id, "offline demonstration")
            assert gateway.totals()["outstanding"] == MICRO
            try:
                gateway.reserve(bucket="demo", bound_microusd=1)
            except BudgetRejection:
                pass
            else:
                raise AssertionError("An ambiguous charge must still consume the cap")
            gateway.release(reservation.request_id, "synthetic request never dispatched")
            reservation = gateway.reserve(bucket="demo", bound_microusd=MICRO)
            gateway.settle(reservation.request_id, actual_cost_microusd=MICRO // 4)
            assert gateway.totals()["charged"] == MICRO // 4
            assert gateway.totals()["outstanding"] == 0
        finally:
            gateway.close()

    print("PASS: blob storage, snapshot reconstruction, and budget accounting")
    print("Offline check only; live mini-SWE-agent/Docker integration was not run.")


if __name__ == "__main__":
    main()
