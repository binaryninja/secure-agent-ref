"""Unit checks for the core primitives.

These are intentionally small — the demos are the system-level test
surface; this module covers a few invariants that are awkward to
read out of demo output.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secagent.capabilities import Capability, _new_id
from secagent.labels import (
    Confidentiality,
    Integrity,
    Label,
    join_all,
    public_label,
)


def test_label_join_picks_higher_conf_lower_integrity() -> None:
    a = Label(Confidentiality.PUBLIC, Integrity.SYSTEM_TRUSTED, "a", "t")
    b = Label(Confidentiality.TENANT_PRIVATE, Integrity.UNTRUSTED_EXTERNAL, "b", "t")
    j = a.join(b)
    assert j.confidentiality == Confidentiality.TENANT_PRIVATE
    assert j.integrity == Integrity.UNTRUSTED_EXTERNAL


def test_join_all_handles_empty() -> None:
    assert join_all([]) is None


def test_capability_attenuate_cannot_widen() -> None:
    cap = Capability(
        capability_id=_new_id(),
        task_id="t",
        tool="github.read_file",
        action="run",
        scope={"repo": ["acme/a", "acme/b"]},
        expires_at=time.time() + 60,
    )
    narrower = cap.attenuate(repo=["acme/a"])
    assert narrower.scope["repo"] == ["acme/a"]
    try:
        cap.attenuate(branch="main")  # not in original scope
    except ValueError:
        pass
    else:
        raise AssertionError("attenuate widened scope")


def test_capability_expiry_denies_cover() -> None:
    cap = Capability(
        capability_id=_new_id(),
        task_id="t",
        tool="x",
        action="run",
        scope={"k": [1]},
        expires_at=time.time() - 1,  # already expired
    )
    ok, reason = cap.covers("x", "run", {"k": 1})
    assert not ok and "expired" in reason


def test_public_label_helper_marks_untrusted_external() -> None:
    label = public_label("web.public:https://example.com", "t1")
    assert label.confidentiality == Confidentiality.PUBLIC
    assert label.integrity == Integrity.UNTRUSTED_EXTERNAL


def main() -> int:
    funcs = [obj for name, obj in globals().items() if name.startswith("test_") and callable(obj)]
    for fn in funcs:
        fn()
        print(f"  pass  {fn.__name__}")
    print(f"\n{len(funcs)} unit tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
