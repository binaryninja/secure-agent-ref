"""End-to-end runner: each demo's main() must return 0.

The asserts inside each demo are the actual security claims —
attacker scenarios must deny, benign scenarios must allow. This
runner just sequences them and treats any non-zero exit (or raised
assertion) as a failure.

LLM-backed demos (08+) are skipped automatically if
``ANTHROPIC_API_KEY`` is not set, so this script also serves as a
pre-flight check on a CI runner without API credentials.

Run: ``python tests/test_demos.py`` from the repo root.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "demos"))

# Trigger the .env loader so ANTHROPIC_API_KEY presence reflects
# what the LLM demos will actually see at run time.
from secagent.llm_planner import _load_dotenv_once  # noqa: E402

_load_dotenv_once()

DEMO_FILES = sorted((REPO / "demos").glob("[0-9][0-9]_*.py"))
LLM_DEMOS = {"08_llm_research.py", "09_llm_lethal_trifecta.py"}


def run_demo(path: Path) -> int:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.main()


def main() -> int:
    failures: list[str] = []
    skipped: list[str] = []
    have_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    for f in DEMO_FILES:
        if f.name in LLM_DEMOS and not have_key:
            print(f"\n##### {f.name} (skipped — no ANTHROPIC_API_KEY) #####")
            skipped.append(f.name)
            continue
        print(f"\n##### {f.name} #####")
        try:
            rc = run_demo(f)
        except SystemExit as e:
            rc = int(e.code or 0)
        except AssertionError as e:
            print(f"  FAIL: {e}")
            failures.append(f.name)
            continue
        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}")
            failures.append(f.name)
            continue
        if rc != 0:
            failures.append(f.name)
    print("\n=========================")
    ran = len(DEMO_FILES) - len(skipped)
    print(f"ran {ran} demos, {len(failures)} failed, {len(skipped)} skipped")
    if failures:
        for name in failures:
            print(f"  - {name}")
        return 1
    print("all demos passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
