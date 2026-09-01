from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "vectors/v1/manifest.json"
INPUTS = (
    ROOT / "schemas/v1/contracts.schema.json",
    ROOT / "vectors/v1/identity-citation.json",
    ROOT / "vectors/v1/hierarchy-selectors.json",
)


def main() -> None:
    manifest = {
        "schemaVersion": 1,
        "files": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in INPUTS
        ],
    }
    OUTPUT.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
