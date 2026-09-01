from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "vectors/v1/manifest.json"
INPUTS = (
    ROOT / "schemas/v1/contracts.schema.json",
    ROOT / "schemas/sangrep-pack-manifest-v1.json",
    ROOT / "schemas/sangrep-pack-signature-v1.json",
    ROOT / "vectors/v1/identity-citation.json",
    ROOT / "vectors/v1/hierarchy-selectors.json",
    ROOT / "vectors/v1/pack-manifest.json",
    ROOT / "vectors/v1/pack-signing.json",
    ROOT / "trust/development-pack-roots-v1.json",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
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
    rendered = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    if arguments.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
            print("vector-manifest-drift: generated manifest is not current")
            return 1
        print("vector-manifest-drift: passed")
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
