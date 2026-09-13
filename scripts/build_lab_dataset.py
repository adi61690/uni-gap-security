from pathlib import Path
import json, sys
ROOT=Path(__file__).resolve().parents[1]
# Dataset generation is kept in this root script so CI and teammates can reproduce it.
# It delegates to the checked-in generator module below.
sys.path.insert(0, str(ROOT / "scripts"))
from lab_dataset_generator import build
path, manifest = build(ROOT)
print(f"Wrote {path} ({manifest['rows']} rows)")
