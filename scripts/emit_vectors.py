#!/usr/bin/env python3
"""Emit all NIST vectors (FF3 15 + FF3-1 18) from ff31_ref as JSON lines,
each with both enc and dec directions, for the Rust differential test."""
import json, sys
sys.path.insert(0, "/mnt/d/wsl2/duckdb-luajit-libs/libs/privacy")
import ff31_ref as R

for i, (radix, alph, k, t, pt, ct) in enumerate(R.FF3_VECTORS):
    print(json.dumps({"kind": "ff3", "alphabet": alph, "key": k, "tweak": t, "pt": pt, "ct": ct}))
for i, (radix, alph, k, t, pt, ct) in enumerate(R.FF31_VECTORS):
    print(json.dumps({"kind": "ff31", "alphabet": alph, "key": k, "tweak": t, "pt": pt, "ct": ct}))
