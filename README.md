# Forensica - Single-File Digital Forensics Data Recovery Tool

Forensica is a single-file, evidence-first data recovery and imaging CLI for digital forensics. It focuses on reliable acquisition, integrity verification, partition analysis, and signature-based carving.

## Features
- Imaging: bit-for-bit acquisition with multi-hash manifest (SHA-256, BLAKE2b, SHA-1, MD5)
- Verification: recompute and compare global and per-chunk hashes
- Partition parsing: MBR and GPT listing (JSON or human-readable)
- Carving: signature-based recovery for JPEG, PNG, PDF, ZIP (extensible)
- Hashing: compute multiple cryptographic hashes efficiently
- Case: simple case folder init and report aggregation

## Quick start
```bash
python3 forensica.py -h
```

## Usage examples
```bash
# Acquire an image (creates a JSON manifest)
python3 forensica.py image /dev/sdX /evidence/case001/image.dd --chunk-size 8MiB --force

# Verify image against manifest
python3 forensica.py verify /evidence/case001/image.dd --manifest /evidence/case001/image.dd.manifest.json

# List partitions
python3 forensica.py partitions /evidence/case001/image.dd --json

# Carve files by signature
python3 forensica.py carve /evidence/case001/image.dd ./carved --types jpeg,png,pdf,zip --min-size 1KiB --max-size 128MiB --manifest ./carved/carve.manifest.json

# Compute file hashes
python3 forensica.py hash ./carved/000001.jpg --algos sha256,blake2b

# Case utilities
python3 forensica.py case init ./case_dir
python3 forensica.py case report ./case_dir
```

## Notes
- For block devices, you may need elevated privileges.
- Always work from verified images to protect evidence. Use write-blockers in the field and document chain-of-custody separately.
- Carving heuristics are conservative; validate recovered files before use.