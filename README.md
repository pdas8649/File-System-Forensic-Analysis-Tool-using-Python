# Forensica - Digital Forensics Data Recovery Tool

Forensica is a modular, evidence-first data recovery and imaging CLI for digital forensics. It focuses on reliable acquisition, integrity verification, partition analysis, and signature-based carving.

## Features
- Imaging: bit-for-bit acquisition with multi-hash manifest (SHA-256, BLAKE2b, SHA-1, MD5)
- Verification: recompute and compare global and per-chunk hashes
- Partition parsing: MBR and GPT listing
- Carving: signature-based recovery for JPEG, PNG, PDF, ZIP (extensible)
- Hashing: compute multiple cryptographic hashes efficiently

## Install (editable dev)
```bash
pip install -e .
```

## Usage
```bash
# Show help
forensica -h

# Acquire an image (will create a JSON manifest)
forensica image /dev/sdX /evidence/case001/image.dd --chunk-size 8MiB --force

# Verify image against manifest
forensica verify /evidence/case001/image.dd --manifest /evidence/case001/image.dd.manifest.json

# List partitions
forensica partitions /evidence/case001/image.dd

# Carve files by signature
forensica carve /evidence/case001/image.dd ./carved --types jpeg,png,pdf,zip --min-size 1KiB --max-size 128MiB

# Compute file hashes
forensica hash ./carved/000001.jpg --algos sha256,blake2b
```

## Notes
- For block devices, you may need elevated privileges.
- Always work from verified images to protect evidence. Use write-blockers in the field and document chain-of-custody separately.
- Carving heuristics are conservative; validate recovered files before use.