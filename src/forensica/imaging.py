import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional


def _iso_utc_now() -> str:
	return datetime.now(timezone.utc).isoformat()


def image_source(
	source_path: str,
	destination_path: str,
	chunk_size: int,
	force_overwrite: bool = False,
	manifest_path: Optional[str] = None,
) -> int:
	"""Acquire a bit-for-bit image with a cryptographic manifest.

	Returns 0 on success, non-zero on failure.
	"""
	if not os.path.exists(source_path):
		print(f"[error] Source does not exist: {source_path}")
		return 2

	if os.path.exists(destination_path) and not force_overwrite:
		print(f"[error] Destination exists. Use --force to overwrite: {destination_path}")
		return 2

	if manifest_path is None:
		manifest_path = destination_path + ".manifest.json"

	algorithms = ["sha256", "blake2b", "sha1", "md5"]
	global_hashers: Dict[str, hashlib._Hash] = {name: hashlib.new(name) for name in algorithms}
	chunk_hashes_sha256: List[str] = []

	started_at = _iso_utc_now()
	start_time = time.time()
	copied_bytes = 0

	# Ensure destination directory exists
	os.makedirs(os.path.dirname(os.path.abspath(destination_path)) or ".", exist_ok=True)

	try:
		with open(source_path, "rb", buffering=0) as src, open(
			destination_path, "wb" if force_overwrite else "xb", buffering=0
		) as dst:
			while True:
				chunk = src.read(chunk_size)
				if not chunk:
					break
				dst.write(chunk)
				for hasher in global_hashers.values():
					hasher.update(chunk)
				chunk_hashes_sha256.append(hashlib.sha256(chunk).hexdigest())
				copied_bytes += len(chunk)
			# flush and fsync for durability
			dst.flush()
			os.fsync(dst.fileno())
	except PermissionError:
		print("[error] Permission denied. Try running with elevated privileges for block devices.")
		return 5
	except FileExistsError:
		print(f"[error] Destination exists: {destination_path}")
		return 2
	except FileNotFoundError as exc:
		print(f"[error] File not found: {exc}")
		return 2
	except OSError as exc:
		print(f"[error] I/O error: {exc}")
		return 5

	ended_at = _iso_utc_now()
	duration_seconds = max(0.0, time.time() - start_time)

	manifest = {
		"schema_version": 1,
		"source_path": os.path.abspath(source_path),
		"destination_path": os.path.abspath(destination_path),
		"chunk_size": chunk_size,
		"copied_bytes": copied_bytes,
		"duration_seconds": duration_seconds,
		"hashes": {name: hasher.hexdigest() for name, hasher in global_hashers.items()},
		"chunk_hashes_sha256": chunk_hashes_sha256,
		"started_at": started_at,
		"ended_at": ended_at,
	}

	try:
		with open(manifest_path, "w", encoding="utf-8") as mfp:
			json.dump(manifest, mfp, indent=2)
		print(f"[ok] Image complete: {destination_path}")
		print(f"[ok] Manifest written: {manifest_path}")
		print(
			f"[info] Size: {copied_bytes} bytes, Speed: {int(copied_bytes / duration_seconds) if duration_seconds else copied_bytes} B/s"
		)
		return 0
	except OSError as exc:
		print(f"[error] Failed to write manifest: {exc}")
		return 5


def verify_image(path: str, manifest_path: Optional[str] = None) -> int:
	"""Verify an image's integrity optionally using a manifest for chunk-level verification."""
	if not os.path.exists(path):
		print(f"[error] Path does not exist: {path}")
		return 2

	manifest = None
	if manifest_path:
		if not os.path.exists(manifest_path):
			print(f"[error] Manifest not found: {manifest_path}")
			return 2
		with open(manifest_path, "r", encoding="utf-8") as mfp:
			manifest = json.load(mfp)

	# Global hashes
	algorithms = ["sha256", "blake2b", "sha1", "md5"]
	global_hashers: Dict[str, hashlib._Hash] = {name: hashlib.new(name) for name in algorithms}
	chunk_size = manifest.get("chunk_size", 4 * 1024 * 1024) if manifest else 4 * 1024 * 1024
	chunk_hashes: List[str] = []

	try:
		with open(path, "rb", buffering=0) as fp:
			while True:
				chunk = fp.read(chunk_size)
				if not chunk:
					break
				for hasher in global_hashers.values():
					hasher.update(chunk)
				chunk_hashes.append(hashlib.sha256(chunk).hexdigest())
	except OSError as exc:
		print(f"[error] I/O error: {exc}")
		return 5

	computed = {name: hasher.hexdigest() for name, hasher in global_hashers.items()}
	print("[info] Computed hashes:")
	for name, hexval in computed.items():
		print(f"  {name}: {hexval}")

	if manifest:
		print("[info] Comparing to manifest...")
		manifest_hashes = manifest.get("hashes", {})
		global_ok = all(
			algo in manifest_hashes and manifest_hashes[algo] == computed.get(algo)
			for algo in manifest_hashes.keys()
		)
		if not global_ok:
			print("[fail] Global hash mismatch")
			return 1

		manifest_chunk_hashes = manifest.get("chunk_hashes_sha256", [])
		if manifest_chunk_hashes and manifest_chunk_hashes != chunk_hashes:
			print("[fail] Chunk hash list mismatch")
			return 1
		print("[ok] Verification passed")
		return 0
	else:
		print("[ok] Hashing complete (no manifest provided)")
		return 0