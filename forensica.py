#!/usr/bin/env python3
"""
Forensica (single-file) - Digital Forensics Data Recovery Tool

Consolidated one-file script providing:
- Imaging (bit-for-bit) with cryptographic manifest and verification
- Partition parsing (MBR/GPT) with JSON output option
- Signature-based file carving (JPEG/PNG/PDF/ZIP) with manifest
- Hashing utilities (multi-algorithm, streaming)
- Case utilities (init) and report aggregation

Usage:
	python3 forensica.py -h
"""

import argparse
import hashlib
import json
import mmap
import os
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from glob import glob
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# ----------------------------- Hashing Utilities -----------------------------

_SUPPORTED_HASH_ALGOS = {"md5", "sha1", "sha256", "blake2b"}


def _create_hashers(algorithms: Iterable[str]) -> Dict[str, "hashlib._Hash"]:
	hashers: Dict[str, "hashlib._Hash"] = {}
	for algo in algorithms:
		name = algo.lower()
		if name not in _SUPPORTED_HASH_ALGOS:
			raise ValueError(f"Unsupported hash algorithm: {algo}")
		hashers[name] = hashlib.new(name)
	return hashers


def hash_file_multi(path: str, algorithms: Iterable[str] = ("sha256",), chunk_size: int = 4 * 1024 * 1024) -> Dict[str, str]:
	"""Compute multiple cryptographic hashes for a file efficiently.

	Returns a mapping of algorithm name to hex digest.
	"""
	hashers = _create_hashers(algorithms)
	with open(path, "rb", buffering=0) as fp:
		while True:
			chunk = fp.read(chunk_size)
			if not chunk:
				break
			for hasher in hashers.values():
				hasher.update(chunk)
	return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def hash_bytes_multi(data: bytes, algorithms: Iterable[str] = ("sha256",)) -> Dict[str, str]:
	"""Compute multiple hashes for a bytes object."""
	hashers = _create_hashers(algorithms)
	for hasher in hashers.values():
		hasher.update(data)
	return {name: hasher.hexdigest() for name, hasher in hashers.items()}


# --------------------------------- Imaging ----------------------------------

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


# ------------------------------ Partitioning --------------------------------

_SECTOR_SIZE = 512

_MBR_TYPE_LABELS: Dict[int, str] = {
	0x00: "Empty",
	0x01: "FAT12",
	0x04: "FAT16 <32M",
	0x05: "Extended",
	0x06: "FAT16",
	0x07: "NTFS/exFAT/HPFS",
	0x0B: "FAT32 (CHS)",
	0x0C: "FAT32 (LBA)",
	0x0E: "FAT16 (LBA)",
	0x0F: "Extended (LBA)",
	0x82: "Linux swap",
	0x83: "Linux filesystem",
	0x8E: "Linux LVM",
	0xEE: "GPT Protective",
}


def _read_exact(fp, size: int) -> bytes:
	data = fp.read(size)
	if len(data) != size:
		raise EOFError("Unexpected end of file")
	return data


def _parse_mbr(fp) -> List[Dict[str, int]]:
	fp.seek(0)
	mbr = _read_exact(fp, _SECTOR_SIZE)
	if mbr[510:512] != b"\x55\xAA":
		return []
	entries: List[Dict[str, int]] = []
	for i in range(4):
		offset = 446 + i * 16
		entry = mbr[offset : offset + 16]
		ptype = entry[4]
		lba_start = struct.unpack_from("<I", entry, 8)[0]
		sectors = struct.unpack_from("<I", entry, 12)[0]
		if ptype == 0x00 or sectors == 0:
			continue
		entries.append(
			{
				"index": i + 1,
				"type": ptype,
				"type_label": _MBR_TYPE_LABELS.get(ptype, f"0x{ptype:02x}"),
				"lba_start": lba_start,
				"lba_end": lba_start + sectors - 1,
				"sectors": sectors,
				"bytes": sectors * _SECTOR_SIZE,
			}
		)
	return entries


def _guid_str(g: bytes) -> str:
	# GUID bytes are in mixed-endian: first 3 fields little-endian
	a = struct.unpack_from("<I", g, 0)[0]
	b = struct.unpack_from("<H", g, 4)[0]
	c = struct.unpack_from("<H", g, 6)[0]
	d = g[8:10].hex()
	e = g[10:16].hex()
	return f"{a:08x}-{b:04x}-{c:04x}-{d}-{e}"


def _parse_gpt(fp) -> List[Dict[str, object]]:
	# GPT header at LBA 1
	fp.seek(_SECTOR_SIZE)
	head = _read_exact(fp, _SECTOR_SIZE)
	if head[0:8] != b"EFI PART":
		return []
	# Offsets per UEFI spec
	entries_lba = struct.unpack_from("<Q", head, 72)[0]
	num_entries = struct.unpack_from("<I", head, 80)[0]
	entry_size = struct.unpack_from("<I", head, 84)[0]
	if entry_size < 128 or entry_size > 1024:
		return []
	fp.seek(entries_lba * _SECTOR_SIZE)
	entries: List[Dict[str, object]] = []
	for idx in range(num_entries):
		raw = _read_exact(fp, entry_size)
		ptype_guid = raw[0:16]
		first_lba = struct.unpack_from("<Q", raw, 32)[0]
		last_lba = struct.unpack_from("<Q", raw, 40)[0]
		if first_lba == 0 and last_lba == 0:
			continue
		name_utf16 = raw[56:56 + 72]
		try:
			name = name_utf16.decode("utf-16le").rstrip("\x00").strip()
		except Exception:
			name = ""
		entries.append(
			{
				"index": idx + 1,
				"first_lba": first_lba,
				"last_lba": last_lba,
				"bytes": (last_lba - first_lba + 1) * _SECTOR_SIZE,
				"type_guid": _guid_str(ptype_guid),
				"name": name,
			}
		)
	return entries


def list_partitions(path: str, output_json: bool = False) -> int:
	if not os.path.exists(path):
		print(f"[error] Path does not exist: {path}")
		return 2
	try:
		with open(path, "rb", buffering=0) as fp:
			mbr_entries = _parse_mbr(fp)
			gpt_entries = _parse_gpt(fp)
	except OSError as exc:
		print(f"[error] I/O error: {exc}")
		return 5

	if output_json:
		print(
			json.dumps(
				{
					"gpt": gpt_entries,
					"mbr": mbr_entries,
				},
				indent=2,
			)
		)
		return 0

	if gpt_entries:
		print("[info] GPT partitions:")
		for e in gpt_entries:
			print(
				f"  #{e['index']:>2}  {e['type_guid']}  start={e['first_lba']}  end={e['last_lba']}  bytes={e['bytes']}  name='{e['name']}'"
			)
		return 0
	elif mbr_entries:
		print("[info] MBR partitions:")
		for e in mbr_entries:
			print(
				f"  #{e['index']:>2}  type={e['type_label']}  start={e['lba_start']}  end={e['lba_end']}  bytes={e['bytes']}"
			)
		return 0
	else:
		print("[info] No partition table detected (raw/unpartitioned)")
		return 0


# ---------------------------------- Carver ----------------------------------

@dataclass(frozen=True)
class Signature:
	name: str
	extensions: List[str]
	header: bytes
	footer: Optional[bytes]


_SIGNATURES: Dict[str, Signature] = {
	"jpeg": Signature("jpeg", ["jpg", "jpeg"], b"\xff\xd8\xff", b"\xff\xd9"),
	"png": Signature(
		"png",
		["png"],
		b"\x89PNG\r\n\x1a\n",
		b"\x00\x00\x00\x00IEND\xaeB`\x82",
	),
	"pdf": Signature("pdf", ["pdf"], b"%PDF", b"%%EOF"),
	"zip": Signature("zip", ["zip"], b"PK\x03\x04", b"PK\x05\x06"),
}


_DEF_CHUNK = 8 * 1024 * 1024


def _select_signatures(names: Sequence[str]) -> List[Signature]:
	selected: List[Signature] = []
	for n in names:
		key = n.lower()
		if key in _SIGNATURES:
			selected.append(_SIGNATURES[key])
	return selected


def _out_carve_manifest(path: str, source_path: str, records: List[Dict[str, object]]) -> None:
	manifest = {
		"schema_version": 1,
		"source_path": os.path.abspath(source_path),
		"items": records,
	}
	with open(path, "w", encoding="utf-8") as fp:
		json.dump(manifest, fp, indent=2)


def carve_image(
	source_path: str,
	output_dir: str,
	signature_types: Sequence[str],
	max_file_size: int,
	min_file_size: int,
	manifest_path: Optional[str] = None,
) -> int:
	if not os.path.exists(source_path):
		print(f"[error] Source does not exist: {source_path}")
		return 2
	os.makedirs(output_dir, exist_ok=True)

	sigs = _select_signatures(signature_types)
	if not sigs:
		print("[error] No supported signature types selected")
		return 2

	records: List[Dict[str, object]] = []

	try:
		with open(source_path, "rb") as fp:
			try:
				mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
			except (ValueError, OSError):
				mm = None

			if mm is not None:
				count, recs = _carve_from_bytes(mm, sigs, output_dir, max_file_size, min_file_size)
				records.extend(recs)
				mm.close()
			else:
				count, recs = _carve_streaming(fp, sigs, output_dir, max_file_size, min_file_size)
				records.extend(recs)
			print(f"[ok] Carved {count} files into {output_dir}")
			if manifest_path is None:
				manifest_path = os.path.join(output_dir, "carve.manifest.json")
			_out_carve_manifest(manifest_path, source_path, records)
			print(f"[ok] Carving manifest written: {manifest_path}")
			return 0
	except OSError as exc:
		print(f"[error] I/O error: {exc}")
		return 5


def _carve_from_bytes(
	data: mmap.mmap, sigs: Sequence[Signature], output_dir: str, max_size: int, min_size: int
) -> Tuple[int, List[Dict[str, object]]]:
	n = data.size()
	pos = 0
	count = 0
	records: List[Dict[str, object]] = []
	while pos < n:
		# find earliest header among signatures
		header_hits: List[Tuple[int, Signature]] = []
		for sig in sigs:
			idx = data.find(sig.header, pos)
			if idx != -1:
				header_hits.append((idx, sig))
		if not header_hits:
			break
		start, sig = min(header_hits, key=lambda x: x[0])
		search_end = min(start + max_size, n)
		end = -1
		if sig.footer is not None:
			end_candidate = data.find(sig.footer, start + len(sig.header), search_end)
			if end_candidate != -1:
				end = end_candidate + len(sig.footer)
		if end == -1:
			pos = start + len(sig.header)
			continue
		size = end - start
		if size < min_size or size > max_size:
			pos = end
			continue
		count += 1
		out_path = os.path.join(output_dir, f"{count:06d}.{sig.extensions[0]}")
		with open(out_path, "wb") as out:
			out.write(data[start:end])
		records.append(
			{
				"index": count,
				"type": sig.name,
				"offset_start": start,
				"offset_end": end,
				"bytes": size,
				"path": os.path.abspath(out_path),
			}
		)
		pos = end
	return count, records


def _carve_streaming(
	fp, sigs: Sequence[Signature], output_dir: str, max_size: int, min_size: int
) -> Tuple[int, List[Dict[str, object]]]:
	# Basic streaming scanner with overlap
	window = _DEF_CHUNK
	overlap = 64  # bytes
	buf = b""
	file_offset = 0
	count = 0
	records: List[Dict[str, object]] = []
	while True:
		chunk = fp.read(window)
		if not chunk:
			break
		data = buf + chunk
		pos = 0
		limit = len(data)
		while pos < limit:
			header_hits: List[Tuple[int, Signature]] = []
			for sig in sigs:
				idx = data.find(sig.header, pos)
				if idx != -1:
					header_hits.append((idx, sig))
			if not header_hits:
				break
			start_rel, sig = min(header_hits, key=lambda x: x[0])
			start_abs = file_offset - len(buf) + start_rel
			# Search for footer within available data first
			end_rel = data.find(sig.footer, start_rel + len(sig.header)) if sig.footer else -1
			if end_rel == -1:
				# Footer may span into next chunk; move pos just past header and continue
				pos = start_rel + len(sig.header)
				continue
			end_abs = file_offset - len(buf) + end_rel + len(sig.footer or b"")
			size = end_abs - start_abs
			if size < min_size or size > max_size:
				pos = end_rel + (len(sig.footer or b""))
				continue
			# Emit carved file from the current buffer segment
			count += 1
			out_path = os.path.join(output_dir, f"{count:06d}.{sig.extensions[0]}")
			with open(out_path, "ab") as out:
				out.write(data[start_rel:end_rel + len(sig.footer or b"")])
			records.append(
				{
					"index": count,
					"type": sig.name,
					"offset_start": start_abs,
					"offset_end": end_abs,
					"bytes": size,
					"path": os.path.abspath(out_path),
				}
			)
			pos = end_rel + (len(sig.footer or b""))
		# keep tail for overlap
		buf = data[-overlap:]
		file_offset += len(chunk)
	return count, records


# ------------------------------- Case & Report -------------------------------

def init_case(path: str) -> int:
	abs_path = os.path.abspath(path)
	os.makedirs(abs_path, exist_ok=True)
	for sub in ["evidence", "carved", "manifests", "reports", "notes"]:
		os.makedirs(os.path.join(abs_path, sub), exist_ok=True)
	print(f"[ok] Case initialized at {abs_path}")
	return 0


def _find_manifests(case_dir: str) -> List[str]:
	manifests: List[str] = []
	for pattern in [
		os.path.join(case_dir, "**", "*.manifest.json"),
		os.path.join(case_dir, "**", "carve.manifest.json"),
	]:
		manifests.extend(glob(pattern, recursive=True))
	return sorted(set(os.path.abspath(p) for p in manifests))


def generate_report(case_dir: str, output_path: Optional[str] = None) -> int:
	case_dir_abs = os.path.abspath(case_dir)
	if not os.path.isdir(case_dir_abs):
		print(f"[error] Not a directory: {case_dir_abs}")
		return 2

	manifests = _find_manifests(case_dir_abs)
	if not manifests:
		print("[info] No manifests found to report")
		return 0

	report: Dict[str, object] = {
		"case_dir": case_dir_abs,
		"manifests": [],
	}
	for mpath in manifests:
		try:
			with open(mpath, "r", encoding="utf-8") as fp:
				content = json.load(fp)
			report["manifests"].append({"path": mpath, "content": content})
		except Exception as exc:
			report["manifests"].append({"path": mpath, "error": str(exc)})

	if output_path is None:
		output_path = os.path.join(case_dir_abs, "report.json")

	with open(output_path, "w", encoding="utf-8") as out:
		json.dump(report, out, indent=2)
	print(f"[ok] Report written: {output_path}")
	return 0


# ------------------------------------ CLI -----------------------------------

def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		prog="forensica",
		description=(
			"Forensica - A modular, evidence-first data recovery tool for digital forensics"
		),
	)

	sub = parser.add_subparsers(dest="command", required=True)

	# image
	p_image = sub.add_parser(
		"image",
		description="Acquire a bit-for-bit image from a source (file or block device) to a destination file",
	)
	p_image.add_argument("source", help="Path to source device or image file")
	p_image.add_argument("destination", help="Output image file path (raw)")
	p_image.add_argument(
		"--chunk-size",
		type=str,
		default="4MiB",
		help="Read/write chunk size (e.g., 1MiB, 4MiB, 8MiB)",
	)
	p_image.add_argument(
		"--force",
		action="store_true",
		help="Overwrite destination if it exists",
	)
	p_image.add_argument(
		"--manifest",
		type=str,
		default=None,
		help="Manifest JSON output path (defaults to destination + .manifest.json)",
	)

	# verify
	p_verify = sub.add_parser(
		"verify",
		description="Verify the integrity of an image against a manifest or print hashes",
	)
	p_verify.add_argument("path", help="File/image to hash or verify")
	p_verify.add_argument(
		"--manifest",
		type=str,
		default=None,
		help="If provided, compare computed hashes to a manifest JSON",
	)

	# partitions
	p_part = sub.add_parser(
		"partitions",
		description="Parse and display MBR/GPT partitions from an image or device",
	)
	p_part.add_argument("path", help="Path to block device or image file")
	p_part.add_argument(
		"--json",
		action="store_true",
		help="Emit JSON instead of human-readable output",
	)

	# carve
	p_carve = sub.add_parser(
		"carve",
		description="File carving by signature from unstructured image or device",
	)
	p_carve.add_argument("source", help="Path to source image or device")
	p_carve.add_argument("output_dir", help="Directory to write recovered files")
	p_carve.add_argument(
		"--types",
		type=str,
		default="jpeg,png,pdf,zip",
		help="Comma-separated types to carve (supported: jpeg,png,pdf,zip)",
	)
	p_carve.add_argument(
		"--max-size",
		type=str,
		default="256MiB",
		help="Maximum size of carved file",
	)
	p_carve.add_argument(
		"--min-size",
		type=str,
		default="1KiB",
		help="Minimum size of carved file",
	)
	p_carve.add_argument(
		"--manifest",
		type=str,
		default=None,
		help="Carving manifest output path (defaults to output_dir/carve.manifest.json)",
	)

	# hash
	p_hash = sub.add_parser(
		"hash",
		description="Compute cryptographic hashes for a file",
	)
	p_hash.add_argument("path", help="Path to file")
	p_hash.add_argument(
		"--algos",
		type=str,
		default="sha256,blake2b",
		help="Comma-separated list of algorithms (sha256, sha1, md5, blake2b)",
	)

	# case management
	p_case = sub.add_parser(
		"case",
		description="Case utilities (init/report)",
	)
	sub_case = p_case.add_subparsers(dest="case_cmd", required=True)
	p_case_init = sub_case.add_parser("init", description="Initialize a case folder structure")
	p_case_init.add_argument("path", help="Path to create the case directory")

	p_case_report = sub_case.add_parser("report", description="Generate a simple case report")
	p_case_report.add_argument("case_dir", help="Case directory (will scan for manifests)")
	p_case_report.add_argument(
		"--output",
		type=str,
		default=None,
		help="Output report path (defaults to case_dir/report.json)",
	)

	return parser


def parse_size(size_str: str) -> int:
	units = [
		("kib", 1024),
		("mib", 1024 ** 2),
		("gib", 1024 ** 3),
		("kb", 1000),
		("mb", 1000 ** 2),
		("gb", 1000 ** 3),
		("b", 1),
	]
	s = size_str.strip().lower().replace(" ", "")
	for suffix, factor in units:
		if s.endswith(suffix):
			val = float(s[: -len(suffix)].strip())
			return int(val * factor)
	# plain integer bytes
	return int(float(s))


def _sanitize_ipython_argv(argv: List[str]) -> List[str]:
	cleaned: List[str] = []
	skip_next = False
	for i, a in enumerate(argv):
		if skip_next:
			skip_next = False
			continue
		# Jupyter/IPython often passes '-f <kernel.json>' or just the kernel json
		if a == "-f" and i + 1 < len(argv):
			skip_next = True
			continue
		if a.lower().endswith(".json") and ("kernel" in a.lower() or "jupyter" in a.lower()):
			continue
		cleaned.append(a)
	return cleaned


def main(argv: Optional[List[str]] = None) -> int:
	if argv is None:
		argv = sys.argv[1:]
	argv = _sanitize_ipython_argv(argv)
	parser = build_parser()
	args = parser.parse_args(argv)

	if args.command == "image":
		chunk_size = parse_size(args.chunk_size)
		return image_source(
			source_path=args.source,
			destination_path=args.destination,
			chunk_size=chunk_size,
			force_overwrite=args.force,
			manifest_path=args.manifest,
		)
	elif args.command == "verify":
		return verify_image(args.path, manifest_path=args.manifest)
	elif args.command == "partitions":
		return list_partitions(args.path, output_json=getattr(args, "json", False))
	elif args.command == "carve":
		max_size = parse_size(args.max_size)
		min_size = parse_size(args.min_size)
		selected = [t.strip() for t in args.types.split(",") if t.strip()]
		return carve_image(
			source_path=args.source,
			output_dir=args.output_dir,
			signature_types=selected,
			max_file_size=max_size,
			min_file_size=min_size,
			manifest_path=args.manifest,
		)
	elif args.command == "hash":
		algos = [a.strip() for a in args.algos.split(",") if a.strip()]
		digests = hash_file_multi(args.path, algorithms=algos)
		for algo, hexdigest in digests.items():
			print(f"{algo}: {hexdigest}")
		return 0
	elif args.command == "case":
		if args.case_cmd == "init":
			return init_case(args.path)
		elif args.case_cmd == "report":
			return generate_report(args.case_dir, output_path=args.output)
		else:
			parser.print_help()
			return 2
	else:
		parser.print_help()
		return 2


if __name__ == "__main__":
	sys.exit(main())