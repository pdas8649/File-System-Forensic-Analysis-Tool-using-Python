import os
import struct
import json
from typing import Dict, List, Optional, Tuple

_SECTOR_SIZE = 512

_MBR_TYPE_LABELS: Dict[int, str] = {
	0x00: "Empty",
	0x01: "FAT12",
	0x04: "FAT16 <32M",
	0x05: "Extended",
	0x06: "FAT16",
	0x07: "NTFS/exFAT/HPFS",
	0x0b: "FAT32 (CHS)",
	0x0c: "FAT32 (LBA)",
	0x0e: "FAT16 (LBA)",
	0x0f: "Extended (LBA)",
	0x82: "Linux swap",
	0x83: "Linux filesystem",
	0x8e: "Linux LVM",
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
		status = entry[0]
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


def _guid_str(g: bytes) -> str:
	# GUID bytes are in mixed-endian: first 3 fields little-endian
	a = struct.unpack_from("<I", g, 0)[0]
	b = struct.unpack_from("<H", g, 4)[0]
	c = struct.unpack_from("<H", g, 6)[0]
	d = g[8:10].hex()
	e = g[10:16].hex()
	return f"{a:08x}-{b:04x}-{c:04x}-{d}-{e}"


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