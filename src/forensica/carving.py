import mmap
import os
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


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
			_out_manifest(manifest_path, source_path, records)
			print(f"[ok] Carving manifest written: {manifest_path}")
			return 0
	except OSError as exc:
		print(f"[error] I/O error: {exc}")
		return 5


def _out_manifest(path: str, source_path: str, records: List[Dict[str, object]]) -> None:
	manifest = {
		"schema_version": 1,
		"source_path": os.path.abspath(source_path),
		"items": records,
	}
	with open(path, "w", encoding="utf-8") as fp:
		json.dump(manifest, fp, indent=2)


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