import json
import os
from glob import glob
from typing import Dict, List, Optional


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