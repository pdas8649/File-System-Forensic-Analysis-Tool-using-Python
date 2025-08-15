import os

def init_case(path: str) -> int:
	abs_path = os.path.abspath(path)
	os.makedirs(abs_path, exist_ok=True)
	for sub in ["evidence", "carved", "manifests", "reports", "notes"]:
		os.makedirs(os.path.join(abs_path, sub), exist_ok=True)
	print(f"[ok] Case initialized at {abs_path}")
	return 0