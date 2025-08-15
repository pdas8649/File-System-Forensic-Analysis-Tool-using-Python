import hashlib
import os
from typing import Dict, Iterable, List

_SUPPORTED = {"md5", "sha1", "sha256", "blake2b"}


def _create_hashers(algorithms: Iterable[str]) -> Dict[str, "hashlib._Hash"]:
	hashers: Dict[str, "hashlib._Hash"] = {}
	for algo in algorithms:
		name = algo.lower()
		if name not in _SUPPORTED:
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