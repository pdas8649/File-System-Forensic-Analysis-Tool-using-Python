import argparse
import sys
from typing import Optional

from .imaging import image_source
from .carving import carve_image
from .partition import list_partitions
from .hashing import hash_file_multi


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


def main(argv: Optional[list[str]] = None) -> int:
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
		from .imaging import verify_image

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
			from .case import init_case

			return init_case(args.path)
		elif args.case_cmd == "report":
			from .report import generate_report

			return generate_report(args.case_dir, output_path=args.output)
		else:
			parser.print_help()
			return 2
	else:
		parser.print_help()
		return 2


if __name__ == "__main__":
	sys.exit(main())