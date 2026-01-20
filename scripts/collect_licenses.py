import argparse
import importlib.metadata
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("vcpkg_installed_dir", type=Path)
parser.add_argument("crypto")
args = parser.parse_args()

LICENSE_PATHS: dict[str, Path] = {}

# vcpkg dependencies
vcpkg_deps = [
    "mlspp",
    "nlohmann-json",
    "boringssl" if args.crypto == "boringssl" else "openssl",
]
LICENSE_PATHS.update(
    {dep: (args.vcpkg_installed_dir / "share" / dep / "copyright") for dep in vcpkg_deps}
)

# libdave
LICENSE_PATHS["libdave"] = Path.cwd() / "libdave" / "LICENSE"

# nanobind
nanobind_files = importlib.metadata.files("nanobind")
assert nanobind_files
LICENSE_PATHS["nanobind"] = next(Path(f.locate()) for f in nanobind_files if f.name == "LICENSE")

for p in LICENSE_PATHS.values():
    if not p.is_file():
        raise RuntimeError(f"unable to find license file: {p}")

print(";".join(f"{dep}\\;{path}" for dep, path in LICENSE_PATHS.items()))
