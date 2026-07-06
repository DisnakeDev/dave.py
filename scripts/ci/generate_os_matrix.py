import json
import re
from os import getenv

single = ["macos-26-intel", "macos-26", "windows-latest", "windows-11-arm"]
ubuntu_archs = {
    "ubuntu-latest": ["native", "ppc64le", "s390x", "riscv64"],
    "ubuntu-24.04-arm": ["native"],
}
# this will be the only one for now
crypto = ["openssl_3"]

matrix: list[dict[str, str]] = []

# simple os, nothing fancy
for os in single:
    matrix += [{"os": os}]

# linux runs on multiple archs and with/without musl
for os, archs in ubuntu_archs.items():
    for arch in archs:
        for libc in ["glibc", "musl"]:
            matrix += [{"os": os, "arch": arch, "libc": libc}]

# mix in crypto libraries into every entry
matrix = [{**m, "crypto": c} for m in matrix for c in crypto]

# add display names, these are just for displaying on GitHub
for m in matrix:
    m["display-name"] = ", ".join(filter(None, [m["os"], m.get("arch"), m.get("libc")]))
    # why on earth does GHA not have a `replace()` function
    m["artifact-tag"] = m["display-name"].replace(", ", "-")

# optionally filter only requested platforms

if plat_filter := getenv("PLATFORM_FILTER"):
    matrix = [m for m in matrix if re.search(plat_filter, m["artifact-tag"])]

print(json.dumps(matrix))
