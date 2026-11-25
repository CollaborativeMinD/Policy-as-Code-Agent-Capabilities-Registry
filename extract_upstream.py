"""Materialize only the pinned sovereign-port wheel from the supplied archive."""

import argparse
from pathlib import Path
from zipfile import ZipFile

from policy_engine import digest, require


WHEEL = "hmt_mcp_plus_server_kernel-1.0.0-py3-none-any.whl"
WHEEL_SHA256 = "19f4e7e02c3f1b53aeb99d65bfbf8c076e2b20725fec5488e11313731d04a206"
MEMBER = "hmt-mcp-plus-server-kernel/release/dist/" + WHEEL


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--directory", type=Path, default=Path("local-upstream"))
    args = parser.parse_args()
    with ZipFile(args.archive) as archive, archive.open(MEMBER) as member:
        wheel = member.read(1_048_577)
    require(len(wheel) <= 1_048_576 and digest(wheel) == WHEEL_SHA256, "UPSTREAM_WHEEL_PIN_MISMATCH")
    args.directory.mkdir(exist_ok=True)
    destination = args.directory / WHEEL
    with destination.open("xb") as output:
        output.write(wheel)
    print(destination)


if __name__ == "__main__":
    main()
