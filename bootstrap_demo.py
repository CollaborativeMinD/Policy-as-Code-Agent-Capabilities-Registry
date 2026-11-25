"""Mint short-lived, separate local demo identities without printing credentials."""

import argparse
import os
from pathlib import Path
from secrets import token_urlsafe
from time import time

from policy_engine import digest
from registry_assets import asset


def render(tokens, expires):
    policy = asset("policy.example.toml").read_text(encoding="utf-8")
    for principal, token in tokens.items():
        policy = policy.replace(f"{principal.upper()}_SHA256", digest(token))
    return policy.replace("expires_at = 1", f"expires_at = {expires}").encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    root = parser.parse_args().directory
    root.mkdir(mode=0o700)
    tokens = {principal: token_urlsafe(32).encode() for principal in ("admin", "operator", "viewer")}
    for principal, token in tokens.items():
        descriptor = os.open(root / f"{principal}.token", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(token)
    policy = render(tokens, int(time()) + 3600)
    (root / "policy.toml").write_bytes(policy)
    print(digest(policy))


if __name__ == "__main__":
    main()
