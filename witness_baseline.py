"""Test-only sovereign authority and harmless list-files receipt."""

from hashlib import sha256
from hmac import compare_digest, new
import json
import os
from pathlib import Path
import sys


def stamp(body, key):
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + new(key, raw, sha256).hexdigest()


def main():
    lane = sys.argv[1]
    request = json.load(sys.stdin)
    if lane == "authority":
        names = list(json.loads(Path(__file__).with_name("baseline_catalog.json").read_text())["tools"])
        secret = os.environ["HMT_TEST_AUTHORITY_KEY"].encode()
        verified = compare_digest(request.pop("mac"), stamp(request, secret))
        allowed = verified and request["principal_id"] == "operator" and not Path("revoked").exists()
        if request["operation"] == "admit_call":
            allowed = allowed and request["tool_name"] == "list_files"
        reply = {
            "schema_version": "1.0.0", "request_id": request["request_id"],
            "decision": "ADMIT" if allowed else "DENY", "reason_codes": ["TEST_FIXTURE"],
            "visible_tools": [entry["name"] for entry in names] if allowed and request["operation"] == "visibility" else [],
            "lease_id": "fixture-lease" if allowed else None, "epoch_digest": "sha256:" + "e" * 64 if allowed else None,
        }
        print(json.dumps(reply | {"mac": stamp(reply, secret)}))
    elif lane == "tool" and request["tool_name"] == "list_files":
        with Path("effects").open("a", encoding="utf-8") as log:
            log.write("1\n")
        print('{"status":"PASS","reason_codes":["TEST_FIXTURE"],"paths":["example.txt"]}')


if __name__ == "__main__":
    main()
