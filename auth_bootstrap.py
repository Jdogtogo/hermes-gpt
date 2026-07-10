"""Local bootstrap for Hermes-GPT OAuth credentials.

The generated password is written only to a mode-0600 local file. This command
prints paths and status, never the password itself.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from operator_auth import AuthRuntimeConfig, bootstrap_credentials


def main() -> None:
    parser = argparse.ArgumentParser(description="Create Hermes-GPT OAuth login credentials.")
    parser.add_argument("--issuer-url", required=True)
    parser.add_argument("--resource-url", required=True)
    parser.add_argument("--root", default=str(Path.home() / ".hermes" / "auth" / "hermes-gpt"))
    parser.add_argument("--scope", default="hermes:operator")
    parser.add_argument("--username", default="justin")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    config = AuthRuntimeConfig(
        issuer_url=args.issuer_url.rstrip("/"),
        resource_server_url=args.resource_url.rstrip("/"),
        scope=args.scope,
        root=Path(args.root).expanduser().resolve(),
        username=args.username,
    )
    result = bootstrap_credentials(config, force=args.force)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
