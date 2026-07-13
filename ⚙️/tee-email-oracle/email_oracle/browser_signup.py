"""Standalone browser-based signup using playwright CDP to neko.

This module is used when you want to interactively test or debug the
signup flow through a real browser in the neko container.

Usage:
    python -m email_oracle.browser_signup [--cdp-url http://localhost:9222]
"""

import asyncio

from email_oracle.account_creator import signup_browser
from email_oracle.config import Settings
from email_oracle.cred_store import CredentialStore
from email_oracle.redaction import hash_text


async def main():
    import argparse

    parser = argparse.ArgumentParser(description="Browser signup via neko CDP")
    parser.add_argument("--cdp-url", default="http://localhost:9222", help="CDP endpoint URL")
    parser.add_argument("--domain", default="cock.email", help="Email domain")
    parser.add_argument("--cred-store", default="./data/credentials.enc", help="Credential store path")
    parser.add_argument("--cred-key", default="", help="Credential store key (hex)")
    args = parser.parse_args()

    settings = Settings(
        cdp_url=args.cdp_url,
        cockli_domain=args.domain,
        cred_store_path=args.cred_store,
        cred_store_key=args.cred_key,
    )
    store = CredentialStore(
        settings.cred_store_path,
        settings.cred_store_key,
        dstack_enabled=settings.dstack_enabled,
        dstack_key_path=settings.dstack_key_path,
    )

    creds = await signup_browser(settings)
    store.save(creds)
    print(f"\nAccount created email_hash={hash_text(creds.email)}")
    print(f"Credentials saved to: {settings.cred_store_path}")


if __name__ == "__main__":
    asyncio.run(main())
