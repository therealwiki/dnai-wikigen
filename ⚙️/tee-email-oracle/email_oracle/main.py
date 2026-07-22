"""Email Oracle entrypoint.

Lifecycle:
  1. GENESIS: Create email account (if no credentials exist)
  2. OPERATION: Start FastAPI server for pin extraction

Commands:
  email-oracle genesis   — create account only
  email-oracle serve     — start API server (auto-genesis if needed)
  email-oracle check     — verify IMAP connectivity
"""

import argparse
import asyncio
import getpass
import json
import os
import sys

from email_oracle.config import Settings
from email_oracle.cred_store import CredentialStore
from email_oracle.redaction import hash_text, redact_text


def _emit_bounded_json(payload: dict, *, forbidden_values: tuple[str, ...] = ()) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    for value in forbidden_values:
        if value and len(value) >= 3 and value in rendered:
            raise ValueError("bounded CLI output contains submitted secret material")
    print(rendered)


def _prompt_credentials(prompt_fn=input, secret_prompt_fn=getpass.getpass) -> dict[str, str]:
    username = prompt_fn("Email username: ").strip()
    domain = prompt_fn("Email domain: ").strip()
    password = secret_prompt_fn("Email password / app password: ").strip()
    return {"username": username, "domain": domain, "password": password}


async def cmd_genesis(settings: Settings, store: CredentialStore) -> None:
    """Create a new email account."""
    if store.exists():
        creds = store.load()
        print(f"[genesis] credentials already exist email_hash={hash_text(creds.email)}")
        print("[genesis] delete the credential file to re-create")
        return

    from email_oracle.account_creator import create_account
    creds = await create_account(settings, store)
    print(f"[genesis] complete email_hash={hash_text(creds.email)}")


def cmd_serve(settings: Settings, store: CredentialStore) -> None:
    """Start the API server."""
    import uvicorn

    # Auto-genesis is useful for local demos but brittle in production: account
    # creation failures must not prevent bounded health/attestation endpoints
    # from serving.
    if not store.exists() and settings.auto_genesis:
        print("[serve] no credentials found, running genesis first...")
        asyncio.run(cmd_genesis(settings, store))

    if not store.exists() and settings.auto_genesis:
        print("[serve] genesis failed, cannot start server")
        sys.exit(1)
    if not store.exists():
        print("[serve] no credentials found, starting API in degraded mode")

    print(f"[serve] starting API on {settings.api_host}:{settings.api_port}")
    uvicorn.run(
        "email_oracle.api:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level="info",
    )


def cmd_check(settings: Settings, store: CredentialStore) -> None:
    """Verify IMAP connectivity."""
    if not store.exists():
        print("[check] no credentials found")
        sys.exit(1)

    creds = store.load()
    print(f"[check] testing IMAP email_hash={hash_text(creds.email)}")

    from email_oracle.imap_client import IMAPClient
    client = IMAPClient(creds, settings)
    try:
        client.connect()
        emails = client.list_recent(max_age_seconds=86400, limit=5)
        print(f"[check] IMAP OK — {len(emails)} recent emails")
        for e in emails:
            print(
                f"  {e['date']}  "
                f"from_hash={hash_text(e['from'])} "
                f"subject_hash={hash_text(e['subject'])}"
            )
    except Exception as e:
        print(f"[check] IMAP FAILED: {redact_text(e)}")
        sys.exit(1)
    finally:
        client.disconnect()


def cli():
    parser = argparse.ArgumentParser(
        prog="email-oracle",
        description="TEE Email Oracle — account creation + pin extraction",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("genesis", help="Create a new email account")
    sub.add_parser("serve", help="Start the API server")
    sub.add_parser("check", help="Verify IMAP connectivity")
    provision_p = sub.add_parser(
        "provision-credentials-encrypted-prompt",
        help=(
            "Prompt for mailbox credentials and provision locally; deployed TDX mode "
            "remains blocked until an independent quote verifier is integrated"
        ),
    )
    provision_p.add_argument("api_url", help="Email oracle API base URL")
    provision_p.add_argument(
        "--compose-hash",
        default="",
        help="Expected dstack compose hash; required unless --allow-local-attestation is set",
    )
    provision_p.add_argument("--app-id", default="", help="Expected dstack app ID")
    provision_p.add_argument("--os-image-hash", default="", help="Expected dstack OS image hash")
    provision_p.add_argument(
        "--allow-local-attestation",
        action="store_true",
        help="Allow local-mode attestation for development only",
    )
    provision_p.add_argument(
        "--token-env",
        default="ORACLE_CREDENTIAL_PROVISIONING_TOKEN",
        help="Environment variable containing the provisioning bearer token",
    )

    args = parser.parse_args()

    settings = Settings()
    store = None
    if args.command in {"genesis", "serve", "check"}:
        store = CredentialStore(
            settings.cred_store_path,
            settings.cred_store_key,
            dstack_enabled=settings.dstack_enabled,
            dstack_key_path=settings.dstack_key_path,
        )

    if args.command == "genesis":
        assert store is not None
        asyncio.run(cmd_genesis(settings, store))
    elif args.command == "serve":
        assert store is not None
        cmd_serve(settings, store)
    elif args.command == "check":
        assert store is not None
        cmd_check(settings, store)
    elif args.command == "provision-credentials-encrypted-prompt":
        from email_oracle.credential_uploader import (
            CredentialUploadError,
            CredentialUploadPolicy,
            credential_hashes,
            forbidden_credential_values,
            upload_credentials_payload,
        )

        if not args.allow_local_attestation and not args.compose_hash:
            print("[provision-credentials] --compose-hash is required unless local attestation is allowed")
            sys.exit(1)
        token = os.environ.get(args.token_env, "").strip()
        if not token:
            token = getpass.getpass("Credential provisioning bearer token: ").strip()
        credentials = _prompt_credentials()
        forbidden_values = forbidden_credential_values(credentials, token)
        try:
            result = upload_credentials_payload(
                args.api_url,
                credentials,
                token,
                CredentialUploadPolicy(
                    expected_compose_hash=args.compose_hash,
                    expected_app_id=args.app_id,
                    expected_os_image_hash=args.os_image_hash,
                    allow_local=args.allow_local_attestation,
                ),
            )
            response = {
                "status_code": result.status_code,
                "local_hashes": credential_hashes(credentials),
                "response": result.response,
                "raw_secret_egress": False,
            }
            _emit_bounded_json(response, forbidden_values=forbidden_values)
            sys.exit(0 if result.response.get("status") == "stored" else 1)
        except CredentialUploadError as exc:
            print(f"[provision-credentials] rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[provision-credentials] failed: {redact_text(exc)}")
            sys.exit(1)
        finally:
            for key in list(credentials):
                credentials[key] = ""
            token = ""


if __name__ == "__main__":
    cli()
