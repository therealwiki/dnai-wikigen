"""Phala compose-hash verifier for registry-image deployments."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ComposeHashError(RuntimeError):
    """Raised when compose-hash input cannot be verified."""


@dataclass(frozen=True)
class ImageDigest:
    service: str
    image: str


@dataclass(frozen=True)
class ComposeHashResult:
    compose_hash: str
    rendered_compose_sha256: str
    images: tuple[ImageDigest, ...]
    app_compose: dict[str, Any]

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "compose_hash": self.compose_hash,
            "rendered_compose_sha256": self.rendered_compose_sha256,
            "images": [
                {"service": image.service, "image": image.image}
                for image in self.images
            ],
            "runner": self.app_compose.get("runner"),
            "allowed_envs": self.app_compose.get("allowed_envs", []),
        }


def _sort_object(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, list):
        return [_sort_object(item) for item in value]
    if isinstance(value, dict):
        return {key: _sort_object(value[key]) for key in sorted(value)}
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _preprocess_app_compose(app_compose: dict[str, Any]) -> dict[str, Any]:
    value = dict(app_compose)
    if value.get("runner") == "bash" and "docker_compose_file" in value:
        value.pop("docker_compose_file")
    elif value.get("runner") == "docker-compose" and "bash_script" in value:
        value.pop("bash_script")
    if "pre_launch_script" in value and not value["pre_launch_script"]:
        value.pop("pre_launch_script")
    return value


def dump_app_compose(app_compose: dict[str, Any]) -> str:
    """Return the canonical JSON string used by the Phala Cloud SDK."""
    ordered = _sort_object(_preprocess_app_compose(app_compose))
    rendered = json.dumps(ordered, indent=4, ensure_ascii=False, allow_nan=False)
    return rendered.replace('": ', '":')


def phala_compose_hash(app_compose: dict[str, Any]) -> str:
    """Compute the Phala Cloud compose hash for an app-compose object."""
    return hashlib.sha256(dump_app_compose(app_compose).encode("utf-8")).hexdigest()


def _docker_compose_args(compose_path: Path, env_files: list[Path]) -> list[str]:
    args = ["docker", "compose"]
    for env_file in env_files:
        args.extend(["--env-file", str(env_file)])
    args.extend(["-f", str(compose_path), "config"])
    return args


def _run_compose_config(compose_path: Path, env_files: list[Path], *, as_json: bool) -> str:
    args = _docker_compose_args(compose_path, env_files)
    if as_json:
        args.extend(["--format", "json"])
    try:
        return subprocess.check_output(
            args,
            cwd=str(compose_path.parent),
            stderr=subprocess.STDOUT,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise ComposeHashError(exc.output.strip() or "docker compose config failed") from exc


def _parse_env_keys(env_file: Path) -> list[str]:
    keys: list[str] = []
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key and key not in keys:
            keys.append(key)
    return keys


def _extract_digest_images(compose_config: dict[str, Any], *, allow_tags: bool) -> tuple[ImageDigest, ...]:
    services = compose_config.get("services")
    if not isinstance(services, dict) or not services:
        raise ComposeHashError("compose config has no services")

    images: list[ImageDigest] = []
    mutable_images: list[str] = []
    build_services: list[str] = []
    for service, spec in sorted(services.items()):
        if not isinstance(spec, dict):
            raise ComposeHashError(f"service {service} must be an object")
        if spec.get("build") is not None:
            build_services.append(str(service))
        image = spec.get("image")
        if not isinstance(image, str) or not image.strip():
            raise ComposeHashError(f"service {service} has no image")
        image = image.strip()
        images.append(ImageDigest(service=str(service), image=image))
        if "@sha256:" not in image:
            mutable_images.append(f"{service}={image}")

    if build_services:
        raise ComposeHashError(
            "compose hash verification requires registry images; build services: "
            + ", ".join(build_services)
        )
    if mutable_images and not allow_tags:
        raise ComposeHashError(
            "all service images must be digest-pinned with @sha256: "
            + ", ".join(mutable_images)
        )
    return tuple(images)


def verify_compose_hash(
    compose_path: Path,
    *,
    env_files: list[Path] | None = None,
    expected_hash: str = "",
    allowed_env_file: Path | None = None,
    allowed_envs: list[str] | None = None,
    phala_raw_compose: bool = False,
    allow_tags: bool = False,
) -> ComposeHashResult:
    """Render compose, verify image digests, and compute the Phala compose hash."""
    compose_path = compose_path.resolve()
    if not compose_path.exists():
        raise ComposeHashError(f"compose file not found: {compose_path}")
    env_files = [env_file.resolve() for env_file in (env_files or [])]
    for env_file in env_files:
        if not env_file.exists():
            raise ComposeHashError(f"env file not found: {env_file}")

    rendered_compose = _run_compose_config(compose_path, env_files, as_json=False)
    rendered_json = _run_compose_config(compose_path, env_files, as_json=True)
    try:
        compose_config = json.loads(rendered_json)
    except json.JSONDecodeError as exc:
        raise ComposeHashError("docker compose JSON output could not be parsed") from exc

    images = _extract_digest_images(compose_config, allow_tags=allow_tags)
    docker_compose_file = (
        compose_path.read_text(encoding="utf-8") if phala_raw_compose else rendered_compose
    )
    app_compose: dict[str, Any] = {
        "runner": "docker-compose",
        "docker_compose_file": docker_compose_file,
    }
    allowed_env_names = list(allowed_envs or [])
    if allowed_env_file is not None:
        allowed_env_file = allowed_env_file.resolve()
        if not allowed_env_file.exists():
            raise ComposeHashError(f"allowed env file not found: {allowed_env_file}")
        allowed_env_names.extend(_parse_env_keys(allowed_env_file))
    if allowed_env_names:
        app_compose["allowed_envs"] = list(dict.fromkeys(allowed_env_names))

    actual_hash = phala_compose_hash(app_compose)
    if expected_hash and actual_hash != expected_hash:
        raise ComposeHashError(
            f"compose hash mismatch: expected {expected_hash}, computed {actual_hash}"
        )

    return ComposeHashResult(
        compose_hash=actual_hash,
        rendered_compose_sha256=hashlib.sha256(rendered_compose.encode("utf-8")).hexdigest(),
        images=images,
        app_compose=app_compose,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify a registry-image compose file and compute its Phala compose hash.",
    )
    parser.add_argument("--compose", required=True, help="Docker Compose file to render")
    parser.add_argument(
        "--env-file",
        action="append",
        default=[],
        help="Environment file used by docker compose config; repeatable",
    )
    parser.add_argument(
        "--allowed-env-file",
        default="",
        help="Runtime env file whose keys should be included as allowed_envs",
    )
    parser.add_argument(
        "--allowed-env",
        action="append",
        default=[],
        help="Runtime env key included as an encrypted Phala allowed_env; repeatable",
    )
    parser.add_argument(
        "--phala-raw-compose",
        action="store_true",
        help="Hash the raw compose source plus allowed_envs, matching Phala deploy",
    )
    parser.add_argument("--expected-hash", default="", help="Expected Phala compose hash")
    parser.add_argument(
        "--allow-tags",
        action="store_true",
        help="Allow mutable tag images; development only",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        result = verify_compose_hash(
            Path(args.compose),
            env_files=[Path(path) for path in args.env_file],
            expected_hash=args.expected_hash,
            allowed_env_file=Path(args.allowed_env_file) if args.allowed_env_file else None,
            allowed_envs=list(args.allowed_env),
            phala_raw_compose=args.phala_raw_compose,
            allow_tags=args.allow_tags,
        )
    except ComposeHashError as exc:
        print(f"[verify-compose-hash] rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result.to_public_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
