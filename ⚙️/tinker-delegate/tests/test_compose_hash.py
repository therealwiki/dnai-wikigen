from pathlib import Path
import tempfile
import unittest

from tinker_delegate.compose_hash import (
    ComposeHashError,
    ComposeHashResult,
    ImageDigest,
    _extract_digest_images,
    _parse_env_keys,
    dump_app_compose,
    phala_compose_hash,
    verify_compose_hash,
)


class ComposeHashTest(unittest.TestCase):
    def test_phala_hash_uses_sorted_preprocessed_manifest(self):
        app_compose = {
            "runner": "docker-compose",
            "bash_script": "ignored for docker compose",
            "pre_launch_script": "",
            "docker_compose_file": "services:\n  app:\n    image: example/app@sha256:abc\n",
            "allowed_envs": ["B", "A"],
        }

        canonical = dump_app_compose(app_compose)

        self.assertNotIn("bash_script", canonical)
        self.assertNotIn("pre_launch_script", canonical)
        self.assertIn('"allowed_envs":', canonical)
        self.assertEqual(
            phala_compose_hash(app_compose),
            "290ca10cdccb3949a882397bac8165d56500f97ef02847e1757ece33ed8dcd6e",
        )

    def test_extract_digest_images_rejects_build_contexts_and_mutable_tags(self):
        config = {
            "services": {
                "buildy": {"build": {"context": "."}, "image": "example/buildy@sha256:" + "a" * 64},
                "tagged": {"image": "example/tagged:latest"},
            }
        }

        with self.assertRaisesRegex(ComposeHashError, "build services"):
            _extract_digest_images(config, allow_tags=False)

        del config["services"]["buildy"]
        with self.assertRaisesRegex(ComposeHashError, "digest-pinned"):
            _extract_digest_images(config, allow_tags=False)

    def test_extract_digest_images_accepts_digest_pinned_services(self):
        digest = "b" * 64
        images = _extract_digest_images(
            {"services": {"app": {"image": f"example/app@sha256:{digest}"}}},
            allow_tags=False,
        )

        self.assertEqual(images[0].service, "app")
        self.assertEqual(images[0].image, f"example/app@sha256:{digest}")

    def test_parse_env_keys_preserves_file_order_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / "runtime.env"
            env_file.write_text(
                "\n".join(
                    [
                        "# comment",
                        "export FIRST=one",
                        "SECOND=two # inline comment is kept in value only",
                        "FIRST=override",
                    ]
                ),
                encoding="utf-8",
            )

            self.assertEqual(_parse_env_keys(env_file), ["FIRST", "SECOND"])

    def test_public_result_omits_rendered_app_compose(self):
        result = ComposeHashResult(
            compose_hash="c" * 64,
            rendered_compose_sha256="d" * 64,
            images=(ImageDigest(service="app", image="example/app@sha256:" + "e" * 64),),
            app_compose={
                "runner": "docker-compose",
                "docker_compose_file": "services:\n  app:\n    environment:\n      SECRET=hidden\n",
                "allowed_envs": ["TINKER_API_KEY"],
            },
        )

        public = result.to_public_dict()

        self.assertNotIn("app_compose", public)
        self.assertNotIn("docker_compose_file", public)
        self.assertEqual(public["runner"], "docker-compose")
        self.assertEqual(public["allowed_envs"], ["TINKER_API_KEY"])

    def test_phala_raw_compose_hash_uses_source_text_and_allowed_envs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            compose = Path(tmpdir) / "compose.yaml"
            compose.write_text(
                "\n".join(
                    [
                        "services:",
                        "  app:",
                        "    image: ${APP_IMAGE:-example/app@sha256:" + ("a" * 64) + "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            expected = phala_compose_hash({
                "runner": "docker-compose",
                "docker_compose_file": compose.read_text(encoding="utf-8"),
                "allowed_envs": ["APP_IMAGE"],
            })
            result = verify_compose_hash(
                compose,
                expected_hash=expected,
                allowed_envs=["APP_IMAGE"],
                phala_raw_compose=True,
                allow_tags=False,
            )

        self.assertEqual(result.compose_hash, expected)
        self.assertEqual(result.images[0].image, "example/app@sha256:" + ("a" * 64))


if __name__ == "__main__":
    unittest.main()
