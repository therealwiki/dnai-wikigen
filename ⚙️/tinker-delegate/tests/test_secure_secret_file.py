import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tinker_delegate.api_key_store import ApiKeyStore
from tinker_delegate.compute_provider_release import PINNED_TINKER_BASE_URL
from tinker_delegate.compute_tinker_provider import (
    _load_sealed_provider_configuration,
    _secure_sealed_file,
)
from tinker_delegate.config import Settings
from tinker_delegate.secure_secret_file import (
    SecureSecretFileError,
    read_secure_secret_file,
    secure_secret_file_exists,
    write_secure_secret_file,
)
from tinker_delegate.tinker_client_config_store import TinkerClientConfigStore


STORE_KEY_HEX = "88" * 32


class SecureSecretFileTest(unittest.TestCase):
    def test_short_writes_are_completed_and_both_file_and_directory_are_fsynced(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "secret.bin"
            payload = b"one complete bounded secret"
            real_write = os.write
            real_fsync = os.fsync
            synced_kinds: list[str] = []

            def short_write(descriptor: int, value) -> int:
                return real_write(descriptor, value[:3])

            def recording_fsync(descriptor: int) -> None:
                mode = os.fstat(descriptor).st_mode
                synced_kinds.append("directory" if stat.S_ISDIR(mode) else "file")
                real_fsync(descriptor)

            with (
                patch("tinker_delegate.secure_secret_file.os.write", side_effect=short_write),
                patch("tinker_delegate.secure_secret_file.os.fsync", side_effect=recording_fsync),
            ):
                write_secure_secret_file(path, payload, minimum=1, maximum=128)

            self.assertEqual(
                read_secure_secret_file(path, minimum=1, maximum=128),
                payload,
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertIn("file", synced_kinds)
            self.assertIn("directory", synced_kinds)
            lock_files = list(path.parent.glob(".dnai-secret-lock-*"))
            self.assertEqual(len(lock_files), 1)
            self.assertEqual(stat.S_IMODE(lock_files[0].stat().st_mode), 0o600)
            self.assertEqual(lock_files[0].stat().st_nlink, 1)
            self.assertEqual(lock_files[0].stat().st_size, 0)

    def test_failed_atomic_replace_retains_original_and_cleans_random_temporary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "secret.bin"
            write_secure_secret_file(path, b"original", minimum=1, maximum=128)

            with (
                patch(
                    "tinker_delegate.secure_secret_file.os.replace",
                    side_effect=OSError("injected replace failure"),
                ),
                self.assertRaises(SecureSecretFileError),
            ):
                write_secure_secret_file(path, b"replacement", minimum=1, maximum=128)

            self.assertEqual(
                read_secure_secret_file(path, minimum=1, maximum=128),
                b"original",
            )
            self.assertEqual(list(root.glob(".dnai-secret-*.tmp")), [])

    def test_no_clobber_publication_preserves_file_exists_signal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "secret.bin"
            write_secure_secret_file(path, b"original", minimum=1, maximum=128)

            with self.assertRaises(FileExistsError):
                write_secure_secret_file(
                    path,
                    b"replacement",
                    minimum=1,
                    maximum=128,
                    overwrite=False,
                )

            self.assertEqual(
                read_secure_secret_file(path, minimum=1, maximum=128),
                b"original",
            )

    def test_unsafe_mode_and_hard_link_are_rejected_for_read_exists_and_write(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "secret.bin"
            alias = Path(tmpdir) / "secret.alias"
            write_secure_secret_file(path, b"secret", minimum=1, maximum=128)

            path.chmod(0o640)
            for operation in (
                lambda: read_secure_secret_file(path, minimum=1, maximum=128),
                lambda: secure_secret_file_exists(path, minimum=1, maximum=128),
                lambda: write_secure_secret_file(path, b"new", minimum=1, maximum=128),
            ):
                with self.subTest(boundary="unsafe_mode"), self.assertRaises(
                    SecureSecretFileError
                ):
                    operation()

            path.chmod(0o600)
            os.link(path, alias)
            for operation in (
                lambda: read_secure_secret_file(path, minimum=1, maximum=128),
                lambda: write_secure_secret_file(path, b"new", minimum=1, maximum=128),
            ):
                with self.subTest(boundary="hard_link"), self.assertRaises(
                    SecureSecretFileError
                ):
                    operation()

    def test_destination_and_parent_symlinks_are_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"do-not-touch")
            target.chmod(0o600)
            destination = root / "secret.bin"
            destination.symlink_to(target)

            for operation in (
                lambda: read_secure_secret_file(destination, minimum=1, maximum=128),
                lambda: write_secure_secret_file(
                    destination,
                    b"replacement",
                    minimum=1,
                    maximum=128,
                ),
            ):
                with self.subTest(boundary="file_symlink"), self.assertRaises(
                    SecureSecretFileError
                ):
                    operation()
            self.assertEqual(target.read_bytes(), b"do-not-touch")

            real_parent = root / "real-parent"
            real_parent.mkdir(mode=0o700)
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(SecureSecretFileError):
                write_secure_secret_file(
                    linked_parent / "secret.bin",
                    b"secret",
                    minimum=1,
                    maximum=128,
                )
            self.assertEqual(list(real_parent.iterdir()), [])

    def test_intermediate_ancestor_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            real_ancestor = root / "real-ancestor"
            nested_parent = real_ancestor / "nested-parent"
            nested_parent.mkdir(parents=True, mode=0o700)
            linked_ancestor = root / "linked-ancestor"
            linked_ancestor.symlink_to(real_ancestor, target_is_directory=True)

            with self.assertRaises(SecureSecretFileError):
                write_secure_secret_file(
                    linked_ancestor / "nested-parent" / "secret.bin",
                    b"secret",
                    minimum=1,
                    maximum=128,
                )

            self.assertEqual(list(nested_parent.iterdir()), [])

    def test_path_replacement_during_read_is_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "secret.bin"
            canary = root / "canary.bin"
            payload = b"original-secret"
            write_secure_secret_file(path, payload, minimum=1, maximum=128)
            canary.write_bytes(b"attacker-content")
            canary.chmod(0o600)
            real_read = os.read
            replaced = False

            def replace_path_after_read(descriptor: int, size: int) -> bytes:
                nonlocal replaced
                result = real_read(descriptor, size)
                if not replaced:
                    path.unlink()
                    path.symlink_to(canary)
                    replaced = True
                return result

            with (
                patch(
                    "tinker_delegate.secure_secret_file.os.read",
                    side_effect=replace_path_after_read,
                ),
                self.assertRaises(SecureSecretFileError),
            ):
                read_secure_secret_file(path, minimum=1, maximum=128)

            self.assertTrue(path.is_symlink())
            self.assertEqual(canary.read_bytes(), b"attacker-content")

    def test_nonregular_destination_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fifo = Path(tmpdir) / "secret.bin"
            os.mkfifo(fifo, 0o600)
            fifo.chmod(0o600)

            for operation in (
                lambda: read_secure_secret_file(fifo, minimum=1, maximum=128),
                lambda: write_secure_secret_file(
                    fifo,
                    b"replacement",
                    minimum=1,
                    maximum=128,
                ),
            ):
                with self.subTest(boundary="fifo"), self.assertRaises(
                    SecureSecretFileError
                ):
                    operation()

    def test_preexisting_random_temporary_name_is_never_followed_or_replaced(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            token = "ab" * 16
            temporary = root / f".dnai-secret-{os.getpid()}-{token}.tmp"
            target = root / "attacker-target"
            target.write_bytes(b"unchanged")
            target.chmod(0o600)
            temporary.symlink_to(target)

            with (
                patch(
                    "tinker_delegate.secure_secret_file.secrets.token_hex",
                    return_value=token,
                ),
                self.assertRaises(SecureSecretFileError),
            ):
                write_secure_secret_file(
                    root / "secret.bin",
                    b"secret",
                    minimum=1,
                    maximum=128,
                )

            self.assertTrue(temporary.is_symlink())
            self.assertEqual(target.read_bytes(), b"unchanged")

    def test_writer_lock_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "secret.bin"
            digest = hashlib.sha256(path.name.encode("utf-8")).hexdigest()[:32]
            lock_path = root / f".dnai-secret-lock-{digest}"
            canary = root / "lock-canary"
            canary.write_bytes(b"unchanged")
            canary.chmod(0o600)
            lock_path.symlink_to(canary)

            with self.assertRaises(SecureSecretFileError):
                write_secure_secret_file(path, b"secret", minimum=1, maximum=128)

            self.assertFalse(path.exists())
            self.assertTrue(lock_path.is_symlink())
            self.assertEqual(canary.read_bytes(), b"unchanged")


class SealedStoreIntegrationTest(unittest.TestCase):
    def test_local_wrapping_keys_are_restart_stable_owner_only_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api_path = Path(tmpdir) / "tinker_api_key.enc"
            config_path = Path(tmpdir) / "tinker_client_config.enc"

            api_store = ApiKeyStore(str(api_path))
            config_store = TinkerClientConfigStore(str(config_path))
            api_key = bytes(api_store.key)
            config_key = bytes(config_store.key)
            api_store.save("tml-local-secret")
            config_store.save(project_id="proj-local", base_url=PINNED_TINKER_BASE_URL)

            for path in (
                api_path,
                api_path.with_suffix(".key"),
                config_path,
                config_path.with_suffix(".key"),
            ):
                with self.subTest(path=path.name):
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    self.assertEqual(path.stat().st_nlink, 1)

            reloaded_api = ApiKeyStore(str(api_path))
            reloaded_config = TinkerClientConfigStore(str(config_path))
            self.assertEqual(reloaded_api.key, api_key)
            self.assertEqual(reloaded_config.key, config_key)
            self.assertEqual(reloaded_api.load(), "tml-local-secret")
            self.assertEqual(reloaded_config.load()["project_id"], "proj-local")

    def test_unsafe_local_wrapping_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api_path = Path(tmpdir) / "tinker_api_key.enc"
            ApiKeyStore(str(api_path))
            key_path = api_path.with_suffix(".key")
            key_path.chmod(0o644)

            with self.assertRaises(SecureSecretFileError):
                ApiKeyStore(str(api_path))

        with tempfile.TemporaryDirectory() as tmpdir:
            api_path = Path(tmpdir) / "tinker_api_key.enc"
            key_path = api_path.with_suffix(".key")
            target = Path(tmpdir) / "attacker.key"
            target.write_text("11" * 32)
            target.chmod(0o600)
            key_path.symlink_to(target)

            with self.assertRaises(SecureSecretFileError):
                ApiKeyStore(str(api_path))

    def test_fresh_store_outputs_pass_the_exact_provider_gate_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api_path = Path(tmpdir) / "tinker_api_key.enc"
            config_path = Path(tmpdir) / "tinker_client_config.enc"
            settings = Settings(
                api_key_store_path=str(api_path),
                api_key_store_key=STORE_KEY_HEX,
                client_config_store_path=str(config_path),
                client_config_store_key=STORE_KEY_HEX,
            )
            ApiKeyStore(str(api_path), key_hex=STORE_KEY_HEX).save(
                "tml-provider-secret"
            )
            TinkerClientConfigStore(
                str(config_path),
                key_hex=STORE_KEY_HEX,
            ).save(
                project_id="proj-provider",
                base_url=PINNED_TINKER_BASE_URL,
            )

            self.assertEqual(_secure_sealed_file(api_path, maximum=4 * 1024), api_path)
            self.assertEqual(
                _secure_sealed_file(config_path, maximum=64 * 1024),
                config_path,
            )
            self.assertEqual(
                _load_sealed_provider_configuration(settings),
                ("tml-provider-secret", "proj-provider"),
            )


if __name__ == "__main__":
    unittest.main()
