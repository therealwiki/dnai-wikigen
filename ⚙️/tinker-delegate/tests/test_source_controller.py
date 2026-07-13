import json
import unittest
import unittest.mock

from tinker_delegate.source_controller import (
    SourceControllerError,
    SourceControllerRegistry,
    SourceGrant,
    SourceStatus,
)


def _grant(**kw) -> SourceGrant:
    base = dict(
        source_ref="source://tinker-account",
        controller_ref="tee-runtime",
        approved_by="owner-reviewer",
        scopes=("read", "spend"),
        granted_at=100,
        expires_at=0,
        revoked_at=0,
    )
    base.update(kw)
    return SourceGrant(**base)


class SourceGrantTest(unittest.TestCase):
    def test_self_approval_rejected(self):
        with self.assertRaises(SourceControllerError):
            _grant(controller_ref="same", approved_by="same")

    def test_empty_scopes_rejected(self):
        with self.assertRaises(SourceControllerError):
            _grant(scopes=())

    def test_expiry_before_grant_rejected(self):
        with self.assertRaises(SourceControllerError):
            _grant(granted_at=100, expires_at=50)

    def test_status_transitions(self):
        g = _grant(granted_at=100, expires_at=200, revoked_at=0)
        self.assertEqual(g.status(50), SourceStatus.NOT_YET_ACTIVE)
        self.assertEqual(g.status(150), SourceStatus.ACTIVE)
        self.assertEqual(g.status(200), SourceStatus.EXPIRED)
        revoked = _grant(granted_at=100, revoked_at=150)
        self.assertEqual(revoked.status(160), SourceStatus.REVOKED)

    def test_public_dict_hides_raw_refs(self):
        g = _grant(source_ref="source://secret-acct", controller_ref="secret-controller", approved_by="secret-owner")
        blob = json.dumps(g.to_public_dict(now=150))
        self.assertNotIn("secret-acct", blob)
        self.assertNotIn("secret-controller", blob)
        self.assertNotIn("secret-owner", blob)
        self.assertRegex(g.audit_hash(), r"^0x[0-9a-f]{64}$")


class SourceRegistryTest(unittest.TestCase):
    def test_authorize_active_in_scope(self):
        reg = SourceControllerRegistry((_grant(),))
        auth = reg.authorize("source://tinker-account", "spend", now=150)
        self.assertTrue(auth.allowed)
        self.assertEqual(auth.reason_code, "authorized")
        self.assertFalse(auth.raw_secret_egress)

    def test_authorize_out_of_scope_denied(self):
        reg = SourceControllerRegistry((_grant(scopes=("read",)),))
        auth = reg.authorize("source://tinker-account", "spend", now=150)
        self.assertFalse(auth.allowed)
        self.assertEqual(auth.reason_code, "scope_not_approved")

    def test_authorize_unknown_source_denied(self):
        reg = SourceControllerRegistry((_grant(),))
        auth = reg.authorize("source://other", "read", now=150)
        self.assertFalse(auth.allowed)
        self.assertEqual(auth.reason_code, "no_source_grant")

    def test_authorize_expired_denied(self):
        reg = SourceControllerRegistry((_grant(granted_at=100, expires_at=200),))
        auth = reg.authorize("source://tinker-account", "read", now=250)
        self.assertFalse(auth.allowed)
        self.assertEqual(auth.reason_code, "grant_expired")

    def test_authorize_revoked_denied(self):
        reg = SourceControllerRegistry((_grant(granted_at=100, revoked_at=150),))
        auth = reg.authorize("source://tinker-account", "read", now=200)
        self.assertFalse(auth.allowed)
        self.assertEqual(auth.reason_code, "grant_revoked")

    def test_duplicate_grant_rejected(self):
        with self.assertRaises(SourceControllerError):
            SourceControllerRegistry((_grant(), _grant(scopes=("read",))))

    def test_manifest_is_bounded(self):
        reg = SourceControllerRegistry((_grant(source_ref="source://secret-acct"),))
        manifest = reg.public_manifest(now=150)
        self.assertEqual(manifest["grant_count"], 1)
        self.assertFalse(manifest["raw_secret_egress"])
        self.assertNotIn("secret-acct", json.dumps(manifest))


class SourceRegistryFactoryTest(unittest.TestCase):
    def test_build_disabled_when_no_path(self):
        from tinker_delegate.config import Settings
        from tinker_delegate.source_controller import build_source_registry

        self.assertIsNone(build_source_registry(Settings()))

    def test_load_and_authorize_from_json(self):
        import tempfile
        from pathlib import Path

        from tinker_delegate.source_controller import build_source_registry
        from tinker_delegate.config import Settings

        grants = {
            "grants": [
                {
                    "source_ref": "source://tinker-account",
                    "controller_ref": "tee-runtime",
                    "approved_by": "owner-reviewer",
                    "scopes": ["tinker_compute"],
                    "granted_at": 0,
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grants.json"
            path.write_text(json.dumps(grants), encoding="utf-8")
            reg = build_source_registry(Settings(source_grants_path=str(path)))
            self.assertIsNotNone(reg)
            self.assertTrue(reg.authorize("source://tinker-account", "tinker_compute", now=10).allowed)

    def test_self_approving_grant_file_rejected(self):
        import tempfile
        from pathlib import Path

        from tinker_delegate.source_controller import load_source_registry, SourceControllerError

        bad = {
            "grants": [
                {
                    "source_ref": "source://x",
                    "controller_ref": "same",
                    "approved_by": "same",  # self-approval
                    "scopes": ["read"],
                    "granted_at": 0,
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaises(SourceControllerError):
                load_source_registry(path)


class ControlPlaneSourceGateTest(unittest.TestCase):
    def _make_cp(self, registry, *, source_ref="source://tinker-account", scope="tinker_compute"):
        from tinker_delegate.control_plane import ControlPlane

        cp = ControlPlane.__new__(ControlPlane)
        cp._deals = {}
        cp._run_metadata_store = None
        cp._source_registry = registry
        cp._source_ref = source_ref
        cp._source_scope = scope
        # Stub session/service-client creation so we only test the gate.
        cp._create_service_client = lambda: object()
        return cp

    def _active_grant(self, scope=("tinker_compute",)):
        return SourceGrant(
            source_ref="source://tinker-account",
            controller_ref="tee-runtime",
            approved_by="owner-reviewer",
            scopes=scope,
            granted_at=0,
        )

    def test_no_registry_allows_use(self):
        cp = self._make_cp(None)
        # No gate configured -> deal-funded proceeds (session created).
        with unittest.mock.patch("tinker_delegate.control_plane.IsolatedTinkerSession", lambda *a, **k: object()):
            ctx = cp.on_deal_funded("deal-1", "b", "s", 10**18, 10**15)
        self.assertIsNotNone(ctx)

    def test_active_grant_allows_use(self):
        reg = SourceControllerRegistry((self._active_grant(),))
        cp = self._make_cp(reg)
        with unittest.mock.patch("tinker_delegate.control_plane.IsolatedTinkerSession", lambda *a, **k: object()):
            ctx = cp.on_deal_funded("deal-1", "b", "s", 10**18, 10**15)
        self.assertIsNotNone(ctx)

    def test_out_of_scope_grant_denies_use(self):
        from tinker_delegate.control_plane import SourceAccessDenied

        reg = SourceControllerRegistry((self._active_grant(scope=("read",)),))
        cp = self._make_cp(reg)
        with self.assertRaises(SourceAccessDenied):
            cp.on_deal_funded("deal-1", "b", "s", 10**18, 10**15)
        self.assertEqual(cp._deals, {})  # no session created

    def test_revoked_grant_denies_use(self):
        from tinker_delegate.control_plane import SourceAccessDenied

        revoked = SourceGrant(
            source_ref="source://tinker-account",
            controller_ref="tee-runtime",
            approved_by="owner-reviewer",
            scopes=("tinker_compute",),
            granted_at=0,
            revoked_at=1,
        )
        cp = self._make_cp(SourceControllerRegistry((revoked,)))
        with self.assertRaises(SourceAccessDenied):
            cp.on_deal_funded("deal-1", "b", "s", 10**18, 10**15)


if __name__ == "__main__":
    import unittest.mock  # noqa: F401
    unittest.main()
