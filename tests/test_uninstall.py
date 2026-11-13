import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "encap.py"
SPEC = importlib.util.spec_from_file_location("encap_uninstall_test", SOURCE)
ENCAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENCAP)


class UninstallTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "home"
        self.home.mkdir()
        state = self.home / ".local/state/encap"
        for name, value in (("STATE_DIR", state), ("STATE_FILE", state / "session.plist"), ("LOCK_FILE", state / "lock")):
            current = patch.object(ENCAP, name, value)
            current.start()
            self.addCleanup(current.stop)
        self.config = self.home / ".config/encap"
        self.config.mkdir(parents=True)
        (self.config / "config.json").write_text(json.dumps({
            "access_token_file": str(self.config / "device.token"),
            "tls_host": "example.test",
        }))
        (self.config / "device.token").write_text("private token")
        (self.config / "device.conf").write_text("private key")
        self.share = self.home / ".local/share/encap"
        (self.share / "bin").mkdir(parents=True)
        (self.share / "encap.py").write_text("client")
        self.local_bin = self.home / ".local/bin"
        self.local_bin.mkdir(parents=True)
        (self.local_bin / "encap").write_text("#!/bin/sh\n")
        (self.local_bin / "wstunnel").symlink_to(self.share / "bin/wstunnel")
        self.other = self.local_bin / "other-tool"
        self.other.write_text("keep")
        self.public = Path(self.temp.name) / "public/encap"
        self.public.parent.mkdir()
        self.public.write_text('#!/bin/sh\nexec "$HOME/.local/bin/encap" "$@"\n')

    def test_removes_client_and_credentials_but_keeps_other_tools(self):
        with patch.object(ENCAP, "release_public") as release:
            ENCAP.uninstall(home=self.home, public_paths=(self.public,))
        self.assertFalse(self.config.exists())
        self.assertFalse(self.share.exists())
        self.assertFalse((self.local_bin / "encap").exists())
        self.assertFalse((self.local_bin / "wstunnel").exists())
        self.assertFalse(self.public.exists())
        self.assertFalse((self.home / ".local/state/encap").exists())
        self.assertTrue(self.other.exists())
        release.assert_called_once()

    def test_failed_disconnect_preserves_installation(self):
        with patch.object(ENCAP, "load_state", return_value={"active": True}), patch.object(
            ENCAP, "disconnect", side_effect=ENCAP.EncapError("Could not restore network")
        ):
            with self.assertRaisesRegex(ENCAP.EncapError, "Could not restore network"):
                ENCAP.uninstall(home=self.home, public_paths=(self.public,))
        self.assertTrue(self.config.exists())
        self.assertTrue(self.share.exists())
        self.assertTrue(self.public.exists())

    def test_active_session_is_disconnected_before_removal(self):
        with patch.object(ENCAP, "load_state", side_effect=({"active": True}, None)), patch.object(
            ENCAP, "disconnect"
        ) as disconnect, patch.object(ENCAP, "release_public"):
            ENCAP.uninstall(home=self.home, public_paths=(self.public,))
        disconnect.assert_called_once_with()
        self.assertFalse(self.config.exists())

    def test_unknown_public_command_is_preserved(self):
        self.public.write_text("#!/bin/sh\necho unrelated\n")
        with patch.object(ENCAP, "release_public"):
            ENCAP.uninstall(home=self.home, public_paths=(self.public,))
        self.assertTrue(self.public.exists())


if __name__ == "__main__":
    unittest.main()
