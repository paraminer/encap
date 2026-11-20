import importlib.util
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "encap.py"
SPEC = importlib.util.spec_from_file_location("encap_wireguard_test", SOURCE)
ENCAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENCAP)

PROFILE = """[Interface]
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=
Address = 10.77.77.3/32
MTU = 1280
Table = off

[Peer]
PublicKey = bPKScysvFEBAgBczTFKiN2caUfsRXDUCNfFwZYLUmXM=
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 20
"""


class FakeSystem:
    """Stands in for sudo, wireguard-go, wg and ifconfig; records each command."""

    def __init__(self, run_dir, fail=None):
        self.run_dir = run_dir
        self.fail = fail
        self.commands = []
        self.inputs = []
        self.sockets = []

    def __call__(self, args, timeout=30, check=True, input=None):
        args = list(args)
        if args[:2] == ["sudo", "-n"]:
            args = args[2:]
        self.commands.append(args)
        if input is not None:
            self.inputs.append(input)
        code, out = 0, ""
        name = Path(args[0]).name
        if self.fail and self.fail == args[:len(self.fail)]:
            code = 1
        elif name == "env":
            marker = Path(args[1].split("=", 1)[1])
            marker.write_text("utun9\n")
            sock = socket.socket(socket.AF_UNIX)
            sock.bind(str(self.run_dir / "utun9.sock"))
            self.sockets.append(sock)
        elif name == "cat":
            path = Path(args[1])
            code, out = (0, path.read_text()) if path.exists() else (1, "")
        elif name == "rm":
            for item in args[2:]:
                Path(item).unlink(missing_ok=True)
        elif name == "ifconfig" and len(args) == 2:
            code = 0 if (self.run_dir / "utun9.sock").exists() else 1
            out = f"{args[1]}: flags=8051<UP> mtu 1500\n"
        if check and code:
            raise ENCAP.EncapError(f"{name} failed")
        return subprocess.CompletedProcess(args, code, out, "")


class WireGuardTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name)
        self.profile = self.run_dir / "e-test.conf"
        self.profile.write_text(PROFILE)
        self.config = {"profile": str(self.profile), "wireguard_go": "/bin/wireguard-go", "wg": "/bin/wg"}
        patcher = patch.object(ENCAP, "WIREGUARD_RUN", self.run_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def system(self, **options):
        fake = FakeSystem(self.run_dir, **options)
        patcher = patch.object(ENCAP, "run", fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(lambda: [sock.close() for sock in fake.sockets])
        return fake

    def test_up_matches_wg_quick(self):
        fake = self.system()
        self.assertEqual(ENCAP.wireguard_up(self.config), "utun9")
        marker = str(self.run_dir / "e-test.name")
        commands = [command for command in fake.commands if command[0] != "cat"]
        self.assertEqual(commands, [
            ["mkdir", "-p", str(self.run_dir)],
            ["/usr/bin/env", f"WG_TUN_NAME_FILE={marker}", "/bin/wireguard-go", "utun"],
            ["/bin/wg", "addconf", "utun9", "/dev/stdin"],
            ["ifconfig", "utun9", "inet", "10.77.77.3/32", "10.77.77.3", "alias"],
            ["ifconfig", "utun9", "mtu", "1280"],
            ["ifconfig", "utun9", "up"],
        ])
        config = fake.inputs[0]
        self.assertIn("PrivateKey", config)
        self.assertIn("Endpoint = 127.0.0.1:51820", config)
        for key in ("Address", "MTU", "Table"):
            self.assertNotIn(key, config)
        self.assertTrue(ENCAP.profile_active(self.profile))

    def test_down_removes_socket_and_marker(self):
        fake = self.system()
        ENCAP.wireguard_up(self.config)
        ENCAP.wireguard_down(self.profile)
        self.assertIn(["rm", "-f", str(self.run_dir / "utun9.sock")], fake.commands)
        self.assertIn(["rm", "-f", str(self.run_dir / "e-test.name")], fake.commands)
        self.assertFalse(ENCAP.profile_active(self.profile))

    def test_failed_setup_is_rolled_back(self):
        self.system(fail=["ifconfig", "utun9", "mtu"])
        with self.assertRaises(ENCAP.EncapError):
            ENCAP.wireguard_up(self.config)
        self.assertFalse(ENCAP.profile_active(self.profile))
        self.assertFalse((self.run_dir / "utun9.sock").exists())

    def test_stale_marker_without_interface_is_cleared(self):
        self.system()
        (self.run_dir / "e-test.name").write_text("utun9\n")
        ENCAP.wireguard_down(self.profile)
        self.assertFalse(ENCAP.profile_active(self.profile))

    def test_bundled_tools_win(self):
        bundled = self.run_dir / "bin"
        bundled.mkdir()
        tool = bundled / "wg"
        tool.write_text("#!/bin/sh\n")
        tool.chmod(0o755)
        with patch.object(ENCAP, "BUNDLED_BIN", bundled):
            self.assertEqual(ENCAP.resolve_binary("/opt/homebrew/bin/wg"), str(tool))
            self.assertEqual(ENCAP.resolve_binary("wg"), str(tool))


if __name__ == "__main__":
    unittest.main()
