from pathlib import Path
import subprocess
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "encap.py"
# The Python the installer pins; argparse behaviour differs between versions.
PINNED = Path.home() / ".local/share/encap/python/bin/python3"
PROBE = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location("encap", sys.argv[1])
encap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(encap)
encap.load_state = lambda: None
encap.banner = lambda: None
def reached(*args):
    raise SystemExit(42)
encap.enroll_public = reached
sys.argv = ["encap", "--config", "/nonexistent/encap.json"]
encap.main()
"""


class CommandLineTest(unittest.TestCase):
    def check(self, python):
        result = subprocess.run([str(python), "-I", "-c", PROBE, str(SOURCE)], capture_output=True, text=True, timeout=20)
        self.assertNotIn("invalid choice", result.stderr)
        self.assertEqual(result.returncode, 42, result.stderr)

    def test_bare_encap_opens_the_tunnel(self):
        self.check("python3")

    @unittest.skipUnless(PINNED.exists(), "pinned Python is not installed")
    def test_bare_encap_opens_the_tunnel_on_pinned_python(self):
        self.check(PINNED)


if __name__ == "__main__":
    unittest.main()
