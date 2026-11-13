import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def executable(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o755)


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home with space"
        self.home.mkdir()
        self.local_bin = self.home / ".local" / "bin"
        self.prefix = self.root / "Application Support" / "Homebrew"
        self.prefix_bin = self.prefix / "bin"
        self.fake_bin = self.root / "fake-bin"
        self.repo = self.root / "repo"
        self.repo.mkdir()
        shutil.copy2(ROOT / "bootstrap.sh", self.repo / "bootstrap.sh")
        shutil.copy2(ROOT / "encap.py", self.repo / "encap.py")
        executable(self.fake_bin / "uname", '#!/bin/sh\ncase "$1" in -s) echo Darwin ;; -m) echo arm64 ;; esac\n')
        executable(self.fake_bin / "brew", '#!/bin/sh\nif [ "$1" = --prefix ]; then printf "%s\\n" "$ENCAP_TEST_PREFIX"; fi\n')
        executable(self.fake_bin / "curl", '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; out=$1; fi; shift; done\nprintf archive > "$out"\n')
        executable(self.fake_bin / "netstat", '#!/bin/sh\nexit 0\n')
        executable(self.fake_bin / "tar", '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = -C ]; then shift; dest=$1; fi; shift; done\nprintf "#!/bin/sh\\nexit 0\\n" > "$dest/wstunnel"\nprintf license > "$dest/LICENSE"\n')
        executable(
            self.prefix_bin / "python3",
            f'#!/bin/sh\nif [ "$1" = - ]; then cat >/dev/null; exit 0; fi\nexec {shlex.quote(sys.executable)} "$@"\n',
        )

    def environment(self, *paths):
        env = os.environ.copy()
        env["HOME"] = str(self.home)
        env["ENCAP_TEST_PREFIX"] = str(self.prefix)
        env["PATH"] = ":".join([str(self.fake_bin), *map(str, paths), "/usr/bin", "/bin", "/usr/sbin", "/sbin"])
        return env

    def install(self, env):
        result = subprocess.run(
            ["/bin/sh", str(self.repo / "bootstrap.sh")],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Encap installed", result.stdout)
        self.assertNotIn("Tunnel open", result.stdout)
        return result

    def check_command(self, env, expected):
        result = subprocess.run(
            ["/bin/sh", "-c", "command -v encap; encap status"],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines()[0], str(expected))
        self.assertIn("Tunnel closed", result.stdout)

    def test_clean_install_in_existing_path(self):
        env = self.environment(self.local_bin)
        self.install(env)
        self.assertEqual((self.local_bin / "encap").read_text().splitlines()[0], "#!/bin/sh")
        self.check_command(env, self.local_bin / "encap")
        self.assertFalse((self.home / ".local/state/encap/session.plist").exists())

    def test_upgrade_replaces_bad_interpreter_and_preserves_registration(self):
        old = self.local_bin / "encap"
        executable(old, "#!/Users/27boz_i/Library/Application Support/encap/python\n")
        config = self.home / ".config/encap/config.json"
        config.parent.mkdir(parents=True)
        config.write_text("private config")
        token = config.with_name("device.token")
        token.write_text("private token")
        key = config.with_name("device.conf")
        key.write_text("private key")
        env = self.environment(self.local_bin)
        self.install(env)
        self.assertEqual(old.read_text().splitlines()[0], "#!/bin/sh")
        self.check_command(env, old)
        self.assertEqual(config.read_text(), "private config")
        self.assertEqual(token.read_text(), "private token")
        self.assertEqual(key.read_text(), "private key")

    def test_installs_public_launcher_when_local_bin_is_not_in_path(self):
        env = self.environment(self.prefix_bin)
        self.install(env)
        public = self.prefix_bin / "encap"
        self.assertEqual(public.read_text().splitlines()[0], "#!/bin/sh")
        self.check_command(env, public)
        executable(public, "#!/Users/27boz_i/Library/Application Support/encap/python\n")
        self.install(env)
        self.check_command(env, public)

    def test_upgrade_replaces_broken_local_symlink(self):
        old = self.local_bin / "encap"
        old.parent.mkdir(parents=True)
        old.symlink_to(self.home / "Library/Application Support/encap/old")
        env = self.environment(self.local_bin)
        self.install(env)
        self.assertFalse(old.is_symlink())
        self.check_command(env, old)


if __name__ == "__main__":
    unittest.main()
