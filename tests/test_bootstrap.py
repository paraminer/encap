import os
import hashlib
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
        bootstrap = self.repo / "bootstrap.sh"
        fake_binary = b"#!/bin/sh\nexit 0\n"
        bootstrap.write_text(bootstrap.read_text().replace(
            "3c814a9b16481b6b17b9ea02b679b8b21454788da6c61366c4d26fca823c9feb",
            hashlib.sha256(fake_binary).hexdigest(),
        ))
        executable(self.fake_bin / "uname", '#!/bin/sh\ncase "$1" in -s) echo Darwin ;; -m) echo arm64 ;; esac\n')
        executable(self.fake_bin / "brew", '#!/bin/sh\nif [ "$1" = --prefix ]; then printf "%s\\n" "$ENCAP_TEST_PREFIX"; exit 0; fi\nif [ "$1" = install ]; then printf "%s\\n" "$*" >> "$ENCAP_TEST_BREW_LOG"; for tool in wg wg-quick wireguard-go; do printf "#!/bin/sh\\nexit 0\\n" > "$ENCAP_TEST_PREFIX/bin/$tool"; chmod +x "$ENCAP_TEST_PREFIX/bin/$tool"; done; fi\n')
        executable(self.fake_bin / "curl", '#!/bin/sh\nprintf "%s\\n" "$*" >> "$ENCAP_TEST_CURL_LOG"\nwhile [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; out=$1; fi; shift; done\nprintf archive > "$out"\n')
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
        env["ENCAP_TEST_BREW_LOG"] = str(self.root / "brew.log")
        env["ENCAP_TEST_CURL_LOG"] = str(self.root / "curl.log")
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

    def test_reinstall_reuses_verified_dependencies(self):
        env = self.environment(self.local_bin)
        self.install(env)
        self.assertEqual((self.root / "brew.log").read_text().count("wireguard-tools"), 1)
        self.assertEqual(len((self.root / "curl.log").read_text().splitlines()), 1)
        self.install(env)
        self.assertEqual((self.root / "brew.log").read_text().count("wireguard-tools"), 1)
        self.assertEqual(len((self.root / "curl.log").read_text().splitlines()), 1)

    def test_modified_cached_transport_is_redownloaded(self):
        env = self.environment(self.local_bin)
        self.install(env)
        (self.home / ".local/share/encap/bin/wstunnel").write_text("modified")
        self.install(env)
        self.assertEqual(len((self.root / "curl.log").read_text().splitlines()), 2)

    def test_existing_python_skips_brew_python(self):
        (self.prefix_bin / "python3").unlink()
        executable(self.fake_bin / "python3", f'#!/bin/sh\nif [ "$1" = - ]; then cat >/dev/null; exit 0; fi\nexec {shlex.quote(sys.executable)} "$@"\n')
        env = self.environment(self.local_bin)
        self.install(env)
        self.assertNotIn("python@3.14", (self.root / "brew.log").read_text())
        self.check_command(env, self.local_bin / "encap")

    def test_install_command_updates_current_zsh_path(self):
        env = self.environment()
        command = (
            f'/bin/sh {shlex.quote(str(self.repo / "bootstrap.sh"))}'
            ' && export PATH="$HOME/.local/bin:$PATH" && hash -r'
            ' && command -v encap && encap status'
        )
        result = subprocess.run(
            ["/bin/zsh", "-c", command], env=env,
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(str(self.local_bin / "encap"), result.stdout)
        self.assertIn("Tunnel closed", result.stdout)


if __name__ == "__main__":
    unittest.main()
