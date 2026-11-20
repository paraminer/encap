import hashlib
import io
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "bootstrap.sh").read_text()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def executable(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o755)


def archive(path, members):
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    return sha(path.read_bytes())


def pin(script, name, value):
    script, count = re.subn(rf"(\n\s*{name}=)[0-9a-f]{{64}}", rf"\g<1>{value}", script, count=1)
    assert count == 1, name
    return script


class BootstrapTest(unittest.TestCase):
    """Runs the real installer against local copies of every download."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home with space"
        self.home.mkdir()
        self.local_bin = self.home / ".local/bin"
        self.share = self.home / ".local/share/encap"
        self.fake_bin = self.root / "fake-bin"
        self.downloads = self.root / "downloads"
        self.downloads.mkdir()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "encap.py").write_bytes((ROOT / "encap.py").read_bytes())

        python = f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n'.encode()
        tool = b"#!/bin/sh\nexit 0\n"
        wg = b"#!/bin/sh\necho wireguard-tools\n"
        wstunnel = b"#!/bin/sh\necho wstunnel\n"
        script = SCRIPT
        for name, value in (
            ("encap_python_sha", archive(self.downloads / "python.tar.gz", {"python/bin/python3": python})),
            ("encap_wireguard_go_blob", archive(self.downloads / "wireguard-go.tar.gz", {"wireguard-go/0.0.20250522/bin/wireguard-go": tool})),
            ("encap_wireguard_go_sha", sha(tool)),
            ("encap_wg_blob", archive(self.downloads / "wireguard-tools.tar.gz", {"wireguard-tools/1.0.20260223/bin/wg": wg})),
            ("encap_wg_sha", sha(wg)),
            ("encap_wstunnel_archive_sha", archive(self.downloads / "wstunnel.tar.gz", {"wstunnel": wstunnel, "LICENSE": b"license"})),
            ("encap_wstunnel_sha", sha(wstunnel)),
        ):
            script = pin(script, name, value)
        script = pin(script, "encap_source_sha", sha((ROOT / "encap.py").read_bytes()))
        (self.downloads / "encap.py").write_bytes((ROOT / "encap.py").read_bytes())
        self.script = self.repo / "bootstrap.sh"
        self.script.write_text(script)

        executable(self.fake_bin / "uname", '#!/bin/sh\ncase "$1" in -s) echo Darwin ;; -m) echo arm64 ;; esac\n')
        executable(self.fake_bin / "sysctl", "#!/bin/sh\necho 1\n")
        executable(self.fake_bin / "sw_vers", '#!/bin/sh\necho "${ENCAP_TEST_MACOS:-15.3}"\n')
        executable(self.fake_bin / "netstat", "#!/bin/sh\nexit 0\n")
        executable(self.fake_bin / "curl", (
            '#!/bin/sh\nfor arg; do url=$arg; done\nprintf "%s\\n" "$url" >> "$ENCAP_TEST_CURL_LOG"\n'
            'case "$url" in\n'
            '  *"$ENCAP_TEST_FAIL"*) [ -n "$ENCAP_TEST_FAIL" ] && { echo "curl: (6) Could not resolve host" >&2; exit 6; } ;;\n'
            'esac\n'
            'case "$url" in\n'
            '  */encap.py) file=encap.py ;;\n'
            '  *python-build-standalone*) file=python.tar.gz ;;\n'
            '  *wireguard-go*) file=wireguard-go.tar.gz ;;\n'
            '  *wireguard-tools*) file=wireguard-tools.tar.gz ;;\n'
            '  *wstunnel*) file=wstunnel.tar.gz ;;\n'
            'esac\n'
            'while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; out=$1; fi; shift; done\n'
            'cp "$ENCAP_TEST_DOWNLOADS/$file" "$out"\n'
        ))

    def environment(self, *paths, **extra):
        env = {
            "HOME": str(self.home),
            "SHELL": "/bin/zsh",
            "ENCAP_TEST_CURL_LOG": str(self.root / "curl.log"),
            "ENCAP_TEST_DOWNLOADS": str(self.downloads),
            "ENCAP_TEST_FAIL": "",
            "PATH": ":".join([str(self.fake_bin), *map(str, paths), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]),
        }
        env.update(extra)
        return env

    def run_installer(self, env, piped=False):
        if piped:
            # Same as `curl -fsSL .../bootstrap.sh | sh`: the script arrives on stdin.
            return subprocess.run(["/bin/sh"], input=self.script.read_text(), cwd=self.home,
                                  env=env, capture_output=True, text=True, timeout=60)
        return subprocess.run(["/bin/sh", str(self.script)], env=env, capture_output=True, text=True, timeout=60)

    def install(self, env, piped=False):
        result = self.run_installer(env, piped)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Encap installed", result.stdout)
        return result

    def downloads_made(self):
        log = self.root / "curl.log"
        return log.read_text().splitlines() if log.exists() else []

    def check_command(self, env, expected):
        result = subprocess.run(["/bin/sh", "-c", "command -v encap; encap status"], env=env,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines()[0], str(expected))
        self.assertIn("Tunnel closed", result.stdout)

    def test_clean_install(self):
        env = self.environment(self.local_bin)
        result = self.install(env)
        self.assertNotIn("brew", result.stdout + result.stderr)
        for tool in ("wireguard-go", "wg", "wstunnel"):
            self.assertTrue(os.access(self.share / "bin" / tool, os.X_OK), tool)
        self.assertTrue((self.share / "python/bin/python3").exists())
        self.assertEqual(len(self.downloads_made()), 4)
        self.assertIn('/.local/share/encap/python/bin/python3" -I', (self.local_bin / "encap").read_text())
        self.assertFalse(list(self.home.glob(".local/share/.encap-install.*")))
        self.check_command(env, self.local_bin / "encap")
        self.assertIn('export PATH="$HOME/.local/bin:$PATH"', (self.home / ".zprofile").read_text())

    def test_piped_install_survives_a_tool_reading_stdin(self):
        executable(self.fake_bin / "sw_vers", "#!/bin/sh\ncat >/dev/null\necho 15.3\n")
        env = self.environment(self.local_bin)
        self.install(env, piped=True)
        self.assertTrue(any(url.endswith("/encap.py") for url in self.downloads_made()))
        self.check_command(env, self.local_bin / "encap")

    def test_repeat_install_downloads_nothing(self):
        env = self.environment(self.local_bin)
        self.install(env)
        first = len(self.downloads_made())
        self.install(env)
        self.assertEqual(len(self.downloads_made()), first)
        self.check_command(env, self.local_bin / "encap")

    def test_modified_tool_is_downloaded_again(self):
        env = self.environment(self.local_bin)
        self.install(env)
        (self.share / "bin/wstunnel").write_text("#!/bin/sh\necho modified\n")
        self.install(env)
        self.assertEqual(sum("wstunnel" in url for url in self.downloads_made()), 2)
        self.assertIn("echo wstunnel", (self.share / "bin/wstunnel").read_text())

    def test_failed_download_is_reported_and_keeps_old_install(self):
        env = self.environment(self.local_bin)
        self.install(env)
        (self.share / "bin/wstunnel").write_text("old")
        result = self.run_installer(self.environment(self.local_bin, ENCAP_TEST_FAIL="wstunnel"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("A download failed", result.stderr)
        self.assertIn("Encap installation failed while downloading", result.stderr)
        self.assertEqual((self.share / "bin/wstunnel").read_text(), "old")
        self.check_command(env, self.local_bin / "encap")

    def test_tampered_download_is_rejected(self):
        (self.downloads / "wireguard-tools.tar.gz").write_bytes(b"tampered")
        result = self.run_installer(self.environment(self.local_bin))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wg checksum mismatch", result.stderr)
        self.assertFalse((self.local_bin / "encap").exists())

    def test_old_macos_is_refused_before_any_change(self):
        result = self.run_installer(self.environment(self.local_bin, ENCAP_TEST_MACOS="13.6.1"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Encap needs macOS 14 or newer", result.stderr)
        self.assertFalse((self.home / ".local").exists())

    def test_upgrade_from_homebrew_install_keeps_registration(self):
        executable(self.local_bin / "encap", "#!/Users/someone/Library/Application Support/encap/python\n")
        (self.share / "bin").mkdir(parents=True)
        (self.share / "bin/wstunnel").write_text("old")
        (self.share / "LICENSE").write_text("old")
        (self.local_bin / "wstunnel").symlink_to(self.share / "bin/wstunnel")
        config = self.home / ".config/encap"
        config.mkdir(parents=True)
        for name in ("config.json", "device.token", "device.conf"):
            (config / name).write_text(f"private {name}")
        env = self.environment(self.local_bin)
        self.install(env)
        self.assertEqual((self.local_bin / "encap").read_text().splitlines()[0], "#!/bin/sh")
        self.assertFalse((self.local_bin / "wstunnel").exists())
        self.assertFalse((self.share / "LICENSE").exists())
        for name in ("config.json", "device.token", "device.conf"):
            self.assertEqual((config / name).read_text(), f"private {name}")
        self.check_command(env, self.local_bin / "encap")

    def test_broken_local_symlink_is_replaced(self):
        self.local_bin.mkdir(parents=True)
        (self.local_bin / "encap").symlink_to(self.home / "Library/Application Support/encap/old")
        env = self.environment(self.local_bin)
        self.install(env)
        self.assertFalse((self.local_bin / "encap").is_symlink())
        self.check_command(env, self.local_bin / "encap")

    def test_old_shared_command_is_pointed_at_new_install(self):
        shared = self.root / "shared-bin"
        executable(shared / "encap", '#!/bin/sh\nexec "$HOME/Library/Application Support/encap/python" "$@"\n')
        env = self.environment(shared)
        self.install(env)
        self.assertIn('exec "$HOME/.local/bin/encap"', (shared / "encap").read_text())
        self.check_command(env, shared / "encap")

    def test_foreign_command_is_left_alone(self):
        shared = self.root / "shared-bin"
        executable(shared / "encap", "#!/bin/sh\necho another program\n")
        result = self.run_installer(self.environment(shared))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Another encap command is first in PATH", result.stderr)
        self.assertEqual((shared / "encap").read_text(), "#!/bin/sh\necho another program\n")

    def test_readme_command_works_in_current_zsh(self):
        env = self.environment()
        command = (
            f"/bin/sh {shlex.quote(str(self.script))}"
            ' && export PATH="$HOME/.local/bin:$PATH" && hash -r'
            " && command -v encap && encap status"
        )
        result = subprocess.run(["/bin/zsh", "-f", "-c", command], env=env,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(str(self.local_bin / "encap"), result.stdout)
        self.assertIn("Tunnel closed", result.stdout)


if __name__ == "__main__":
    unittest.main()
