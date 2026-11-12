#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    printf 'macOS is required.\n' >&2
    exit 1
fi

encap_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
encap_temp=$(mktemp -d)
trap 'rm -rf -- "$encap_temp"' EXIT HUP INT TERM

encap_brew=$(command -v brew || true)
if [ -z "$encap_brew" ]; then
    case "$(uname -m)" in
        arm64) encap_brew=/opt/homebrew/bin/brew ;;
        x86_64) encap_brew=/usr/local/bin/brew ;;
        *) printf 'Unsupported Mac architecture.\n' >&2; exit 1 ;;
    esac
fi
if [ ! -x "$encap_brew" ]; then
    if [ ! -r /dev/tty ]; then
        printf 'Open Terminal and run this installer there.\n' >&2
        exit 1
    fi
    printf 'Installing Homebrew. Your Mac may ask for its administrator password.\n'
    curl --proto '=https' --tlsv1.2 --location --fail --silent --show-error \
        https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh -o "$encap_temp/homebrew-install.sh"
    INTERACTIVE=1 /bin/bash "$encap_temp/homebrew-install.sh" </dev/tty
    if [ ! -x "$encap_brew" ]; then
        printf 'Homebrew installation did not complete.\n' >&2
        exit 1
    fi
fi

encap_prefix=$("$encap_brew" --prefix)
PATH="$encap_prefix/bin:$encap_prefix/sbin:$PATH"
export PATH
encap_python=$encap_prefix/bin/python3
if [ ! -x "$encap_python" ] || ! "$encap_python" -c 'import sys; assert sys.version_info >= (3, 10)' >/dev/null 2>&1; then
    "$encap_brew" install python@3.14
    encap_python=$encap_prefix/bin/python3.14
fi

"$encap_python" -c 'import sys; assert sys.version_info >= (3, 10)' || {
    printf 'Python 3.10 or newer is required.\n' >&2
    exit 1
}

if [ "$(basename -- "$0")" = bootstrap.sh ] && [ -f "$encap_root/encap.py" ]; then
    encap_source=$encap_root/encap.py
else
    encap_owner=paraminer
    encap_source=$encap_temp/encap.py
    curl --proto '=https' --tlsv1.2 --location --fail --silent --show-error --retry 3 \
        "https://raw.githubusercontent.com/$encap_owner/encap/main/encap.py" -o "$encap_source"
    "$encap_python" - "$encap_source" <<'PY'
import hashlib
import pathlib
import sys
expected = "066b4913155c7221c0f7b2e24b57452252dd8ab6babc1af82164f88d88c87a21"
actual = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit("Encap source checksum mismatch")
PY
fi

"$encap_brew" install wireguard-tools

case "$(uname -m)" in
    arm64)
        encap_arch=arm64
        encap_hash=87fc0d68563248729c8c45359e5a7501041990145850c43c23a96e51656c2880
        ;;
    x86_64)
        encap_arch=amd64
        encap_hash=68bf470b58f6cb7d3dcd96deb42fb5676b8810ef7751a53f7d9e3f8178a1d085
        ;;
    *)
        printf 'Unsupported Mac architecture.\n' >&2
        exit 1
        ;;
esac

encap_archive=$encap_temp/wstunnel.tar.gz
encap_url=https://github.com/erebe/wstunnel/releases/download/v11.1.0/wstunnel_11.1.0_darwin_${encap_arch}.tar.gz
curl --proto '=https' --tlsv1.2 --location --fail --silent --show-error --retry 3 "$encap_url" -o "$encap_archive"
"$encap_python" - "$encap_archive" "$encap_hash" <<'PY'
import hashlib
import pathlib
import sys
actual = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit("wstunnel checksum mismatch")
PY
tar -xzf "$encap_archive" -C "$encap_temp" wstunnel LICENSE

encap_share=$HOME/.local/share/encap
encap_bin=$HOME/.local/bin
install -d -m 700 "$encap_share" "$encap_share/bin" "$encap_bin"
install -m 700 "$encap_temp/wstunnel" "$encap_share/bin/wstunnel"
install -m 600 "$encap_temp/LICENSE" "$encap_share/LICENSE"
install -m 700 "$encap_source" "$encap_share/encap.py"
if [ -L "$encap_bin/encap" ]; then
    rm -- "$encap_bin/encap"
fi
cat > "$encap_bin/encap" <<EOF
#!/bin/sh
PATH="$encap_prefix/bin:$encap_prefix/sbin:\$HOME/.local/share/encap/bin:\$PATH"
export PATH
exec "$encap_python" "\$HOME/.local/share/encap/encap.py" "\$@"
EOF
chmod 700 "$encap_bin/encap"
ln -sfn "$encap_share/bin/wstunnel" "$encap_bin/wstunnel"

encap_path_line='export PATH="$HOME/.local/bin:$PATH"'
for encap_profile in "$HOME/.zprofile" "$HOME/.zshrc"; do
    if [ ! -f "$encap_profile" ] || ! grep -Fqx "$encap_path_line" "$encap_profile"; then
        printf '\n%s\n' "$encap_path_line" >> "$encap_profile"
    fi
done

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    printf '\n  \033[32m✓\033[0m Encap installed\n    \033[2mopen a new Terminal window and run encap\033[0m\n\n'
else
    printf 'Encap installed. Open a new Terminal window and run encap.\n'
fi
