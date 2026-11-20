#!/bin/sh
# Encap installer for macOS.
#
# Downloads pinned, checksum-verified files into ~/.local/share/encap and adds
# the `encap` command. It needs no Homebrew, no Xcode tools and no password.
# Everything runs inside encap_main, so `curl | sh` reads the whole script
# before running it: a cut-off download or a tool reading stdin cannot stop
# the installation halfway.
set -eu

encap_owner=paraminer
encap_python_release=20261110
encap_python_version=3.13.18
encap_wireguard_go_version=0.0.20250522
encap_wireguard_tools_version=1.0.20260223
encap_wstunnel_version=11.1.0
# Pinned SHA-256 of encap.py on GitHub. Update it whenever encap.py changes.
encap_source_sha=848b050183103fcf21dbc09aa1397f6b8961e33c2a2417c221be3e8bb6456d3a

encap_pins() {
    case $1 in
        arm64)
            encap_python_arch=aarch64
            encap_python_sha=7a2384641584ab9984221fcb0fc9265df465922af71be71410529e2a9c3f0540
            encap_wireguard_go_blob=b1c19618a231e9ca6c62dd268de8ab8905256d96540a252f0cebf05548a3939c
            encap_wireguard_go_sha=c62a563ac888d8c6ca9895ee6f7ac5e7297171f20bc7e1c7e0ec4d6d21415337
            encap_wg_blob=a8103231bca48f4d0db2257a2429f1f3ec18203cc654c48b24736552b3623128
            encap_wg_sha=5c43ca317fbada848fd4ef2f49da59d41797f57c037582f108923f7b1b025f62
            encap_wstunnel_arch=arm64
            encap_wstunnel_archive_sha=87fc0d68563248729c8c45359e5a7501041990145850c43c23a96e51656c2880
            encap_wstunnel_sha=3c814a9b16481b6b17b9ea02b679b8b21454788da6c61366c4d26fca823c9feb
            ;;
        x86_64)
            encap_python_arch=x86_64
            encap_python_sha=d27d59a722db9f69926eb6d9564071247221f45a04da920ea7f3001c97e32f9b
            encap_wireguard_go_blob=db6d403f493b281677d95e79448776275d37b728b966fe23f80f1079ecf35d61
            encap_wireguard_go_sha=356f1384060302a5a8925b80ae0a225c7ebad45b62a850b1ad31a352120c01de
            encap_wg_blob=82e2046eb5642fd202ed22a2012cc1ef2c62b0c95499865bb040801ee37f525a
            encap_wg_sha=dbbc12ba0d8f88a3a4f8e696a9b09c6bce5d1f00cd20b449766ac8395afc45c2
            encap_wstunnel_arch=amd64
            encap_wstunnel_archive_sha=68bf470b58f6cb7d3dcd96deb42fb5676b8810ef7751a53f7d9e3f8178a1d085
            encap_wstunnel_sha=72349e8eda9b80762e809b51dbe3c81aea8094b57da6ab6bb97274f048be4adb
            ;;
    esac
}

encap_color() {
    [ -t 1 ] && [ -z "${NO_COLOR:-}" ]
}

encap_say() {
    encap_step=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    if encap_color; then
        printf '  \033[2m·\033[0m %s\n' "$1"
    else
        printf '%s\n' "$1"
    fi
}

encap_fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

encap_finish() {
    encap_status=$1
    [ -z "${encap_temp:-}" ] || rm -rf -- "$encap_temp"
    [ "$encap_status" -eq 0 ] && return
    if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
        printf '\n  \033[31m✗\033[0m Encap installation failed while %s\n    \033[2mrun the installer again; if it fails, share the output above\033[0m\n\n' "$encap_step" >&2
    else
        printf 'Encap installation failed while %s. Run the installer again; if it fails, share the output above.\n' "$encap_step" >&2
    fi
}

encap_sha() {
    shasum -a 256 "$1" 2>/dev/null | cut -c1-64
}

# encap_get URL FILE [HEADER]: one HTTPS download, retried on network errors.
encap_get() {
    if [ $# -gt 2 ]; then
        curl --proto '=https' --tlsv1.2 --location --fail --silent --show-error \
            --retry 3 --connect-timeout 15 -H "$3" -o "$2" "$1"
    else
        curl --proto '=https' --tlsv1.2 --location --fail --silent --show-error \
            --retry 3 --connect-timeout 15 -o "$2" "$1"
    fi
}

encap_check() {
    [ "$(encap_sha "$1")" = "$2" ] || encap_fail "$3 checksum mismatch"
}

# encap_current FILE SHA: the installed file is already the pinned one.
encap_current() {
    [ -x "$1" ] && [ "$(encap_sha "$1")" = "$2" ]
}

encap_main() {
    encap_step="checking this Mac"
    encap_initial_path=$PATH
    encap_local=
    if [ "$(basename -- "$0")" = bootstrap.sh ] && [ -f "$(dirname -- "$0")/encap.py" ]; then
        encap_local=$(dirname -- "$0")/encap.py
    fi

    [ "$(uname -s)" = Darwin ] || encap_fail "Encap needs macOS."
    encap_macos=$(sw_vers -productVersion)
    [ "${encap_macos%%.*}" -ge 14 ] 2>/dev/null || encap_fail "Encap needs macOS 14 or newer (this Mac has $encap_macos)."
    # The hardware, not the shell: a Terminal running under Rosetta still gets arm64 files.
    if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
        encap_arch=arm64
    else
        encap_arch=$(uname -m)
    fi
    encap_pins "$encap_arch"
    [ -n "${encap_python_sha:-}" ] || encap_fail "Unsupported Mac processor: $encap_arch"

    encap_share=$HOME/.local/share/encap
    encap_bin=$HOME/.local/bin
    install -d -m 700 "$HOME/.local/share" "$encap_share" "$encap_share/bin" "$encap_bin"
    [ ! -d "$encap_bin/encap" ] || [ -L "$encap_bin/encap" ] || encap_fail "Cannot replace the directory $encap_bin/encap"
    # Staging next to the destination keeps every replacement an atomic rename.
    encap_temp=$(mktemp -d "$HOME/.local/share/.encap-install.XXXXXX")

    encap_say "Downloading"
    encap_jobs=
    if [ -n "$encap_local" ]; then
        cp "$encap_local" "$encap_temp/encap.py"
    else
        encap_get "https://raw.githubusercontent.com/$encap_owner/encap/main/encap.py" "$encap_temp/encap.py" &
        encap_jobs="$encap_jobs $!"
    fi
    encap_new_python=false
    if [ ! -f "$encap_share/python/.encap-$encap_python_sha" ] \
        || ! "$encap_share/python/bin/python3" -I -c 'import ssl' >/dev/null 2>&1; then
        encap_new_python=true
        encap_get "https://github.com/astral-sh/python-build-standalone/releases/download/$encap_python_release/cpython-$encap_python_version%2B$encap_python_release-$encap_python_arch-apple-darwin-install_only_stripped.tar.gz" "$encap_temp/python.tar.gz" &
        encap_jobs="$encap_jobs $!"
    fi
    # wireguard-go and wg come straight from Homebrew's prebuilt packages, pinned by digest.
    encap_new_wireguard_go=false
    if ! encap_current "$encap_share/bin/wireguard-go" "$encap_wireguard_go_sha"; then
        encap_new_wireguard_go=true
        encap_get "https://ghcr.io/v2/homebrew/core/wireguard-go/blobs/sha256:$encap_wireguard_go_blob" "$encap_temp/wireguard-go.tar.gz" "Authorization: Bearer QQ==" &
        encap_jobs="$encap_jobs $!"
    fi
    encap_new_wg=false
    if ! encap_current "$encap_share/bin/wg" "$encap_wg_sha"; then
        encap_new_wg=true
        encap_get "https://ghcr.io/v2/homebrew/core/wireguard-tools/blobs/sha256:$encap_wg_blob" "$encap_temp/wireguard-tools.tar.gz" "Authorization: Bearer QQ==" &
        encap_jobs="$encap_jobs $!"
    fi
    encap_new_wstunnel=false
    if ! encap_current "$encap_share/bin/wstunnel" "$encap_wstunnel_sha"; then
        encap_new_wstunnel=true
        encap_get "https://github.com/erebe/wstunnel/releases/download/v$encap_wstunnel_version/wstunnel_${encap_wstunnel_version}_darwin_$encap_wstunnel_arch.tar.gz" "$encap_temp/wstunnel.tar.gz" &
        encap_jobs="$encap_jobs $!"
    fi
    for encap_job in $encap_jobs; do
        wait "$encap_job" || encap_fail "A download failed. Check the internet connection."
    done

    encap_say "Verifying"
    [ -n "$encap_local" ] || encap_check "$encap_temp/encap.py" "$encap_source_sha" "encap.py"
    if [ "$encap_new_python" = true ]; then
        encap_check "$encap_temp/python.tar.gz" "$encap_python_sha" "Python"
        tar -xzf "$encap_temp/python.tar.gz" -C "$encap_temp" python
        "$encap_temp/python/bin/python3" -I -c 'import ssl, sys, termios; assert sys.version_info >= (3, 10)' \
            </dev/null >/dev/null 2>&1 || encap_fail "The downloaded Python does not run on this Mac"
        : > "$encap_temp/python/.encap-$encap_python_sha"
    fi
    install -d -m 700 "$encap_temp/bin"
    if [ "$encap_new_wireguard_go" = true ]; then
        encap_check "$encap_temp/wireguard-go.tar.gz" "$encap_wireguard_go_blob" "wireguard-go"
        tar -xzf "$encap_temp/wireguard-go.tar.gz" -C "$encap_temp" "wireguard-go/$encap_wireguard_go_version/bin/wireguard-go"
        mv "$encap_temp/wireguard-go/$encap_wireguard_go_version/bin/wireguard-go" "$encap_temp/bin/wireguard-go"
        encap_check "$encap_temp/bin/wireguard-go" "$encap_wireguard_go_sha" "wireguard-go"
    fi
    if [ "$encap_new_wg" = true ]; then
        encap_check "$encap_temp/wireguard-tools.tar.gz" "$encap_wg_blob" "wg"
        tar -xzf "$encap_temp/wireguard-tools.tar.gz" -C "$encap_temp" "wireguard-tools/$encap_wireguard_tools_version/bin/wg"
        mv "$encap_temp/wireguard-tools/$encap_wireguard_tools_version/bin/wg" "$encap_temp/bin/wg"
        encap_check "$encap_temp/bin/wg" "$encap_wg_sha" "wg"
        "$encap_temp/bin/wg" --version </dev/null >/dev/null 2>&1 || encap_fail "wg does not run on this Mac"
    fi
    if [ "$encap_new_wstunnel" = true ]; then
        encap_check "$encap_temp/wstunnel.tar.gz" "$encap_wstunnel_archive_sha" "wstunnel"
        tar -xzf "$encap_temp/wstunnel.tar.gz" -C "$encap_temp/bin" wstunnel
        encap_check "$encap_temp/bin/wstunnel" "$encap_wstunnel_sha" "wstunnel"
    fi

    encap_say "Installing"
    if [ "$encap_new_python" = true ]; then
        [ ! -e "$encap_share/python" ] || mv "$encap_share/python" "$encap_temp/old-python"
        mv "$encap_temp/python" "$encap_share/python"
    fi
    for encap_tool in wireguard-go wg wstunnel; do
        if [ -f "$encap_temp/bin/$encap_tool" ]; then
            chmod 700 "$encap_temp/bin/$encap_tool"
            mv -f "$encap_temp/bin/$encap_tool" "$encap_share/bin/$encap_tool"
        fi
    done
    chmod 700 "$encap_temp/encap.py"
    mv -f "$encap_temp/encap.py" "$encap_share/encap.py"
    rm -f "$encap_share/LICENSE"

    cat > "$encap_temp/encap" <<'EOF'
#!/bin/sh
PATH="$HOME/.local/share/encap/bin:$PATH"
export PATH
exec "$HOME/.local/share/encap/python/bin/python3" -I "$HOME/.local/share/encap/encap.py" "$@"
EOF
    chmod 700 "$encap_temp/encap"
    [ ! -L "$encap_bin/encap" ] || rm -f "$encap_bin/encap"
    mv -f "$encap_temp/encap" "$encap_bin/encap"
    # Older versions linked wstunnel here; the launcher now finds it by itself.
    if [ -L "$encap_bin/wstunnel" ] && [ "$(readlink "$encap_bin/wstunnel")" = "$encap_share/bin/wstunnel" ]; then
        rm -f "$encap_bin/wstunnel"
    fi

    encap_step="checking the encap command"
    "$encap_bin/encap" status </dev/null >/dev/null 2>&1 || encap_fail "The encap command did not start"

    encap_step="adding encap to PATH"
    encap_path_line='export PATH="$HOME/.local/bin:$PATH"'
    for encap_profile in .zprofile .zshrc .bash_profile; do
        case "$encap_profile:${SHELL:-}" in
            .bash_profile:*/bash) ;;
            .bash_profile:*) continue ;;
        esac
        encap_profile=$HOME/$encap_profile
        if [ ! -f "$encap_profile" ] || ! grep -Fqx "$encap_path_line" "$encap_profile"; then
            printf '\n%s\n' "$encap_path_line" >> "$encap_profile"
        fi
    done

    # Older versions put an encap command in a shared folder. Point it at this
    # installation so it never runs stale code. Anything else is left alone.
    encap_found=$(PATH=$encap_initial_path command -v encap || true)
    if [ -n "$encap_found" ] && [ "$encap_found" != "$encap_bin/encap" ]; then
        grep -Eiq 'encap|Application Support' "$encap_found" 2>/dev/null \
            || encap_fail "Another encap command is first in PATH: $encap_found"
        printf '#!/bin/sh\nexec "$HOME/.local/bin/encap" "$@"\n' > "$encap_temp/encap-public"
        if [ -w "$(dirname -- "$encap_found")" ]; then
            install -m 755 "$encap_temp/encap-public" "$encap_found"
        else
            sudo -p '  Password to update the old encap command: ' install -m 755 "$encap_temp/encap-public" "$encap_found"
        fi
    fi
    encap_ready=$(PATH=$encap_initial_path command -v encap || true)
    if [ -n "$encap_ready" ]; then
        PATH=$encap_initial_path "$encap_ready" status </dev/null >/dev/null 2>&1 \
            || encap_fail "The encap command in PATH did not start: $encap_ready"
    fi

    encap_step="finishing"
    if encap_color; then
        if [ -n "$encap_ready" ]; then
            printf '\n  \033[32m✓\033[0m Encap installed\n    \033[2mrun encap to connect\033[0m\n\n'
        else
            printf '\n  \033[32m✓\033[0m Encap installed\n    \033[2mopen a new Terminal window and run encap\033[0m\n\n'
        fi
    elif [ -n "$encap_ready" ]; then
        printf 'Encap installed. Run encap to connect.\n'
    else
        printf 'Encap installed. Open a new Terminal window and run encap.\n'
    fi
}

encap_step="starting"
trap 'encap_finish $?' EXIT
trap 'exit 130' HUP INT TERM
encap_main "$@"
