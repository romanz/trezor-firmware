#!/usr/bin/env bash
set -e

SITE="https://data.trezor.io/dev/firmware/releases/emulators/"
cd "$(dirname "$0")"

# download all emulators without index files, without directories and only if not present
wget -e robots=off \
    --no-verbose \
    --no-clobber \
    --no-parent \
    --no-directories \
    --no-host-directories \
    --recursive \
    --reject "index.html*" \
    -P emulators/ \
    $SITE

chmod u+x emulators/trezor-emu-*

# are we in Nix(OS)?
command -v nix-shell >/dev/null && nix-shell -p autoPatchelfHook SDL2 SDL2_image --run "autoPatchelf emulators/trezor-emu-*"
