#!/usr/bin/env bash
# Generate scripts/nvme_psk.key if it does not already exist.
# The key uses the NVMe TLS interchange PSK format (NVMeTLSkey-1:01:<base64>:).
# Both the controller (nvmf_setup.sh) and the host (host_run.sh) read this file.
#
# SPDK's keyring module requires the key file to be owned by the same uid as
# the running process (nvmf_tgt and spdk_nvme_perf both run as root via sudo),
# so this script re-execs itself under sudo if not already root.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PSK_FILE="$SCRIPT_DIR/nvme_psk.key"

if [ "$EUID" -ne 0 ]; then
    exec sudo "$SCRIPT_DIR/gen_psk.sh" "$@"
fi

if [ -f "$PSK_FILE" ]; then
    echo "PSK already exists at $PSK_FILE"
    exit 0
fi

echo "Generating PSK key at $PSK_FILE..."
KEY_HEX=$(xxd -p -c32 -l 32 /dev/urandom)
python3 - > "$PSK_FILE" <<EOF
import base64, zlib
key_bytes = bytes.fromhex("$KEY_HEX")
crc = zlib.crc32(key_bytes).to_bytes(4, byteorder="little")
b64 = base64.b64encode(key_bytes + crc).decode("utf-8")
print("NVMeTLSkey-1:01:{}:".format(b64), end="")
EOF
chmod 600 "$PSK_FILE"
echo "PSK saved to $PSK_FILE (owned by root, mode 600)"
