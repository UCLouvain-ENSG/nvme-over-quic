#!/bin/bash
# Launch a QEMU VM with a virtio-blk device backed by an SPDK vhost-user socket.
#
# The guest sees the remote NVMe (served by nvmf_tgt over TCP/TLS/QUIC) as /dev/vda
# (or /dev/vdb if you boot from a separate image).
#
# Prerequisite stack:
#   1. sudo ./scripts/controller_run.sh -m 0x1          (NVMf target)
#   2. sudo ./scripts/nvmf_setup.sh -t <tcp|tls|quic> -b m
#   3. sudo ./scripts/vhost_run.sh -m 0x2               (vhost bridge, separate terminal)
#   4. sudo ./scripts/vhost_nvmf_setup.sh -t <tcp|tls|quic>
#   5. ./scripts/qemu_start.sh --image <path>           (this script)
#
# Usage: ./qemu_start.sh [--image <path>] [--vhost-socket <path>]
#                        [--memory <MB>] [--cpus <n>] [--ssh-port <port>]
#                        [-- <extra qemu args...>]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VM_IMAGE=""
VHOST_SOCKET="/tmp/spdk_vhost/vhost.blk.0"
VM_MEMORY=2048
VM_CPUS=2
SSH_PORT=10022
EXTRA_ARGS=()
HUGEPAGES_PATH="/dev/hugepages"

usage() {
    cat <<EOF
Usage: $0 [options] [-- <extra qemu args>]

  --image <path>            OS disk image (qcow2/raw). Optional: boot from ISO
  --vhost-socket <path>     SPDK vhost socket (default: /tmp/spdk_vhost/vhost.blk.0)
  --memory <MB>             VM RAM in MB (default: 2048)
  --cpus <n>                vCPU count (default: 2)
  --ssh-port <port>         Host port forwarded to VM SSH port 22 (default: 10022)
  --hugepages               Use /dev/hugepages for shared memory (better performance)
  --iso <path>              Boot from ISO (sets image as cdrom, iso as boot drive)

The remote NVMe device appears in the guest as /dev/vda (or /dev/vdb if booting
from a separate image). Run I/O inside the VM with:
  sudo fio --ioengine=libaio --direct=1 --bs=4k --rw=randread \\
           --iodepth=32 --filename=/dev/vda --runtime=30 --time_based --name=test
EOF
    exit 0
}

USE_HUGEPAGES=false
ISO_IMAGE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --image) VM_IMAGE="$2"; shift 2 ;;
        --vhost-socket) VHOST_SOCKET="$2"; shift 2 ;;
        --memory|-m) VM_MEMORY="$2"; shift 2 ;;
        --cpus) VM_CPUS="$2"; shift 2 ;;
        --ssh-port) SSH_PORT="$2"; shift 2 ;;
        --hugepages) USE_HUGEPAGES=true; shift ;;
        --iso) ISO_IMAGE="$2"; shift 2 ;;
        -h|--help) usage ;;
        --) shift; EXTRA_ARGS+=("$@"); break ;;
        *) EXTRA_ARGS+=("$1"); shift ;;
    esac
done

if [ ! -S "$VHOST_SOCKET" ]; then
    echo "Error: vhost socket not found at $VHOST_SOCKET"
    echo ""
    echo "Make sure the following are running:"
    echo "  1. sudo ./scripts/controller_run.sh -m 0x1"
    echo "  2. sudo ./scripts/nvmf_setup.sh -t tcp -b m"
    echo "  3. sudo ./scripts/vhost_run.sh -m 0x2"
    echo "  4. sudo ./scripts/vhost_nvmf_setup.sh -t tcp"
    exit 1
fi

# Build memory backend: must be shared so vhost can map guest memory.
# memfd share=on works without pre-allocated hugepages.
# hugepages (mem-path) gives better performance at the cost of requiring
# nr_hugepages to be set (see README for hugepage setup).
if $USE_HUGEPAGES; then
    MEM_BACKEND="memory-backend-file,id=mem0,size=${VM_MEMORY}M,mem-path=${HUGEPAGES_PATH},share=on,prealloc=on"
else
    MEM_BACKEND="memory-backend-memfd,id=mem0,size=${VM_MEMORY}M,share=on"
fi

QEMU_CMD=(
    qemu-system-x86_64
    -enable-kvm
    -cpu host
    -smp "$VM_CPUS"
    -m "${VM_MEMORY}M"
    -object "$MEM_BACKEND"
    -numa "node,memdev=mem0"

    # vhost-user-blk: the remote NVMe exposed as virtio-blk
    -chardev "socket,id=vhost_blk,path=${VHOST_SOCKET}"
    -device "vhost-user-blk-pci,chardev=vhost_blk,num-queues=${VM_CPUS}"

    # User-mode networking with SSH port forward
    -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"
    -device "virtio-net-pci,netdev=net0"

    # Serial console on stdout
    -serial stdio
    -display none
)

# Boot disk / ISO
if [ -n "$ISO_IMAGE" ]; then
    QEMU_CMD+=(-cdrom "$ISO_IMAGE" -boot d)
    [ -n "$VM_IMAGE" ] && QEMU_CMD+=(-drive "file=${VM_IMAGE},format=qcow2,if=virtio,index=1")
elif [ -n "$VM_IMAGE" ]; then
    QEMU_CMD+=(-drive "file=${VM_IMAGE},format=qcow2,if=virtio,index=0")
fi

QEMU_CMD+=("${EXTRA_ARGS[@]}")

echo "Starting QEMU VM"
echo "  Vhost socket:  $VHOST_SOCKET"
MEM_TYPE=$($USE_HUGEPAGES && echo "hugepages" || echo "memfd")
echo "  Memory:        ${VM_MEMORY}M (shared via $MEM_TYPE)"
echo "  CPUs:          $VM_CPUS"
echo "  SSH port:      localhost:$SSH_PORT -> VM:22"
[ -n "$VM_IMAGE" ]  && echo "  Boot image:    $VM_IMAGE"
[ -n "$ISO_IMAGE" ] && echo "  ISO:           $ISO_IMAGE"
echo ""
echo "Remote NVMe device in guest: /dev/vda"
echo "SSH into VM: ssh -p $SSH_PORT user@localhost"
echo ""

exec "${QEMU_CMD[@]}"
