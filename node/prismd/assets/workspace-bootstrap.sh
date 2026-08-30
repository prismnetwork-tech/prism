#!/bin/sh
set -eu

umask 077
control=/run/prism/control
deadline=$(( $(date +%s) + 30 ))

while [ ! -f "$control/network-ready" ]; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "network policy was not installed" >&2
        exit 1
    fi
    sleep 1
done

command -v nvidia-smi >/dev/null
command -v ssh-keygen >/dev/null
sshd_path=$(command -v sshd)
command -v runuser >/dev/null
command -v python3 >/dev/null
python3 -m jupyter --version >/dev/null
id workspace >/dev/null
nvidia-smi -L >/dev/null

# The device nodes arrive owned by root with nothing granted to anyone else, and
# the renter's session is not root, so without this they get a shell that cannot
# open the GPU they are paying for: `nvidia-smi` answers "Failed to initialize
# NVML: Insufficient Permissions". NVIDIA's own tooling opens these to everyone
# on an ordinary host. Here it is narrower than that sounds, because the
# workspace is a single-tenant VM holding one card and there is nobody else in
# it to widen them to.
for node in /dev/nvidia*; do
    [ -c "$node" ] && chmod 0666 "$node"
done
if [ -d /dev/nvidia-caps ]; then
    chmod 0755 /dev/nvidia-caps
    for node in /dev/nvidia-caps/*; do
        [ -c "$node" ] && chmod 0444 "$node"
    done
fi

install -d -m 0700 -o workspace -g workspace /workspace
install -d -m 0755 /run/sshd
install -m 0400 "$control/authorized_keys" /run/prism/authorized_keys
chown workspace:workspace /run/prism/authorized_keys
ssh-keygen -q -t ed25519 -N "" -f /run/prism/ssh_host_key

# A report the renter can use has to commit to the key their session will
# terminate on, so it is taken after the key exists and before anything is
# listening on it. set -e makes a reporter that cannot produce one end the
# lease here rather than serve a session no report covers. The challenge comes
# from a mount the host controls and is not trusted: a stale or invented one
# hashes into report data the control plane refuses.
if [ -f "$control/attestation_challenge" ]; then
    command -v prismd >/dev/null

    # The kernel exposes the report through configfs and nothing mounts it for
    # us. Mounting is the only way to reach it: /dev/sev-guest is a guest device
    # the host cannot hand over. Unmount before the renter can reach anything,
    # so the session they get holds no route to the interface that signs for it.
    mounted_tsm=
    if [ ! -d /sys/kernel/config/tsm ]; then
        mkdir -p /sys/kernel/config
        mount -t configfs none /sys/kernel/config
        mounted_tsm=yes
    fi

    prismd snp-report \
        --challenge-file "$control/attestation_challenge" \
        --lease-id "$(cat "$control/lease_id")" \
        --channel-key-file /run/prism/ssh_host_key.pub \
        --output-directory /run/prism/evidence

    if [ -n "$mounted_tsm" ]; then
        umount /sys/kernel/config
    fi

    # A confidential guest is given its own copy of every directory the host
    # offers it, so anything written into that mount stays inside and the node
    # never sees the report it is supposed to forward. Standard output is the
    # one channel out that does not ask the host to reach in. Nothing is
    # disclosed by it: the report is a public statement about this guest, and it
    # is signed by the processor, so a node relaying it cannot alter a byte
    # without the control plane noticing.
    for artifact in guest-report.bin guest-chain.b64 guest-channel-key.pub; do
        if [ -f "/run/prism/evidence/$artifact" ]; then
            printf 'prism-evidence %s %s\n' \
                "$artifact" "$(base64 -w0 < "/run/prism/evidence/$artifact")"
        fi
    done
else
    # No report covers this key, so the node says which one it started and
    # signs for it. The renter gets a name to check the box against, backed by
    # the operator's bond rather than by the processor. Never printed alongside
    # a report: the report is the stronger statement about the same key and two
    # claims invite the weaker one being read as the answer.
    printf 'prism-evidence channel-key.pub %s\n' \
        "$(base64 -w0 < /run/prism/ssh_host_key.pub)"
fi

cat >/run/prism/sshd_config <<'EOF'
Port 2222
ListenAddress 0.0.0.0
Protocol 2
HostKey /run/prism/ssh_host_key
PidFile /run/prism/sshd.pid
AuthorizedKeysFile /run/prism/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
GatewayPorts no
AllowUsers workspace
Subsystem sftp internal-sftp
EOF

"$sshd_path" -D -e -f /run/prism/sshd_config &
sshd_pid=$!
jupyter_token=$(cat "$control/jupyter_token")
runuser -u workspace -- env \
    HOME=/workspace \
    JUPYTER_RUNTIME_DIR=/workspace/.jupyter-runtime \
    python3 -m jupyter lab \
    --no-browser \
    --ip=0.0.0.0 \
    --port=8888 \
    --ServerApp.root_dir=/workspace \
    --IdentityProvider.token="$jupyter_token" \
    --ServerApp.allow_remote_access=False &
jupyter_pid=$!

shutdown() {
    kill "$sshd_pid" "$jupyter_pid" 2>/dev/null || true
    wait "$sshd_pid" "$jupyter_pid" 2>/dev/null || true
}

trap shutdown EXIT INT TERM
while kill -0 "$sshd_pid" 2>/dev/null && kill -0 "$jupyter_pid" 2>/dev/null; do
    sleep 1
done
exit 1
