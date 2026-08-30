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

# A shared lease runs on the host's kernel, so there is no guest to take a
# report and nothing an attestation could measure. A challenge in the control
# directory means this workspace was started for a lease that was promised one,
# and serving the session anyway would look like evidence.
if [ -f "$control/attestation_challenge" ]; then
    echo "this lease asked for a guest report and this node cannot produce one" >&2
    exit 1
fi

# The node advertises one card and hands over one card. If the toolkit injected
# more than that, the renter is looking at hardware nobody sold them, so the
# lease ends here rather than serving the whole machine.
if [ "$(nvidia-smi -L | grep -c '^GPU ')" -ne 1 ]; then
    echo "more than one GPU reached this workspace" >&2
    exit 1
fi

install -d -m 0700 -o workspace -g workspace /workspace
install -d -m 0755 /run/sshd
install -m 0400 "$control/authorized_keys" /run/prism/authorized_keys
chown workspace:workspace /run/prism/authorized_keys
ssh-keygen -q -t ed25519 -N "" -f /run/prism/ssh_host_key

# The renter has no way to recognise the box they were handed unless somebody
# names the key it answers on. Nothing here can attest to it, so the node says
# what it started and signs for it, and the control plane passes that on marked
# as the operator's word. Printed before sshd binds, so the key is published
# before there is anything to connect to. The encoding avoids `base64 -w0`
# because the image is the renter's and busybox has no such flag.
printf 'prism-evidence channel-key.pub %s\n' \
    "$(base64 < /run/prism/ssh_host_key.pub | tr -d '\n')"

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
