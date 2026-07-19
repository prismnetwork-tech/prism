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

install -d -m 0700 -o workspace -g workspace /workspace
install -d -m 0755 /run/sshd
install -m 0400 "$control/authorized_keys" /run/prism/authorized_keys
chown workspace:workspace /run/prism/authorized_keys
ssh-keygen -q -t ed25519 -N "" -f /run/prism/ssh_host_key

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
