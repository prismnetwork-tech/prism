#!/usr/bin/env bash
# Roll one backend service on the EC2 host to the image CI built for a commit.
#
#   scripts/deploy-ec2-service.sh <ssh-host> <service> <sha>
#
# The host pins each service to an image tag in /opt/prism/.env and compose
# only recreates a container when that line changes, so the tag is the commit
# SHA and never a moving name. The pull runs before the .env edit: a failed
# pull after the edit leaves the host pointing at an image it does not have,
# and the next restart is dead.
set -euo pipefail

host=$1
service=$2
sha=$3
binary="prism-${service}"
var="PRISM_$(printf '%s' "$service" | tr 'a-z-' 'A-Z_')_IMAGE"
image="ghcr.io/prismnetwork-tech/prism/${binary}:${sha}"

ssh "$host" "set -euo pipefail
  sudo docker pull --quiet '$image' >/dev/null
  sudo cp /opt/prism/.env /opt/prism/.env.bak.\$(date +%Y%m%d-%H%M%S)
  sudo sed -i 's|^${var}=.*|${var}=${image}|' /opt/prism/.env
  grep -q '^${var}=${image}\$' /opt/prism/.env
  cd /opt/prism && sudo docker compose up -d --no-deps '$service' >/dev/null
  for _ in \$(seq 1 30); do
    status=\$(sudo docker compose ps --format '{{.Status}}' '$service')
    case \"\$status\" in *healthy*|Up*) printf '%s %s\n' '$service' \"\$status\"; exit 0 ;; esac
    sleep 2
  done
  sudo docker compose ps '$service'; exit 1"
