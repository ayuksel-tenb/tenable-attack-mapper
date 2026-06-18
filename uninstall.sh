#!/usr/bin/env bash
#
# Fresh start: tear down the attack-navigator viewer this tool brings up — its
# containers, the locally-built Navigator image, network and volumes. Only
# attack-navigator resources are touched; unrelated containers are left alone.
#
# Usage:  ./uninstall.sh
set -euo pipefail
cd "$(dirname "$0")"

# If the viewer repo is checked out here (the show-matrix skill clones it into
# ./attack-navigator), use its compose file for a clean teardown.
if [ -f attack-navigator/docker-compose.yml ]; then
  echo "==> docker compose down in ./attack-navigator"
  ( cd attack-navigator && docker compose down --rmi local --volumes --remove-orphans ) 2>/dev/null || true
fi

echo "==> Removing any stray attack-navigator containers and the built image"
# Match by name / image so unrelated containers (e.g. a Tenable SC lab box) are
# never removed.
ids="$(docker ps -aq \
  --filter "name=attack-navigator" \
  --filter "ancestor=attack-navigator:local" \
  --filter "ancestor=mitre/attack-navigator" 2>/dev/null | sort -u)"
if [ -n "${ids}" ]; then
  docker rm -f ${ids} 2>/dev/null || true
fi
docker image rm attack-navigator:local 2>/dev/null || true

echo "Done. For a fresh start, ask \"open the attack matrix\" again (or run"
echo "docker compose up -d viewer inside the attack-navigator checkout)."
