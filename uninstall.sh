#!/usr/bin/env bash
#
# Fresh start: blow away everything this project runs in Docker — the
# attack-navigator viewer + official Navigator containers, their locally-built
# image, network and volumes, plus any stray/old containers from earlier runs.
# Only attack-navigator / tenable-attack-mapper resources are touched; unrelated
# containers (e.g. a Tenable SC lab box) are never removed.
#
# Usage:  ./uninstall.sh
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Compose teardown (if a viewer checkout is reachable)"
# The viewer may be cloned here (./attack-navigator, by the show-matrix skill) or
# sit beside this repo (../attack-navigator).
for d in attack-navigator ../attack-navigator; do
  if [ -f "$d/docker-compose.yml" ]; then
    ( cd "$d" && docker compose down --rmi local --volumes --remove-orphans ) 2>/dev/null || true
  fi
done

echo "==> Removing related containers (by compose project / name / image)"
# Docker ANDs different --filter keys, so query each separately and union the IDs.
ids="$(
  docker ps -aq --filter "label=com.docker.compose.project=attack-navigator"
  docker ps -aq --filter "name=attack-navigator"
  docker ps -aq --filter "name=tenable-attack-mapper"
  docker ps -aq --filter "ancestor=attack-navigator:local"
  docker ps -aq --filter "ancestor=mitre/attack-navigator"
  docker ps -aq --filter "ancestor=tenable-attack-mapper"
)"
ids="$(printf '%s\n' "${ids}" | sort -u | grep . || true)"
if [ -n "${ids}" ]; then
  docker rm -f ${ids} 2>/dev/null || true
fi

echo "==> Removing built images and the compose network"
docker image rm attack-navigator:local 2>/dev/null || true
docker image rm tenable-attack-mapper 2>/dev/null || true
docker network rm attack-navigator_default 2>/dev/null || true

echo "Done. For a fresh start, ask \"open the attack matrix\" again."
