#!/usr/bin/env bash
# Bootstrap the test OpenLDAP. Reconstructs the standalone setup.sh.
#
# The image (cleanstart/openldap) is distroless — no shell, no chown. So we:
#   1. concat seed/*.ldif on the host
#   2. run `slapadd` directly as the entrypoint, as uid 101:102 (the image's
#      ldap user) so the generated files are already ldap-owned
#   3. `docker compose up -d`, then wait for :389
#
# Idempotent: skips slapadd if ./data/slapd.d is already populated.
# `--reset` wipes ./data and rebuilds from scratch.
set -euo pipefail

cd "$(dirname "$0")"

IMAGE="cleanstart/openldap:2.6.13"
LDAP_UID=101   # ldap user in the image (/etc/passwd)
LDAP_GID=102

RESET=0
[[ "${1:-}" == "--reset" ]] && RESET=1

if [[ $RESET -eq 1 ]]; then
  echo ">> reset: tearing down + wiping data"
  docker compose down -v 2>/dev/null || true
  # slapadd-created files are owned by the container's ldap uid; wipe them with
  # a throwaway busybox (the openldap image has no shell/rm).
  if [[ -d ./data ]]; then
    docker run --rm -v "$PWD/data:/d" busybox sh -c 'rm -rf /d/*' 2>/dev/null || true
  fi
  rm -rf ./data ./seed/_combined.ldif ./init-config/_combined.ldif
fi

mkdir -p ./data/slapd.d ./data/openldap-data ./data/accesslog-data ./certs
chmod -R 777 ./data   # let the container's ldap uid write into bind mounts

if [[ -z "$(ls -A ./data/slapd.d 2>/dev/null)" ]]; then
  # This slapd build's slapadd does not expand `include:` schema directives, so
  # we splice the image's own schema ldifs (cn=<name>,cn=schema,cn=config) in
  # their place, producing a self-contained config ldif.
  echo ">> building config ldif (extracting schema from image)"
  schema_tmp=$(mktemp -d)
  cid=$(docker create "$IMAGE")
  for s in core cosine inetorgperson dyngroup nis; do
    docker cp "$cid:/etc/openldap/schema/$s.ldif" "$schema_tmp/$s.ldif"
  done
  docker rm "$cid" >/dev/null

  combined=./init-config/_combined.ldif
  split=$(grep -n '^dn: olcDatabase={-1}frontend' ./init-config/slapd-config.ldif | head -1 | cut -d: -f1)
  {
    head -n "$((split - 1))" ./init-config/slapd-config.ldif | grep -v '^include:'
    echo
    for s in core cosine inetorgperson dyngroup nis; do cat "$schema_tmp/$s.ldif"; echo; done
    tail -n "+$split" ./init-config/slapd-config.ldif
  } >"$combined"
  rm -rf "$schema_tmp"

  echo ">> slapadd cn=config (-n0)"
  docker run --rm --user "${LDAP_UID}:${LDAP_GID}" \
    -v "$PWD/init-config:/init-config:ro" \
    -v "$PWD/data/slapd.d:/etc/openldap/slapd.d" \
    -v "$PWD/data/openldap-data:/var/lib/openldap/openldap-data" \
    -v "$PWD/data/accesslog-data:/var/lib/openldap/accesslog-data" \
    --entrypoint slapadd "$IMAGE" \
    -n 0 -F /etc/openldap/slapd.d -l /init-config/_combined.ldif

  echo ">> slapadd seed data (-n1)"
  : >./seed/_combined.ldif
  for f in ./seed/0*.ldif; do cat "$f" >>./seed/_combined.ldif; echo >>./seed/_combined.ldif; done
  docker run --rm --user "${LDAP_UID}:${LDAP_GID}" \
    -v "$PWD/seed:/seed:ro" \
    -v "$PWD/data/slapd.d:/etc/openldap/slapd.d:ro" \
    -v "$PWD/data/openldap-data:/var/lib/openldap/openldap-data" \
    -v "$PWD/data/accesslog-data:/var/lib/openldap/accesslog-data" \
    --entrypoint slapadd "$IMAGE" \
    -n 1 -F /etc/openldap/slapd.d -l /seed/_combined.ldif
else
  echo ">> data/slapd.d already populated, skipping slapadd (use --reset to rebuild)"
fi

echo ">> starting containers"
docker compose up -d

echo -n ">> waiting for ldap://localhost:389 "
for _ in $(seq 1 60); do
  if (exec 3<>/dev/tcp/localhost/389) 2>/dev/null; then
    exec 3>&- 3<&-
    echo "ready"
    echo
    echo "OpenLDAP test instance up:"
    echo "  URL      ldap://localhost:389"
    echo "  Base DN  dc=example,dc=org"
    echo "  Bind DN  cn=admin,ou=users,dc=example,dc=org"
    echo "  Bind PW  adminpassword"
    echo "  GUI      http://localhost:8080  (admin / adminpassword)"
    echo
    echo "Try:  openldap-cli --profile test user add toto.titi"
    exit 0
  fi
  echo -n "."
  sleep 1
done

echo "timeout" >&2
echo "container failed to open :389 — inspect with: docker compose logs openldap" >&2
exit 1
