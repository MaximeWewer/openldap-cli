#!/usr/bin/env bash
# Bootstrap the test OpenLDAP. Reconstructs the standalone setup.sh.
#
# The image (cleanstart/openldap) is distroless — no shell, no chown. So we:
#   1. concat seed/*.ldif on the host
#   2. run `slapadd` directly as the entrypoint, as uid 101:102 (the image's
#      ldap user) so the generated files are already ldap-owned
#   3. `docker compose up -d`, then wait for :389
#
# Idempotent: skips slapadd if ./testdata/slapd.d is already populated.
# `--reset` wipes ./testdata and rebuilds from scratch.
#
# The runtime state MUST live in a directory the go tool ignores (one named
# `testdata`, or prefixed with `_` or `.`). slapadd creates
# testdata/slapd.d/cn=config owned by the container's ldap uid and mode 0750, so
# the go tool cannot read it — and, unable to rule out that it is a package, it
# fails `go mod tidy` / `go test ./...` with both "permission denied" and
# "malformed import path ... invalid char '='". Renaming this to plain ./data
# brings that back.
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
  if [[ -d ./testdata ]]; then
    docker run --rm -v "$PWD/testdata:/d" busybox sh -c 'rm -rf /d/*' 2>/dev/null || true
  fi
  rm -rf ./testdata ./seed/_combined.ldif ./init-config/_combined.ldif ./certs
fi

mkdir -p ./testdata/slapd.d ./testdata/openldap-data ./testdata/accesslog-data ./certs
chmod -R 777 ./testdata   # let the container's ldap uid write into bind mounts

# ---- TLS -----------------------------------------------------------------
# A throwaway CA + server certificate so :636 really serves LDAPS and the `tls`
# commands have something to read. Keys are world-readable and the CA is
# self-signed on purpose: this instance is disposable, never a template.
TLS=0
if [[ -s ./certs/ca.crt && -s ./certs/server.crt && -s ./certs/server.key && -s ./certs/client.crt ]]; then
  TLS=1
  echo ">> certs already present, skipping generation"
elif command -v openssl >/dev/null 2>&1; then
  echo ">> generating a test CA + server certificate"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout ./certs/ca.key -out ./certs/ca.crt \
    -subj "/CN=openldap-cli Test Root CA/O=openldap-cli test" \
    -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes \
    -keyout ./certs/server.key -out ./certs/server.csr \
    -subj "/CN=openldap/O=openldap-cli test" >/dev/null 2>&1
  # the names a client may ask for: the compose hostname, and localhost from the host
  printf 'subjectAltName=DNS:openldap,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' >./certs/ext.cnf
  openssl x509 -req -in ./certs/server.csr -days 3650 \
    -CA ./certs/ca.crt -CAkey ./certs/ca.key -CAcreateserial \
    -extfile ./certs/ext.cnf -out ./certs/server.crt >/dev/null 2>&1
  # a client certificate too, so mutual TLS (client_cert/client_key) is testable
  openssl req -newkey rsa:2048 -nodes \
    -keyout ./certs/client.key -out ./certs/client.csr \
    -subj "/CN=e2e.client/O=openldap-cli test" >/dev/null 2>&1
  printf 'extendedKeyUsage=clientAuth\n' >./certs/client-ext.cnf
  openssl x509 -req -in ./certs/client.csr -days 3650 \
    -CA ./certs/ca.crt -CAkey ./certs/ca.key -CAcreateserial \
    -extfile ./certs/client-ext.cnf -out ./certs/client.crt >/dev/null 2>&1
  chmod 644 ./certs/ca.crt ./certs/server.crt ./certs/server.key ./certs/client.crt ./certs/client.key
  TLS=1
else
  echo ">> openssl not found: skipping TLS setup (:636 will not serve, `tls` tests will skip)" >&2
fi

if [[ -z "$(ls -A ./testdata/slapd.d 2>/dev/null)" ]]; then
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

  # point cn=config at the certificates, inside the first record
  if [[ $TLS -eq 1 ]]; then
    grep -q '^olcArgsFile:' "$combined" || { echo "no olcArgsFile anchor in $combined" >&2; exit 1; }
    sed -i '0,/^olcArgsFile:.*$/s||&\nolcTLSCACertificateFile: /etc/openldap/certs/ca.crt\nolcTLSCertificateFile: /etc/openldap/certs/server.crt\nolcTLSCertificateKeyFile: /etc/openldap/certs/server.key|' "$combined"
  fi

  echo ">> slapadd cn=config (-n0)"
  docker run --rm --user "${LDAP_UID}:${LDAP_GID}" \
    -v "$PWD/init-config:/init-config:ro" \
    -v "$PWD/certs:/etc/openldap/certs:ro" \
    -v "$PWD/testdata/slapd.d:/etc/openldap/slapd.d" \
    -v "$PWD/testdata/openldap-data:/var/lib/openldap/openldap-data" \
    -v "$PWD/testdata/accesslog-data:/var/lib/openldap/accesslog-data" \
    --entrypoint slapadd "$IMAGE" \
    -n 0 -F /etc/openldap/slapd.d -l /init-config/_combined.ldif

  echo ">> slapadd seed data (-n1)"
  : >./seed/_combined.ldif
  for f in ./seed/0*.ldif; do cat "$f" >>./seed/_combined.ldif; echo >>./seed/_combined.ldif; done
  # publish the CA in the tree as well (RFC 4523), so `tls ca-list` / `ca-export`
  # have a directory-published source to read, next to the one on the wire
  if [[ $TLS -eq 1 ]]; then
    {
      echo "dn: cn=TestRootCA,dc=example,dc=org"
      echo "objectClass: top"
      echo "objectClass: applicationProcess"
      echo "objectClass: pkiCA"
      echo "cn: TestRootCA"
      echo "cACertificate;binary:: $(openssl x509 -in ./certs/ca.crt -outform DER | base64 -w0)"
      echo
    } >>./seed/_combined.ldif
  fi
  docker run --rm --user "${LDAP_UID}:${LDAP_GID}" \
    -v "$PWD/seed:/seed:ro" \
    -v "$PWD/testdata/slapd.d:/etc/openldap/slapd.d:ro" \
    -v "$PWD/testdata/openldap-data:/var/lib/openldap/openldap-data" \
    -v "$PWD/testdata/accesslog-data:/var/lib/openldap/accesslog-data" \
    --entrypoint slapadd "$IMAGE" \
    -n 1 -F /etc/openldap/slapd.d -l /seed/_combined.ldif
else
  echo ">> data/slapd.d already populated, skipping slapadd (use --reset to rebuild)"
fi

echo ">> starting the LDAP server"
docker compose up -d openldap

# The GUI is a convenience and must never be able to fail the bootstrap: its
# port is the one most likely to be taken on a developer machine, and losing a
# web UI is no reason to leave the directory unstarted.
GUI_PORT="${PHPLDAPADMIN_PORT:-8080}"
if docker compose --profile gui up -d phpldapadmin >/dev/null 2>&1; then
  GUI="http://localhost:${GUI_PORT}  (admin / adminpassword)"
else
  GUI="not started - port ${GUI_PORT} busy? retry with PHPLDAPADMIN_PORT=8081 $0"
fi

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
    echo "  GUI      ${GUI}"
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
