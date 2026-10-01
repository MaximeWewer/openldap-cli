# Test OpenLDAP

Self-contained OpenLDAP for exercising `openldap-cli`

## Run

```bash
make test-up       # bootstrap + start (idempotent)
make test-reset    # wipe data + rebuild
make test-down     # stop
```

`bootstrap.sh` reconstructs the upstream `setup.sh`: `slapadd -n0` for
`cn=config`, `slapadd -n1` for the concatenated `seed/*.ldif`, fix ownership,
then `docker compose up -d`.

## Access

|         |                                                          |
| ------- | -------------------------------------------------------- |
| URL     | `ldap://localhost:389` (`:636` TLS, no certs by default) |
| Base DN | `dc=example,dc=org`                                      |
| Bind DN | `cn=admin,ou=users,dc=example,dc=org`                    |
| Bind PW | `adminpassword`                                          |
| GUI     | http://localhost:8080                                    |

## TLS

`bootstrap.sh` mints a throwaway CA and server certificate into `certs/` (needs
`openssl` on the host; without it the step is skipped and `:636` stays shut),
points `cn=config` at them, and publishes the CA in the tree as
`cn=TestRootCA,dc=example,dc=org` so both certificate sources - the handshake
and `cACertificate` - have something to return.

A client certificate (`certs/client.crt` + `.key`, signed by the same CA) comes
with it, so mutual TLS - `client_cert`/`client_key` - is exercisable too.

Keys are world-readable and the CA is self-signed on purpose. This instance is
disposable; none of it is a template for anything real.

```bash
openldap-cli --profile test-root tls show      # over ldaps://localhost:636
openldap-cli --profile test-root tls ca-list   # the one published in the tree
```

## Seed

`ou=users` (admin, user1.name, user2.name), `ou=groups` (admin, demo),
`ou=service-accounts` (phpldapadmin, ssp), `ou=policies` (defaultppolicy).
Passwords are cleartext — `slapadd` bypasses the ppolicy hashing overlay; fine
for a throwaway test instance, **never** for prod.

**nis schema:** the bootstrap also loads the `nis` schema (beyond upstream's
core/cosine/inetorgperson/dyngroup) so `user add --posix` (posixAccount) works.
Load it in prod too if you use `--posix`.

**Test-only deviation:** the two rootDN passwords in `slapd-config.ldif` are set
to known cleartext (`cn=admin,dc=example,dc=org` → `rootpassword`,
`cn=adminconfig,cn=config` → `configpassword`) instead of upstream's SSHA
hashes, so ACL-restricted writes (ppolicy under `ou=policies`, `cn=config`) can
be exercised. Use the `test-root` profile for those. Prod keeps real hashes.
