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
