# openldap-cli

**Manage OpenLDAP from one fast, typed command — no more `ldapmodify` LDIF golf,
no more brittle bash wrappers.**

A single static Go binary that turns everyday directory work — users, groups,
service accounts, password policies, ACLs, diagnostics — into clean commands with
sane defaults and machine-readable output. Point it at any OpenLDAP server.

```bash
openldap-cli user add toto.titi                 # derives cn/sn/mail, generates a strong password
openldap-cli -o json user info toto.titi | jq   # structured output, pipe-friendly
openldap-cli group add-member devs toto.titi
openldap-cli users delete --filter '(title=Intern)' --yes
```

### Why

- **One binary, zero deps.** Static Go — drop it anywhere, including your LDAP container.
- **Opinionated, not cryptic.** `user add`, `group create`, `svc add` instead of
  hand-rolled LDIF; strong passwords, schema-aware `--set`, posix accounts on demand.
- **Built for scripting.** `-o json|yaml|text`, logs on stderr / data on stdout,
  exit codes you can trust. Bulk verbs (`users`, `groups`, `svcs`) for fleet changes.
- **Goes where the GUIs stop.** `cn=config` ACL surgery, ppolicy lifecycle,
  `cn=Monitor` stats, accesslog audits — first-class commands.
- **Multi-environment.** Named profiles (`--profile prod`), env overrides, a
  separate config bind for `cn=config` writes.
- **Scales past the size limit.** Bulk reads and `backup` page automatically and
  transparently lift `olcSizeLimit` via the config bind — no truncated lists, no
  manual server tuning.

## Install

Grab a static binary from the [Releases](../../releases) page — no runtime, no
dependencies (amd64 + arm64 each; verify against `checksums.txt`):

- **Linux / macOS** — `openldap-cli_<ver>_<os>_<arch>.tar.gz`
  (`tar xzf …` → `./openldap-cli`)
- **Windows** — `openldap-cli_<ver>_windows_<arch>.exe`

Or build it:

```bash
make build      # -> ./openldap-cli   (static, stripped; Go 1.26+)
make install    # -> $GOBIN/openldap-cli
```

## Testing & checks

```bash
make unit         # pure unit tests (no server): acl, config, domain, humanize,
                  # ldaptime, ldapx façade, ldif, output, pwd, schema
make integration  # ldapx façade vs the test LDAP — run `make test-up` first
make e2e          # build the binary + drive every command group end-to-end
make lint         # golangci-lint (~23 linters; config in .golangci.yml)
make security     # gosec
```

## Configure

Settings come from `~/.openldap-cli.yaml` (or `--config PATH`), overridden by
`LDAP_*` env vars. Pick a profile with `--profile` (defaults to the file's
`default:` key, else `default`). See [`.openldap-cli.example.yaml`](.openldap-cli.example.yaml).

```yaml
default: prod
profiles:
  prod:
    url: ldaps://ldap.example.org:636
    base_dn: dc=example,dc=org
    bind_dn: cn=admin,ou=users,dc=example,dc=org   # data admin
    bind_pw: ""                                    # prefer LDAP_BIND_PW
    user_ou: ou=users
    group_ou: ou=groups
    policy_ou: ou=policies
    mail_domain: example.org
    # second bind for cn=config writes (svc ACL, ops reads):
    config_bind_dn: cn=adminconfig,cn=config
    config_bind_pw: ""                             # prefer LDAP_CONFIG_BIND_PW
```

Env overrides: `LDAP_URL`, `LDAP_BASE_DN`, `LDAP_BIND_DN`, `LDAP_BIND_PW`,
`LDAP_USER_OU`, `LDAP_GROUP_OU`, `LDAP_POLICY_OU`, `LDAP_MAIL_DOMAIN`,
`LDAP_CONFIG_BIND_DN`, `LDAP_CONFIG_BIND_PW`, `LDAP_START_TLS`, `LDAP_INSECURE`,
`LDAP_SASL_EXTERNAL`.

### SASL EXTERNAL over `ldapi://` (passwordless local admin)

Set `sasl_external: true` (or `LDAP_SASL_EXTERNAL=true`) with an `ldapi://`
URL to bind via **SASL/EXTERNAL** — the identity comes from the Unix-socket
peer credentials, so `bind_dn`/`bind_pw` (and even `config_bind_dn`) are not
needed. Run as **root on the LDAP host** to manage `cn=config` with no stored
password, the CLI equivalent of `ldapsearch -Y EXTERNAL -H ldapi:///`:

```yaml
profiles:
  local-root:
    url: ldapi:///              # default socket /var/run/slapd/ldapi
    base_dn: dc=example,dc=org
    sasl_external: true
```

```bash
sudo openldap-cli --profile local-root config acl list 'olcDatabase={1}mdb,cn=config'
```

This works only if the server maps the peer identity to a privileged DN
(`olcAuthzRegexp` + a `cn=config` ACL granting `gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth`);
a custom socket path is `url: ldapi://%2Frun%2Fslapd%2Fldapi`.

### Switching profiles

```bash
openldap-cli profile list          # all profiles, * marks the default
openldap-cli profile current       # active profile, passwords masked
openldap-cli profile use prod      # persist the switch (edits `default:`, keeps comments)
openldap-cli --profile dev user …  # one-off override for a single command
```

### Two binds

Some operations write to `cn=config` (which only the config rootDN may touch).
Set `config_bind_dn`/`config_bind_pw` (e.g. `cn=adminconfig,cn=config`) for:
`svc add/delete` (ACL injection), `config`/`entry --config-bind`, and all `ops`
reads. Commands that only touch the data tree use the regular `bind_dn`.

On the LDAP host you can skip the config bind entirely with **SASL EXTERNAL over
`ldapi://`** — see [below](#sasl-external-over-ldapi-passwordless-local-admin).

## Global flags

| Flag            | Default                | Purpose                                                   |
| --------------- | ---------------------- | --------------------------------------------------------- |
| `-p, --profile` | file `default:`        | which profile to use                                      |
| `-c, --config`  | `~/.openldap-cli.yaml` | config file path                                          |
| `-o, --output`  | `text`                 | result format: `text` \| `json` \| `yaml` (stdout)        |
| `--log-level`   | `info`                 | `trace`\|`debug`\|`info`\|`warn`\|`error` (logs → stderr) |
| `--log-format`  | `console`              | `console` \| `json`                                       |

Logs go to **stderr**, results to **stdout** — so `-o json … | jq` stays clean.

## Commands

### general

| Command                                                                                           | Notes                                                                                                                                                |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `whoami`                                                                                          | bound identity (LDAP Who Am I ext-op) — connection sanity check                                                                                      |
| `search <filter> [--base] [--scope base\|one\|sub] [--attrs a,b] [--operational] [--config-bind]` | raw search escape hatch; `--operational` also returns `+` attrs (`entryUUID`, `pwdChangedTime`, `contextCSN`…); `--config-bind` searches `cn=config` |
| `import-ldif <file> [--stop-on-error]`                                                            | add entries from an LDIF file                                                                                                                        |
| `version`                                                                                         | print version                                                                                                                                        |

> `user` subcommands resolve a login within `user_ou`. If you `user move` someone
> out of it, manage them by DN with `search`/`entry` instead.

### entry (generic write/read on any DN — the escape hatch)

The write-side counterpart of `search`, for entries the typed commands don't
cover. Uses the data bind; `--config-bind` targets `cn=config`.

| Command                                                             | Notes                                                                                     |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `entry get <dn> [attr...]`                                          | read one entry (base scope; all attrs if none named) — like `ldapsearch`                  |
| `entry add <dn> <attr=value>...`                                    | create an entry from `attr=value` pairs (repeat a name for multi-values) — like `ldapadd` |
| `entry set <dn> <attr> [value...] [--add]`                          | replace an attribute; no value = delete it; `--add` appends — like `ldapmodify`           |
| `entry rename <dn> <new-rdn> [--newsuperior <dn>] [--keep-old-rdn] [--no-fix-acl]` | modrdn / move — like `ldapmodrdn`; re-points the `olcAccess` rules naming the old DN (data entries only) |
| `entry delete <dn>`                                                 | delete any leaf entry — like `ldapdelete`                                                 |

### user

| Command                                                                                                              | Notes                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `user add <login> [--password\|--no-password] [--set k=v …] [--posix [--uid-number\|--gid-number\|--home\|--shell]]` | `firstname.lastname` derives givenName/sn/displayName; a **plain login** (e.g. `demo1`) sets uid/cn/sn=login; **generates a strong password sized to the effective ppolicy** if none given (printed once); `--set` adds arbitrary attributes — unknown-to-schema ones are **warned & skipped**; `--posix` auto-assigns uidNumber (needs `nis` schema) |
| `user delete <login>`                                                                                                | refint auto-purges group memberships                                                                                                                                                                                                                                                                                                                  |
| `user info <login>`                                                                                                  | attrs + groups + lockout/mustChange/failures + assigned policy                                                                                                                                                                                                                                                                                        |
| `user passwd <login> [--password]`                                                                                   | Password Modify ext-op (ppolicy hashes). Without `--password` the CLI generates one **client-side, sized to the effective ppolicy** (`pwdMinLength`) and **retries stronger** if the server still rejects it — no manual sizing                                                                                                                       |
| `user set <login> <attr> [value...]`                                                                                 | replace attribute; no value = delete it                                                                                                                                                                                                                                                                                                               |
| `user rename <old> <new.login>` `[--no-fix-acl]`                                                                     | cn modrdn + refresh derived attrs (refint rewrites group member DNs); re-points the `olcAccess` rules naming the old DN                                                                                                                                                                                                                                                                                  |
| `user unlock <login>`                                                                                                | clears `pwdAccountLockedTime`; best-effort failure-counter reset via Relax control                                                                                                                                                                                                                                                                    |
| `user force-reset <login> [--clear]`                                                                                 | sets/clears `pwdReset`                                                                                                                                                                                                                                                                                                                                |
| `user move <login> <new-parent-dn>` `[--no-fix-acl]`                                                                 | modrdn to another OU (keeps RDN); re-points the `olcAccess` rules naming the old DN                                                                                                                                                                                                                                                                                                                      |

(Listing, import and export are inherently set-oriented — see `users` below.)

### users / groups / svcs (bulk — plural scopes)

Plural commands act on many targets at once (the singular forms act on one).

| Command                                                           | Notes                                                                                            |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `users delete [login…] [--group\|--filter] [--yes]`               | by explicit logins and/or a selector                                                             |
| `users unlock [login…] [--group\|--filter\|--all-locked] [--yes]` |                                                                                                  |
| `users force-reset [login…] [--group\|--filter] [--yes]`          |                                                                                                  |
| `users set <attr> <value> [login…] [--group\|--filter] [--yes]`   | empty value = delete the attribute                                                               |
| `users passwd [login…] [--group\|--filter] [--yes]`               | generates a fresh password per user (printed)                                                    |
| `users list [--group\|--locked\|--posix]`                         | filtered listing                                                                                 |
| `users import <csv> [--stop-on-error]`                            | rows: `firstname.lastname[,group][,mail-override]`                                               |
| `users export [--group] [--with-hash] [--ldif]`                   | CSV → stdout (global `-o` N/A); `--with-hash` exposes hashes; `--ldif` writes re-importable LDIF |
| `groups list [--members]` / `svcs list`                           | listings                                                                                         |
| `groups delete <name…>` / `svcs delete <name…>`                   | bulk delete by name                                                                              |

Selectors (`--group`/`--filter`/`--all-locked`) require **`--yes`** (they print
the match count and refuse otherwise); explicit logins don't. `--stop-on-error`
aborts on the first failure (default: continue, per-item result).

### group / ou

| Command                                               | Notes                                          |
| ----------------------------------------------------- | ---------------------------------------------- |
| `group create <name> --member <login> …`              | groupOfNames needs ≥1 member                   |
| `group info <name>`                                   | (listing is `groups list`)                     |
| `group add-member <group> <login…>` / `remove-member` | removing the last member violates groupOfNames |
| `group set <name> <attr> [value…]`                    | replace an attribute (no value deletes it). Use `add-member` for membership — this replaces the whole attribute |
| `group rename <name> <new-name>` `[--no-fix-acl]`     | `cn` modrdn. `memberOf` follows on its own; the `olcAccess` rules naming the old DN are **re-pointed at the new one** (needs the config bind — see Gotchas) |
| `group delete <name>`                                 |                                                |
| `ou create <name> [--parent DN]`                      | parent must be ACL-writable by your bind       |
| `ou info <name> [--parent]` / `ou set <name> <attr> [value…]` | read an OU / replace an attribute (no value deletes it) |
| `ou rename <name> <new-name> [--parent] [--no-fix-acl]` | `ou` modrdn; entries below it follow, and so do the `olcAccess` rules naming them. To change parent, use `entry rename --newsuperior` |
| `ou list` / `ou delete <name> [--parent]`             | delete refuses a non-empty OU                  |

### ppolicy (writes to `ou=policies` need a rootDN bind)

| Command                                                                                                                                                                  | Notes                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| `ppolicy set <name> [--min-length --max-age --expire-warning --in-history --max-failure --lockout-duration --check-quality --lockout --must-change --allow-user-change]` | create or update; only the flags you pass are written |
| `ppolicy assign <login> <policy> [--clear]`                                                                                                                              | sets `pwdPolicySubentry` (regular admin)              |
| `ppolicy list` / `ppolicy show <name>` / `ppolicy delete <name>`                                                                                                         | list/show (any bind); delete needs rootDN             |

### svc (service accounts — entry + `cn=config` ACL)

| Command                                                         | Notes                                                                      |
| --------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `svc add <name> --subtree DN --access read\|write [--password]` | creates entry **and** injects an `olcAccess` clause; auto 32-char password |
| `svc passwd <name> [--password]`                                |                                                                            |
| `svc delete <name>`                                             | deletes entry **and** strips its ACL clauses                               |
| `svc info <name>`                                               | surfaces the ACL clauses referencing the account (listing is `svcs list`)  |
| `svc grant <name> --tree DN [--members-of <group>] [--access read\|write]` (alias `grant-read`) | **the "an app must work on a tree" recipe**: emits both rules it needs — the container rule (so the tree can be used as a search base) plus the entry rule — each auto-placed above the rule that would shadow it, `by * break` (additive), idempotent. The container access follows `--access`: `search` for read, **`write` for `--access write`** (creating/deleting a child needs write on the parent). `--members-of` narrows the entry rule to that group's members (least privilege) |
| `svc revoke <name> [--tree DN]`                                                | the counterpart of `svc grant`: `--tree` undoes **one** grant (both its rules), leaving the account's access to other trees alone; without `--tree` it removes every clause the account has on the database. Co-grantees in the same rule keep their access; rules left with no grantee are dropped |

`olcAccess` is ordered: edits delete `{N}old` + add `{N}new` in one modify. New
rules for an un-covered subtree are **appended at the end** — verify they
evaluate before any broad catch-all. Deleting the sole grantee of a rule leaves
an orphan `to <subtree> by * none` (same as the bash script).

### ops (diagnostics — read via the config bind)

| Command                                                                | Notes                                                                                   |
| ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `ops db-stats`                                                         | per-DB entries + used/max size (human-readable) and page usage % (catch `MDB_MAP_FULL`) |
| `ops audit-binds [--since 24h\|7d] [--user]`                           | bind summary from `cn=accesslog`                                                        |
| `ops accesslog-purge [--keep-days] [--sweep] [--dry-run] [--set SPEC]` | tunes `olcAccessLogPurge`; server purges on next sweep                                  |
| `ops who-can-write <dn>`                                               | `olcAccess` rules referencing a DN (read manually)                                      |
| `ops replication`                                                      | local `contextCSN`; multi-peer drift is HA-only                                         |
| `ops monitor`                                                          | runtime stats from `cn=Monitor` (connections, operations, threads, statistics)          |

### config (cn=config — needs the config bind)

| Command                                                                        | Notes                                                                                                                    |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| `config db list` / `config overlay list`                                       | introspect databases / overlays (`list` marks each overlay `active` or `DISABLED`)                                       |
| `config db resize <db-dn> <size>`                                              | set `olcDbMaxSize` (accepts `4GiB`/`512MiB`/bytes); remaps the LMDB env — can disrupt slapd under load (see Gotchas)     |
| `config overlay enable <name> [--db <dn>] [--no-module]`                       | enable an overlay (memberof, refint, ppolicy, accesslog, unique, …) on the database holding `base_dn`; **loads its module first** if the schema is missing, and resolves its config `objectClass` from the server's schema. Idempotent; re-enables one turned off by `disable`. `--no-module` fails instead of loading |
| `config overlay disable <name> [--db <dn>] [--purge]`                          | set `olcDisabled: TRUE` — stops the overlay live but **keeps its settings**, so `enable` restores them. `--purge` deletes the entry and its settings instead. The module stays loaded either way (slapd refuses to unload one) |
| `config acl list <database-dn>`                                                | show `olcAccess` rules on a database                                                                                     |
| `config acl move <database-dn> <from> <to>`                                    | reorder an `olcAccess` rule (renumbers the rest, live) — fixes a specific rule shadowed by a broader one placed above it |
| `config acl grant <database-dn> <target> --access <a> (--group <g> \| --dn <d>) [--scope sub\|base] [--filter '(…)'] [--at N] [--terminator break\|none]` | add a `by <who> <access>` clause; `--group` grants **all its members**; `--scope base` grants the container only (needed to *search* a tree); `--filter` narrows the rule to matching entries (least privilege); `--at` places a new rule **above** the broad rule that would shadow it; new rules end in `by * break` (additive) |
| `config acl revoke <database-dn> (--group <g> \| --dn <d>)`                      | remove every clause referencing that group or DN, and **drop the rules left with nothing to say** (a rule whose last clause was the revoked one — slapd rejects a clauseless rule, which used to fail the whole revoke — or one left as a no-op `by * break`). An explicit `by * none` deny is kept: dropping it would widen access |
| `config acl lint <database-dn>`                                                 | report rules that can never fire — a specific rule shadowed by a broader one above it (the classic "grant with no effect" / `noSuchObject`), and rules left doing nothing after a revoke |
| `config set <dn> <attr> [value…]`                                              | set/delete any `cn=config` attribute (e.g. `olcAccessLogSuccess`)                                                        |
| `config limits get [--db]`                                                     | show `olcSizeLimit`/`olcTimeLimit`/`olcLimits`                                                                           |
| `config limits set [--db] [--size N\|unlimited] [--time N] [--for <selector>]` | raise the search size cap; `--for` writes a per-identity `olcLimits`                                                     |

### backup (logical LDIF over the wire — no docker/shell/volume needed)

| Command                                   | Notes                                                                                                                                                  |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `backup data <file> [--operational]`      | dump the `base_dn` subtree as LDIF; gzip when the name ends in `.gz`. Pages automatically and lifts `olcSizeLimit` (see below) so nothing is truncated |
| `backup config <file>`                    | dump `cn=config` (config bind). Inspection / DR record — **not** restorable live over LDAP                                                             |
| `backup restore <file> [--stop-on-error]` | re-add entries from a plain or gzipped LDIF (auto-detected). **Bind as the rootDN**                                                                    |

Restore strips server-managed attributes (`entryUUID`, `entryCSN`,
`structuralObjectClass`, `memberOf`, ppolicy timers …) and sends the **Relax**
control so a pre-hashed `userPassword` is accepted under a strict ppolicy — but
Relax is only honored for the **rootDN**, so run restores with a rootDN profile.
This is a logical backup; it **complements**, and does not replace, a
filesystem / `slapcat` backup (operational/replication state and the config tree
are not restorable over the wire).

### schema

| Command                                     | Notes                                             |
| ------------------------------------------- | ------------------------------------------------- |
| `schema list-classes` / `schema list-attrs` | list objectClass / attributeType names            |
| `schema show <name>`                        | raw definition of an objectClass or attributeType |

## Test environment

A throwaway, self-contained OpenLDAP (Docker) so you can try the CLI in seconds —
real overlays (memberof, refint, ppolicy, accesslog) and a seeded tree:

```bash
make test-up      # bootstrap + start (idempotent)
make test-reset   # wipe + rebuild
make test-down    # stop
```

Bind `cn=admin,ou=users,dc=example,dc=org` / `adminpassword`, base
`dc=example,dc=org`, GUI http://localhost:8080. The example config ships `test`
(data admin) and `test-root` (rootDN, for `ppolicy set` / OUs under the base)
profiles. See [`tests/README.md`](tests/README.md) for details.

## Gotchas worth knowing

- **ppolicy lockout is real:** repeated bad binds (`pwdMaxFailure`) lock the
  data admin. Recover via a rootDN profile (`user unlock <admin>`).
- **`ppolicy set` / OUs under the base / `svc` ACLs** require the rootDN — your
  `ou=users` admin has write only inside specific subtrees.
- **`--posix`** needs the `nis` schema loaded server-side.
- **`olcAccess` order matters — and the trap when reordering.** Rules are
  evaluated by index and evaluation **stops at the first matching `to` target**,
  so a specific rule below a broad one never fires (a classic cause of a
  `noSuchObject`/code 32 where the base entry's `disclose` was denied). Use
  `config acl move` to raise it — and **`config acl lint` finds these for you**
  (it reports every rule an earlier one shadows). **But** raising a narrow rule
  that ends in `by * none` blocks every identity the broader rule served on that
  entry (rootDN excepted) — give it a `by * break` (or the needed `by …`
  clauses) first, editing the rule with `config set`.
- **Several accounts, same tree → one rule (or a group), not two rules.**
  Evaluation stops at the first rule whose `to` matches, so a **second rule with
  the same `to`** is dead — the first grantee works, the rest silently don't.
  Grant all of them in the **same** rule instead: `config acl grant` inserts a
  `by <who>` clause into the existing rule (multiple `by` clauses coexist, one
  per identity). For many/rotating accounts, grant a **group** once
  (`--group readers`) and manage membership — no ACL edits per account.
- **A rename carries its ACLs with it — the CLI repairs them for you.** slapd
  rewrites nothing in `olcAccess`: on its own, after `group rename devs
  engineers`, a rule granting `group.exact="cn=devs,…"` would still name a DN
  that no longer exists, stop matching, and drop every member's access **with no
  error anywhere** (the client sees `noSuchObject`, not "denied"). So every
  command that changes a DN — `user rename`, `user move`, `group rename`,
  `ou rename`, `entry rename` — re-points the rules naming the old DN at the new
  one, including the `filter=(memberOf=…)` of a `svc grant --members-of` and the
  rules naming entries *below* a renamed container. `memberOf` needs nothing: the
  memberof overlay maintains it. This needs the **config bind**; without it the
  rename still happens and says loudly that the ACLs were not checked.
  `--no-fix-acl` opts out. Two rule forms cannot be rewritten mechanically and
  are reported for review instead: `dn.regex=` (a literal substitution can change
  what a pattern matches) and `set=`.
- **Generated passwords adapt to the policy.** `user passwd` / `user add` /
  `users passwd` size the generated password to the effective `pwdMinLength`
  (resolved from the user's `pwdPolicySubentry`, the overlay `olcPPolicyDefault`
  via the config bind, or a sole policy) and retry stronger on a constraint
  violation. If a custom complexity module still rejects it after a few tries,
  the error says so — pass `--password` explicitly.
- **`user export --with-hash`** prints password hashes — sensitive output.
- **Resizing `olcDbMaxSize` can disrupt slapd.** `config db resize` (and
  `config set olcDbMaxSize`) remap the LMDB env. On a live, busy server this
  races with active transactions and can briefly interrupt — sometimes restart —
  slapd (observed intermittently, any database, under concurrent load). The new
  size is persisted to `cn=config` and applied regardless, and the command warns
  first. Prefer a quiet maintenance window.
- **`backup restore` needs the rootDN:** the Relax control (re-adding a
  `userPassword` under a strict ppolicy) is only honored for the rootDN. As a
  data admin, password-bearing entries fail the policy check. `backup` is a
  logical dump — for config-tree / replication-state recovery, keep a
  `slapcat`/filesystem backup.
- **Listing >500 entries is handled for you.** OpenLDAP's `olcSizeLimit`
  (default 500) caps results per bound identity, and RFC 2696 paging does **not**
  bypass it. So `users list` / `users export` / `groups list` / `backup data` (and
  the `--group` / `--filter` selectors) page automatically and, if the server
  caps the result, **temporarily lift the limit via the config bind** (a scoped
  `olcLimits` override on the data database), return everything, then restore
  `olcLimits` — logging a warning when they do. This needs a working
  `config_bind_dn` / `config_bind_pw`; without one (or with bad config
  credentials) you get a clear error telling you to set the config bind or bind
  as the rootDN — never a silent truncation. (Bulk `users import` has no such limit.)
  Prefer a permanent fix? `config limits set --for 'dn.exact=<admin-dn>' --size unlimited --db 'olcDatabase={1}mdb,cn=config'`.

## Layout

```
cmd/openldap-cli/   main entrypoint (package main)
internal/
  cli/      cobra commands (user, users, group, ..., ops, config, schema)
  config/   profile loading (yaml + env)
  ldapx/    thin go-ldap/v3 wrapper (connect, search, modify, modrdn, ...)
  domain/   YOUR conventions — naming + schema (edit here)
  acl/      olcAccess surgery        (unit-tested)
  ldif/     LDIF read/write          (unit-tested)
  pwd/      password generation      (unit-tested)
  schema/   schema NAME parser       (unit-tested)
  output/   text/json/yaml rendering
tests/      faithful test OpenLDAP (compose + bootstrap)
```

## Examples

> Try any of these against the throwaway server: `make test-up`, then add
> `--profile test` (or `--profile test-root` for `cn=config` / `ou=policies` writes).

### Users

```bash
# create — strong password generated and printed once
openldap-cli user add toto.titi
openldap-cli user add demo1 --no-password                 # plain login, no password
openldap-cli user add jane.doe --posix --set title=SRE --set 'telephoneNumber=+33...'

openldap-cli user info toto.titi                          # identity + groups + lockout/policy
openldap-cli -o json user info toto.titi | jq .groups

openldap-cli user set toto.titi description "On call"     # set/replace an attribute
openldap-cli user set toto.titi telephoneNumber           # (no value) delete it
openldap-cli user passwd toto.titi --password 's3cret-but-long-enough'
openldap-cli user rename toto.titi toto.tata              # cn modrdn + refresh derived attrs
openldap-cli user move toto.tata ou=contractors,dc=example,dc=org

openldap-cli user force-reset toto.tata                   # must change password next login
openldap-cli user unlock toto.tata                        # clear ppolicy lockout
openldap-cli user delete toto.tata
```

### Groups & OUs

```bash
openldap-cli group create devs --member toto.titi --member jane.doe
openldap-cli group add-member devs demo1
openldap-cli group info devs
openldap-cli groups list
openldap-cli group remove-member devs demo1
openldap-cli group set devs description 'Core team'
openldap-cli group set devs description                    # no value = delete it
openldap-cli group rename devs engineers                  # warns about ACLs naming cn=devs
openldap-cli group delete engineers

openldap-cli ou create contractors --parent ou=users,dc=example,dc=org
openldap-cli ou list
openldap-cli ou info contractors --parent ou=users,dc=example,dc=org
openldap-cli ou set contractors description 'External staff' --parent ou=users,dc=example,dc=org
openldap-cli ou rename contractors externals --parent ou=users,dc=example,dc=org  # children follow
openldap-cli ou delete externals --parent ou=users,dc=example,dc=org
```

### Bulk (plural scopes)

```bash
# CSV: rows are  firstname.lastname[,group][,mail-override]
openldap-cli users import staff.csv
openldap-cli users list --group devs
openldap-cli users list --locked

# act on many: explicit list and/or a selector (selectors need --yes)
openldap-cli users set title Intern alice.smith bob.jones
openldap-cli users force-reset --group interns --yes
openldap-cli users unlock --all-locked --yes
openldap-cli users passwd alice.smith bob.jones              # one fresh password per user
openldap-cli users delete --filter '(title=Intern)' --yes

# export / re-import
openldap-cli users export > users.csv
openldap-cli users export --ldif > users.ldif
openldap-cli import-ldif users.ldif
openldap-cli groups delete old.team another.team          # bulk delete groups by name
openldap-cli svcs delete legacy.agent                     # entry only (ACL cleanup: singular `svc delete`)
```

### Service accounts (entry + cn=config ACL)

```bash
openldap-cli svc add backup-agent --subtree ou=users,dc=example,dc=org --access read
openldap-cli svcs list
openldap-cli svc info backup-agent                           # shows the ACL clauses granting it
openldap-cli svc passwd backup-agent
openldap-cli svc delete backup-agent                         # also strips its ACL clauses
```

### Give an app access to a tree (the common recipe)

An app working on a tree needs **two** rules: one on the container — so the tree
can be used as a search base; without it a search fails with `noSuchObject` even
when the entries are readable — and one on the entries. `svc grant` emits both,
places each above whatever would shadow it, and ends them with `by * break` so no
other identity is affected:

```bash
# read-only: the app may list ONLY the members of a group (least privilege)
openldap-cli svc grant app --tree ou=users,dc=example,dc=org --members-of admins
# read-only: the app may list every group
openldap-cli svc grant app --tree ou=groups,dc=example,dc=org
# read-write: the app may also create / modify / delete entries in the tree
openldap-cli svc grant app --tree ou=devices,dc=example,dc=org --access write

# hand one tree back (the other grants above are untouched)
openldap-cli svc revoke app --tree ou=devices,dc=example,dc=org
# ...or cut the account off entirely
openldap-cli svc revoke app

openldap-cli config acl lint 'olcDatabase={1}mdb,cn=config'   # prove nothing is shadowed
```

The container access follows `--access`: `search` for a read grant, **`write` for
`--access write`** — creating or deleting a child needs write on the *parent*
(slapd says `no write access to parent` otherwise).

`--members-of` fits read and modify; a brand-new entry cannot match a `memberOf`
filter before it exists, so **creating** entries needs an unfiltered grant.

Re-running is a no-op, so it is safe in a provisioning script. Prefer it over
hand-writing `olcAccess`; drop to `config acl grant --scope/--filter/--at` only
when you need a shape it does not cover.

### Password policies (writes need the rootDN)

```bash
openldap-cli --profile prod-root ppolicy set strict --min-length 16 --max-failure 3 --lockout --lockout-duration 1800
openldap-cli ppolicy list
openldap-cli ppolicy show strict
openldap-cli ppolicy assign toto.titi strict                 # override the default policy
openldap-cli ppolicy assign toto.titi --clear                # back to default
openldap-cli --profile prod-root ppolicy delete strict       # needs the rootDN too
```

### Config & schema

```bash
openldap-cli config db list
openldap-cli config overlay list                          # each one: active | DISABLED
# turn an overlay on (loads memberof.so if it isn't loaded yet) — memberof is
# what makes `svc grant --members-of` and the memberOf attribute work:
openldap-cli --profile prod-root config overlay enable memberof
openldap-cli --profile prod-root config overlay disable ppolicy   # off, settings kept
openldap-cli --profile prod-root config overlay enable ppolicy    # back on, as it was
openldap-cli config acl list 'olcDatabase={1}mdb,cn=config'
openldap-cli --profile prod-root config acl move 'olcDatabase={1}mdb,cn=config' 8 5   # raise a shadowed rule
# several service accounts, same rights on a tree -> one group grant:
openldap-cli group create readers --member svc.a
openldap-cli group add-member readers svc.b
openldap-cli --profile prod-root config acl grant 'olcDatabase={1}mdb,cn=config' \
  'ou=app,dc=example,dc=org' --group readers --access read
openldap-cli --profile prod-root config db resize 'olcDatabase={2}mdb,cn=config' 4GiB # olcDbMaxSize
openldap-cli --profile prod-root config limits set --size 5000                        # raise the search cap

openldap-cli schema list-classes
openldap-cli schema show inetOrgPerson

# generic cn=config writer (the escape hatch for any olc* attribute)
openldap-cli --profile prod-root config set 'olcOverlay={4}accesslog,olcDatabase={1}mdb,cn=config' olcAccessLogSuccess TRUE
openldap-cli schema list-attrs | grep -i mail
```

### Any DN (the `entry` escape hatch)

```bash
openldap-cli entry add 'cn=printer1,ou=devices,dc=example,dc=org' \
  objectClass=device objectClass=top cn=printer1 serialNumber=XZ-42
openldap-cli entry get 'cn=printer1,ou=devices,dc=example,dc=org'
openldap-cli entry set 'cn=team,ou=groups,dc=example,dc=org' member 'cn=x,ou=users,dc=example,dc=org' --add
openldap-cli entry rename 'cn=old,ou=groups,dc=example,dc=org' cn=new
openldap-cli entry delete 'cn=printer1,ou=devices,dc=example,dc=org'
openldap-cli entry get 'cn=module{0},cn=config' olcModuleLoad --config-bind
```

### Diagnostics & search

```bash
openldap-cli whoami                                         # who am I bound as?
openldap-cli ops db-stats                                   # per-DB used/max size (human) — catch MAP_FULL
openldap-cli ops monitor                                    # connections / ops / threads
openldap-cli ops audit-binds --since 24h --user toto.titi
openldap-cli ops who-can-write 'cn=admin,ou=users,dc=example,dc=org'

openldap-cli search '(mail=*@example.org)' --attrs uid,mail
openldap-cli search '(uid=toto.titi)' --operational         # + entryUUID, pwdChangedTime, …
openldap-cli search '(objectClass=olcModuleList)' --base cn=config --config-bind
openldap-cli -o json search '(&(objectClass=inetOrgPerson)(title=SRE))' | jq -r '.entries[].dn'
openldap-cli ops accesslog-purge --keep-days 30 --dry-run   # count first, then drop --dry-run
openldap-cli ops replication                                # local contextCSN (drift check is HA-only)
```

### Backup & restore (no docker/alpine — just the CLI)

```bash
# Dump the data tree to a gzipped LDIF (paged: olcSizeLimit never truncates)
openldap-cli backup data "backup_data_$(date +%Y%m%d).ldif.gz"

# Full-fidelity dump incl. operational attributes (inspection, not restorable)
openldap-cli backup data --operational full_dump.ldif.gz

# Config tree dump — inspection / DR record only (config bind)
openldap-cli --profile prod-root backup config backup_config.ldif.gz

# Restore — bind as the rootDN so the Relax control is honored
openldap-cli --profile prod-root backup restore backup_data_20260630.ldif.gz
```

> Dumps contain password hashes — store them on an encrypted partition.
