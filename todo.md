CLI vs ldapadd / ldapmodify / ldapsearch

Ce que la CLI apporte en plus (c'est un outil d'admin opinionated, pas un client LDAP brut) :
- Commandes métier : user add dérive cn/sn/mail + génère un mdp dimensionné à la ppolicy ; svc add crée l'entrée et injecte l'ACL cn=config ; group/ou/ppolicy typés.
- Chirurgie ACL que ldapmodify ne fait pas tout seul : svc add/delete (inject/remove de clauses by), config acl move (réordonne + renumérote). En brut c'est le ballet delete {N} / add {N} à la main.
- Double bind (data + cn=config) automatique ; profils ; sortie structurée json/yaml + stdout/stderr propre ; verbes bulk avec sélecteurs (--group/--filter) ; backup/restore LDIF gz over-the-wire avec contournement du olcSizeLimit ; diagnostics (ops monitor/db-stats/audit-binds/replication) ; tailles/uptime lisibles.

Là où tu retombes encore sur ldap* (les vrais manques) :

┌─────────────────────────────────────────────────────────────────────────────┬─────────────────────────────────────┬────────────────────────────────────────────────────────┐
│                                   Besoin                                    │                ldap*                │                    CLI aujourd'hui                     │
├─────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────┤
│ Modifier un attribut sur un DN quelconque                                   │ ldapmodify                          │ ❌ user set = users only ; config set = cn=config only │
├─────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────┤
│ Supprimer un DN quelconque                                                  │ ldapdelete                          │ ❌ que user/group/ou/svc delete typés                  │
├─────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
│ Ajouter une entrée arbitraire inline                                        │ ldapadd                             │ ~ seulement import-ldif <file>                         │
├─────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────┤
│ modrdn sur un DN quelconque                                                 │ ldapmodrdn                     e                                │
├─────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────┤
│ Voir les attributs opérationnels (+)                                        │ ldapsearch '+'                      │ ~ search --attrs + marche mais pas évident             │
├─────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
│ SASL EXTERNAL / ldapi:// (admin cn=config en root local, sans mot de passe) │ ldapsearch -Y EXTERNAL -H ldapi:/// │ ❌ simple bind + StartTLS seulement                    │
├─────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────┤
│ compare (asserter une valeur sans lire)                                     │ ldapcompare                                                     │
└─────────────────────────────────────────────────────────────────────────────┴─────────────────────────────────────┴────────────────────────────────────────────────────────┘

Ce que je recommande d'ajouter

1. Primitives génériques entry (le gros manque — l'échappatoire écriture, pendant du search en lecture) :
entry set <dn> <attr> [values…]      # modify n'importe quel DN (replace / delete)
entry delete <dn>                    # ldapdelete
entry rename <dn> <newrdn> [--newsuperior <dn>]   # ldapmodrdn
entry add <dn> <objectClass…> --set a=b …         # ldapadd inline (sinon import-ldif)
Ça ferme le trou « je dois toucher une entrée non standard » qui te force aujourd'hui vers ldapmodify. user setccourcis typés au-dessus.

2. search --operational (ajoute +) — 5 lignes, pratique pour voir entryUUID, pwdChangedTime, contextCSN, etc.

3. (Plus gros, à évaluer) SASL EXTERNAL sur ldapi:// — te permettrait d'administrer cn=config en root sur l'hôtpasse, comme tes screenshots (-Y EXTERNAL -H ldapi:///). Vrai gain opérationnel, mais dépend du support go-ldap(à vérifier) → chantier séparé.

Ce que je n'ajouterais PAS : un équivalent slapacl (test d'accès effectif) — c'est local au serveur, pas faisab ops who-can-write reste l'approximation.
