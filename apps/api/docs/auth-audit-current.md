# Audit actuel du module AUTH

Date: 2026-06-11
Portee: `apps/api` Fastify + TypeScript + Prisma/PostgreSQL.

Ce rapport analyse le code reel du workspace au moment de l'audit. Les references de lignes sont celles de cette version.

## A. Verdict global

Niveau actuel: avance, proche production pour l'auth principale.

Scores:

- Securite: 8.4/10
- Architecture: 8/10
- Maintenabilite: 8/10
- Production readiness: 7.6/10

Resume strict:

- Les anciens points critiques ont largement ete traites: CSRF, JWT claims, secret separation, refresh idempotent, outbox email chiffree, login lock, RBAC tenant, CI PostgreSQL, seed PrismaPg, migrations de hardening.
- Les risques restants ne sont plus principalement des bugs de code auth simples. Ils sont surtout operationnels: sequence de migration tenant sur DB existante, provider email reel avec idempotency garantie, observabilite multi-instance, execution obligatoire des tests DB, et politique complete avant exposition MFA/API keys.
- Aucun endpoint MFA/API key ne doit etre expose avant policy complete: rotation, revocation, recovery, audit, rate-limit et UX securite.

## B. Tableau complet des problemes

| ID | Fichier | Fonction/zone | Gravite | Categorie | Probleme detecte | Impact reel | Correction recommandee | Priorite |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P1 | `prisma/migrations/20260610120000_auth_production_hardening/migration.sql:1-10` | Tenant hardening | Haute | DB | Migration bloque si `Store.organizationId` contient encore NULL. | Deploy production casse si DB existante non backfillee. | Executer migration nullable, `tenant:backfill-stores`, puis `tenant:preflight` avant `migrate deploy`. | P0 |
| P2 | `src/jobs/preflightTenantMigration.ts:47-62` | Preflight | Haute | Production | Le preflight explique la procedure, mais ne peut pas appliquer automatiquement la migration nullable. | Risque humain de mauvaise sequence de release. | Ajouter runbook release obligatoire + dry-run CI/staging sur dump anonymise. | P0 |
| P3 | `src/lib/email.ts:274-337` | Provider HTTP | Haute | Fiabilite | Adapter HTTP generique, pas encore mappe a un provider reel. | Idempotency peut etre mal interpretee par SendGrid/Postmark/Mailgun/etc. | Creer adapter provider-specifique avec tests sandbox et status mapping. | P1 |
| P4 | `src/config/env.ts:539-547` | SMTP | Haute | Fiabilite | SMTP reste volontairement best-effort si `EMAIL_ALLOW_SMTP_BEST_EFFORT=true`. | Duplicats possibles apres panne partielle DB apres acceptation SMTP. | Preferer `EMAIL_PROVIDER=http` avec vraie cle idempotency provider. | P1 |
| P5 | `src/lib/email.ts:477-503` | `SENT_UNKNOWN` | Haute | Operabilite | Etat robuste present, mais remediation reste manuelle/runbook. | Un operateur peut relancer et envoyer un doublon. | Ajouter commande/dashboard de reconciliation SENT_UNKNOWN avec decision explicite. | P1 |
| P6 | `src/lib/metrics.ts:13-19` | Metrics | Moyenne | Observabilite | Metrics en memoire par process. | Vue fragmentee en multi-instance. | Scraper chaque instance ou exporter OTel/Prometheus collector. | P2 |
| P7 | `src/lib/operationalErrors.ts:29-41` | Logging | Moyenne | Observabilite | `reportOperationalError` ecrit JSON sur `console.error`, pas encore branche a logger app/SIEM. | Alerting dependant de la collecte stdout. | Integrer Pino logger, OTel events ou transport SIEM. | P2 |
| P8 | `src/modules/auth/auth.integration.test.ts:43-45` | Tests DB | Haute | Test | Les tests DB se skipent localement sans `RUN_DB_TESTS=true`. | Regression transactionnelle invisible en local. | Garder CI obligatoire et ajouter script dev `test:integration:db` documente. | P1 |
| P9 | `.github/workflows/api-ci.yml:57-69` | CI | Moyenne | Production | Workflow est complet, mais son execution depend de GitHub/branche protegee. | Si CI non activee/protegee, les garanties ne bloquent pas le merge. | Proteger `main/develop`, required checks, status checks obligatoires. | P1 |
| P10 | `src/modules/auth/session.service.ts:87-215` | Refresh idempotency | Moyenne | Securite | Reponse refresh stockee chiffree temporairement pour retry idempotent. | Si DB + secret compromis pendant TTL, refresh replay possible. | TTL court conserve, cleanup obligatoire, secret via KMS a terme. | P2 |
| P11 | `src/modules/auth/session.service.ts:262-363` | Grace refresh | Moyenne | Securite/UX | Apres grace consommee, meme contexte retourne 409, pas toujours replay si pas d'idempotency key. | Client sans idempotency key doit gerer retry proprement. | Rendre l'idempotency key obligatoire cote frontend pour `/refresh`. | P2 |
| P12 | `src/modules/auth/password.service.ts:96-123` | Reset password | Moyenne | Performance | Nouveau password hashe avant validation du token, puis compare a l'historique. | DoS CPU possible sur reset si rate limit contourne. | Verifier token avant hash lourd, ou maintenir rate-limit strict + cout bcrypt mesure. | P2 |
| P13 | `src/modules/auth/registration.service.ts:55-64` | Register existant | Moyenne | Securite | Reponse HTTP generique, mais chemin existant n'a pas les memes effets DB/email. | Enumeration possible par timing avance. | Ajouter jitter controle ou chemin dummy outbox/audit interne si menace elevee. | P3 |
| P14 | `prisma/schema.prisma:421-447` | ApiKey | Moyenne | DB | XOR owner est dans migration CHECK, pas exprimable directement dans Prisma schema. | Drift de migration pourrait casser la garantie. | Test DB qui tente user+organization et aucun owner. | P2 |
| P15 | `prisma/schema.prisma:449-473` | MFA | Haute | Securite | Modele MFA est une fondation; aucune policy de verification/recovery exposee. | Exposer trop tot peut creer bypass ou lockout. | Garder endpoints absents jusqu'au design complet MFA. | P1 |
| P16 | `src/middlewares/role.middleware.ts:493-546` | Tenant guard | Moyenne | Test | `requireStoreInOrganization` existe mais doit etre compose partout dans les routes metier. | Cross-tenant access si un module ERP oublie le guard. | Creer conventions route helpers + tests metier par module. | P1 |
| P17 | `src/plugins/security.ts:16-33` | Redis rate-limit | Moyenne | Production | Fail-closed au startup si Redis indisponible. | API refuse de demarrer en prod si Redis down. | C'est sur; documenter SLA Redis ou ajouter fallback explicite par env. | P2 |
| P18 | `src/utils/token.ts:40-42` | Legacy token hash | Moyenne | Secrets | Fallback legacy vers `PASSWORD_PEPPER` tant que deadline active. | Blast radius prolonge jusqu'a retrait. | Planifier suppression apres `LEGACY_SECRET_FALLBACK_UNTIL`. | P2 |
| P19 | `src/plugins/metrics.ts` + `monitoring/prometheus-alerts.yml` | Alerting | Moyenne | Production | Alertes existent pour audit/security/SENT_UNKNOWN, mais pas deployees par code. | Aucun signal si Prometheus rules non chargees. | Ajouter runbook verification des rules en staging/prod. | P2 |
| P20 | Dependances | `npm audit` | Moyenne | Supply chain | Advisories moderees Prisma/Hono signalees precedemment sans fix upstream. | Risque upstream selon chemin exploitable. | Dependabot actif, `audit:ci` high/critical, revue hebdo advisories. | P2 |

## C. Analyse fichier par fichier

### `src/modules/auth/auth.route.ts`

Role: expose les endpoints auth.

Points corrects:

- CSRF applique sur register, verify, resend, forgot, reset, login, refresh, logout, logout-all, change-password (`auth.route.ts:38-128`).
- Rate-limit specifique login et rate-limit general auth (`auth.route.ts:31-35`, `79-103`).
- `logout` accepte le refresh cookie sans `requireAuth`, ce qui permet de sortir meme avec access token expire (`auth.route.ts:105-110`).

Risques restants:

- Les futures routes metier doivent composer `requireAuth` + guards tenant/RBAC. Rien dans ce fichier ne protege les modules ERP futurs.

Correction:

- Ajouter un helper de route metier, par exemple `withStorePermission(storeIdParam, permission)` qui compose `requireAuth`, `requireStoreInOrganization`, `requireStorePermission`.

### `src/modules/auth/auth.schema.ts`

Role: validation DTO.

Points corrects:

- Schemas `.strict()` partout (`auth.schema.ts:17-62`).
- Token 128 hex exact (`auth.schema.ts:12-15`).
- Password policy stricte et limite bcrypt 72 chars (`auth.schema.ts:3-10`).

Risques restants:

- `storeId` impose CUID (`auth.schema.ts:22-24`). Correct si tout le modele utilise CUID, mais a documenter si import externe avec UUID.

Correction:

- Ajouter OpenAPI/Swagger pour rendre ces contrats visibles aux clients.

### `src/modules/auth/auth.controller.ts`

Role: parse input, appelle services, pose/supprime cookies.

Points corrects:

- Exposition des tokens dev conditionnee par `EXPOSE_AUTH_TOKENS`, lui-meme restreint dans `env.ts`.
- Refresh prend l'idempotency key header (`session.service.ts:160-215` cote service).

Risques restants:

- Verifier que le refresh cookie reste `HttpOnly`, `Secure` en prod, `SameSite` coherent avec le frontend. Information complete dans controller non relue dans cet extrait.

Correction:

- Documenter exact cookie policy dans `docs/auth.md` et ajouter test sur `Set-Cookie`.

### `src/modules/auth/registration.service.ts`

Role: inscription, creation user, token verification email, outbox.

Points corrects:

- Validation store actif + organization active avant association (`registration.service.ts:41-52`, repository `findActiveStoreForRegistration`).
- Hash password lance en parallele de lookup pour reduire timing brut (`registration.service.ts:55-57`).
- User + password history + auth token + outbox dans une transaction (`registration.service.ts:73-109`).
- Inline email failure maintenant reportee via `reportOperationalError` (`registration.service.ts:129-134`).

Risques restants:

- Chemin email existant retourne generique mais n'a pas les memes side effects (`registration.service.ts:59-64`). Pour une menace forte, timing/side channel peut rester exploitable.

Correction:

- Ajouter jitter controle et/ou audit interne non sensible pour tentatives sur email existant.

### `src/modules/auth/password.service.ts`

Role: forgot/reset/change password.

Points corrects:

- Forgot password renvoie une reponse generique et n'expose pas l'existence utilisateur.
- Reset lit token valide, verifie password history, puis consomme token atomiquement (`password.service.ts:98-139`).
- Change password garde la session courante et revoke les autres sessions.
- Inline email failure maintenant structuree (`password.service.ts:78-83`).

Risques restants:

- `hashPassword(data.password)` est execute avant `findValidAuthToken` (`password.service.ts:96-104`). Cela protege certains timings mais augmente le cout CPU pour token invalide.

Correction:

- Si l'endpoint est expose internet fortement attaque, valider d'abord token format + presence DB, puis hasher. Garder rate-limit strict dans tous les cas.

### `src/modules/auth/email-verification.service.ts`

Role: verify et resend email verification.

Points corrects:

- Verification consomme le token dans transaction avant update user (`email-verification.service.ts:19-37`).
- Resend invalide les anciens tokens avant de creer le nouveau (`email-verification.service.ts:65-94`).
- Inline email failure structuree (`email-verification.service.ts:97-102`).

Risques restants:

- Resend retourne vite pour user inexistant/deja verifie (`email-verification.service.ts:59-63`), ce qui peut laisser un timing signal.

Correction:

- Meme logique que register: jitter faible ou chemin dummy si menace enumeration elevee.

### `src/modules/auth/session.service.ts`

Role: login, refresh, logout, rotation refresh.

Points corrects:

- JWT access token contient issuer, audience, jti, sessionId et sub; `requireAuth` revalide DB.
- Login lock atomique externalise.
- Refresh idempotent via `RefreshRotation`, hash idempotency key et response refresh token chiffree (`session.service.ts:87-215`).
- Grace window courte, grace consommee une seule fois (`session.service.ts:217-363`).
- Reuse detection revoke famille/session quand contexte suspect.

Risques restants:

- Client sans idempotency key peut recevoir 409 sur replay meme contexte apres grace (`session.service.ts:262-287`).
- Service reste le fichier le plus dense du module.

Correction:

- Rendre `Idempotency-Key` obligatoire dans le client pour `/refresh`.
- Extraire progressivement `refresh.service.ts`, `login.service.ts`, `logout.service.ts`.

### `src/modules/auth/auth.repository.ts`

Role: premiere couche repository.

Points corrects:

- Centralise une partie des includes et mutations session/token/user.
- Typage `PrismaClientLike` compatible transaction.

Risques restants:

- Repository partiel: plusieurs services utilisent encore `prisma` directement.

Correction:

- Continuer l'extraction seulement quand les modules ERP consommeront auth; ne pas sur-abstraire trop tot.

### `src/middlewares/auth.middleware.ts`

Role: authentification access token + rechargement session DB.

Points corrects:

- Verifie `iss`, `aud`, `jti` (`auth.middleware.ts:34-40`).
- Refuse session absente/revoquee/expiree, user inactif, mismatch `sub/session.userId`.
- Recharge roles store/org depuis DB (`auth.middleware.ts:42-115`).

Risques restants:

- Requete DB par endpoint protege. C'est le bon choix securite, mais il faudra surveiller latence et index.

Correction:

- Si charge tres forte: cache court par sessionId avec invalidation revocation, mais seulement apres mesures.

### `src/middlewares/role.middleware.ts`

Role: RBAC/tenant guards.

Points corrects:

- Separe `PlatformRole` et roles tenant (`role.middleware.ts:158-187`, `289-423`).
- `requireStoreInOrganization` existe (`role.middleware.ts:493-546`).
- Audit denial centralise.

Risques restants:

- Les guards ne protegent rien s'ils ne sont pas composes dans les futures routes metier.

Correction:

- Imposer des route builders metier et tests d'autorisation par ressource ERP.

### `src/lib/email.ts`

Role: outbox email, chiffrement, delivery, retry.

Points corrects:

- Chiffrement `enc:v1:<keyId>:` pour body email (`email.ts:183-193`).
- Scrub body apres `SENT` (`email.ts:529-548`).
- `SENT_UNKNOWN` si SMTP/provider accepte mais update DB echoue (`email.ts:459-503`).
- Heartbeat lock pour eviter stale lock pendant provider lent (`email.ts:517-538`).
- Legacy encryption/scrub jobs (`email.ts:682-764`).
- Correction appliquee: erreurs delivery/heartbeat/persistence passent par `reportOperationalError`, et `lastErrorSource` reflete `SMTP` ou `HTTP_PROVIDER` (`email.ts:352-455`).

Risques restants:

- Provider HTTP generique, pas encore certifie contre une API email reelle.
- SMTP reste best-effort par nature.

Correction:

- Adapter provider officiel + test sandbox + alerte `SENT_UNKNOWN`.

### `src/config/env.ts`

Role: validation configuration.

Points corrects:

- Secrets separes: password pepper, token hash, refresh idempotency.
- `EXPOSE_AUTH_TOKENS` bloque hors test/local strict (`env.ts:273-286`).
- Redis rate-limit requis en production (`env.ts:580-585`).
- Cleanup tokens obligatoire en production (`env.ts:550-559`).
- SMTP best-effort exige opt-in explicite (`env.ts:538-547`).
- CORS local interdit en prod (`env.ts:473-488`).

Risques restants:

- Keyrings sont en env JSON; acceptable, mais moins fort qu'un KMS/Vault.

Correction:

- Migration future vers KMS/Vault pour pepper/email/idempotency secrets.

### `src/plugins/security.ts`

Role: Helmet, CORS, Redis rate limit, CSRF.

Points corrects:

- Redis ping au startup et fail-closed (`security.ts:25-33`).
- CORS allowlist multi-origine (`security.ts:11-13`, `58-68`).
- CSRF cookie `HttpOnly`, `Secure` en prod, SameSite strict (`security.ts:77-92`).
- Helmet active; CSP optionnelle.

Risques restants:

- Fail-closed Redis peut rendre l'API indisponible si Redis down. C'est un choix de securite, a assumer operationnellement.

Correction:

- Documenter SLA Redis ou ajouter `RATE_LIMIT_FAIL_OPEN=false` explicite si besoin.

### `src/plugins/jwt.ts`

Role: plugin cookie + JWT.

Points corrects:

- HS256 explicitement signe et verifie (`jwt.ts:9-16`).

Risques restants:

- HS256 impose gestion stricte d'un secret symetrique. Pour separation service-to-service, envisager RS256/EdDSA.

Correction:

- Garder HS256 pour monolithe; migrer a cle asymetrique si plusieurs services valident les tokens.

### `prisma/schema.prisma`

Role: modele de donnees.

Points corrects:

- `Session`, `RefreshToken`, `RefreshRotation`, `AuthToken`, `LoginLock`, `PasswordHistory`, `AuditLog`, `SecurityEvent`, `EmailOutbox`.
- `Store.organizationId` NOT NULL dans schema (`schema.prisma:160-178`).
- `ApiKey` et `MfaFactor` fondations presentes (`schema.prisma:421-473`).

Risques restants:

- CHECK `ApiKey_owner_xor_check` existe en migration, pas visible dans schema Prisma (`schema.prisma:441` comment seulement).
- MFA est une structure, pas une feature securisee exposee.

Correction:

- Tests DB des constraints et policy complete avant endpoints.

### CI, docs, monitoring

Points corrects:

- CI PostgreSQL force `RUN_DB_TESTS=true`, `migrate deploy`, seed, preflight, outbox jobs, Prisma diff, tests, build (`api-ci.yml:57-69`).
- Dependabot active pour npm/Fastify/Prisma/Hono (`dependabot.yml:1-18`).
- Alertes Prometheus pour `SENT_UNKNOWN`, audit failure, security event failure (`prometheus-alerts.yml:4-30`).

Risques restants:

- Les alertes doivent etre chargees dans l'infra reelle.
- Branch protections doivent rendre CI bloquante.

## D. Failles de securite exploitables

1. Mauvaise sequence migration tenant

- Scenario: DB production existante contient des stores sans organisation; `migrate deploy` applique hardening et leve exception.
- Impact: deploy casse, downtime possible.
- Gravite: Haute.
- Solution: sequence obligatoire: migration nullable, backfill, preflight, hardening.

2. Duplicate email apres panne partielle provider

- Scenario: provider SMTP accepte le mail, puis update DB `SENT` echoue. L'etat devient `SENT_UNKNOWN`; un retry humain peut renvoyer.
- Impact: reset/verification email duplique, confusion utilisateur.
- Gravite: Haute.
- Solution: provider avec idempotency key reelle + dashboard SENT_UNKNOWN.

3. Refresh retry sans idempotency key

- Scenario: client mobile envoie refresh, perd la reponse, renvoie sans idempotency key.
- Impact: 409 ou grace consommee, UX degradee; si contexte change fortement, revoke famille.
- Gravite: Moyenne.
- Solution: rendre `Idempotency-Key` obligatoire cote client pour refresh.

4. User enumeration timing avance

- Scenario: attaquant mesure latence register/resend entre user existant et inexistant.
- Impact: enumeration probabiliste.
- Gravite: Moyenne.
- Solution: jitter controle ou chemin dummy.

## E. Points manquants / introuvables

- Endpoints MFA complets: setup, verify, recovery, disable, backup codes, rate-limit.
- Endpoints API key complets: create, rotate, revoke, scopes, audit, lastUsedAt, prefix lookup.
- OpenAPI/Swagger auth.
- Tests DB des CHECK constraints `ApiKey_owner_xor_check` et migration MFA.
- Tests de composition guards sur vraies routes ERP.
- Export OTel/Prometheus collector multi-instance.
- Integration SIEM ou logger structure branche au runtime Fastify.
- Runbook operationnel pour `SENT_UNKNOWN`.
- Tests provider email sandbox.
- Branch protections documentees pour rendre `.github/workflows/api-ci.yml` bloquant.

## F. Architecture cible parfaite

```text
auth/
  controllers/
    auth.controller.ts
    session.controller.ts
    password.controller.ts
    email-verification.controller.ts
    mfa.controller.ts
    api-key.controller.ts
  services/
    registration.service.ts
    login.service.ts
    refresh.service.ts
    logout.service.ts
    password.service.ts
    email-verification.service.ts
    mfa.service.ts
    api-key.service.ts
  repositories/
    user.repository.ts
    session.repository.ts
    token.repository.ts
    permission.repository.ts
    audit.repository.ts
  guards/
    require-auth.guard.ts
    require-role.guard.ts
    require-permission.guard.ts
    require-tenant-boundary.guard.ts
  tokens/
    jwt.service.ts
    refresh-token.service.ts
    auth-token.service.ts
  policies/
    password.policy.ts
    mfa.policy.ts
    api-key.policy.ts
  outbox/
    email-outbox.service.ts
    email-provider.adapter.ts
  tests/
    unit/
    integration/
    security/
```

## G. Modele de donnees cible

Deja present:

- `User`, `Session`, `RefreshToken`, `RefreshRotation`
- `AuthToken` pour verification email/reset password
- `Role`, `Permission`, `RolePermission`
- `Membership`, `UserStoreAccess`
- `AuditLog`, `SecurityEvent`
- `LoginAttempt`, `LoginLock`
- `EmailOutbox`
- `ApiKey`, `MfaFactor`, `MfaChallenge`, `PasswordHistory`

A renforcer avant exposition:

- `ApiKey`: tests CHECK XOR, scopes types, rotation history optionnelle.
- `MfaFactor`: secret chiffre via KMS/Vault, recovery codes haches, challenge TTL strict.
- `SecurityEvent`: pipeline SIEM/alerting.

## H. Plan de correction professionnel

Urgent critique:

1. Executer `npm run tenant:preflight` sur DB cible.
2. Si necessaire, executer `npm run tenant:backfill-stores`.
3. Appliquer hardening migration seulement apres preflight vert.

Securite:

1. Rendre `Idempotency-Key` obligatoire dans le client refresh.
2. Garder MFA/API key non exposes jusqu'a policy complete.
3. Supprimer fallback legacy secrets apres deadline.

Architecture:

1. Extraire `refresh.service.ts` si `session.service.ts` grossit encore.
2. Completer repositories par domaine quand les modules ERP consomment auth.

Base de donnees:

1. Ajouter tests DB pour CHECK ApiKey XOR.
2. Ajouter tests DB sur migration tenant avec fixture NULL.

Tests:

1. Garder CI PostgreSQL obligatoire.
2. Ajouter tests CSRF/cookies `Set-Cookie`.
3. Ajouter tests guards sur routes ERP reelles.

Production readiness:

1. Deployer Prometheus alerts.
2. Branch protections GitHub.
3. Provider email HTTP idempotent.
4. OTel ou Prometheus collector multi-instance.

## I. Top 20 corrections prioritaires

1. Preflight/backfill tenant sur DB cible.
2. Branch protections CI obligatoires.
3. Provider email HTTP avec idempotency key reelle.
4. Runbook/dashboard `SENT_UNKNOWN`.
5. Tests DB CHECK `ApiKey_owner_xor_check`.
6. Tests migration tenant fixture NULL.
7. Idempotency key refresh obligatoire cote client.
8. Tests cookies auth/refresh/CSRF.
9. Deploiement Prometheus alert rules.
10. Integration logger/SIEM pour `reportOperationalError`.
11. OTel/Prometheus collector multi-instance.
12. Supprimer legacy secret fallback apres deadline.
13. Ne pas exposer MFA avant recovery/rate-limit/audit.
14. Ne pas exposer API keys avant rotation/revocation/scopes/audit.
15. Ajouter OpenAPI auth.
16. Route builders metier pour guards tenant.
17. Tests RBAC sur routes ERP reelles.
18. Provider email sandbox tests.
19. Runbook rotation pepper/email/idempotency secrets.
20. Revue hebdo npm advisories Prisma/Fastify/Hono.

## J. Version ideale attendue

Le niveau final attendu:

- Auth session-based robuste avec revocation DB immediate.
- Refresh token rotation idempotente, testee en concurrence et observee.
- Password policy avec pepper versionne et rehash progressif.
- Outbox email transactionnelle, chiffree, idempotente provider, monitorable.
- Tenant boundary obligatoire par construction des routes.
- CI DB obligatoire, migrations verifiees, drift detecte.
- Observabilite SIEM/OTel, audit et security events exploitables.
- MFA/API keys exposes seulement avec parcours complet, recovery, audit et rate-limit.

## K. Code corrige / patchs

Corrections appliquees pendant cet audit:

1. `src/lib/email.ts`

- Ajout de `reportOperationalError`.
- `lastErrorSource` devient dynamique: `SMTP` ou `HTTP_PROVIDER`.
- Les erreurs delivery, heartbeat et persistence sont loggees en JSON structure.

2. `src/modules/auth/registration.service.ts`

- L'echec inline email processing est remonte via `reportOperationalError`.

3. `src/modules/auth/password.service.ts`

- L'echec inline password reset email est remonte via `reportOperationalError`.

4. `src/modules/auth/email-verification.service.ts`

- L'echec inline resend verification email est remonte via `reportOperationalError`.

Exemple de politique client refresh recommandee:

```ts
await fetch("/api/auth/refresh", {
  method: "POST",
  headers: {
    "x-csrf-token": csrfToken,
    "idempotency-key": crypto.randomUUID(),
  },
  credentials: "include",
});
```

Exemple de test DB a ajouter pour ApiKey XOR:

```ts
await assert.rejects(() =>
  prisma.apiKey.create({
    data: {
      userId,
      organizationId,
      name: "invalid",
      keyHash: "hash",
      keyPrefix: "prefix",
    },
  })
);
```
