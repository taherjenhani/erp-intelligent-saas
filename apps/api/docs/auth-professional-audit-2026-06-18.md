# Audit professionnel du module Auth

Date: 2026-06-18
Perimetre: `apps/api` - Fastify, TypeScript, Prisma 7, PostgreSQL, JWT, sessions, refresh tokens, email outbox.
Objectif: analyser l'etat actuel reel du module auth avant production, identifier les risques residuels, et definir les ameliorations prioritaires.

## 1. Resume executif

Le module auth est maintenant solide et proche d'un niveau production pour les flux classiques: inscription, verification email, login, refresh token, logout, reset password, changement de mot de passe, RBAC tenant, audit, outbox email, rate limiting et tests DB.

Les corrections majeures sont presentes:

- JWT durci avec `iss`, `aud`, `jti`, algorithme explicite HS256 ou RS256, `kid` et JWKS.
- Refresh token rotation robuste avec `RefreshRotation`, idempotency key, grace window courte, detection reuse, et revocation de famille.
- Password hashing avec bcrypt + pepper versionne.
- Secrets separes: `PASSWORD_PEPPER`, `TOKEN_HASH_SECRET`, `REFRESH_IDEMPOTENCY_SECRET`, `EMAIL_OUTBOX_ENCRYPTION_KEY`.
- Validation Zod stricte sur les schemas auth.
- CSRF sur les routes sensibles.
- Redis obligatoire en production pour le rate limiting.
- LoginLock atomique PostgreSQL.
- EmailOutbox transactionnel, chiffre, scrub apres `SENT`, et statut `SENT_UNKNOWN`.
- `SecurityEvent` et `AuditLog` indexes par `correlationId`.
- CI PostgreSQL presente avec migrations, seed, preflight tenant, jobs outbox, tests unitaires, tests integration DB et build.

Conclusion courte: le code du module auth est propre et fortement renforce. Les risques critiques restants sont majoritairement operationnels: appliquer la protection de branche GitHub, executer le runbook sur la DB cible, configurer le provider email reel, brancher les alertes et maintenir la surveillance supply-chain.

## 2. Score global

Score actuel: 88 / 100.

Lecture du score:

- Securite applicative: 90 / 100
- Robustesse refresh/session: 92 / 100
- Validation/erreurs: 88 / 100
- Prisma/DB/migrations: 86 / 100
- Multi-tenant/RBAC: 84 / 100
- Observabilite/audit: 82 / 100
- Tests/CI: 88 / 100
- Readiness production operationnelle: 78 / 100

Le module n'est plus fragile techniquement. Le dernier ecart est l'industrialisation: branch protection, secrets/KMS, provider email avec idempotence contractuelle, monitoring externe et execution controlee des migrations sur la vraie base.

## 3. Points forts detectes

### 3.1 JWT durci

Fichiers:

- `src/plugins/jwt.ts`
- `src/plugins/jwks.ts`
- `src/utils/authTokens.ts`
- `src/middlewares/auth.middleware.ts`

Points forts:

- Algorithme explicite: HS256 par defaut, RS256 optionnel.
- Verification limitee aux algorithmes attendus.
- `kid` pris en charge en RS256.
- JWKS expose uniquement si RS256 est active.
- Claims `iss`, `aud`, `jti`, `sub`, `sessionId` presents.
- `requireAuth` recharge la session et l'utilisateur depuis la DB, ce qui compense la nature stateless du JWT.

### 3.2 Refresh token rotation robuste

Fichiers:

- `src/modules/auth/session.service.ts`
- `src/modules/auth/auth.repository.ts`
- `prisma/schema.prisma`

Points forts:

- Refresh token stocke en hash HMAC, pas en clair.
- Rotation avec `replacedByTokenId`, `rotatedAt`, `graceConsumedAt`.
- `RefreshRotation` garde l'idempotence des retries legitimes.
- Detection de reuse avec revocation de famille et session.
- Tests integration DB sur refresh concurrent.

### 3.3 Email outbox professionnel

Fichiers:

- `src/lib/email.ts`
- `src/jobs/encryptEmailOutboxLegacy.ts`
- `src/jobs/rotateEmailOutboxKey.ts`
- `src/jobs/listSentUnknownEmailOutbox.ts`
- `prisma/schema.prisma`

Points forts:

- Outbox transactionnel.
- Payload `text/html` chiffre avec prefixe `enc:v1:<keyId>:...`.
- `messageId` stable et `idempotencyKey`.
- `SENT_UNKNOWN` si le provider accepte l'email mais que la mise a jour DB echoue.
- Scrub du contenu sensible apres `SENT`.
- Heartbeat de lock pendant livraison email.
- Jobs de legacy encryption et rotation de cle.

### 3.4 Validation stricte

Fichier: `src/modules/auth/auth.schema.ts`

Points forts:

- Tous les schemas auth sont `.strict()`.
- Mot de passe: longueur, majuscule, minuscule, chiffre, special, limite bcrypt 72.
- Tokens auth: exactement 128 caracteres hex.
- Emails normalises en lowercase.

### 3.5 Rate limiting et anti-bruteforce

Fichiers:

- `src/plugins/security.ts`
- `src/modules/auth/auth.route.ts`
- `src/modules/auth/login-lock.service.ts`

Points forts:

- Redis obligatoire en production pour `@fastify/rate-limit`.
- Limite separee pour `/login`.
- Limite separee pour `/refresh`.
- Lockout progressif atomique par email et IP.
- Reset du lock apres succes.

### 3.6 Audit et observabilite

Fichiers:

- `src/lib/audit.ts`
- `src/lib/securityEvents.ts`
- `src/lib/operationalErrors.ts`
- `src/plugins/metrics.ts`

Points forts:

- `AuditLog` et `SecurityEvent` separes.
- `correlationId` en colonne indexee.
- Metriques Prometheus format texte.
- Token obligatoire quand `/metrics` est active.
- Export webhook operationnel possible.
- Redaction Pino des headers/cookies/passwords/tokens.

### 3.7 CI PostgreSQL

Fichier: `.github/workflows/api-ci.yml`

Points forts:

- Service PostgreSQL reel.
- `npm ci`, audit runtime, migrations deploy, seed, tenant preflight, jobs outbox.
- `prisma validate`, `migrate diff`, tests unitaires, tests integration DB, build.
- `RUN_DB_TESTS=true` en CI.

## 4. Problemes critiques detectes (CRITICAL)

Aucun probleme CRITICAL directement exploitable n'a ete trouve dans le code actuel analyse.

Important: cette conclusion suppose que la configuration production respecte `env.ts`, que Redis est disponible, que la DB cible passe le runbook tenant, et que les endpoints MFA/API key restent desactives tant que leur politique complete n'est pas livree.

## 5. Problemes HIGH

### H1 - Protection de branche GitHub non garantie par le depot

Fichier: `.github/branch-protection-develop.json`
Fonction/zone: processus GitHub externe
Severite: HIGH

Probleme: le fichier de configuration existe, mais l'application effective de la branch protection sur GitHub n'est pas prouvable depuis le code. Sans protection de branche, un push direct peut contourner la CI PostgreSQL.

Impact: regression auth non testee, migration dangereuse ou dependance vulnerable peut entrer dans `develop`/`main`.

Recommandation:

- Appliquer la protection de branche via UI GitHub ou `gh api`.
- Rendre obligatoire le job `API CI`.
- Interdire le push direct sur `develop` et `main`.
- Exiger pull request + status checks + review.

Exemple:

```powershell
gh api `
  --method PUT `
  repos/<owner>/<repo>/branches/develop/protection `
  --input .github/branch-protection-develop.json
```

Test a ajouter:

- Verification operationnelle: tenter un push direct sur `develop` avec un compte non admin et confirmer le refus.
- Verification GitHub: documenter une capture ou sortie API de branch protection active.

### H2 - Migration tenant dependante de l'etat reel de la DB cible

Fichiers:

- `prisma/migrations/20260604103000_auth_multitenant_outbox_hardening/migration.sql`
- `prisma/migrations/20260610120000_auth_production_hardening/migration.sql`
- `src/jobs/preflightTenantMigration.ts`
- `src/jobs/backfillStoreOrganizations.ts`

Fonction/zone: migration `Store.organizationId` nullable puis NOT NULL
Severite: HIGH

Probleme: la strategie est correcte, mais elle exige une sequence de production stricte. Si une base existante contient des stores sans organisation et que la migration hardening est appliquee directement, le deploy echoue.

Impact: blocage deploy production, rollback complexe, risque de maintenance non planifiee.

Recommandation:

1. Appliquer la migration nullable si la DB existante ne l'a pas encore.
2. Executer `STORE_ORGANIZATION_BACKFILL_MAP`.
3. Executer `npm run tenant:backfill-stores`.
4. Executer `npm run tenant:preflight`.
5. Executer `npx prisma migrate deploy`.

Exemple:

```powershell
$env:STORE_ORGANIZATION_BACKFILL_MAP='{"STORE_CODE":"ORG_CODE"}'
npm run tenant:backfill-stores
npm run tenant:preflight
npx prisma migrate deploy
```

Test a ajouter:

- Test pre-deploy sur snapshot anonymise de production.
- Test CI supplementaire avec une DB simulee contenant `Store.organizationId IS NULL`, puis backfill, puis preflight.

### H3 - Provider email SMTP reste best-effort

Fichiers:

- `src/lib/email.ts`
- `src/config/env.ts`

Fonction/zone: `deliverEmailViaSmtp`, `deliverEmailViaResendProvider`, `deliverEmailViaHttpProvider`
Severite: HIGH si SMTP est utilise en production; MEDIUM si Resend/HTTP est utilise.

Probleme: SMTP ne donne pas une vraie idempotency key provider. Le code a reduit le risque avec `messageId`, outbox, locks, `SENT_UNKNOWN`, et env bloque SMTP en production sauf `EMAIL_ALLOW_SMTP_BEST_EFFORT=true`. Mais une garantie entreprise demande un provider API qui respecte l'idempotence.

Impact: double livraison possible apres panne partielle: provider accepte l'email, puis la persistance locale echoue, puis retry manuel ou automatique.

Recommandation:

- Utiliser `EMAIL_PROVIDER=resend` ou `EMAIL_PROVIDER=http` avec un provider qui documente l'idempotence.
- Brancher une alerte sur `SENT_UNKNOWN`.
- Garder SMTP uniquement avec acceptation explicite de risque.

Exemple:

```env
EMAIL_PROVIDER=resend
RESEND_API_KEY=...
OPERATIONAL_EVENTS_WEBHOOK_URL=https://ops.example.com/auth-events
OPERATIONAL_EVENTS_WEBHOOK_TOKEN=...
```

Test a ajouter:

- Test sandbox provider: deux appels avec la meme idempotency key doivent retourner le meme `providerMessageId`.
- Test incident: forcer une erreur DB apres succes provider et verifier alerte `SENT_UNKNOWN`.

### H4 - MFA/API key ne sont pas encore des fonctionnalites exposees et terminees

Fichiers:

- `prisma/schema.prisma`
- `src/config/env.ts`

Fonction/zone: `ApiKey`, `MfaFactor`, `MfaChallenge`, gates `API_KEY_ENDPOINTS_ENABLED`, `MFA_ENDPOINTS_ENABLED`
Severite: HIGH si exposes avant design complet; INFO actuellement car les gates existent.

Probleme: les modeles DB sont presents, mais les endpoints, UX de recovery, rotation, revocation, rate-limit specifique, audit complet et tests ne sont pas livres dans les fichiers actuels.

Impact: exposer ces endpoints trop tot peut creer une surface d'attaque critique: bypass MFA, API keys non revocables, recovery faible.

Recommandation:

- Garder `API_KEY_ENDPOINTS_ENABLED=false` et `MFA_ENDPOINTS_ENABLED=false`.
- N'activer qu'avec `AUTH_ENTERPRISE_FEATURES_POLICY_ACK=rotation-recovery-audit-rate-limit-approved`.
- Implementer MFA et API keys comme modules separes avec tests DB.

Exemple de policy d'activation:

```env
API_KEY_ENDPOINTS_ENABLED=false
MFA_ENDPOINTS_ENABLED=false
AUTH_ENTERPRISE_FEATURES_POLICY_ACK=
```

Test a ajouter:

- Test env: impossible de demarrer avec MFA/API keys actives sans ack.
- Tests futurs: enrollment TOTP, challenge verify, recovery codes, revoke factor, rotate API key.

### H5 - Secrets et keyrings encore portes par variables d'environnement, pas par KMS/Vault

Fichiers:

- `src/config/env.ts`
- `src/utils/hash.ts`
- `src/utils/token.ts`
- `src/lib/email.ts`

Fonction/zone: keyrings password, JWT, token hash, email outbox
Severite: HIGH pour environnement entreprise regule; MEDIUM pour MVP production bien controle.

Probleme: le code supporte les keyrings, mais la source de verite reste l'environnement. Un niveau entreprise demande KMS/Vault/Secret Manager avec rotation auditee.

Impact: rotation manuelle fragile, risque d'exposition par mauvaise gestion d'env, audit secret incomplet.

Recommandation:

- Centraliser les secrets dans AWS KMS/Secrets Manager, GCP Secret Manager, Azure Key Vault ou Vault.
- Charger les keyrings au demarrage avec version explicite.
- Documenter la rotation et le rollback.

Exemple:

```text
PASSWORD_PEPPER_KEYS <- secret manager JSON versionne
EMAIL_OUTBOX_ENCRYPTION_KEYS <- KMS data key ring
JWT_PRIVATE_KEY/JWT_PUBLIC_KEYS <- KMS/Vault, rotation par kid
```

Test a ajouter:

- Test rotation: ancien hash password reste verifiable, nouveau hash utilise `PASSWORD_PEPPER_KEY_ID` actif.
- Test email key rotation: un outbox ancien se dechiffre puis se rechiffre avec la cle active.

## 6. Problemes MEDIUM

### M1 - Metrics in-memory par instance

Fichiers:

- `src/lib/metrics.ts`
- `src/plugins/metrics.ts`

Fonction/zone: `samples` Map locale
Severite: MEDIUM

Probleme: les metriques sont fiables par process mais non agregees. En multi-instance, chaque pod/VM a sa propre vue.

Impact: alertes partielles si Prometheus ne scrape pas toutes les instances; pas de tracing distribue.

Recommandation:

- Scraper chaque instance avec label `instance`.
- Ajouter OpenTelemetry metrics/traces pour les flux auth critiques.
- Ajouter dashboards par instance et agreges.

Exemple:

```text
Prometheus scrape:
- target: api-1:5000/metrics
- target: api-2:5000/metrics
labels: service=erp-api, env=production
```

Test a ajouter:

- Test monitoring staging: deux instances produisent chacune `erp_api_instance_info`.

### M2 - `RefreshRotation.responseRefreshToken` stocke temporairement un refresh token chiffre

Fichiers:

- `src/modules/auth/session.service.ts`
- `src/jobs/cleanupTokens.ts`
- `prisma/schema.prisma`

Fonction/zone: idempotency replay refresh
Severite: MEDIUM

Probleme: pour repondre de facon idempotente a un retry legitime, le nouveau refresh token est stocke chiffre temporairement dans `RefreshRotation.responseRefreshToken`. C'est un compromis correct, mais il depend du cleanup.

Impact: si DB + secret d'idempotence sont compromis avant cleanup, un attaquant peut reconstruire un refresh token recent.

Recommandation:

- Garder `REFRESH_IDEMPOTENCY_TTL_MS` tres court.
- Activer `TOKEN_CLEANUP_WORKER_ENABLED=true` ou `TOKEN_CLEANUP_EXTERNAL_SCHEDULED=true` en production.
- Surveiller le nombre de `responseRefreshToken IS NOT NULL` expire.

Exemple:

```env
REFRESH_IDEMPOTENCY_TTL_MS=60000
TOKEN_CLEANUP_WORKER_ENABLED=true
```

Test a ajouter:

- Test DB: apres execution `tokens:cleanup`, les rotations expirees ont `responseRefreshToken=null`.

### M3 - Contexte refresh permissif si `userAgent` ou `ipAddress` sont absents

Fichier: `src/modules/auth/session.service.ts`
Fonction/zone: comparaison du contexte refresh
Severite: MEDIUM

Probleme: le code compare strictement si une valeur est stockee, mais les sessions peuvent contenir `userAgent` ou `ipAddress` null. Dans ce cas, la verification contextuelle est plus permissive.

Impact: une session creee sans user-agent ou IP affaiblit la detection de reuse pendant la grace window.

Recommandation:

- En production, stocker toujours IP + user-agent normalise.
- Considerer un `deviceFingerprintHash` stable.
- Rejeter la grace si le contexte historique est incomplet.

Exemple:

```ts
if (!session.userAgent || !session.ipAddress) {
  return false;
}
return session.userAgent === context.userAgent &&
  session.ipAddress === context.ipAddress;
```

Test a ajouter:

- Test refresh reuse grace avec session sans userAgent/ip: doit refuser la grace et ne pas emettre de nouveau token.

### M4 - Enumeration utilisateur encore possible par timing

Fichiers:

- `src/modules/auth/registration.service.ts`
- `src/modules/auth/password.service.ts`
- `src/modules/auth/email-verification.service.ts`

Fonction/zone: `registerUser`, `requestPasswordReset`, `resendEmailVerification`
Severite: MEDIUM

Probleme: les reponses sont generiques, mais les chemins internes n'ont pas tous le meme cout. Par exemple, l'inscription d'un email existant evite certaines operations transactionnelles/outbox.

Impact: un attaquant avance peut mesurer les temps pour inferer l'existence d'un email si rate-limit et bruit reseau sont faibles.

Recommandation:

- Garder les messages generiques.
- Ajouter jitter controle ou equalisation minimale sur endpoints sensibles.
- Journaliser et limiter par email + IP.

Exemple:

```ts
await sleepRandomBetween(80, 160);
return { created: false, emailVerificationToken: null };
```

Test a ajouter:

- Test comportemental: email existant et inconnu retournent meme status/code/body.

### M5 - Role global `User.role` peut rester ambigu avec `PlatformRole`

Fichiers:

- `prisma/schema.prisma`
- `src/middlewares/role.middleware.ts`
- `src/middlewares/auth.middleware.ts`

Fonction/zone: `Role`, `PlatformRole`, `requireRole`, `requirePlatformRole`
Severite: MEDIUM

Probleme: `PlatformRole` separe correctement le super admin plateforme, mais `User.role` utilise encore l'enum `Role`, qui contient `SUPER_ADMIN`. Cela peut creer une confusion dans les futures routes metier si un developpeur utilise `requireRole(["SUPER_ADMIN"])` au lieu de `requirePlatformRole(["SUPER_ADMIN"])`.

Impact: escalation logique possible dans de futurs modules ERP mal branches.

Recommandation:

- Documenter une regle stricte: `SUPER_ADMIN` plateforme passe uniquement par `platformRole`.
- Interdire `User.role=SUPER_ADMIN` par convention ou migration future.
- Preferer guards tenant: `requireOrganizationPermission`, `requireStorePermission`, `requireStoreInOrganization`.

Exemple:

```ts
preHandler: [
  requireAuth,
  requirePlatformRole(["SUPER_ADMIN"]),
]
```

Test a ajouter:

- Test RBAC: un `User.role=SUPER_ADMIN` avec `platformRole=USER` ne doit pas passer un endpoint plateforme.

### M6 - `requireStoreInOrganization` bypass la verification pour `SUPER_ADMIN`

Fichier: `src/middlewares/role.middleware.ts`
Fonction/zone: `requireStoreInOrganization`
Severite: MEDIUM

Probleme: le guard retourne immediatement pour `platformRole=SUPER_ADMIN`. C'est acceptable pour l'autorisation, mais si le guard est aussi utilise pour valider la coherence URL `organizationId/storeId`, un super admin pourrait appeler une route avec une paire incoherente.

Impact: erreurs metier ou donnees incoherentes dans les futurs modules si les handlers supposent que la relation store/org a ete validee.

Recommandation:

- Separarer autorisation et validation de coherence.
- Ajouter un guard `assertStoreBelongsToOrganization` qui s'applique meme au super admin.

Exemple:

```ts
preHandler: [
  requireAuth,
  assertStoreBelongsToOrganization("storeId", "organizationId"),
  requireStorePermission("storeId", "stores.write"),
]
```

Test a ajouter:

- Test route metier: super admin avec store d'une autre organisation doit recevoir 403 ou 400 selon la politique.

### M7 - Audit/security events best-effort

Fichiers:

- `src/lib/audit.ts`
- `src/lib/securityEvents.ts`
- `src/lib/operationalErrors.ts`

Fonction/zone: `writeAuditLog`, `writeSecurityEvent`
Severite: MEDIUM

Probleme: l'audit ne bloque pas les flux auth si l'ecriture echoue. C'est bon pour disponibilite, mais certaines conformites exigent un audit durable.

Impact: perte possible d'evenements de securite lors d'une panne DB partielle ou erreur d'export.

Recommandation:

- Garder best-effort pour login normal.
- Pour operations critiques admin, envisager transactional audit ou durable event outbox.
- Alerter sur `audit_log_write_failed` et `security_event_write_failed`.

Exemple:

```text
Alert:
sum(rate(erp_audit_log_write_total{status="failure"}[5m])) > 0
```

Test a ajouter:

- Test injection d'erreur audit: l'auth continue, mais `reportOperationalError` est appele.

### M8 - Pas encore d'export OpenTelemetry natif

Fichiers:

- `src/config/env.ts`
- `src/lib/operationalErrors.ts`

Fonction/zone: `OTEL_*` env seulement
Severite: MEDIUM

Probleme: des variables OTEL existent, mais aucun SDK OpenTelemetry natif n'est initialise dans les fichiers fournis.

Impact: tracing distribue absent pour refresh, DB, email provider, rate-limit.

Recommandation:

- Ajouter `@opentelemetry/sdk-node`.
- Instrumenter Fastify, pg/prisma si possible, fetch provider email.
- Garder webhook operationnel pour alerting simple.

Exemple:

```text
Non trouve dans les fichiers fournis: initialisation OpenTelemetry SDK.
```

Test a ajouter:

- Test staging: traces visibles pour `POST /api/auth/login` et `POST /api/auth/refresh`.

### M9 - Service session encore volumineux

Fichier: `src/modules/auth/session.service.ts`
Fonction/zone: login, refresh, logout, idempotency, reuse detection
Severite: MEDIUM

Probleme: le service concentre beaucoup de logique critique. Il est teste, mais plus difficile a lire et a faire evoluer.

Impact: risque de regression lors de futures features MFA/device/session management.

Recommandation:

- Extraire `refresh-rotation.service.ts`.
- Extraire `logout.service.ts`.
- Extraire `session.repository.ts`.
- Garder les transactions dans des fonctions courtes.

Exemple d'organisation:

```text
modules/auth/session/
  login.service.ts
  refresh.service.ts
  logout.service.ts
  refresh-rotation.service.ts
  session.repository.ts
```

Test a ajouter:

- Tests unitaires purs pour `canUseRefreshReuseGrace`, `tryReplayRefreshIdempotencyResult`, `revokeRefreshTokenFamilyAndSession`.

### M10 - `npm audit:full` reste sensible aux dependances dev/optionnelles

Fichiers:

- `package.json`
- `.github/dependabot.yml`

Fonction/zone: dev tooling, `tsx`/`esbuild`, SMTP optional `nodemailer`
Severite: MEDIUM

Probleme: l'audit runtime est propre via `npm run audit:ci`, mais l'audit complet peut rester non bloquant a cause de dependances de developpement ou optional SMTP.

Impact: bruit CI, risque supply-chain si ces outils sont utilises dans un chemin sensible ou en production.

Recommandation:

- Garder `audit:ci` bloquant.
- Garder `audit:full` visible non bloquant.
- Dependabot actif.
- Eviter d'installer `nodemailer` en production si `EMAIL_PROVIDER=resend/http`.

Test a ajouter:

- Job hebdomadaire Dependabot/security audit avec ticket automatique.

## 7. Problemes LOW

### L1 - CSP Helmet desactivee par defaut

Fichiers:

- `src/plugins/security.ts`
- `src/config/env.ts`

Fonction/zone: `HELMET_CSP_ENABLED`
Severite: LOW actuellement

Probleme: CSP est desactivee par defaut. Pour une API JSON pure, c'est acceptable. Si Swagger, docs HTML, admin panel ou contenu web sont servis par cette app, CSP doit etre activee.

Impact: risque XSS plus important si contenu HTML est servi plus tard.

Recommandation:

- Garder `SERVE_WEB_CONTENT=false`.
- Activer `HELMET_CSP_ENABLED=true` avant de servir du HTML.

Test a ajouter:

- Test headers si `SERVE_WEB_CONTENT=true`: CSP doit etre presente.

### L2 - `AuthToken` TTL fixe a 30 minutes

Fichier: `src/modules/auth/auth-token.service.ts`
Fonction/zone: `AUTH_TOKEN_DURATION_MS`
Severite: LOW

Probleme: le TTL email verification/reset password est constant dans le code.

Impact: moins flexible selon environnement ou politique entreprise.

Recommandation:

- Ajouter `AUTH_TOKEN_TTL_MS` ou TTL separe `PASSWORD_RESET_TOKEN_TTL_MS`, `EMAIL_VERIFICATION_TOKEN_TTL_MS`.

Test a ajouter:

- Test env parse + expiration token.

### L3 - `package.json` garde une cle `prisma.seed` en plus de `prisma.config.ts`

Fichiers:

- `package.json`
- `prisma.config.ts`

Fonction/zone: seed Prisma
Severite: LOW

Probleme: le seed est defini dans `prisma.config.ts`, mais `package.json` contient aussi `prisma.seed`. Ce n'est pas bloquant, mais peut preter a confusion.

Impact: faible. Maintenance moins nette.

Recommandation:

- Garder une seule source officielle, idealement `prisma.config.ts` avec Prisma 7.

Test a ajouter:

- CI continue deja de tester `npx prisma db seed`.

### L4 - Endpoints de health/readiness auth non specialises

Fichier: `src/app.ts`
Fonction/zone: route `/`
Severite: LOW

Probleme: l'app expose une route simple "ERP API running", mais pas de readiness dediee DB/Redis/outbox.

Impact: orchestration Kubernetes ou load balancer moins precis.

Recommandation:

- Ajouter `/healthz` minimal et `/readyz` avec DB/Redis checks.
- Ne pas exposer de secrets ou details internes.

Test a ajouter:

- Test readiness retourne 503 si DB indisponible.

## 8. Analyse securite Auth

### 8.1 Register

Fichiers:

- `src/modules/auth/auth.route.ts`
- `src/modules/auth/auth.controller.ts`
- `src/modules/auth/registration.service.ts`
- `src/modules/auth/auth.schema.ts`

Etat:

- CSRF actif.
- Rate limit route actif.
- Schema strict.
- Email normalise.
- Password fort.
- Creation user transactionnelle avec email token et outbox.
- Reponse generique si email existe.

Risque residuel:

- Timing enumeration possible malgre reponse generique.
- Politique anti-abuse register peut etre renforcee avec fingerprint/device/risk score.

Recommandation:

- Ajouter jitter controle.
- Ajouter monitoring `REGISTER` par IP/email domain.
- Considerer verification captcha/risk engine uniquement si exposition publique forte.

### 8.2 Verify email

Fichiers:

- `src/modules/auth/email-verification.service.ts`
- `src/modules/auth/auth-token.service.ts`

Etat:

- Token stocke hashe.
- Token consomme atomiquement.
- Schema token strict 128 hex.
- Audit `EMAIL_VERIFIED`.

Risque residuel:

- TTL fixe.

Recommandation:

- Configurer TTL par env si besoin.

### 8.3 Resend verification

Etat:

- CSRF et rate-limit actifs.
- Reponse generique si user absent/deja verifie.
- Ancien token invalide avant nouveau token.

Risque residuel:

- Timing enumeration.
- Besoin d'une limite par email plus durable si attaque longue.

Recommandation:

- Ajouter `EmailActionLock` ou utiliser Redis avec cle email normalisee.

### 8.4 Login

Fichiers:

- `src/modules/auth/session.service.ts`
- `src/modules/auth/login-lock.service.ts`

Etat:

- CSRF actif.
- Rate-limit IP+email.
- LoginLock email + IP.
- Password bcrypt + HMAC pepper.
- Email verification obligatoire.
- Audit login success/failure.
- Session DB creee et refresh cookie HttpOnly.

Risque residuel:

- Pas de MFA dans le flux login actuellement.
- Timing enumeration partiellement mitigee mais pas totalement prouvee.

Recommandation:

- Ajouter MFA challenge apres password quand MFA est active.
- Ajouter tests de timing seulement si menace elevee.

### 8.5 Refresh

Etat:

- CSRF actif.
- Rate-limit dedie.
- Cookie refresh HttpOnly.
- Rotation DB.
- Idempotency key supportee.
- Reuse detection.
- Grace window courte.

Risque residuel:

- Replay idempotent stocke temporairement chiffre.
- Contexte user-agent/IP permissif si non stocke.

Recommandation:

- Activer cleanup worker.
- Enforcer contexte complet en production.
- Ajouter device fingerprint hash.

### 8.6 Logout

Etat:

- `POST /logout` accepte refresh cookie + CSRF sans `requireAuth`, ce qui permet de se deconnecter meme si access token expire.
- `POST /logout-all` est derriere `requireAuth`.
- Revocation session + refresh tokens.
- Cookie clear aligne sur path/domain.

Risque residuel:

- Aucun probleme majeur detecte.

### 8.7 Forgot password

Etat:

- CSRF et rate-limit actifs.
- Reponse generique.
- Token reset hashe.
- Outbox transactionnel.

Risque residuel:

- Timing enumeration possible.
- Provider email doit etre fiable.

Recommandation:

- Provider Resend/HTTP avec idempotence.
- Limite email durable.

### 8.8 Reset password

Etat:

- Schema password fort.
- Token valide lu avant consommation definitive.
- Password history verifie avant `markAuthTokenUsed`.
- Revocation des autres sessions/tokens.
- Audit `PASSWORD_RESET_COMPLETED`.

Risque residuel:

- Le hash du nouveau password est calcule avant validation token; cout CPU sur tokens invalides, mitige par rate-limit.

Recommandation:

- Option: valider token avant hash si attaque CPU observee.

### 8.9 Change password

Etat:

- `requireAuth`.
- Ancien mot de passe exige.
- Password history.
- Revocation des autres sessions.
- Audit.

Risque residuel:

- Pas de confirmation MFA pour changement password.

Recommandation:

- Quand MFA existe, exiger step-up MFA pour `change-password`.

### 8.10 Me

Etat:

- `requireAuth`.
- Session DB rechargee.
- Roles/store/org reloades depuis DB.

Risque residuel:

- Aucun majeur.

## 9. Architecture

Structure actuelle observee:

```text
src/modules/auth/
  auth.controller.ts
  auth.route.ts
  auth.schema.ts
  auth.repository.ts
  auth.service.ts
  auth.types.ts
  auth.mapper.ts
  auth-audit.service.ts
  auth-token.service.ts
  email-verification.service.ts
  login-lock.service.ts
  password-history.service.ts
  password.service.ts
  registration.service.ts
  session.service.ts
```

Evaluation:

- Separation routes/controller/service correcte.
- Schema Zod separe.
- Repository existe mais reste partiel.
- Services par domaine deja introduits.
- `session.service.ts` reste le plus volumineux et critique.

Recommandation architecture:

```text
src/modules/auth/
  application/
    register.usecase.ts
    login.usecase.ts
    refresh.usecase.ts
    logout.usecase.ts
    password-reset.usecase.ts
  domain/
    refresh-rotation.policy.ts
    password.policy.ts
    login-lock.policy.ts
  infrastructure/
    auth.repository.ts
    session.repository.ts
    token.repository.ts
    email-outbox.repository.ts
  presentation/
    auth.route.ts
    auth.controller.ts
    auth.schema.ts
```

## 10. DB / Prisma

Points forts:

- Migrations presentes et versionnees.
- `Store.organizationId` NOT NULL apres hardening.
- Indexes sur sessions, refresh, audit, security events.
- `ApiKey_owner_xor_check` en migration.
- `MfaFactor.encryptedSecret` au lieu de hash inexploitable.
- `shadowDatabaseUrl` configure.
- Seed Prisma 7 via `prisma.config.ts`.

Risques:

- Migration tenant exige sequence operationnelle.
- Certains invariants DB Prisma non representables dans schema sont dans migrations SQL; il faut surveiller `migrate diff`.

Recommandation:

- Garder `npx prisma migrate diff --from-migrations prisma/migrations --to-schema prisma/schema.prisma --exit-code` en CI.
- Documenter les contraintes SQL manuelles.

## 11. Multi-tenant

Etat:

- `Organization`, `Membership`, `Store.organizationId`, `UserStoreAccess`.
- Guards org/store.
- `requireStoreInOrganization`.
- Registration valide que le store appartient a une organisation active.

Risques:

- Confusion possible entre role global, role organisation et role store.
- `SUPER_ADMIN` bypass relation store/org dans `requireStoreInOrganization`.

Recommandation:

- En routes metier, toujours combiner:

```ts
preHandler: [
  requireAuth,
  assertStoreBelongsToOrganization("storeId", "organizationId"),
  requireStorePermission("storeId", "stores.write"),
]
```

Non trouve dans les fichiers fournis:

- Routes metier ERP utilisant systematiquement ces guards.

## 12. Permissions / roles

Etat:

- `Permission`, `RolePermission`, `Role`.
- Guards: role, platform role, permission, store role, store permission, organization role, organization permission.
- Audit `ACCESS_DENIED`.

Risques:

- `Role` contient encore `SUPER_ADMIN` et peut etre utilise hors contexte.
- `RolePermission` est global par role; si deux organisations veulent des policies differentes, il faudra un modele plus fin.

Recommandation:

- Pour MVP: conserver RBAC global + memberships.
- Pour enterprise avance: ajouter policy ABAC ou permissions par organisation.

Non trouve dans les fichiers fournis:

- Tests integration routes metier ERP avec permissions store/org.

## 13. Validation / erreurs

Etat:

- Zod strict.
- `AppError`, `AuthError`, `ValidationError`, `PermissionError`.
- Error handler central avec `correlationId`.
- 429 normalise.

Risques:

- Les details Zod sont renvoyes au client. C'est utile pour API, mais peut exposer trop de structure si API publique tres sensible.

Recommandation:

- En production publique, option pour masquer les details Zod et logger cote serveur.

Test a ajouter:

- Snapshot des erreurs auth pour garantir format stable:

```json
{
  "success": false,
  "code": "AUTH_INVALID_CREDENTIALS",
  "message": "Invalid email or password",
  "correlationId": "..."
}
```

## 14. Logs / audit

Etat:

- Pino redaction dans Fastify.
- `AuditLog`.
- `SecurityEvent`.
- Operational webhook.
- `correlationId` sanitize.

Risques:

- Audit best-effort.
- Pas de SIEM natif.

Recommandation:

- Brancher `OPERATIONAL_EVENTS_WEBHOOK_URL` vers SIEM/alertmanager.
- Ajouter un export regulier `SecurityEvent` vers SIEM.

## 15. Rate limiting / bruteforce

Etat:

- Redis obligatoire en production.
- Login limit IP+email.
- Refresh limit dedie.
- Auth route generic limit.
- LoginLock atomique.

Risques:

- Forgot/resend/register beneficient du rate limit route, mais pas d'un lock durable par action/email equivalent a LoginLock.

Recommandation:

- Ajouter `AuthActionLock` ou Redis keys par action:

```text
auth:forgot-password:<email>
auth:resend-verification:<email>
auth:register:<ip>
```

Test a ajouter:

- 6 appels `/forgot-password` meme email => 429 ou lock.

## 16. Tests

Tests observes:

- Unitaires: app/env/email/metrics/RBAC/auth schema.
- Integration DB: register/verify/login/me, reset token reuse, refresh concurrent, LoginLock, SENT_UNKNOWN, legacy encryption/rotation.
- CI PostgreSQL force `RUN_DB_TESTS=true`.

Manques principaux:

- Tests tenant guards sur routes metier reelles.
- Tests branch protection non automatisables dans le repo.
- Tests provider email sandbox Resend/HTTP.
- Tests JWT RS256/JWKS avec rotation de cle.
- Tests cleanup worker pour `RefreshRotation.responseRefreshToken`.

Recommandation:

```text
npm test
npm run test:integration:db
npm run build
npm run audit:ci
```

## 17. Fonctionnalites manquantes

Non trouve dans les fichiers fournis:

- Endpoints MFA complets.
- Endpoints API key complets.
- Device/session management utilisateur: lister appareils, nommer appareil, revoke session precise.
- Step-up authentication pour operations sensibles.
- OpenTelemetry SDK natif.
- Health/readiness DB/Redis/outbox.
- SIEM exporter dedie.
- Provider email sandbox test contractuel.
- Branch protection appliquee cote GitHub.

## 18. Risques production

Risques restants par ordre:

1. Branch protection non appliquee: CI contournable.
2. DB cible pas dans le bon etat tenant: deploy peut bloquer.
3. Email provider mal configure: verification/reset non delivres.
4. `SENT_UNKNOWN` non surveille: incidents email invisibles.
5. Metrics non agregees: signaux incomplets en multi-instance.
6. Secrets sans KMS/Vault: rotation manuelle fragile.
7. MFA/API keys actives trop tot: surface critique incomplete.
8. Supply-chain dev/optional a surveiller via Dependabot.

## 19. Roadmap phases 1-4

### Phase 1 - Avant production immediate

- Appliquer branch protection GitHub.
- Executer `tenant:preflight` sur DB cible.
- Si necessaire executer `tenant:backfill-stores`.
- Executer `email:outbox:encrypt-legacy`.
- Configurer `EMAIL_PROVIDER=resend` ou `http`.
- Configurer alerte `SENT_UNKNOWN`.
- Activer Redis rate-limit.
- Activer cleanup token worker ou schedule externe.

### Phase 2 - Stabilisation production

- Ajouter readiness `/readyz`.
- Ajouter dashboards Prometheus/Grafana.
- Ajouter test contractuel provider email.
- Ajouter tests RS256/JWKS rotation.
- Ajouter tests tenant guards routes metier.

### Phase 3 - Architecture et maintenabilite

- Extraire `refresh-rotation.service.ts`.
- Completer repositories session/token/RBAC.
- Documenter conventions PlatformRole vs tenant Role.
- Ajouter ADR auth/security.

### Phase 4 - Niveau entreprise avance

- KMS/Vault pour secrets.
- OTel traces/metrics.
- SIEM integration.
- MFA complet avec recovery.
- API keys avec rotation/scopes/audit.
- Device management utilisateur.
- ABAC policy engine si les permissions ERP deviennent complexes.

## 20. Refactoring target

Structure cible recommandee:

```text
src/modules/auth/
  presentation/
    auth.route.ts
    auth.controller.ts
    auth.schema.ts
  application/
    register.usecase.ts
    verify-email.usecase.ts
    login.usecase.ts
    refresh-token.usecase.ts
    logout.usecase.ts
    password-reset.usecase.ts
    change-password.usecase.ts
  domain/
    password.policy.ts
    refresh-rotation.policy.ts
    login-lock.policy.ts
    tenant-access.policy.ts
  infrastructure/
    auth.repository.ts
    session.repository.ts
    token.repository.ts
    rbac.repository.ts
    audit.repository.ts
  tests/
    auth.integration.test.ts
    refresh-rotation.test.ts
    tenant-rbac.test.ts
```

Regle de refactor:

- Ne pas refactorer tout en une fois.
- Extraire d'abord refresh rotation, car c'est la logique la plus sensible.
- Garder les tests integration DB comme filet de securite.

## 21. Recommandations securite avancees

1. Passer RS256 en production avec rotation `kid`.
2. Stocker JWT private keys dans KMS/Vault.
3. Ajouter blocklist de `jti` seulement pour cas incident critique; la session DB couvre deja la revocation normale.
4. Ajouter MFA step-up pour password change, API key create, role changes.
5. Ajouter device fingerprint hash et session management.
6. Ajouter OTel tracing sur login/refresh/email.
7. Ajouter SIEM pour `SecurityEvent`.
8. Ajouter rate limit durable par action/email pour forgot/resend.
9. Ajouter tests chaos DB/email pour `SENT_UNKNOWN`.
10. Ajouter runbook de rotation `PASSWORD_PEPPER`, `TOKEN_HASH_SECRET`, JWT, email outbox.

## 22. Production-ready checklist

| Controle | Etat actuel | Decision |
|---|---:|---|
| JWT alg explicite | OK | Pret |
| JWT iss/aud/jti | OK | Pret |
| RS256 + JWKS | OK optionnel | Pret si configure |
| Refresh rotation | OK | Pret |
| Refresh concurrent idempotent | OK teste DB | Pret |
| Password bcrypt + pepper | OK | Pret |
| Pepper key id | OK | Pret |
| TOKEN_HASH_SECRET separe | OK | Pret |
| Email outbox transactionnel | OK | Pret |
| Outbox chiffree/scrubbee | OK | Pret |
| SENT_UNKNOWN | OK | Pret, alerte a configurer |
| Provider email idempotent | Partiel | Utiliser Resend/HTTP |
| CSRF routes sensibles | OK | Pret |
| Rate limit Redis prod | OK via env | Verifier Redis prod |
| LoginLock atomique | OK teste DB | Pret |
| CORS production explicite | OK via env | Configurer |
| Helmet | OK | CSP selon contenu web |
| Validation Zod strict | OK | Pret |
| Error handler central | OK | Pret |
| AuditLog/SecurityEvent | OK | Pret |
| Metrics token | OK | Pret |
| Metrics multi-instance | Partiel | Scrape/OTel requis |
| CI PostgreSQL | OK | Pret |
| Branch protection | Non prouve | A appliquer |
| Tenant preflight/backfill | Scripts OK | A executer DB cible |
| MFA complet | Non trouve dans les fichiers fournis | Ne pas exposer |
| API keys complet | Non trouve dans les fichiers fournis | Ne pas exposer |
| KMS/Vault | Non trouve dans les fichiers fournis | Recommande entreprise |
| SIEM/OTel natif | Non trouve dans les fichiers fournis | Recommande entreprise |

## 23. Conclusion

Le module auth a atteint un niveau technique avance: la plupart des faiblesses classiques d'un backend auth Node.js sont corrigees ou fortement mitigees. Les pieces importantes sont en place: sessions DB, refresh rotation idempotente, secrets separes, validation stricte, CSRF, Redis rate-limit en production, LoginLock, email outbox chiffre, audit, security events, metrics et CI PostgreSQL.

Il ne faut pas exposer MFA/API keys avant leur design complet. Il faut aussi appliquer la branch protection GitHub et executer le runbook tenant/outbox sur la vraie DB cible avant une mise en production.

Priorite recommandee maintenant:

1. Appliquer branch protection GitHub.
2. Executer runbook DB cible: `tenant:preflight`, `tenant:backfill-stores` si besoin, migrations.
3. Configurer provider email API avec idempotency key.
4. Brancher alerte `SENT_UNKNOWN`.
5. Activer Redis + cleanup worker en production.
6. Ajouter tests RS256/JWKS, tenant guards metier, cleanup idempotency replay.
7. Planifier KMS/Vault + OTel/SIEM pour niveau entreprise.
