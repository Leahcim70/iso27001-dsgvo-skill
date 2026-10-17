# Prüfkatalog Code

Nur die für den Scope relevanten Abschnitte prüfen. Jeder Punkt: Anti-Pattern → Fix → Referenz.

**Fachlicher Prüfstand: 2026-10-16.** Technische Prüfideen; kein Katalog stets
zwingender gesetzlicher Maßnahmen. Voraussetzungen, Ausnahmen und Primärquellen:
[`dsgvo.md`](dsgvo.md), [`iso27001-annex-a.md`](iso27001-annex-a.md).
Nur synthetische Beispieldaten verwenden. Aus einem Indikator allein keinen Rechtsverstoß ableiten.

## 1. Secrets & Konfiguration
- [ ] Keine API-Keys, Passwörter, Private Keys, Connection-Strings im Code, in Tests, Dockerfiles, CI-Configs, `.env` im Repo, Git-History → Secret-Manager / Env; Rotation nach Leak. *(ISO 5.17, 8.4, 8.24)*
- [ ] `.env`, `*.pem`, `*.key` in `.gitignore`. *(8.4)*
- [ ] Debug-Modus/Stacktraces in Prod deaktiviert (`DEBUG=False`, `app.debug`, `NODE_ENV=production`). *(8.9, 8.12)*
- [ ] Getrennte Konfiguration & Credentials je Umgebung. *(8.31)*

## 2. Authentisierung & Sessions
- [ ] Passwörter: Argon2id (bevorzugt), bcrypt (cost ≥ 12) oder scrypt. Nie MD5/SHA-x ungesalzen, nie reversibel. *(8.5, 8.24, Art. 32)*
- [ ] Brute-Force-Schutz: Rate-Limit/Backoff, ggf. Lockout mit Entsperrweg. *(8.5)*
- [ ] Keine User-Enumeration (identische Meldung bei "User unbekannt" und "Passwort falsch", auch bei Reset). *(8.5)*
- [ ] Session-Cookies: `HttpOnly`, `Secure`, `SameSite=Lax/Strict`; Session-Rotation nach Login; Idle- und Absolute-Timeout. *(8.5)*
- [ ] JWT: Algorithmus fest (`alg: none` ablehnen), kurze Laufzeit, Signaturprüfung, Revocation-Strategie; keine pbD im Payload (nur Base64!). *(8.5, 8.12)*
- [ ] MFA für Admins/privilegierte Konten. *(8.2, 8.5)*
- [ ] Reset-Tokens: zufällig (CSPRNG), einmalig, kurzlebig, gehasht gespeichert. *(5.17)*

## 3. Autorisierung
- [ ] Deny-by-Default; jede Route/Resolver/Handler hat explizite Berechtigungsprüfung. *(5.15, 8.3)*
- [ ] Objektebene (IDOR/BOLA): `WHERE id = ? AND tenant_id = ?` bzw. Ownership-Check, nicht nur "eingeloggt". *(8.3)*
- [ ] Mandantentrennung durchgängig (auch in Caches, Queues, Dateispeicher-Pfaden, Suchindex). *(8.3)*
- [ ] Mass Assignment verhindert (Allowlist für schreibbare Felder; `role`, `isAdmin` nie aus Request übernehmen). *(8.28)*
- [ ] API-Responses filtern – keine internen/sensiblen Felder (Passwort-Hash, Tokens, interne Notizen) serialisieren. *(8.3, 8.12, Art. 5 1c)*
- [ ] Tests für AuthZ vorhanden (negativ: fremder Mandant, fehlende Rolle). *(8.29)*

## 4. Eingaben & Injection (OWASP)
- [ ] SQL nur parametrisiert/ORM; keine String-Konkatenation/f-Strings mit Eingaben. *(8.28)*
- [ ] Kein `eval`, `exec`, `Function()`, `os.system`, `shell=True`, `child_process.exec` mit Eingaben. *(8.18, 8.28)*
- [ ] XSS: Auto-Escaping aktiv; `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `|safe` nur mit Sanitizer (DOMPurify). CSP gesetzt. *(8.28)*
- [ ] CSRF-Schutz für cookie-basierte Sessions. *(8.28)*
- [ ] SSRF: Ausgehende Requests mit Nutzer-URLs gegen Allowlist; Metadaten-Endpunkte (169.254.169.254) blockieren. *(8.28, 8.20)*
- [ ] Path Traversal: Dateipfade normalisieren und gegen Basisverzeichnis prüfen. *(8.28)*
- [ ] Unsichere Deserialisierung (`pickle`, `yaml.load` ohne SafeLoader, Java `ObjectInputStream`) vermeiden. *(8.28)*
- [ ] Uploads: Typ via Magic Bytes, Größenlimit, zufälliger Dateiname, außerhalb Webroot, kein Execute. *(8.7)*

## 5. Kryptografie & Transport
- [ ] TLS ≥ 1.2 (bevorzugt 1.3), HSTS; Zertifikatsprüfung **nie** deaktiviert (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`). *(8.21, 5.14)*
- [ ] Keine `http://`-Endpunkte für pbD/Credentials (Ausnahme localhost). *(5.14)*
- [ ] Symmetrisch: AES-256-GCM oder ChaCha20-Poly1305; kein ECB, kein DES/3DES/RC4; IV/Nonce nie wiederverwenden. *(8.24)*
- [ ] Zufall für Sicherheitszwecke aus CSPRNG (`secrets`, `crypto.randomBytes`, `SecureRandom`), nicht `Math.random`/`random`. *(8.24)*
- [ ] Hashes für Integrität: SHA-256+; MD5/SHA-1 nur für nicht-sicherheitsrelevante Checksummen. *(8.24)*
- [ ] Schlüssel in KMS/HSM/Vault, nicht neben den Daten; Rotation möglich. *(8.24)*
- [ ] Verschlüsselung at rest für DB/Storage/Backups aktiv; Feldverschlüsselung für Art.-9-Daten. *(8.24, Art. 32)*

## 6. Personenbezogene Daten – Erhebung & Speicherung
- [ ] Datenminimierung: Jedes pbD-Feld hat erkennbaren Zweck; keine Speicherung kompletter Drittanbieter-Payloads. *(Art. 5 1c, 25)*
- [ ] Besondere Kategorien (Art. 9) identifiziert, gesondert geschützt. *(Art. 9, ISO 5.12)*
- [ ] Aufbewahrungsfristen technisch umgesetzt (TTL-Index, Lösch-Job, Partition-Drop). *(Art. 5 1e, ISO 8.10)*
- [ ] Soft-Delete wird nach Frist zu Hard-Delete/Anonymisierung. *(Art. 17, ISO 8.10)*
- [ ] Löschung kaskadiert: Relationen, Dateien/Blobs, Caches (Redis), Suchindex (Elastic/Algolia), Analytics, Drittsysteme (Webhooks), Vektor-DB/Embeddings. *(Art. 17, 19)*
- [ ] Export-Funktion für Auskunft/Portabilität (JSON/CSV). *(Art. 15, 20)*
- [ ] Einwilligungen mit Zweck, Zeitstempel, Textversion gespeichert; Widerruf wirkt sofort. *(Art. 7)*
- [ ] Pseudonymisierung für Analytics/Reporting (z. B. HMAC mit geheimem Schlüssel statt einfachem Hash). *(Art. 25, 32, ISO 8.11)*

## 7. Logging, Monitoring, Fehler
- [ ] Keine Passwörter, Tokens, Session-IDs, vollständige Kreditkarten-/IBAN-Nummern, Gesundheitsdaten in Logs. *(ISO 8.12, 8.15, Art. 5 1c)*
- [ ] E-Mail/Name/IP in Logs nur wenn nötig, sonst maskiert/pseudonymisiert; Log-Aufbewahrung befristet (z. B. 7–30 Tage für Access-Logs, IPs ggf. kürzen). *(Art. 5 1e)*
- [ ] Security-Events geloggt: Login ok/fehlgeschlagen, Logout, Passwort-/MFA-Änderung, Rollenänderung, Zugriff verweigert, Datenexport, Admin-Aktionen, Löschungen. *(ISO 8.15)*
- [ ] Strukturiertes Logging mit UTC-Zeitstempel, Actor-ID, Request-ID. *(8.15, 8.17)*
- [ ] Fehlermeldungen an Clients generisch, Details nur intern. *(8.12)*
- [ ] Error-Tracking (Sentry etc.): PII-Scrubbing aktiv (`send_default_pii=False`, `beforeSend`), EU-Region. *(8.12, Art. 28, 44)*
- [ ] Alerting auf sicherheitsrelevante Anomalien. *(8.16, Art. 33)*

## 8. Frontend, Cookies, Tracking (TDDDG § 25)
- [ ] Analytics/Marketing-Skripte (GA, GTM, Meta Pixel, Hotjar, LinkedIn Insight, TikTok) erst nach Opt-in laden. *(TDDDG § 25, Art. 6, 7)*
- [ ] Fremdressourcen (Fonts/CDN/Icons) inventarisieren; lokal hosten oder Rechtsgrundlage und Transfers prüfen. Ein Abruf allein belegt keine Einwilligungspflicht nach § 25 TDDDG. *(Art. 6, 44 ff.)*
- [ ] YouTube/Vimeo/Maps: Zwei-Klick-Lösung / `youtube-nocookie` + Consent. *(TDDDG § 25)*
- [ ] Endgerätezugriffe einschließlich Storage erfassen; Einwilligung oder eine der beiden Ausnahmen nach § 25 Abs. 2 TDDDG prüfen. DSGVO-Verarbeitung getrennt bewerten.
- [ ] Consent-Banner: "Ablehnen" gleichwertig zu "Akzeptieren", keine vorausgewählten Checkboxen. *(Art. 7, Planet49)*
- [ ] Keine pbD in URLs/Query-Strings (landen in Logs, Referrer, Browser-History). *(ISO 8.12)*
- [ ] Keine pbD/Secrets im Client-Bundle oder in `NEXT_PUBLIC_`/`VITE_`-Variablen. *(8.12)*
- [ ] Security-Header: CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, `frame-ancestors`. *(8.28, 8.9)*

## 9. Drittanbieter & Datenübermittlung
- [ ] Liste aller externen Endpunkte/SDKs erstellen, die pbD erhalten (E-Mail-Versand, Payment, SMS, LLM-APIs, Analytics, Monitoring, Maps, CRM). *(Art. 28, ISO 5.19–5.22)*
- [ ] Empfängerrollen, EU/EWR, Unterauftragnehmer und Fernzugriffe feststellen; Transfermechanismus und aktuellen Status fallbezogen prüfen. EU-Region allein genügt nicht. *(Art. 26, 28, 44 ff.)*
- [ ] LLM/KI-APIs: Keine unnötigen pbD im Prompt; Zero-Data-Retention/Training-Opt-out prüfen; ggf. Pseudonymisierung vor Versand. *(Art. 5, 28, 44)*
- [ ] Webhooks ausgehend signiert, eingehend verifiziert. *(5.14)*

## 10. Datenbank & Infrastruktur (IaC)
- [ ] DB/Cache/Storage nicht öffentlich erreichbar (Security Groups, `publicly_accessible = false`, kein öffentlicher Bucket/ACL). *(8.20, 8.22)*
- [ ] Encryption at rest aktiviert (`storage_encrypted`, `encrypted = true`, SSE-KMS). *(8.24)*
- [ ] Least-Privilege IAM; keine `*:*`-Policies, keine Root-Keys. *(5.15, 8.2)*
- [ ] Backups aktiviert, verschlüsselt, Retention definiert. *(8.13)*
- [ ] Container: kein `root`-User, gepinnte Base-Images, keine Secrets in Layern. *(8.8, 8.9)*
- [ ] Audit-Logging der Cloud aktiv (CloudTrail, Activity Log). *(8.15)*

## 11. Entwicklungsprozess
- [ ] Dependency-Scanning und Lockfiles; keine bekannten kritischen CVEs. *(8.8)*
- [ ] SAST/Secret-Scanning in CI (Semgrep, CodeQL, gitleaks, trufflehog). *(8.25, 8.29)*
- [ ] Branch Protection, Pflicht-Review. *(8.4, 8.32)*
- [ ] Testdaten synthetisch (Faker), keine Prod-Dumps in Fixtures/Seeds. *(8.33)*
- [ ] Lizenzen der Dependencies kompatibel. *(5.31)*

## Typische Fix-Snippets

**Python – Ereignis protokollieren, personenbezogene Inhalte weglassen**
```python
import logging
logger = logging.getLogger(__name__)
logger.info("account_export_completed")
```

Keine E-Mail, Tokens oder Request-Payloads in Nachricht, Formatierungsargumente,
Zusatzfelder oder Exceptions übernehmen. Benötigte Akteur-/Objektzuordnungen
gesondert minimieren und schützen. Ein Regex-Filter nur für E-Mails ist kein
allgemeiner PII-Schutz. Filter an Loggern greifen nicht automatisch auf Meldungen
untergeordneter Logger; alle Ausgabewege müssen gesondert betrachtet werden.
Quelle: [Python-Logging, Weiterleitung und Filter](https://docs.python.org/3/library/logging.html#logging.Logger.propagate).

**Python – Passwort-Hashing**
```python
from argon2 import PasswordHasher
ph = PasswordHasher()  # Argon2id, sichere Defaults
hash_ = ph.hash(password)
ph.verify(hash_, candidate)
```

**Pseudonymisierung mit HMAC**
```python
import hmac, hashlib, os
KEY = os.environ["PSEUDONYM_KEY"].encode()  # aus Secret-Manager
def pseudonym(value: str) -> str:
    return hmac.new(KEY, value.lower().encode(), hashlib.sha256).hexdigest()
```

**Node – Objekt-Autorisierung**
```js
const doc = await db.document.findFirst({
  where: { id: req.params.id, tenantId: req.user.tenantId },
});
if (!doc) return res.sendStatus(404); // 404 statt 403 verhindert Enumeration
```

**Consent-gesteuertes Laden**
```js
if (consent.has("analytics")) {
  const s = document.createElement("script");
  s.src = "/vendor/analytics.js"; s.async = true;
  document.head.appendChild(s);
}
```

**PostgreSQL – Aufbewahrungsfrist**
```sql
-- Nur Beispiel: Frist/Zweck und rechtliche Aufbewahrung vorher festlegen.
DELETE FROM access_log WHERE created_at < now() - interval '30 days';
```

Das Leeren von Name/E-Mail belegt keine Anonymisierung. Andere Felder,
Verknüpfungen, Zusatzinformationen und betroffene Folgesysteme prüfen; keinen
Status `anonymized_at` allein aus dem Löschen zweier Felder ableiten.
