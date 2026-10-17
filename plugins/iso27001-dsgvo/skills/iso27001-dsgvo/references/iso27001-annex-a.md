# ISO/IEC 27001:2022 – Annex A, code-relevante Controls

Annex A 2022 umfasst 93 Controls in 4 Themen: 5 Organisatorisch (37), 6 Personen (8), 7 Physisch (14), 8 Technologisch (34). Hier nur Controls, die sich in Code, Architektur, CI/CD oder Konfiguration niederschlagen. Detail-Umsetzungshinweise stehen in ISO/IEC 27002:2022; Datenschutz-Erweiterung in ISO/IEC 27701.

Die Kurzbezeichnungen sind sinngemäße Übersetzungen, nicht der Normtext.

**Fachlicher Prüfstand: 2026-10-16.** Technische Einordnung mit Bezug auf
[ISO/IEC 27001:2022](https://www.iso.org/standard/27001); keine autorisierte
Übersetzung, vollständige Normprüfung oder Bestätigung durch ISO/IEC/DIN.
Normvolltexte nur mit passenden Nutzungsrechten verwenden; die
[ISO-Copyright-/KI-Nutzungsbedingungen](https://www.iso.org/copyright.html)
gesondert prüfen. Gesetzliche Grundlagen und Organisationskontext bleiben erforderlich.

## Organisatorische Controls (Abschnitt 5)

| Control | Thema | Prüffragen im Code |
|---|---|---|
| 5.9 | Inventar von Informationen und Werten | Ist erkennbar, welche Datenarten/Systeme es gibt (Schema-Doku, Datenkatalog)? |
| 5.12 | Klassifizierung von Informationen | Sind sensible Felder gekennzeichnet (Annotationen, Schema-Kommentare, Tags)? |
| 5.13 | Kennzeichnung | Werden Klassifizierungen technisch durchgesetzt (z. B. Logging-Filter nach Tag)? |
| 5.14 | Informationsübertragung | Verschlüsselte Übertragung (TLS), sichere Dateiübergaben, keine pbD per Klartext-Mail/URL |
| 5.15 | Zugriffssteuerung | Zentral definierte AuthZ-Policy, Deny-by-Default, Prüfung auf Objektebene (IDOR) |
| 5.16 | Identitätsmanagement | Eindeutige Identitäten, keine Shared Accounts, Lifecycle (Deaktivierung) |
| 5.17 | Authentisierungsinformationen | Keine hartcodierten Secrets, sichere Passwort-Speicherung, Reset-Flows sicher |
| 5.18 | Zugriffsrechte | Rollenmodell, Rechtevergabe nachvollziehbar, Entzug wirksam (Token-Revocation) |
| 5.19–5.22 | Lieferantenbeziehungen | Third-Party-SDKs/APIs inventarisiert, Rollen und Vertragsbasis geklärt; AVV bei Auftragsverarbeitung |
| 5.23 | Nutzung von Cloud-Diensten | Region, Verschlüsselung, IAM-Konfiguration, Exit-Fähigkeit |
| 5.28 | Sammlung von Beweismitteln | Manipulationssichere Logs (append-only, signiert, zentral) |
| 5.31 | Gesetzliche/vertragliche Anforderungen | Lizenzkonformität der Dependencies, Exportkontrolle Krypto |
| 5.33 | Schutz von Aufzeichnungen | Integrität und Aufbewahrung von Records (Audit-Trails, Rechnungen) |
| 5.34 | Privatsphäre und Schutz von PII | DSGVO-Umsetzung → `dsgvo.md` |
| 5.37 | Dokumentierte Betriebsabläufe | Runbooks, IaC statt manueller Konfiguration |

## Personenbezogene Controls (Abschnitt 6)

| 6.8 | Meldung von Sicherheitsereignissen | Gibt es Mechanismen (security.txt, Alerting), Vorfälle zu melden/erkennen? |

## Physische Controls (Abschnitt 7)

| 7.10 | Speichermedien | Sichere Löschung von Datenträgern / Volumes beim Decommissioning |
| 7.14 | Sichere Entsorgung/Wiederverwendung | Cloud-Volumes/Snapshots löschen, nicht nur abhängen |

## Technologische Controls (Abschnitt 8) – Kernbereich

| Control | Thema | Prüffragen im Code |
|---|---|---|
| 8.2 | Privilegierte Zugriffsrechte | Admin-Funktionen separat geschützt, MFA, Just-in-Time, Audit-Log |
| 8.3 | Beschränkung des Informationszugriffs | Mandantentrennung, Row-Level-Security, Objekt-Berechtigungsprüfung, Feld-Filterung in API-Responses |
| 8.4 | Zugriff auf Quellcode | Repo-Rechte, Branch Protection, keine Secrets im Repo/History |
| 8.5 | Sichere Authentisierung | MFA-Option, Brute-Force-Schutz, sichere Sessions (HttpOnly, Secure, SameSite), Session-Timeout, keine User-Enumeration |
| 8.7 | Schutz gegen Schadsoftware | Upload-Prüfung (Typ, Größe, ggf. AV-Scan), keine Ausführung hochgeladener Dateien |
| 8.8 | Management technischer Schwachstellen | Dependency-Scanning (Dependabot, Renovate, `npm audit`, `pip-audit`, Trivy), Lockfiles, gepinnte Base-Images |
| 8.9 | Konfigurationsmanagement | Sichere Defaults, Debug aus in Prod, IaC versioniert, Härtung (CIS) |
| 8.10 | Löschung von Informationen | Löschroutinen vorhanden und wirksam, Fristen umgesetzt |
| 8.11 | Datenmaskierung | Maskierung in UI/Logs/Exports (IBAN `DE** **** 1234`), Pseudonymisierung für Analytics |
| 8.12 | Verhinderung von Datenabfluss (DLP) | Keine pbD in Logs, Fehlermeldungen, URLs, Client-Bundles, Analytics-Events; Egress-Kontrolle |
| 8.13 | Datensicherung | Backups vorhanden, verschlüsselt, Restore getestet |
| 8.15 | Protokollierung | Sicherheitsereignisse geloggt mit Zeit, Akteur, Aktion, Objekt, Ergebnis; Schutz vor Manipulation; keine sensiblen Inhalte |
| 8.16 | Überwachung | Alerting auf Anomalien (Login-Fehlversuche, Massenexporte, 5xx-Spitzen) |
| 8.17 | Uhrzeitsynchronisation | UTC-Zeitstempel, NTP; einheitliche Zeitzone in Logs |
| 8.18 | Privilegierte Hilfsprogramme | Keine Shell-/Eval-Ausführung mit Nutzereingaben |
| 8.19 | Software-Installation auf Systemen | Reproduzierbare Builds, signierte Artefakte |
| 8.20 | Netzwerksicherheit | Segmentierung, Security Groups minimal, keine `0.0.0.0/0` auf DB-Ports |
| 8.21 | Sicherheit von Netzwerkdiensten | TLS-Konfiguration, Zertifikatsprüfung nicht deaktiviert |
| 8.22 | Trennung von Netzwerken | Prod/Non-Prod getrennt, interne Dienste nicht öffentlich |
| 8.23 | Web-Filterung | (meist organisatorisch) Egress-Allowlist für Server |
| 8.24 | Einsatz von Kryptografie | Aktuelle Algorithmen, Key-Management (KMS/HSM), Rotation, keine Eigenbau-Krypto |
| 8.25 | Sicherer Entwicklungslebenszyklus | Security in Definition of Done, Code Review, SAST/DAST in CI |
| 8.26 | Anforderungen an Anwendungssicherheit | Security-Anforderungen dokumentiert, Input-Validierung, Transaktionssicherheit |
| 8.27 | Sichere Systemarchitektur | Defense in Depth, Zero Trust, Least Privilege, Secure by Default |
| 8.28 | Sicheres Programmieren | OWASP Top 10 / ASVS: Injection, XSS, CSRF, SSRF, Deserialisierung, Path Traversal, Fehlerbehandlung |
| 8.29 | Sicherheitstests | Security-Unit-Tests (AuthZ-Tests!), SAST, DAST, Pentests vor Release |
| 8.30 | Ausgelagerte Entwicklung | Vorgaben für Dienstleister, Review von Fremdcode |
| 8.31 | Trennung von Entwicklungs-, Test- und Produktivumgebung | Separate Credentials, Configs, Datenbanken; kein Prod-Zugriff aus Dev |
| 8.32 | Änderungsmanagement | PR-Pflicht, Reviews, CI-Gates, nachvollziehbare Deployments, Rollback |
| 8.33 | Testdaten | Keine echten pbD in Tests/Fixtures/Seeds; synthetische oder anonymisierte Daten |
| 8.34 | Schutz bei Audit-Tests | Pentests/Audits mit begrenztem, protokolliertem Zugriff |

## Abgrenzung

- ISO 27001 verlangt ein ISMS (Kapitel 4–10: Kontext, Führung, Risikobeurteilung, SoA, interne Audits, Verbesserung). Code kann nur Nachweise für Annex-A-Controls liefern – die Zertifizierbarkeit hängt am Managementsystem.
- Anwendbarkeit und Umsetzung anhand von Risikobehandlung und Statement of Applicability (SoA) der Organisation prüfen. Ohne diese Informationen nur einen Zuordnungsvorschlag ausgeben; keine Nichtkonformität behaupten.
- Bei alten Control-Verweisen den verwendeten Normstand und Zertifizierungs-/Übergangskontext klären. Änderungen am ISMS einschließlich anwendbarer Amendments gesondert prüfen; diese technische Checkliste deckt sie nicht vollständig ab.
