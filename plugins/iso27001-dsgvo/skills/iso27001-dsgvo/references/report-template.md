# Berichtsvorlage

````markdown
# Technische Datenschutz- und Security-Vorprüfung: <Projekt/Modul>

**Datum:** <JJJJ-MM-TT> · **Scope:** <Dateien/Verzeichnisse/Commit> · **Stack:** <Sprachen, Frameworks, Cloud>
**Fachliche Zuordnung:** DSGVO, BDSG, TDDDG, ausgewählte ISO/IEC-27001:2022-Annex-A-Controls
**Quellen/Prüfstand:** <Primärquellen, Abrufdatum, ungeprüfte Annahmen>
> Technische Einschätzung, keine Rechtsberatung, rechtliche Freigabe, Konformitätsgarantie oder Zertifizierung. Keine sensiblen Originalwerte wiedergeben.

## Prüfumfang und Grenzen
- Scanner-Version/Commit, Exit-Code, `complete`, `skipped` und Ausschlüsse: <...>
- Nicht geprüfte Dateitypen, Bereiche, Datenflüsse und organisatorische Nachweise: <...>
- Ein Scan ohne Treffer bestätigt keine Sicherheit oder Rechtskonformität.

## Zusammenfassung
| Schweregrad | Anzahl |
|---|---|
| KRITISCH | n |
| HOCH | n |
| MITTEL | n |
| NIEDRIG | n |
| INFO | n |

<2–3 Sätze Gesamtbild.>

## Datenfluss-Inventur
| Datenkategorie | Quelle | Speicherort | Empfänger/Drittland | Frist | Art. 9? |
|---|---|---|---|---|---|
| <Kategorien, keine Originalwerte> | <Quelle> | <System> | <Empfänger, Rolle, Ort/Fernzugriffe ungeprüft?> | <Frist mit Grund> | <ja/nein/unklar> |

## Befunde

### [KRITISCH] K-1: <Kurztitel>
- **Ort:** `src/auth/login.py:42`
- **Problem:** <Was ist falsch, warum riskant>
- **Bewertungsstatus:** <bestätigte technische Schwäche / heuristischer Hinweis / rechtlich zu prüfen>
- **Kontext/Annahmen:** <Voraussetzungen, fehlende Nachweise und Grenzen>
- **Referenz:** DSGVO Art. 32 · ISO 27001 A.8.24
- **Fix:**
  ```python
  <korrigierter Code>
  ```

### [HOCH] H-1: ...

## Ohne bestätigten Befund im angegebenen Scope
<Tatsächlich geprüfte Bereiche mit Methode und Grenzen; keine pauschale Freigabe.>

## Organisatorische Punkte (nicht im Code lösbar)
- [ ] Empfängerrolle mit <Anbieter> klären; ggf. AVV (Art. 28) oder Art.-26-Vereinbarung
- [ ] VVT-Eintrag für <Verarbeitung> (Art. 30)
- [ ] DSFA-Erforderlichkeit prüfen (Art. 35)
- [ ] Datenschutzhinweis an tatsächliche Verarbeitung anpassen (Art. 13)

## Top-3-Maßnahmen
1. ...
2. ...
3. ...
````

Bei Diffs/PRs: kompaktere Form; Grenzen, Bewertungsstatus und offene Datenflüsse erhalten.
Bei Bedarf zusätzlich als JSON (für CI): `[{id, severity, status, assumptions, file, line, title, sources:[...], gdpr:[...], iso:[...], fix}]`.
