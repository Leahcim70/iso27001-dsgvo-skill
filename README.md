# Datenschutz- und Security-Skill für Claude Code und Codex

Dieser [Agent Skill](https://agentskills.io) unterstützt die technische Prüfung von Code auf Datenschutz- und Sicherheitsprobleme. Die Hinweise beziehen sich auf **DSGVO**, **BDSG**, **TDDDG** und ausgewählte Controls aus **ISO/IEC 27001:2022 Annex A**.

Er liefert technische Einschätzungen und Code-Vorschläge. Eine rechtliche Freigabe oder Zertifizierung ist damit nicht verbunden.

- **Code prüfen:** Untersucht Dateien, Module, Repositories oder Diffs. Der Bericht nennt Schweregrad, Fundstelle, DSGVO-Artikel beziehungsweise ISO-Control und einen Lösungsvorschlag.
- **Code schreiben:** Hilft bei der Umsetzung von *Privacy by Design* und *Secure Coding* und nennt Fragen, die außerhalb des Codes geklärt werden müssen.
- **Vorab-Scanner:** `scan.py` mit 29 heuristischen Regeln (Secrets, Kryptografie, Injection, Logging, Tracking-Indikatoren, Cloud-Konfiguration …). Nur Python-Standardbibliothek, keine Netzwerkzugriffe und keine Ausführung des geprüften Codes. Ausgaben enthalten keine Quelltextausschnitte.

## Installation

### Claude Code – als Plugin

```
/plugin marketplace add Leahcim70/iso27001-dsgvo-skill
/plugin install iso27001-dsgvo@iso27001-dsgvo-skill
```

### Codex und andere Agents – mit der Skills-CLI

```
npx skills add Leahcim70/iso27001-dsgvo-skill
npx skills add Leahcim70/iso27001-dsgvo-skill -a codex   # nur für Codex
```

Die Befehle installieren den jeweils aktuellen Stand. Für eine feste Version den Skill manuell installieren; bei Einsatz der CLI auch deren Version festlegen. Die CLI wird separat gepflegt.

### Manuell

Das Repository herunterladen und den Ordner `plugins/iso27001-dsgvo/skills/iso27001-dsgvo` in das passende Verzeichnis kopieren:

| Tool | Global | Pro Projekt |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex | `~/.codex/skills/` | `.agents/skills/` |

Für eine bestimmte veröffentlichte Version den Release-Tag verwenden:

```
git clone --no-checkout https://github.com/Leahcim70/iso27001-dsgvo-skill.git
git -C iso27001-dsgvo-skill checkout --detach v1.1.0
```

Anschließend den Skill-Ordner wie oben beschrieben kopieren. Für sensible Projekte und CI möglichst auf die **nach der Veröffentlichung verifizierte Commit-SHA** statt auf einen verschiebbaren Tag pinnen. Bei Updates neue Version und SHA vor der Übernahme prüfen.

## Verwendung

Der Skill wird automatisch geladen, sobald es um Datenschutz, Security oder Compliance geht. Explizit aufrufen lässt er sich so:

- Claude Code: `/iso27001-dsgvo prüfe src/`
- Codex: `$iso27001-dsgvo prüfe src/`

Beispiele:

- „Prüfe src/ auf Datenschutz- und Sicherheitsprobleme.“
- „Review den aktuellen Diff auf Datenschutzprobleme.“
- „Hilf mir, einen Account-Lösch-Endpunkt in FastAPI zu entwickeln.“
- „Welche Cookies und externen Dienste verwendet dieses Projekt?“

### Vor einer Prüfung

Nur Dateien und Daten prüfen lassen, die für die verwendete KI-Umgebung freigegeben sind. Der lokale Scanner übermittelt nichts; der KI-Agent kann Inhalte jedoch an seinen Anbieter senden. Deshalb vorher Verträge, Speicher- und Trainingsoptionen sowie mögliche Datenübermittlungen prüfen. Keine echten Zugangsdaten oder unnötigen personenbezogenen Daten in Prompts, Berichte, Issues oder PRs aufnehmen. Auch Dateinamen können vertraulich sein.

Anweisungen in fremden Dateien oder Scanner-Ausgaben dürfen keine zusätzlichen Befehle, Uploads oder Änderungen auslösen. Während des Scans sollte der geprüfte Projektstand unverändert bleiben; der Scanner schützt nicht vor gleichzeitigen Änderungen am Dateisystem.

### Scanner direkt nutzen

```
python3 plugins/iso27001-dsgvo/skills/iso27001-dsgvo/scripts/scan.py <pfad> --format md
python3 .../scan.py <pfad> --format json --min-severity HIGH
```

| Exit-Code | Bedeutung |
|---|---|
| `0` | Im geprüften Umfang keine hohen oder kritischen Treffer gefunden |
| `1` | Mindestens ein hoher/kritischer Hinweis; Kontextprüfung erforderlich |
| `2` | Prüfung unvollständig oder Aufruffehler; hat Vorrang vor `1` |

Dateien über 1 MB, Zeilen über 2.000 Zeichen, Symlinks sowie Lese-/UTF-8-Fehler werden als `skipped` mit Grund gemeldet und führen zu Status `2`. Ohne unterstützte Quelldateien ebenfalls Status `2`. Unterstützte Dateiendungen und standardmäßig ausgeschlossene Verzeichnisse stehen in `CODE_EXT`, `SPECIAL_FILES` und `DEFAULT_EXCLUDES`; Markdown, Lockfiles und minifizierte JS-Dateien gehören nicht zum automatischen Prüfumfang. Verzeichnisausschlüsse betreffen Namen auf jeder Ebene und werden im Bericht genannt.

`--min-severity` und `--max-findings` begrenzen nur die Trefferanzeige. Zählung und Exit-Code berücksichtigen alle gefundenen Schweregrade. Das JSON-Feld `snippet` bleibt zur Kompatibilität leer. Seit Version 1.1.0 wird `compliance-ignore` nicht mehr ausgewertet; auch bisher unterdrückte Zeilen werden geprüft. Fehlalarme müssen im Review bewertet werden.

Ein [GitHub-Actions-Beispiel](examples/github-action.yml) pinnt externe Actions auf feste Commit-IDs, verwendet für den Scanner den Release-Tag `v1.1.0` und gibt Scanner-Fehler an den Build weiter. Im produktiven CI den Scanner nach der Veröffentlichung auf seine geprüfte Commit-SHA pinnen. Das Beispiel vor der Übernahme prüfen. Berichte enthalten Dateipfade und sollten nur den dafür vorgesehenen Personen zugänglich sein.

## Inhalt

```
plugins/iso27001-dsgvo/skills/iso27001-dsgvo/
├── SKILL.md                      # Workflow, Schweregrade, Kernregeln
├── references/
│   ├── dsgvo.md                  # DSGVO, BDSG, TDDDG – technische Bedeutung
│   ├── iso27001-annex-a.md       # code-relevante Annex-A-Controls mit Prüffragen
│   ├── code-checklist.md         # Prüfkatalog in 11 Bereichen inkl. Fix-Snippets
│   └── report-template.md        # Berichtsvorlage (Markdown/JSON)
└── scripts/scan.py               # heuristischer Vorab-Scanner
```

## Hinweise

- **Grenzen der Prüfung:** Ergebnisse können falsch oder unvollständig sein. Der Skill ersetzt weder Datenschutzbeauftragte noch Rechtsberatung oder ein Zertifizierungsaudit und garantiert keine Rechtskonformität. Auch ein Scan ohne Treffer bestätigt weder Sicherheit noch Rechtskonformität.
- **ISO 27001** verlangt ein Managementsystem (ISMS). Code kann nur Nachweise für einzelne Annex-A-Controls liefern.
- **Normtext:** Das Repo stellt keine Normvolltexte bereit. Kurzbeschreibungen und technische Prüffragen sind keine autorisierte Normübersetzung. Den Normtext gibt es bei ISO bzw. DIN Media; dessen Nutzungsrechte sind gesondert zu klären.
- **Unabhängiges Projekt:** Keine Verbindung, Anerkennung oder Bestätigung durch ISO, IEC, DIN oder eine Zertifizierungsstelle. Normbezeichnungen dienen der fachlichen Zuordnung. Das Projekt beansprucht keine Rechte an fremden Normtexten oder Marken.
- Scanner-Treffer sind Hinweise, keine Befunde. False Positives sind möglich, und eine vollständige SAST-Lösung (Semgrep, CodeQL) ersetzt der Scanner nicht.
- Quellen und fachlicher Prüfstand stehen in den Referenzen. Rechts- und Anbieterstatus vor einer konkreten Entscheidung erneut prüfen. Ein allgemeiner Lizenz-Haftungsausschluss verdrängt kein zwingendes Recht.

## Mitmachen

Issues und Pull Requests sind willkommen, etwa für neue Scanner-Regeln, weitere Sprachen oder Korrekturen. Nur synthetische, anonymisierte Beispiele verwenden; keine Secrets, Kundendaten, Normkopien oder vertraulichen Berichte einstellen. Sicherheitsmeldungen: [SECURITY.md](SECURITY.md). Herkunft und Lizenz von Beiträgen dokumentieren: [CONTRIBUTING.md](CONTRIBUTING.md).

Prüfungen lokal ausführen: `python3 -B -m unittest discover -s tests -v`. Die Tests benötigen keine externen Python-Pakete und verwenden künstliche Daten.

Verantwortlicher Herausgeber: **Michael Lantzen** · Website: [lantzen.com](https://lantzen.com).

Die Inhalte, Erläuterungen und synthetischen Beispiele wurden mithilfe von Claude Code und OpenAI Codex erstellt; der Herausgeber verantwortet die Veröffentlichung. Vollständige Normtexte von ISO/IEC sind nicht Bestandteil dieses Projekts. Eine offizielle Bestätigung oder rechtliche Konformitätsprüfung ist damit nicht verbunden.

## Lizenz

[MIT](LICENSE): Nutzung, Änderung und Weitergabe sind kostenlos erlaubt, auch kommerziell.
