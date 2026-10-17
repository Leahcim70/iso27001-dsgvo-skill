# DSGVO / BDSG / TDDDG – technisch relevante Vorschriften

Kurzfassung mit Fokus darauf, was im Code sichtbar oder umsetzbar ist. Keine Rechtsberatung.

**Fachlicher Prüfstand: 2026-10-16.** Ausgangspunkt ist die
[DSGVO im EU-Amtsblatt](https://eur-lex.europa.eu/legal-content/DE/ALL/?uri=CELEX%3A32016R0679).
Artikelverweise beziehen sich hierauf; nationale Vorschriften und Rechtsprechung
sind unten direkt verlinkt. Vor Einzelfallbewertungen aktuellen Gesetzes-,
Rechtsprechungs- und Anbieterstatus prüfen. Ungeprüfte Annahmen kennzeichnen.

## Grundbegriffe (Art. 4)

- **Personenbezogene Daten (pbD):** Alle Informationen über eine identifizierte oder identifizierbare natürliche Person. Dazu zählen auch IP-Adressen (EuGH C-582/14 „Breyer“), Cookie-/Geräte-IDs, Standortdaten, Online-Kennungen, User-IDs, sofern eine Zuordnung möglich ist.
- **Pseudonymisierung:** Zuordnung nur mit gesondert aufbewahrten Zusatzinformationen möglich → bleibt pbD, senkt aber das Risiko.
- **Anonymisierung:** Identifizierung unter Berücksichtigung vernünftigerweise einsetzbarer Mittel nicht mehr möglich (Erwägungsgrund 26). Das Entfernen einzelner Felder oder ein Hash allein belegt dies nicht. Pseudonymisierte Daten bleiben grundsätzlich pbD.
- **Verarbeitung:** Jeder Vorgang – Erheben, Speichern, Loggen, Übertragen, Löschen.

## Art. 5 – Grundsätze

| Grundsatz | Technische Bedeutung |
|---|---|
| Rechtmäßigkeit, Transparenz (1a) | Jede Verarbeitung braucht eine Rechtsgrundlage (Art. 6); Datenschutzhinweis muss zur tatsächlichen Verarbeitung passen |
| Zweckbindung (1b) | Daten nicht für andere Zwecke wiederverwenden (z. B. Support-Daten nicht für Marketing); Zweck pro Feld/Tabelle dokumentierbar |
| Datenminimierung (1c) | Nur nötige Felder erheben; keine "Vielleicht-mal-brauchen"-Spalten; Pflichtfelder kritisch prüfen; keine Vollkopie von API-Responses |
| Richtigkeit (1d) | Berichtigung muss möglich sein |
| Speicherbegrenzung (1e) | Aufbewahrungsfristen, automatische Löschung/Anonymisierung (TTL, Jobs), auch für Logs und Backups |
| Integrität & Vertraulichkeit (1f) | Verschlüsselung, Zugriffskontrolle, Schutz vor Verlust → Art. 32 |
| Rechenschaftspflicht (2) | Nachweisbarkeit: Audit-Logs, Einwilligungsnachweise, Dokumentation |

## Art. 6 – Rechtsgrundlagen

a) Einwilligung · b) Vertrag/vorvertraglich · c) rechtliche Pflicht · d) lebenswichtige Interessen · e) öffentliche Aufgabe · f) berechtigtes Interesse (mit Abwägung).
**Code-Relevanz:** Zweck und passende Grundlage fallbezogen dokumentieren; fehlende Vertragserforderlichkeit bedeutet nicht automatisch Einwilligungspflicht. Newsletter können zusätzlich § 7 UWG betreffen; Endgerätezugriffe gesondert nach § 25 TDDDG prüfen. Ein Consent-Flag allein belegt keine wirksame Einwilligung.

## Art. 7 – Einwilligung

- Nachweispflicht → Einwilligung mit Zeitstempel, Version des Textes, Zweck, Kanal speichern.
- Widerruf so einfach wie Erteilung → Widerrufs-Endpunkt/UI.
- Keine vorausgewählten Checkboxen (EuGH C-673/17 „Planet49“).
- Freiwilligkeit einschließlich Kopplung prüfen (Art. 7 Abs. 4); Leistung nicht ohne gesonderte Prüfung von einer nicht erforderlichen Einwilligung abhängig machen.
- **Art. 8:** Bei direkt an Kinder gerichteten Diensten der Informationsgesellschaft und Verarbeitung auf Einwilligungsbasis gilt in DE die 16-Jahre-Grenze; darunter ist die Einwilligung/Zustimmung des Trägers elterlicher Verantwortung erforderlich. Keine allgemeine Altersgrenze für jede Verarbeitung.

## Art. 9 – Besondere Kategorien

Gesundheit, Genetik, Biometrie (zur Identifizierung), ethnische Herkunft, politische Meinung, Religion, Gewerkschaft, Sexualleben/-orientierung. Verarbeitung grundsätzlich verboten, Ausnahmen eng. **Code:** Felder kennzeichnen, gesondert verschlüsseln, Zugriff stark einschränken, DSFA (Art. 35) wahrscheinlich nötig. Art. 10: strafrechtliche Daten ähnlich restriktiv.

## Art. 12–22 – Betroffenenrechte (technisch umsetzen)

| Recht | Umsetzung im Code |
|---|---|
| Art. 15 Auskunft | Personenbezogene Inhalte und erforderliche Informationen aus relevanten Systemen ermitteln; Identität und Rechte Dritter schützen. Frist nach Art. 12 Abs. 3 grundsätzlich ein Monat; begründete Verlängerung möglich |
| Art. 16 Berichtigung | Edit-Funktion, Propagation an Drittsysteme |
| Art. 17 Löschung | Voraussetzungen/Ausnahmen prüfen; betroffene Daten in Relationen, Caches, Suchindex, Dateien, Queues und Drittsystemen berücksichtigen. Backup-Fristen und Löschungen nach Restore dokumentieren. Aufbewahrungspflichten nach Unterlagenart prüfen: regelmäßig 6/8/10 Jahre, Sonderfälle siehe unten. Aufbewahrungspflichtige Daten zweckgebunden und zugriffsbeschränkt erhalten |
| Art. 18 Einschränkung | Status-Flag "restricted", das Verarbeitung außer Speicherung blockiert |
| Art. 19 Mitteilungspflicht | Empfänger über Berichtigung/Löschung informieren (Webhooks/API-Calls) |
| Art. 20 Datenübertragbarkeit | Bei automatisierter Verarbeitung auf Einwilligungs-/Vertragsbasis bereitgestellte Daten in geeignetem maschinenlesbarem Format; Umfang und Rechte Dritter beachten |
| Art. 21 Widerspruch | Direktwerbung einschließlich zugehörigem Profiling nach Widerspruch beenden; sonst Voraussetzungen und Ausnahmen gesondert prüfen |
| Art. 22 Automatisierte Entscheidungen | Bei Entscheidungen mit rechtlicher Wirkung (Scoring, Ablehnung): menschliches Eingreifen ermöglichen, Logik erklärbar |

## Art. 25 – Privacy by Design & by Default

- Datenschutzfreundliche Voreinstellungen: Profile nicht öffentlich, Tracking aus, minimale Freigaben.
- Pseudonymisierung früh in der Pipeline, Trennung von Identitäts- und Nutzungsdaten.
- Gilt für jede Neuentwicklung → Modus B des Skills.

## Art. 28 – Auftragsverarbeitung

Alle externen Endpunkte/SDKs mit Datenempfang inventarisieren und die tatsächliche
Rolle bestimmen: Auftragsverarbeiter, eigenständig Verantwortlicher oder gemeinsam
Verantwortliche. Art. 28 verlangt einen AV-Vertrag bei Auftragsverarbeitung;
Art. 26 betrifft gemeinsame Verantwortlichkeit. Dienstnamen allein entscheiden die Rolle nicht.
Beispiele und Abgrenzung: [EDSA-Leitlinien 07/2020, finale Fassung 2.1](https://www.edpb.europa.eu/system/files/documents/2023-10/EDPB_guidelines_202007_controllerprocessor_final_en.pdf).

## Art. 30 – Verzeichnis von Verarbeitungstätigkeiten (VVT)

Organisatorisch, aber Code liefert die Fakten: Datenkategorien, Empfänger, Fristen, TOMs.

## Art. 32 – Sicherheit der Verarbeitung (TOM)

Explizit genannt: Pseudonymisierung und Verschlüsselung; Vertraulichkeit, Integrität, Verfügbarkeit, Belastbarkeit; Wiederherstellbarkeit; regelmäßige Überprüfung. Stand der Technik → siehe Kryptografie-Abschnitt in `code-checklist.md`.

## Art. 33/34 – Datenpannen

Art. 33: Verantwortliche melden unverzüglich und möglichst binnen 72 Stunden ab
Kenntnis, außer die Verletzung führt voraussichtlich nicht zu einem Risiko für
Rechte und Freiheiten. Verzögerungen begründen; Verletzungen dokumentieren.
Auftragsverarbeiter informieren den Verantwortlichen unverzüglich.
Art. 34: Betroffene grundsätzlich bei voraussichtlich hohem Risiko benachrichtigen;
gesetzliche Ausnahmen gesondert prüfen. **Code:** Erkennung, Zugriffsschutz,
Zeitpunkte und betroffene Daten nachvollziehbar machen.

## Art. 35 – Datenschutz-Folgenabschätzung

Erforderlichkeit nach Art. 35, Verarbeitungskontext und einschlägigen Aufsichtslisten
prüfen. Umfangreiche besondere Kategorien, systematische Überwachung und Bewertungen
mit erheblichen Auswirkungen können Auslöser sein. KI allein begründet keine DSFA-Pflicht.
Offene Erforderlichkeitsprüfung kennzeichnen; eine bestätigte erhebliche Lücke risikogerecht priorisieren.
Quelle: [DSK-Liste nach Art. 35 Abs. 4](https://www.datenschutzkonferenz-online.de/media/ah/20181017_ah_DSK_DSFA_Muss-Liste_Version_1.1_Deutsch.pdf).

## Art. 44–49 – Drittlandübermittlung

- EU/EWR, Empfänger, Unterauftragnehmer und mögliche Fernzugriffe feststellen.
  Bei Drittlandübermittlungen aktuellen Angemessenheitsbeschluss (Art. 45), geeignete
  Garantien (Art. 46) oder eine eng auszulegende Ausnahme (Art. 49) prüfen.
  SCC erfordern eine Prüfung der tatsächlichen Schutzwirkung und ggf. Zusatzmaßnahmen.
- Anbieterstatus, Zertifizierungsumfang und Gültigkeit nicht aus Namen oder Region ableiten.
  Eine EU-Region allein schließt Drittlandzugriffe nicht aus.
- Aktuelle Ausgangsquellen: [EU-Kommission zu Angemessenheitsbeschlüssen](https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/adequacy-decisions_en)
  und [Standardvertragsklauseln, Beschluss (EU) 2021/914](https://eur-lex.europa.eu/eli/dec_impl/2021/914/oj).

## Art. 83 – Bußgelder

Bis 20 Mio. € oder 4 % des weltweiten Jahresumsatzes (Art. 5, 6, 9, Betroffenenrechte, Drittland); bis 10 Mio. € / 2 % (u. a. Art. 25, 28, 32).

---

## BDSG (Deutschland)

- **[§ 26 BDSG / Beschäftigtendaten](https://www.gesetze-im-internet.de/bdsg_2018/__26.html):**
  Rechtsgrundlage, Erforderlichkeit und Verhältnismäßigkeit fallbezogen prüfen.
  [EuGH C-34/21 vom 30.03.2023](https://infocuria.curia.europa.eu/tabs/redirect/juris/document/document.jsf?docid=272066&doclang=DE)
  betrifft hessische Vorschriften und Anforderungen des Art. 88 DSGVO. Daraus keine
  pauschale Unanwendbarkeit von § 26 oder automatische Ersatzgrundlage Art. 6 b/c ableiten.
  Auswirkungen aktueller Rechtsprechung und Mitbestimmung bei Überwachung gesondert klären.
- **§ 22 BDSG:** Maßnahmen bei besonderen Kategorien.
- **[§ 38 BDSG](https://www.gesetze-im-internet.de/bdsg_2018/__38.html):**
  Ergänzend zu Art. 37 DSGVO regelmäßig mindestens 20 Personen, die ständig mit
  automatisierter Verarbeitung beschäftigt sind. Unabhängig von der Zahl bestehen
  weitere Tatbestände, insbesondere DSFA-pflichtige Verarbeitungen sowie bestimmte
  geschäftsmäßige Übermittlungen und Markt-/Meinungsforschung.

## TDDDG (früher TTDSG, umbenannt Mai 2024)

- **[§ 25 TDDDG](https://www.gesetze-im-internet.de/ttdsg/__25.html):**
  Speicherung/Zugriff auf bereits gespeicherte Endgeräteinformationen grundsätzlich
  mit informierter Einwilligung. Abs. 2 enthält zwei Ausnahmen: alleiniger Zweck
  Nachrichtenübertragung oder unbedingte Erforderlichkeit für einen ausdrücklich
  gewünschten digitalen Dienst. Zweck und tatsächliche Technik prüfen; Produktname
  oder Cookie-Kategorie allein belegt keine Ausnahme.
- Gilt unabhängig davon, ob pbD betroffen sind.
- **Prüfindikatoren:** Analytics/Pixel, Fremdressourcen und Embeds inventarisieren.
  Ein externer Abruf oder eine IP-Übermittlung allein belegt keinen Zugriff im Sinne
  des § 25. DSGVO-Rechtsgrundlage und Transfers getrennt prüfen. Bei erforderlicher
  Einwilligung darf die Verarbeitung nicht vorher beginnen; Freiwilligkeit und
  gleichwertige Ablehnmöglichkeit beachten.

## Weitere relevante Normen (Hinweis, nicht Kernumfang)

- **NIS2 / NIS2UmsuCG:** Risikomanagement-Pflichten für wichtige/besonders wichtige Einrichtungen; überschneidet sich stark mit ISO 27001.
- **[EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/deu):** Rolle,
  System, Verwendungszweck und Anwendungszeitpunkt prüfen. Ein Prompt-/Skill-Repository
  ist nicht allein wegen seines KI-Bezugs ein Hochrisiko-KI-System.
- **[Cyber Resilience Act](https://eur-lex.europa.eu/eli/reg/2024/2847/oj):**
  Produkt, kommerzielle Bereitstellung und Rolle prüfen; nichtkommerziell bereitgestellte
  freie Open-Source-Software wird ausgenommen. Bei Anwendbarkeit Art. 14 ab 11.09.2026,
  überwiegende Pflichten ab 11.12.2027 (Art. 71). Die MIT-Erlaubnis kommerzieller
  Weiterverwendung durch Dritte macht die eigene Veröffentlichung nicht automatisch kommerziell.
- **[§ 257 HGB](https://www.gesetze-im-internet.de/hgb/__257.html) /
  [§ 147 AO](https://www.gesetze-im-internet.de/ao_1977/__147.html):**
  Regelmäßig zehn Jahre für bestimmte Bücher/Abschlüsse, acht für Buchungsbelege,
  sechs für andere aufbewahrungspflichtige Unterlagen. Sonderfälle, Übergangsregeln,
  Fristbeginn und steuerliche Ablaufhemmungen beachten; § 257 Abs. 4 HGB enthält
  insbesondere längere Fristen für bestimmte Finanz-/Versicherungsunternehmen.
  Zweckgebundene Aufbewahrung technisch von sonstiger Nutzung trennen.
