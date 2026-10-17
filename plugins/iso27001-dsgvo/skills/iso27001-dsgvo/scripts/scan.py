#!/usr/bin/env python3
"""Heuristischer DSGVO/ISO-27001-Vorab-Scanner (nur Python-Standardbibliothek).

Findet Muster, die auf Compliance-Probleme hindeuten. Treffer sind HINWEISE,
keine Befunde - jeder Treffer muss im Kontext geprüft werden.

Nutzung:
  python3 scan.py <pfad> [--format md|json|text] [--min-severity LOW]
                          [--exclude DIR ...] [--max-findings N]
Exit-Code: 0 = keine hohen/kritischen Hinweise im unterstützten Prüfumfang,
1 = hohe/kritische Hinweise, 2 = unvollständige Prüfung oder Aufruffehler.
Ausgaben enthalten keine Quelltextausschnitte. Alte compliance-ignore-Marker
unterdrücken keine Treffer. Kein Exit-Code bestätigt rechtliche Konformität.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, asdict

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_DE = {"CRITICAL": "KRITISCH", "HIGH": "HOCH", "MEDIUM": "MITTEL",
          "LOW": "NIEDRIG", "INFO": "INFO"}

CODE_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".go",
    ".rb", ".php", ".cs", ".rs", ".swift", ".scala", ".vue", ".svelte", ".html",
    ".htm", ".sql", ".sh", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
    ".conf", ".env", ".tf", ".hcl", ".properties", ".xml", ".dockerfile",
}
SPECIAL_FILES = {"Dockerfile", ".env", "docker-compose.yml", "Jenkinsfile"}
DEFAULT_EXCLUDES = {
    ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt",
    "__pycache__", ".venv", "venv", "env", "target", ".terraform", "coverage",
    ".idea", ".vscode", ".pytest_cache", ".mypy_cache",
}
MAX_FILE_BYTES = 1_000_000


@dataclass
class Rule:
    id: str
    severity: str
    title: str
    pattern: re.Pattern
    gdpr: list
    iso: list
    hint: str
    exts: set | None = None  # None = alle


def r(p: str, flags=re.IGNORECASE) -> re.Pattern:
    return re.compile(p, flags)


PII = r"(e-?mail|password|passwort|passwd|pwd|token|secret|iban|ssn|credit_?card|kreditkarte|birth|geburt|phone|telefon|address|adresse|first_?name|last_?name|vorname|nachname|ip_?addr)"

RULES = [
    # --- Secrets ---
    Rule("SEC-001", "CRITICAL", "Hartcodiertes Secret/Passwort",
         r(r"""(api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|pwd|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"][^'"\s${}<>]{8,}['"]"""),
         ["Art. 32"], ["5.17", "8.24", "8.4"],
         "Secret in Secret-Manager/Env auslagern und rotieren."),
    Rule("SEC-002", "CRITICAL", "Private Key im Code",
         r(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", 0),
         ["Art. 32"], ["5.17", "8.24", "8.4"],
         "Schlüssel entfernen, aus Git-History tilgen, rotieren."),
    Rule("SEC-003", "CRITICAL", "Bekanntes Token-Format (AWS/GitHub/Slack/Stripe/OpenAI/Anthropic)",
         r(r"(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-(proj-)?[A-Za-z0-9]{32,})", 0),
         ["Art. 32"], ["5.17", "8.4"],
         "Token sofort widerrufen und über Secret-Manager bereitstellen."),
    Rule("SEC-004", "HIGH", "Connection-String mit Zugangsdaten",
         r(r"(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp|mssql)://[^\s:/'\"]+:[^\s@'\"${}]+@"),
         ["Art. 32"], ["5.17", "8.24"],
         "Credentials aus URL entfernen, per Env/Secret-Manager injizieren."),

    # --- Kryptografie ---
    Rule("CRY-001", "HIGH", "Schwacher Hash (MD5/SHA-1)",
         r(r"\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)|createHash\(\s*['\"](md5|sha1)['\"]|MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\""),
         ["Art. 32"], ["8.24"],
         "Für Sicherheitszwecke SHA-256+; für Passwörter Argon2id/bcrypt."),
    Rule("CRY-002", "HIGH", "Unsicherer Cipher/Modus (DES/3DES/RC4/ECB)",
         r(r"\b(DES|3DES|TripleDES|RC4|ARC4|Blowfish)\b|AES/ECB|MODE_ECB|['\"]aes-\d+-ecb['\"]", 0),
         ["Art. 32"], ["8.24"],
         "AES-256-GCM oder ChaCha20-Poly1305 verwenden."),
    Rule("CRY-003", "HIGH", "TLS-Zertifikatsprüfung deaktiviert",
         r(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)|ssl\._create_unverified_context"),
         ["Art. 32"], ["8.21", "5.14"],
         "Zertifikatsprüfung aktivieren, ggf. eigenes CA-Bundle konfigurieren."),
    Rule("CRY-004", "MEDIUM", "Nicht-kryptografischer Zufall in Sicherheitskontext",
         r(r"(token|secret|password|otp|nonce|salt|session|reset).{0,40}(Math\.random\(|random\.(random|randint|choice)\(|rand\(\))"),
         ["Art. 32"], ["8.24"],
         "CSPRNG nutzen: secrets / crypto.randomBytes / SecureRandom."),
    Rule("CRY-005", "MEDIUM", "Unverschlüsselte HTTP-Verbindung",
         r(r"""['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|schemas\.|www\.w3\.org|example\.|xmlns)[^'"\s]+"""),
         ["Art. 32"], ["5.14", "8.21"],
         "HTTPS verwenden."),

    # --- Injection / Secure Coding ---
    Rule("INJ-001", "CRITICAL", "Mögliche SQL-Injection (String-Bau)",
         r(r"""(execute|query|raw|exec)\s*\(\s*(f['"]|['"][^'"]*['"]\s*(\+|%)|`[^`]*\$\{)[^)]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b"""),
         ["Art. 32"], ["8.28"],
         "Parametrisierte Queries/ORM verwenden."),
    Rule("INJ-002", "HIGH", "Dynamische Code-/Shell-Ausführung",
         r(r"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|os\.system\s*\(|shell\s*=\s*True|child_process\.exec\s*\(|Runtime\.getRuntime\(\)\.exec"),
         ["Art. 32"], ["8.18", "8.28"],
         "Keine Ausführung mit Nutzereingaben; Argumentlisten statt Shell."),
    Rule("INJ-003", "MEDIUM", "Unsichere Deserialisierung",
         r(r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)|ObjectInputStream|unserialize\s*\("),
         ["Art. 32"], ["8.28"],
         "Sichere Formate (JSON) bzw. yaml.safe_load nutzen."),
    Rule("XSS-001", "MEDIUM", "Unescaped HTML-Ausgabe",
         r(r"dangerouslySetInnerHTML|v-html=|\.innerHTML\s*=|\|\s*safe\b|\{\{\{|mark_safe\s*\(|html_safe"),
         ["Art. 32"], ["8.28"],
         "Nur mit Sanitizer (z. B. DOMPurify) einsetzen, CSP setzen."),

    # --- Logging / Datenabfluss ---
    Rule("LOG-001", "HIGH", "Personenbezogene/sensible Daten im Log",
         r(r"(console\.(log|info|warn|error|debug)|(log|logger|logging|_log|self\.log(ger)?)\.(info|debug|warn|warning|error|exception|trace)|print|System\.out\.println|fmt\.Print\w*|Log\.\w)\s*\(.{0,120}" + PII),
         ["Art. 5 Abs. 1 c", "Art. 32"], ["8.12", "8.15", "8.11"],
         "Sensible Felder entfernen oder maskieren; Log-Filter einsetzen."),
    Rule("LOG-002", "MEDIUM", "Debug-Modus aktiv",
         r(r"""\bDEBUG\s*[:=]\s*(True|true|1|['"]true['"])|app\.run\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True"""),
         ["Art. 32"], ["8.9", "8.12"],
         "Debug in Produktion deaktivieren, per Env steuern."),
    Rule("LOG-003", "HIGH", "Error-Tracking mit PII aktiviert",
         r(r"send_?default_?pii\s*[:=]\s*(True|true)|sendDefaultPii\s*:\s*true"),
         ["Art. 5 Abs. 1 c", "Art. 28"], ["8.12"],
         "PII-Übermittlung deaktivieren, beforeSend-Scrubbing nutzen."),
    Rule("URL-001", "MEDIUM", "Sensible Daten in URL/Query-String",
         r(r"""[?&](email|e-mail|password|passwort|token|api_?key|iban|phone|telefon)=(?!\s*['"]?\s*$)"""),
         ["Art. 5 Abs. 1 f", "Art. 32"], ["8.12"],
         "Im Request-Body oder Header übertragen."),

    # --- Tracking / TDDDG ---
    Rule("TRK-001", "HIGH", "Tracking-/Analytics-Dienst (Consent prüfen)",
         r(r"googletagmanager\.com|google-analytics\.com|gtag\(|\bfbq\(|connect\.facebook\.net|hotjar\.com|clarity\.ms|snap\.licdn\.com|analytics\.tiktok\.com|mixpanel|segment\.(com|io)|amplitude"),
         ["Art. 6", "Art. 7", "Art. 44"], ["5.34"],
         "Endgerätezugriff (§ 25 TDDDG), Rechtsgrundlage, Empfängerrolle und Transfers getrennt prüfen."),
    Rule("TRK-002", "MEDIUM", "Externe Ressource mit IP-Übermittlung (Fonts/CDN/Embeds)",
         r(r"fonts\.googleapis\.com|fonts\.gstatic\.com|youtube\.com/embed|maps\.googleapis\.com|google\.com/maps/embed|player\.vimeo\.com|use\.fontawesome\.com|kit\.fontawesome\.com"),
         ["Art. 6", "Art. 44"], ["5.34"],
         "Lokal hosten oder Rechtsgrundlage/Transfers prüfen; § 25 TDDDG nur bei Endgerätezugriff prüfen."),
    Rule("TRK-003", "LOW", "Client-Storage-Nutzung (Erforderlichkeit prüfen)",
         r(r"localStorage\.setItem|sessionStorage\.setItem|document\.cookie\s*=|indexedDB\.open"),
         ["Art. 6"], ["5.34"],
         "Einwilligung oder Ausnahme nach § 25 Abs. 2 TDDDG prüfen; Speicherung allein belegt keinen Verstoß."),

    # --- Sessions / Cookies ---
    Rule("SES-001", "MEDIUM", "Cookie ohne Secure/HttpOnly",
         r(r"(httpOnly|httponly|HttpOnly)\s*[:=]\s*(false|False)|(secure)\s*[:=]\s*(false|False)\b|SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False"),
         ["Art. 32"], ["8.5"],
         "Secure, HttpOnly und SameSite setzen."),
    Rule("SES-002", "HIGH", "JWT ohne Signaturprüfung / alg none",
         r(r"""verify_signature['"]?\s*:\s*False|algorithms\s*=\s*\[\s*['"]none['"]|jwt\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true"""),
         ["Art. 32"], ["8.5"],
         "Signatur und Ablauf immer prüfen, Algorithmus fest vorgeben."),

    # --- Infrastruktur / IaC ---
    Rule("IAC-001", "HIGH", "Öffentlich erreichbare Ressource",
         r(r"""publicly_accessible\s*=\s*true|acl\s*=\s*['"]public-read(-write)?['"]|cidr_blocks\s*=\s*\[\s*['"]0\.0\.0\.0/0['"]\s*\]|block_public_acls\s*=\s*false"""),
         ["Art. 32"], ["8.20", "8.22"],
         "Zugriff auf benötigte Netze beschränken."),
    Rule("IAC-002", "HIGH", "Verschlüsselung at rest deaktiviert",
         r(r"(storage_encrypted|encrypted|encryption_enabled|enable_encryption)\s*=\s*false"),
         ["Art. 32"], ["8.24"],
         "Verschlüsselung (KMS) aktivieren."),
    Rule("IAC-003", "MEDIUM", "Überprivilegierte IAM-Policy",
         r(r""""Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\]|"Resource"\s*:\s*"\*".{0,40}"Action"\s*:\s*"\*\""""),
         ["Art. 32"], ["5.15", "8.2"],
         "Least Privilege: Aktionen und Ressourcen einschränken."),
    Rule("IAC-004", "LOW", "Container läuft als root",
         r(r"^\s*USER\s+root\b", re.IGNORECASE | re.MULTILINE),
         ["Art. 32"], ["8.9"],
         "Unprivilegierten User verwenden."),
    Rule("IAC-005", "INFO", "Cloud-Region außerhalb EU (Drittland prüfen)",
         r(r"""['"](us|ap|sa|ca|me|af)-(east|west|south|north|central|northeast|southeast)-\d['"]|['"](us|asia|southamerica|northamerica|australia)-[a-z]+\d['"]"""),
         ["Art. 44"], ["5.23"],
         "EU/EWR, Empfänger und Fernzugriffe prüfen; Region allein belegt weder Transfer noch dessen Zulässigkeit."),

    # --- Datenschutz-Struktur ---
    Rule("PII-001", "INFO", "Besondere Kategorie (Art. 9) möglich",
         r(r"\b(diagnos\w*|health_?data|gesundheit\w*|medical|krankheit|religion|konfession|ethnic\w*|ethnie|sexual_?orientation|biometric\w*|fingerprint_?template|gewerkschaft|union_?member\w*|political_?opinion)\b"),
         ["Art. 9", "Art. 35"], ["5.12", "8.24"],
         "Gesondert schützen (Feldverschlüsselung, Zugriff), DSFA prüfen."),
    Rule("PII-002", "LOW", "Personenbezogene Daten in Test-/Seed-Daten",
         r(r"[\w.+-]+@(gmail|gmx|web|t-online|outlook|hotmail|yahoo|icloud)\.(com|de|net)"),
         ["Art. 5 Abs. 1 c"], ["8.33"],
         "Synthetische Daten (z. B. @example.com, Faker) verwenden."),
]

TEST_HINT = re.compile(r"(^|/)(tests?|spec|__tests__|fixtures?|seeds?|mocks?)(/|$)|\.(test|spec)\.", re.I)


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    file: str
    line: int
    snippet: str
    gdpr: list
    iso: list
    hint: str


@dataclass
class ScanIssue:
    file: str
    reason: str
    line: int | None = None


def iter_files(root: str, excludes: set, issues: list):
    def skip(path, reason):
        issues.append(ScanIssue(os.path.relpath(path, root), reason))

    if os.path.islink(root):
        skip(root, "symlink")
        return
    if os.path.isfile(root):
        yield root
        return
    for dp, dns, fns in os.walk(root, onerror=lambda exc: skip(exc.filename or root, "read_error")):
        for name in dns[:]:
            path = os.path.join(dp, name)
            if name in excludes:
                dns.remove(name)
            elif os.path.islink(path):
                dns.remove(name)
                skip(path, "symlink")
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext in CODE_EXT or fn in SPECIAL_FILES or fn.startswith(".env"):
                if fn.endswith((".min.js", ".lock")) or fn in {"package-lock.json"}:
                    continue
                yield os.path.join(dp, fn)


def scan_file(path: str, rel: str, issues: list) -> list:
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            issues.append(ScanIssue(rel, "symlink"))
            return []
        if not stat.S_ISREG(info.st_mode):
            issues.append(ScanIssue(rel, "not_regular"))
            return []
        if info.st_size > MAX_FILE_BYTES:
            issues.append(ScanIssue(rel, "size"))
            return []
        with open(path, "rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            issues.append(ScanIssue(rel, "size"))
            return []
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        issues.append(ScanIssue(rel, "encoding"))
        return []
    except OSError:
        issues.append(ScanIssue(rel, "read_error"))
        return []
    is_test = bool(TEST_HINT.search(rel.replace(os.sep, "/")))
    out = []
    for no, line in enumerate(lines, 1):
        if len(line) > 2000:
            issues.append(ScanIssue(rel, "line_length", no))
            continue
        for rule in RULES:
            if rule.id == "PII-002" and not is_test:
                continue
            if rule.pattern.search(line):
                sev = rule.severity
                if is_test and rule.id.startswith(("SEC-", "LOG-", "CRY-005")):
                    sev = SEVERITIES[max(0, SEVERITIES.index(sev) - 1)]
                # Keep the JSON field for consumers, but never copy source into reports.
                out.append(Finding(rule.id, sev, rule.title, rel, no, "",
                                   rule.gdpr, rule.iso, rule.hint))
    return out


def location(path: str) -> str:
    # Quote control characters and Markdown syntax in untrusted file names.
    return re.sub(r"([`*_{}\[\]()<>#!|~])", r"\\\1", json.dumps(path, ensure_ascii=True))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--format", choices=["md", "json", "text"], default="md")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="INFO")
    ap.add_argument("--exclude", nargs="*", default=[])
    ap.add_argument("--max-findings", type=int, default=500)
    a = ap.parse_args()
    if a.max_findings < 1:
        ap.error("--max-findings muss mindestens 1 sein")

    root = os.path.abspath(a.path)
    if not os.path.exists(root):
        print("Pfad nicht gefunden oder nicht zugänglich.", file=sys.stderr)
        return 2
    excludes = DEFAULT_EXCLUDES | set(a.exclude)
    base = root if os.path.isdir(root) else os.path.dirname(root)
    min_i = SEVERITIES.index(a.min_severity)

    findings, issues, nfiles, considered = [], [], 0, 0
    for f in iter_files(root, excludes, issues):
        considered += 1
        before = len(issues)
        findings += scan_file(f, os.path.relpath(f, base), issues)
        if all(x.reason == "line_length" for x in issues[before:]):
            nfiles += 1
    if not considered and not issues:
        issues.append(ScanIssue(".", "no_supported_files"))
    findings.sort(key=lambda x: (-SEVERITIES.index(x.severity), x.file, x.line))
    visible = [x for x in findings if SEVERITIES.index(x.severity) >= min_i]
    truncated = len(visible) > a.max_findings
    shown = visible[: a.max_findings]

    counts = {s: sum(1 for x in findings if x.severity == s) for s in reversed(SEVERITIES)}
    if a.format == "json":
        print(json.dumps({"files_scanned": nfiles, "files_considered": considered,
                          "complete": not issues, "skipped": [asdict(x) for x in issues],
                          "excluded_directories": sorted(excludes), "min_severity": a.min_severity,
                          "counts": counts, "truncated": truncated,
                          "findings": [asdict(x) for x in shown]}, ensure_ascii=False, indent=2))
    elif a.format == "text":
        for x in shown:
            print(f"{SEV_DE[x.severity]:8} {x.rule} {location(x.file)}:{x.line} {x.title}")
        print(f"Prüfung {'unvollständig' if issues else 'im unterstützten Umfang beendet'}; "
              f"{nfiles} Dateien gelesen. Keine Konformitätsaussage.")
    else:
        print(f"# Vorab-Scan DSGVO / ISO 27001\n\n{nfiles} Dateien gescannt. "
              "Treffer sind Hinweise und müssen im Kontext verifiziert werden.\n")
        print("| Schweregrad | Anzahl |\n|---|---|")
        for s, c in counts.items():
            print(f"| {SEV_DE[s]} | {c} |")
        print()
        for x in shown:
            print(f"- **[{SEV_DE[x.severity]}] {x.rule} – {x.title}** · {location(x.file)}:{x.line}  \n"
                  f"  DSGVO: {', '.join(x.gdpr)} · ISO 27001: {', '.join('A.' + i for i in x.iso)} · {x.hint}")
        if truncated:
            print(f"\n… {len(visible) - len(shown)} weitere Treffer abgeschnitten (--max-findings).")
        print("\nKein Nachweis rechtlicher Konformität; nur unterstützte Dateitypen und Regeln geprüft.")
    if a.format != "json":
        print("Ausgeschlossene Verzeichnisnamen: " + ", ".join(location(x) for x in sorted(excludes)))
        for item in issues:
            print(f"Nicht vollständig geprüft: {location(item.file)}"
                  f"{':' + str(item.line) if item.line else ''} ({item.reason})")
    if issues:
        return 2
    return 1 if counts["CRITICAL"] or counts["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
