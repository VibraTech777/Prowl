# 🦁 Prowl

> Methodical OSINT reconnaissance for pentesters. Point it at a domain, walk away with intelligence.

Prowl is an open-source CLI that automates company reconnaissance: DNS records, certificates, WHOIS, GitHub org members, employee emails, French corporate registries, web crawl, and more — all from a single command. Built for stability and precision over speed, with verbose output so you always know what it found and why.

---

## ⚡ Install

**Requires Python 3.11+ and [pipx](https://pipx.pypa.io).**

```bash
pipx install git+https://github.com/VibraTech777/Prowl.git
```

Copy `.env.example` to `.env` and fill in your API keys (all optional — sources without a key are skipped automatically), or export the same variables in your shell:

```bash
cp .env.example .env
```

---

## 🚀 Quick Start

```bash
# Basic recon on any domain
prowl -d acme.com

# French company — adds BODACC, Annuaire Entreprises, Pappers
prowl -d acme.fr --french --siren 123456789

# Discover employees and pivot to their public profiles
prowl -d acme.com --pivot 1

# Full run: French company + pivot + PDF report
prowl -d acme.fr --french --siren 123456789 --company "Acme SAS" --pivot 1 --output report.pdf
```

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-d, --domain` | Target domain (required) |
| `-c, --company` | Company name — used in report header, GitHub org search, OpenCorporates |
| `-s, --siren` | French SIREN number — required for `--french` collectors |
| `-F, --french` | Enable French collectors: BODACC, Annuaire Entreprises, Pappers |
| `--pivot N` | Pivot on discovered persons (`0` = disabled, the default; `1` = one level). Sources: GitHub, EmailFormat, GitLeak, WhatsMyName |
| `--pivot-limit N` | Max persons to pivot on per level (default: 25) |
| `--depth N` | Web crawler depth (default: 1). No effect with `--no-crawl` |
| `--crawl / --no-crawl` | Web crawler, on by default. `--no-crawl` disables it and keeps the scan passive |
| `-m, --mode` | `short` (default) or `deep`. Collector tier filter — currently all collectors are Tier 1, so both behave the same |
| `-o, --output FILE` | Save report as `.json` or `.pdf` |
| `-V, --version` | Print version and exit |

---

## 🔑 API Keys

Set these as environment variables, or in a `.env` file in the directory you run `prowl` from (see `.env.example`):

| Key | Source | Notes |
|---|---|---|
| `GITHUB_TOKEN` | [github.com/settings/tokens](https://github.com/settings/tokens) | Strongly recommended. Raises rate limit from 60 to 5 000 req/h. Fine-grained token, no scopes needed. |
| `HUNTER_API_KEY` | [hunter.io](https://hunter.io) | Phase-1 employee email search. Free tier available. |
| `PAPPERS_API_KEY` | [pappers.fr](https://www.pappers.fr) | French company data. Required with `--french --siren`. |
| `OPENCORPORATES_API_TOKEN` | [opencorporates.com](https://opencorporates.com) | Required — unauthenticated calls are refused. |

---

## 📡 Collectors

Phase 1 collectors run concurrently and display results as they arrive. The person pivot (phase 2) runs one person at a time, rate-limited.

**Phase 1 — Domain intel**
DNS, WHOIS, crt.sh (certificates), DNSDumpster, GitHub Org⁵, OpenCorporates⁴, BODACC¹, Annuaire Entreprises¹, Pappers¹², Hunter.io³, Web Crawler

**Phase 2 — Person pivot (requires `--pivot`)**
GitHub Person, Email Format, GitLeak, WhatsMyName

¹ Requires `--french --siren`
² Requires `PAPPERS_API_KEY`
³ Requires `HUNTER_API_KEY`
⁴ Requires `OPENCORPORATES_API_TOKEN`
⁵ Runs only with `--pivot`

Prowl always respects `robots.txt`. No `--ignore-robots` flag exists by design.

> **Authorised use only.** The web crawler (on by default) and `--pivot` send real requests — to the target, and, for the pivot, to third-party sites. Use `--no-crawl` for passive collection, and only scan systems and people you have explicit permission to test.

---

## 📄 License

GNU General Public License v3.0 — free to use, modify, and distribute. Derivative works must remain GPL-3.0. See [LICENSE](LICENSE).

© 2026 Cyril Tzaraeff

---

## 👤 Author

Built by Cyril Tzaraeff — OSINT & AI security tooling.
[LinkedIn](https://www.linkedin.com/in/cyril-tzaraeff-513a61343/)
