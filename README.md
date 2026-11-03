<div align="center">

<img width="633" src="https://user-images.githubusercontent.com/104733166/185790639-b1f09747-aea3-4f64-a52f-d70efd820a22.png" alt="WebOSINT banner">

# WebOSINT

**Passive domain intelligence from your terminal: one command, ten sources, a few seconds.**

<img src="https://img.shields.io/badge/version-3.0-purple?style=flat-square"/>
<img src="https://img.shields.io/badge/python-3.8%2B-purple?style=flat-square&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/recon-passive-purple?style=flat-square"/>
<img src="https://img.shields.io/badge/docker-ready-purple?style=flat-square&logo=docker&logoColor=white"/>
<a href="https://github.com/C3n7ral051nt4g3ncy/webosint/blob/master/LICENSE"><img src="https://img.shields.io/badge/licence-MIT-purple?style=flat-square"/></a>

<a href="https://github.com/C3n7ral051nt4g3ncy"><img alt="GitHub" src="https://img.shields.io/badge/GitHub-C3n7ral051nt4g3ncy-purple?style=for-the-badge&logo=github&logoColor=white"/></a>
<a href="https://ko-fi.com/tacticalintelanalyst"><img alt="Ko-fi" src="https://img.shields.io/badge/Ko--fi-support-purple?style=for-the-badge&logo=ko-fi&logoColor=white"/></a>
<a href="https://user-images.githubusercontent.com/104733166/171052611-1f76b07c-832f-4a4a-9a0a-2f94595c28c9.png"><img alt="BTC" src="https://img.shields.io/badge/Bitcoin-donate-purple?style=for-the-badge&logo=bitcoin&logoColor=white"/></a>

[Quick start](#-quick-start) · [Usage](#-usage) · [Modules](#-modules) · [API keys](#-api-keys) · [Docker](#-docker) · [Troubleshooting](#-troubleshooting) · [Changelog](#-whats-new-in-v30)

</div>

---

## 🌐 What is WebOSINT?

WebOSINT is a Python tool for **passive reconnaissance on a domain**. Give it a domain (or a URL) and it collects registration, hosting, DNS, certificate, subdomain, reputation, WHOIS history and credential exposure data from public sources. It never touches the target's own servers beyond normal DNS resolution.

- ⚡ **Fast.** All modules run in parallel, so a full scan takes seconds.
- 🧭 **Simple.** Run it with no arguments for a guided menu, or script it from the command line.
- 🔑 **No key required to start.** Seven of the ten modules are free. Modules whose key is missing are skipped, not fatal.
- 📄 **Report-ready.** Export to **JSON** for your pipeline or **Markdown** for your case notes.
- 📚 **Batch mode.** Feed it a list of domains.

---

## 🚀 Quick start

```bash
git clone https://github.com/C3n7ral051nt4g3ncy/webosint
cd webosint
python3 -m venv .venv && source .venv/bin/activate   # recommended
pip install -r requirements.txt

python3 webosint.py example.com
```

> [!TIP]
> Run `python3 webosint.py` without arguments for **interactive mode**: type a domain, then press Enter to run every module, or type the numbers of the ones you want (`2,4,7`).

---

## 🛠️ Usage

```bash
python3 webosint.py example.com                          # every module
python3 webosint.py https://www.example.com/page         # URLs are cleaned automatically
python3 webosint.py example.com -m dns,whois,subdomains  # only these (names or numbers: -m 4,5,7)
python3 webosint.py example.com -x reverse_ip,history    # everything except these
python3 webosint.py example.com -o result.json --md report.md
python3 webosint.py -f domains.txt -o results.json       # batch, one domain per line
python3 webosint.py --list                               # show modules
```

Pipe the results into other tools with `--json`:

```bash
python3 webosint.py example.com -m subdomains --json | jq -r '.modules.subdomains.data.subdomains[]'
```

<details>
<summary><b>All options</b></summary>

| Option | Description |
|---|---|
| `domains` | One or more domains or URLs |
| `-f`, `--file` | Read domains from a file (one per line, `#` for comments) |
| `-m`, `--modules` | Modules to run: comma list of names or numbers |
| `-x`, `--exclude` | Modules to skip |
| `-o`, `--output` | Save results as JSON |
| `--md` | Save results as a Markdown report |
| `--json` | Print raw JSON to stdout (no banner, no colours) |
| `--full` | Don't truncate long lists (reverse IP, subdomains) in the terminal |
| `-t`, `--timeout` | Per-request timeout in seconds (default `20`) |
| `-w`, `--workers` | Number of parallel workers (default `10`) |
| `--config` | Path to an alternative `config.json` |
| `--no-banner`, `--no-color` | Quieter output (`NO_COLOR` is also respected) |
| `-v`, `--version` | Show version |

</details>

<details>
<summary><b>Example output</b></summary>

```text
▶ Target: example.com  (10 modules in parallel)
  ✔ Domain Registration              0.6s
  ✔ DNS Records                      0.3s
  ✔ IP Address & Geolocation         0.9s
  ✔ Reverse IP (shared hosting)      1.2s
  ✔ WHOIS                            0.6s
  ✔ Credential Exposure              2.1s
  ✔ SSL Certificates                 6.4s
  ✔ Subdomains                       6.4s
  – Domain Reputation                0.0s
  – WHOIS History                    0.0s

■ Subdomains
    37 unique name(s) — crt.sh (Certificate Transparency)
    api.example.com
    mail.example.com
    ...

■ Domain Reputation
    skipped: no WhoisXML API key (config.json or $WEBOSINT_WHOISXML_KEY)
```
✔ = worked · – = skipped (missing key) · ✘ = failed (reason shown in the report)

</details>

---

## 🧩 Modules

| # | Module | What it reveals for the investigation | Source | Key |
|:-:|---|---|---|:-:|
| 1 | `registration` | Whether the domain is registered (available, parked, or recently dropped domains) | WHOIS | — |
| 2 | `ip` | IPv4/IPv6, hosting provider, ASN, geolocation, cross-checked by two services | DNS · ipinfo.io · ipapi.co | — |
| 3 | `reverse_ip` | Other domains on the same IP: shared hosting, sister sites, related infrastructure | HackerTarget | optional |
| 4 | `dns` | A, AAAA, CNAME, MX (mail provider), NS, TXT (SPF, site verifications for Google/Microsoft/etc.), SOA, CAA, DMARC | local resolver (dnspython) | — |
| 5 | `whois` | Registrar, creation/expiry/update dates, name servers, contact details when not redacted | WHOIS | — |
| 6 | `certs` | Number of certificates, first-seen date (a good proxy for when the site went live), issuers, latest certs | crt.sh | — |
| 7 | `subdomains` | Every hostname that has appeared in a certificate: dev/staging hosts, VPNs, admin panels, forgotten services | crt.sh | — |
| 8 | `reputation` | Reputation score plus failed security tests (malware, SSL, mail config) | WhoisXML | required |
| 9 | `history` | Past registrars and registrant details over time, often revealing the owner before privacy protection was turned on | WhoisFreaks | required |
| 10 | `exposure` | Infostealer and data-breach exposure linked to the domain (employee vs client events, first/last seen) | [Lunar Domain Exposure API](https://docs.webz.io/docs/webz/domain-exposure-api) | — |

> [!NOTE]
> crt.sh is fetched **once** and shared between `certs` and `subdomains`, with automatic retries. It is a free community service and is often overloaded; if it fails, run `-m certs,subdomains` again a minute later.

---

## 🔑 API keys

Keys are **optional**. Put them in `config.json` **or** export them as environment variables, which is handy for Docker or CI and keeps keys out of git.

```json
{
  "WHOIS_XML_API_KEY": "your-key",
  "HACKERTARGET_API_KEY": "your-key",
  "WHOIS_FREAKS_API_KEY": "your-key"
}
```

| Service | Free tier | `config.json` | Environment variable | Unlocks |
|---|---|---|---|---|
| [WhoisXML](https://whois.whoisxmlapi.com) | 500 requests | `WHOIS_XML_API_KEY` | `WEBOSINT_WHOISXML_KEY` | `reputation` |
| [WhoisFreaks](https://whoisfreaks.com) | 100 requests | `WHOIS_FREAKS_API_KEY` | `WEBOSINT_WHOISFREAKS_KEY` | `history` |
| [HackerTarget](https://hackertarget.com/scan-membership/) | a few lookups/day | `HACKERTARGET_API_KEY` | `WEBOSINT_HACKERTARGET_KEY` | unlimited `reverse_ip` |

```bash
WEBOSINT_WHOISXML_KEY=xxxx WEBOSINT_WHOISFREAKS_KEY=yyyy python3 webosint.py example.com
```

> [!WARNING]
> Never commit a `config.json` that contains your real keys. Run `git diff config.json` before pushing, or use the environment variables.

---

## 🐳 Docker

```bash
docker build -t webosint .
docker run --rm -it webosint example.com
docker run --rm -it -e WEBOSINT_WHOISXML_KEY=xxxx webosint example.com -m reputation
docker run --rm -v "$PWD:/out" webosint example.com -o /out/result.json
```

---

## 🩺 Troubleshooting

<details>
<summary><b>Registered domains show as "not registered", or WHOIS is skipped</b></summary>

You probably have both the `whois` and `python-whois` packages installed, and they conflict. WebOSINT detects this and tells you. Fix it with a clean install, ideally in a virtualenv:

```bash
pip3 uninstall -y whois python-whois
pip3 install python-whois
```
</details>

<details>
<summary><b>Certificates / Subdomains fail with a network or non-JSON error</b></summary>

crt.sh is overloaded. Wait a minute and run `python3 webosint.py example.com -m certs,subdomains`. You can also raise the timeout with `-t 60`.
</details>

<details>
<summary><b>Reverse IP says "API count exceeded"</b></summary>

You've used up HackerTarget's free daily lookups. Wait, change IP, or add a HackerTarget key.
</details>

<details>
<summary><b>Long lists are cut off in the terminal</b></summary>

Use `--full`, or export with `-o result.json` / `--md report.md`. Exports always contain the complete lists.
</details>

---

## ✨ What's new in v3.0

- ⚡ **Parallel engine.** All modules run at the same time, with no more forced pauses or y/n prompts between modules.
- 🖥️ **Real CLI.** Module selection (`-m` / `-x`), batch mode (`-f`), JSON/Markdown export, `--json` for piping.
- 🧭 **Interactive menu** when run without arguments.
- 🔑 **Keys from config.json or environment variables.** Missing keys skip a module instead of breaking the run.
- 🧬 **DNS via the local resolver** (dnspython): faster, no rate limit, adds CAA and DMARC.
- 🕵️ **New `exposure` module** using the free Lunar Domain Exposure API ([#5](https://github.com/C3n7ral051nt4g3ncy/WebOSINT/issues/5)).
- 🧹 **Cleaner results.** De-duplicated subdomains (no wildcards or multi-line entries), readable certificate and WHOIS history summaries.
- 🐞 **Fixes.** "Wrong key" exits on valid answers, WHOIS crash, ipinfo crash on missing fields, duplicate crt.sh/WHOIS requests, automatic retries on 429/5xx.
- 🐳 **Docker** now takes arguments: `docker run --rm -it webosint example.com`.

---

## 🤝 Contributing

Ideas, bug reports and PRs are welcome. Open an [issue](https://github.com/C3n7ral051nt4g3ncy/WebOSINT/issues) or start a thread in the [discussions](https://github.com/C3n7ral051nt4g3ncy/webosint/discussions).

Adding a module is simple. Write a function `mod_xxx(ctx)` that returns a dict, then register it in the `MODULES` list in `webosint.py`. The shared `ctx` gives you an HTTP session with retries, plus cached WHOIS, IP and crt.sh lookups.

---

## ⚠️ Disclaimer

This tool is for the OSINT and cyber community. Don't use it for wrong, immoral, or illegal purposes. Respect the terms of service of the APIs it relies on.

---

## 🙏 Credits

- [Hacker Target](https://hackertarget.com), [WhoisXML](https://main.whoisxmlapi.com), [WhoisFreaks](https://whoisfreaks.com), [crt.sh](https://crt.sh), [ipinfo.io](https://ipinfo.io), [ipapi.co](https://ipapi.co) and [Lunar / Webz.io](https://docs.webz.io/docs/webz/domain-exposure-api) for their APIs and free tiers
- [@cipher387](https://github.com/cipher387) / [@cyb_detective](https://twitter.com/cyb_detective) and [Euler Neto](https://github.com/netoeuler) for testing the first release
- [@scorpix06](https://github.com/scorpix06) for the original Docker support

<br>

<div align="center">

### 💜 Support

If WebOSINT saves you time, consider supporting the work via **[Ko-fi](https://ko-fi.com/tacticalintelanalyst)** or **[Bitcoin](https://user-images.githubusercontent.com/104733166/171052611-1f76b07c-832f-4a4a-9a0a-2f94595c28c9.png)**.

<img width="233" src="https://user-images.githubusercontent.com/104733166/178512035-bb81cafc-f785-4426-9268-6634d3c2152d.png">

Made by **[@C3n7ral051nt4g3ncy](https://github.com/C3n7ral051nt4g3ncy)** · [@OSINT_Tactical](https://x.com/OSINT_Tactical) · Licensed under [MIT](LICENSE)

</div>
