#!/usr/bin/env python3
# File name   : webosint.py
# Tool name   : W3b0s1nt (WebOSINT)
# Author      : @C3n7ral051nt4g3ncy
# Version     : 3.0
# Licence     : MIT
# Script Info : WebOSINT is a passive Domain Intelligence recon tool.
#               All modules run in parallel; results can be exported to JSON / Markdown.

"""
Usage examples
--------------
  python3 webosint.py                         # interactive mode (asks for a domain + modules)
  python3 webosint.py example.com             # run every module
  python3 webosint.py example.com -m dns,whois,subdomains
  python3 webosint.py example.com -x reverse_ip,history
  python3 webosint.py -f domains.txt -o results.json --md report.md
  python3 webosint.py --list                  # show available modules
"""

import argparse
import concurrent.futures as cf
import json
import os
import re
import socket
import sys
import threading
import time
from datetime import date, datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import whois  # python-whois
    if not hasattr(whois, "whois"):
        raise ImportError("wrong 'whois' package")
except ImportError:
    whois = None

try:
    import dns.resolver  # dnspython
except ImportError:
    dns = None

VERSION = "3.0"
USER_AGENT = f"WebOSINT/{VERSION} (+https://github.com/C3n7ral051nt4g3ncy/WebOSINT)"
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# --------------------------------------------------------------------------- #
# Terminal colours
# --------------------------------------------------------------------------- #
class C:
    P = "\033[0;35m"   # purple
    G = "\033[0;32m"   # green
    R = "\033[0;31m"   # red
    Y = "\033[0;33m"   # yellow
    D = "\033[2m"      # dim
    B = "\033[1m"      # bold
    X = "\033[0m"      # reset

    @classmethod
    def disable(cls):
        for k in ("P", "G", "R", "Y", "D", "B", "X"):
            setattr(cls, k, "")


BANNER = r"""{P}
  ██╗    ██╗██████╗ ██████╗  ██████╗ ███████╗ ██╗███╗   ██╗████████╗
  ██║    ██║╚════██╗██╔══██╗██╔═████╗██╔════╝███║████╗  ██║╚══██╔══╝
  ██║ █╗ ██║ █████╔╝██████╔╝██║██╔██║███████╗╚██║██╔██╗ ██║   ██║
  ██║███╗██║ ╚═══██╗██╔══██╗████╔╝██║╚════██║ ██║██║╚██╗██║   ██║
  ╚███╔███╔╝██████╔╝██████╔╝╚██████╔╝███████║ ██║██║ ╚████║   ██║
   ╚══╝╚══╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝{X}
  {G}W3b0s1nt v{V} · Passive Domain Intelligence · by @C3n7ral051nt4g3ncy{X}
"""


# --------------------------------------------------------------------------- #
# Config / API keys  (config.json OR environment variables)
# --------------------------------------------------------------------------- #
KEY_ENV = {
    "WHOIS_XML_API_KEY": "WEBOSINT_WHOISXML_KEY",
    "HACKERTARGET_API_KEY": "WEBOSINT_HACKERTARGET_KEY",
    "WHOIS_FREAKS_API_KEY": "WEBOSINT_WHOISFREAKS_KEY",
}


def load_keys(path=CONFIG_FILE):
    cfg = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"{C.Y}[!] Could not read {path}: {exc}{C.X}", file=sys.stderr)
    keys = {}
    for name, env in KEY_ENV.items():
        val = (os.environ.get(env) or cfg.get(name) or "").strip()
        # ignore the placeholder text shipped in config.json
        if val.lower().startswith("paste"):
            val = ""
        keys[name] = val
    return keys


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def normalise_domain(raw):
    """'https://www.Example.com/path?x' -> 'www.example.com'"""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split("@")[-1].split(":")[0]
    return d.strip(".")


def is_valid_domain(d):
    return bool(re.fullmatch(r"(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", d))


def to_jsonable(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(o) for o in obj]
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    return obj


def uniq(seq):
    """Deduplicate (case-insensitive for strings) while keeping order; flatten one level."""
    out, seen = [], set()
    if seq is None:
        return out
    if isinstance(seq, (str, bytes)) or not hasattr(seq, "__iter__"):
        seq = [seq]
    for item in seq:
        key = item.lower() if isinstance(item, str) else item
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


class SkipModule(Exception):
    """Raised when a module cannot run (missing key, missing library...)."""


# --------------------------------------------------------------------------- #
# Shared context: one HTTP session + cached lookups shared between modules
# --------------------------------------------------------------------------- #
class Context:
    def __init__(self, domain, keys, timeout):
        self.domain = domain
        self.keys = keys
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        retry = Retry(total=3, backoff_factor=1.5, status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=("GET",), respect_retry_after_header=True)
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=20)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self._cache, self._locks, self._glock = {}, {}, threading.Lock()

    def cached(self, key, fn):
        """Run fn() once per key even if several threads ask at the same time."""
        with self._glock:
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:
            if key not in self._cache:
                try:
                    self._cache[key] = (True, fn())
                except Exception as exc:  # cache failures too, so we don't retry N times
                    self._cache[key] = (False, exc)
            ok, val = self._cache[key]
        if not ok:
            raise val
        return val

    def get(self, url, timeout=None, **kw):
        r = self.session.get(url, timeout=timeout or self.timeout, **kw)
        r.raise_for_status()
        return r

    # ---- shared lookups ------------------------------------------------- #
    def whois(self):
        if whois is None:
            raise SkipModule("python-whois not installed (pip install python-whois) "
                             "or conflicting 'whois' package installed")
        return self.cached("whois", lambda: whois.whois(self.domain))

    def ips(self):
        def resolve():
            v4, v6 = [], []
            for fam, _, _, _, addr in socket.getaddrinfo(self.domain, None):
                (v4 if fam == socket.AF_INET else v6).append(addr[0])
            return {"ipv4": uniq(v4), "ipv6": uniq(v6)}
        return self.cached("ips", resolve)

    def crtsh(self):
        def fetch():
            r = self.get("https://crt.sh/", params={"q": f"%.{self.domain}", "output": "json"},
                         timeout=max(self.timeout, 60))
            try:
                return r.json()
            except ValueError:
                raise RuntimeError("crt.sh returned a non-JSON answer (service overloaded, retry later)")
        return self.cached("crtsh", fetch)


# --------------------------------------------------------------------------- #
# Modules — each returns a JSON-serialisable dict
# --------------------------------------------------------------------------- #
def mod_registration(ctx):
    try:
        w = ctx.whois()
        registered = bool(w.domain_name)
    except SkipModule:
        raise
    except Exception:
        registered = False
    return {"registered": registered}


def mod_ip(ctx):
    try:
        ips = ctx.ips()
    except socket.gaierror:
        return {"error": "Domain does not resolve (no A/AAAA record)"}
    out = dict(ips)
    out["geo"] = {}
    for ip in ips["ipv4"][:3]:
        try:
            d = ctx.get(f"https://ipinfo.io/{ip}/json").json()
            out["geo"][ip] = {k: d.get(k) for k in
                              ("hostname", "org", "city", "region", "country", "loc", "postal", "timezone")
                              if d.get(k)}
        except Exception as exc:
            out["geo"][ip] = {"error": str(exc)}
        try:  # second source (double verification, kept from v2)
            d = ctx.get(f"https://ipapi.co/{ip}/json/").json()
            if not d.get("error"):
                out["geo"][ip]["asn"] = d.get("asn")
                out["geo"][ip]["asn_org"] = d.get("org")
        except Exception:
            pass
    return out


def mod_reverse_ip(ctx):
    try:
        ips = ctx.ips()["ipv4"]
    except socket.gaierror:
        raise SkipModule("domain does not resolve")
    if not ips:
        raise SkipModule("no IPv4 address")
    params = {"q": ips[0]}
    if ctx.keys["HACKERTARGET_API_KEY"]:
        params["apikey"] = ctx.keys["HACKERTARGET_API_KEY"]
    text = ctx.get("https://api.hackertarget.com/reverseiplookup/", params=params).text.strip()
    if text.lower().startswith(("api count exceeded", "error")):
        return {"ip": ips[0], "error": text}
    domains = [l.strip() for l in text.splitlines() if l.strip()]
    return {"ip": ips[0], "count": len(domains), "domains": domains,
            "source": "HackerTarget (API key)" if "apikey" in params else "HackerTarget (free tier)"}


DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


def mod_dns(ctx):
    if dns is not None:  # local resolver: fast and no rate limit
        res = dns.resolver.Resolver()
        res.lifetime = ctx.timeout
        records = {}

        def q(rtype):
            try:
                return rtype, sorted(r.to_text() for r in res.resolve(ctx.domain, rtype))
            except Exception:
                return rtype, []

        with cf.ThreadPoolExecutor(len(DNS_TYPES)) as ex:
            for rtype, vals in ex.map(q, DNS_TYPES):
                if vals:
                    records[rtype] = vals
        # DMARC lives on a sub-label
        try:
            records["DMARC"] = [r.to_text() for r in res.resolve(f"_dmarc.{ctx.domain}", "TXT")]
        except Exception:
            pass
        return {"source": "dnspython (local resolver)", "records": records}

    # fallback: HackerTarget
    params = {"q": ctx.domain}
    if ctx.keys["HACKERTARGET_API_KEY"]:
        params["apikey"] = ctx.keys["HACKERTARGET_API_KEY"]
    text = ctx.get("https://api.hackertarget.com/dnslookup/", params=params).text.strip()
    records = {}
    for line in text.splitlines():
        if " : " in line:
            t, v = line.split(" : ", 1)
            records.setdefault(t.strip(), []).append(v.strip())
    return {"source": "HackerTarget", "records": records or {"raw": [text]}}


WHOIS_FIELDS = ("domain_name", "registrar", "whois_server", "creation_date", "expiration_date",
                "updated_date", "name_servers", "status", "emails", "dnssec", "name", "org",
                "address", "city", "state", "zipcode", "country")


def mod_whois(ctx):
    w = ctx.whois()
    out = {}
    for f in WHOIS_FIELDS:
        v = w.get(f) if hasattr(w, "get") else getattr(w, f, None)
        if isinstance(v, (list, tuple)):
            v = uniq(v)
            v = v[0] if len(v) == 1 else v
        if v:
            out[f] = to_jsonable(v)
    if not out:
        return {"error": "No WHOIS data returned"}
    return out


def mod_certs(ctx):
    rows = ctx.crtsh()
    certs = {}
    for c in rows:
        certs.setdefault(c.get("id"), c)  # crt.sh returns one row per name
    certs = sorted(certs.values(), key=lambda c: c.get("entry_timestamp") or "", reverse=True)
    issuers = {}
    for c in certs:
        m = re.search(r"O=(\"[^\"]+\"|[^,]+)", c.get("issuer_name", ""))
        issuer = m.group(1).strip('"') if m else c.get("issuer_name", "?")
        issuers[issuer] = issuers.get(issuer, 0) + 1
    latest = [{
        "id": c.get("id"),
        "logged_at": c.get("entry_timestamp"),
        "not_before": c.get("not_before"),
        "not_after": c.get("not_after"),
        "names": uniq(c.get("name_value", "").split("\n")),
        "issuer": c.get("issuer_name"),
        "url": f"https://crt.sh/?id={c.get('id')}",
    } for c in certs[:10]]
    return {"total": len(certs),
            "first_seen": certs[-1].get("not_before") if certs else None,
            "issuers": dict(sorted(issuers.items(), key=lambda kv: -kv[1])),
            "latest": latest}


def mod_subdomains(ctx):
    names = set()
    for c in ctx.crtsh():
        for n in (c.get("name_value", "") + "\n" + c.get("common_name", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n and "@" not in n and (n == ctx.domain or n.endswith("." + ctx.domain)):
                names.add(n)
    subs = sorted(names)
    return {"count": len(subs), "subdomains": subs, "source": "crt.sh (Certificate Transparency)"}


def mod_reputation(ctx):
    key = ctx.keys["WHOIS_XML_API_KEY"]
    if not key:
        raise SkipModule("no WhoisXML API key (config.json or $WEBOSINT_WHOISXML_KEY)")
    d = ctx.get("https://domain-reputation.whoisxmlapi.com/api/v2",
                params={"apiKey": key, "domainName": ctx.domain}).json()
    out = {"reputation_score": d.get("reputationScore"), "mode": d.get("mode")}
    warnings = [{"test": t.get("test"), "warnings": [w.get("warningDescription") for w in t.get("warnings", [])]}
                for t in d.get("testResults", []) if t.get("warnings")]
    if warnings:
        out["warnings"] = warnings
    if "messages" in d or "ErrorMessage" in d:
        out["error"] = d.get("messages") or d.get("ErrorMessage")
    return out


def mod_history(ctx):
    key = ctx.keys["WHOIS_FREAKS_API_KEY"]
    if not key:
        raise SkipModule("no WhoisFreaks API key (config.json or $WEBOSINT_WHOISFREAKS_KEY)")
    d = ctx.get("https://api.whoisfreaks.com/v1.0/whois",
                params={"apiKey": key, "whois": "historical", "domainName": ctx.domain}).json()
    records = d.get("whois_domains_historical") or []
    hist = []
    for r in records:
        reg = r.get("registrant_contact") or {}
        hist.append({k: v for k, v in {
            "query_time": r.get("query_time"),
            "registrar": (r.get("domain_registrar") or {}).get("registrar_name"),
            "created": r.get("create_date"),
            "expires": r.get("expiry_date"),
            "registrant_name": reg.get("name"),
            "registrant_org": reg.get("company"),
            "registrant_email": reg.get("email_address"),
            "registrant_country": reg.get("country_name"),
            "name_servers": r.get("name_servers"),
        }.items() if v})
    return {"total_records": d.get("total_records", len(hist)), "records": hist}


def mod_exposure(ctx):
    """Lunar Domain Exposure API (free, no key) — infostealer / breach exposure (issue #5)."""
    d = ctx.get("https://api.lunarcyber.com/domain-exposure", params={"domain": ctx.domain},
                timeout=max(ctx.timeout, 30)).json()
    data = d.get("data", d) if isinstance(d, dict) else {}
    report = data.get("report") or {}
    period = report.get("period") or {"from": data.get("periodFrom"), "to": data.get("periodTo")}
    out = {"status": data.get("status"),
           "period": {k: v for k, v in period.items() if v},
           "summary": report.get("summary") or {}}
    # keep any extra breakdowns (malware families, services...) as they come
    for k, v in report.items():
        if k not in ("domain", "generated_at", "period", "summary") and v:
            out[k] = v
    out["source"] = "Lunar Domain Exposure API (lunarcyber.com)"
    return out


# key, title, function, short description
MODULES = [
    ("registration", "Domain Registration", mod_registration, "Is the domain registered?"),
    ("ip",           "IP Address & Geolocation", mod_ip, "A/AAAA + ipinfo.io / ipapi.co data"),
    ("reverse_ip",   "Reverse IP (shared hosting)", mod_reverse_ip, "Other domains on the same IP (HackerTarget)"),
    ("dns",          "DNS Records", mod_dns, "A, AAAA, MX, NS, TXT, SOA, CAA, DMARC"),
    ("whois",        "WHOIS", mod_whois, "Registrar, dates, contacts"),
    ("certs",        "SSL Certificates", mod_certs, "Certificate Transparency (crt.sh)"),
    ("subdomains",   "Subdomains", mod_subdomains, "Subdomains seen in CT logs (crt.sh)"),
    ("reputation",   "Domain Reputation", mod_reputation, "WhoisXML reputation  [API key]"),
    ("history",      "WHOIS History", mod_history, "Historical WHOIS, WhoisFreaks  [API key]"),
    ("exposure",     "Credential Exposure", mod_exposure, "Infostealer/breach exposure (Lunar, free)"),
]
MOD_INDEX = {m[0]: m for m in MODULES}


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
def run_domain(domain, selected, keys, timeout, workers, quiet=False):
    ctx = Context(domain, keys, timeout)
    results = {}
    t0 = time.time()

    def run(key):
        start = time.time()
        try:
            res = {"status": "ok", "data": MOD_INDEX[key][2](ctx)}
            if isinstance(res["data"], dict) and res["data"].get("error") and len(res["data"]) <= 2:
                res["status"] = "error"
        except SkipModule as exc:
            res = {"status": "skipped", "reason": str(exc)}
        except requests.RequestException as exc:
            res = {"status": "error", "reason": f"network: {exc.__class__.__name__}: {exc}"}
        except Exception as exc:
            res = {"status": "error", "reason": f"{exc.__class__.__name__}: {exc}"}
        res["elapsed"] = round(time.time() - start, 2)
        return key, res

    if not quiet:
        print(f"\n{C.P}{C.B}▶ Target: {domain}{C.X}  {C.D}({len(selected)} modules in parallel){C.X}",
              file=sys.stderr)
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(run, k) for k in selected]
        for f in cf.as_completed(futs):
            key, res = f.result()
            results[key] = res
            if not quiet:
                icon = {"ok": f"{C.G}✔", "skipped": f"{C.Y}–", "error": f"{C.R}✘"}[res["status"]]
                print(f"  {icon} {MOD_INDEX[key][1]:<30}{C.X}{C.D}{res['elapsed']:>6.1f}s{C.X}", file=sys.stderr)

    ordered = {k: results[k] for k in selected}
    return {"domain": domain, "generated_at": datetime.now().isoformat(timespec="seconds"),
            "elapsed": round(time.time() - t0, 2), "modules": ordered}


# --------------------------------------------------------------------------- #
# Pretty terminal output
# --------------------------------------------------------------------------- #
def _fmt(v):
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v)


def print_kv(d, indent=4):
    pad = " " * indent
    for k, v in d.items():
        if v in (None, "", [], {}):
            continue
        if isinstance(v, dict):
            print(f"{pad}{C.B}{k}{C.X}")
            print_kv(v, indent + 2)
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            print(f"{pad}{C.B}{k}{C.X}")
            for item in v:
                print_kv(item, indent + 4)
                print()
        else:
            print(f"{pad}{C.D}{k.replace('_', ' '):<20}{C.X} {C.G}{_fmt(v)}{C.X}")


def print_list(items, limit, indent=4):
    for it in items[:limit]:
        print(f"{' ' * indent}{C.G}{it}{C.X}")
    if len(items) > limit:
        print(f"{' ' * indent}{C.D}... {len(items) - limit} more (use -o/--md to export the full list, or --full){C.X}")


def print_report(report, full=False):
    limit = 10 ** 9 if full else 40
    print(f"\n{C.P}{C.B}{'═' * 70}\n  {report['domain']}   {C.X}{C.D}{report['generated_at']} · "
          f"{report['elapsed']}s{C.X}\n{C.P}{C.B}{'═' * 70}{C.X}")
    for key, res in report["modules"].items():
        title = MOD_INDEX[key][1]
        print(f"\n{C.P}{C.B}■ {title}{C.X}")
        if res["status"] == "skipped":
            print(f"    {C.Y}skipped: {res['reason']}{C.X}")
            continue
        if res["status"] == "error" and "reason" in res:
            print(f"    {C.R}error: {res['reason']}{C.X}")
            continue
        d = res["data"]
        if key == "registration":
            print(f"    {C.G}✅ registered{C.X}" if d["registered"] else f"    {C.R}❌ not registered (or WHOIS unavailable){C.X}")
        elif key == "reverse_ip" and "domains" in d:
            print(f"    {C.D}{d['count']} domain(s) on {d['ip']} — {d['source']}{C.X}")
            print_list(d["domains"], limit)
        elif key == "subdomains":
            print(f"    {C.D}{d['count']} unique name(s) — {d['source']}{C.X}")
            print_list(d["subdomains"], limit)
        elif key == "dns":
            print(f"    {C.D}source: {d['source']}{C.X}")
            for t, vals in d["records"].items():
                for v in vals:
                    print(f"    {C.B}{t:<6}{C.X} {C.G}{v}{C.X}")
        elif key == "certs":
            print(f"    {C.D}{d['total']} certificate(s) · first seen {d['first_seen']}{C.X}")
            print(f"    {C.B}Issuers:{C.X} " + ", ".join(f"{k} ({v})" for k, v in list(d["issuers"].items())[:6]))
            print(f"    {C.B}Latest:{C.X}")
            for c in d["latest"][: (10 if full else 5)]:
                print(f"      {C.G}{c['logged_at'][:10] if c['logged_at'] else '?'}  "
                      f"{', '.join(c['names'][:3])}{C.X}  {C.D}{c['url']}{C.X}")
        else:
            print_kv(d)
    print()


def to_markdown(reports):
    lines = ["# WebOSINT report", ""]
    for r in reports:
        lines += [f"## {r['domain']}", f"_Generated {r['generated_at']} — {r['elapsed']}s_", ""]
        for key, res in r["modules"].items():
            lines.append(f"### {MOD_INDEX[key][1]}")
            if res["status"] != "ok":
                lines += [f"_{res['status']}: {res.get('reason', res.get('data', {}).get('error', ''))}_", ""]
                continue
            lines += ["```json", json.dumps(res["data"], indent=2, ensure_ascii=False, default=str), "```", ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Interactive mode (no arguments)
# --------------------------------------------------------------------------- #
def interactive(keys):
    try:
        domain = normalise_domain(input(f"{C.P}{C.B}Domain (e.g. example.com): {C.X}"))
        print(f"\n{C.B}Modules:{C.X}")
        for i, (key, title, _, desc) in enumerate(MODULES, 1):
            need = ""
            if key == "reputation" and not keys["WHOIS_XML_API_KEY"]:
                need = f" {C.Y}(no key){C.X}"
            if key == "history" and not keys["WHOIS_FREAKS_API_KEY"]:
                need = f" {C.Y}(no key){C.X}"
            print(f"  {C.P}[{i:>2}]{C.X} {title:<30}{C.D}{desc}{C.X}{need}")
        choice = input(f"\n{C.P}{C.B}Modules to run — Enter = all, or numbers e.g. 2,4,7: {C.X}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if not choice:
        return domain, [m[0] for m in MODULES]
    sel = []
    for part in re.split(r"[,\s]+", choice):
        if part.isdigit() and 1 <= int(part) <= len(MODULES):
            sel.append(MODULES[int(part) - 1][0])
        elif part in MOD_INDEX:
            sel.append(part)
    return domain, uniq(sel) or [m[0] for m in MODULES]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_modules(spec):
    out = []
    for part in spec.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part.isdigit() and 1 <= int(part) <= len(MODULES):
            out.append(MODULES[int(part) - 1][0])
        elif part in MOD_INDEX:
            out.append(part)
        else:
            sys.exit(f"Unknown module '{part}'. Use --list to see available modules.")
    return uniq(out)


def main():
    ap = argparse.ArgumentParser(
        prog="webosint",
        description="WebOSINT — passive domain intelligence. Runs all modules in parallel.",
        epilog="Run without arguments for interactive mode. API keys: config.json or env vars "
               "WEBOSINT_WHOISXML_KEY, WEBOSINT_HACKERTARGET_KEY, WEBOSINT_WHOISFREAKS_KEY.")
    ap.add_argument("domains", nargs="*", help="one or more domains (URLs are accepted too)")
    ap.add_argument("-f", "--file", help="file with one domain per line")
    ap.add_argument("-m", "--modules", help="comma list of modules to run (names or numbers)")
    ap.add_argument("-x", "--exclude", help="comma list of modules to skip")
    ap.add_argument("-o", "--output", help="save results as JSON")
    ap.add_argument("--md", help="save results as a Markdown report")
    ap.add_argument("--json", action="store_true", help="print JSON to stdout (for piping, e.g. into jq)")
    ap.add_argument("--full", action="store_true", help="don't truncate long lists in the terminal")
    ap.add_argument("-t", "--timeout", type=int, default=20, help="per-request timeout in seconds (default 20)")
    ap.add_argument("-w", "--workers", type=int, default=10, help="parallel workers (default 10)")
    ap.add_argument("--config", default=CONFIG_FILE, help="path to config.json")
    ap.add_argument("--list", action="store_true", help="list modules and exit")
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-v", "--version", action="version", version=f"WebOSINT {VERSION}")
    args = ap.parse_args()

    if args.no_color or args.json or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        C.disable()

    if args.list:
        for i, (key, title, _, desc) in enumerate(MODULES, 1):
            print(f"  [{i:>2}] {key:<13} {title:<30} {desc}")
        return

    if not args.no_banner and not args.json:
        print(BANNER.format(P=C.P, G=C.G, X=C.X, V=VERSION), file=sys.stderr)

    keys = load_keys(args.config)

    domains = list(args.domains)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            domains += [l for l in fh.read().splitlines() if l.strip() and not l.startswith("#")]

    if domains:
        selected = parse_modules(args.modules) if args.modules else [m[0] for m in MODULES]
    else:
        if not sys.stdin.isatty():
            ap.error("no domain given")
        d, selected = interactive(keys)
        domains = [d]
    if args.exclude:
        excl = set(parse_modules(args.exclude))
        selected = [s for s in selected if s not in excl]

    domains = uniq(normalise_domain(d) for d in domains)
    bad = [d for d in domains if not is_valid_domain(d)]
    if bad:
        sys.exit(f"Invalid domain(s): {', '.join(bad)}")

    reports = []
    try:
        for d in domains:
            rep = run_domain(d, selected, keys, args.timeout, args.workers, quiet=args.json)
            reports.append(rep)
            if not args.json:
                print_report(rep, full=args.full)
    except KeyboardInterrupt:
        print(f"\n{C.Y}Interrupted.{C.X}", file=sys.stderr)

    payload = reports[0] if len(reports) == 1 else reports
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
        print(f"{C.G}JSON saved → {args.output}{C.X}", file=sys.stderr)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(reports))
        print(f"{C.G}Markdown saved → {args.md}{C.X}", file=sys.stderr)


if __name__ == "__main__":
    main()
