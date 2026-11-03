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
  python3 webosint.py example.com --html --open   # futuristic HTML report
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

VERSION = "3.1"
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
    example = os.path.join(os.path.dirname(os.path.abspath(path)), "config.example.json")
    if not os.path.exists(path) and os.path.exists(example):
        # first run: create your private config.json from the template (it is git-ignored)
        try:
            with open(example, encoding="utf-8") as src, open(path, "w", encoding="utf-8") as dst:
                dst.write(src.read())
            print(f"{C.D}[i] Created {path} from config.example.json; add your API keys there "
                  f"(this file is never committed).{C.X}", file=sys.stderr)
        except OSError:
            pass
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

    def rdap(self):
        """RDAP (the JSON successor of WHOIS). Mandatory for every gTLD (.sarl, .xyz, .app...),
        also offered by many ccTLDs (.fr, .uk, .nl...). Returns the RDAP JSON, or None if the
        registry answered 404 (domain not registered)."""
        def fetch():
            base = rdap_base(self, self.domain.rsplit(".", 1)[-1])
            url = (base or "https://rdap.org/").rstrip("/") + "/domain/" + self.domain
            r = self.session.get(url, timeout=self.timeout,
                                 headers={"Accept": "application/rdap+json, application/json"})
            if r.status_code == 404:
                return None
            r.raise_for_status()
            d = r.json()
            # Registries often publish only the registrar; the registrant record lives at the
            # registrar's own RDAP server, linked with rel="related". Follow it (best effort).
            for link in d.get("links", []):
                href = link.get("href", "")
                if link.get("rel") == "related" and "/domain/" in href.lower() and href != url:
                    try:
                        rr = self.session.get(href, timeout=self.timeout,
                                              headers={"Accept": "application/rdap+json, application/json"})
                        if rr.ok:
                            d["_registrar_rdap"] = rr.json()
                            d["_registrar_rdap_url"] = href
                    except Exception:
                        pass
                    break
            return d
        return self.cached("rdap", fetch)

    def internetdb(self, ip):
        """Shodan InternetDB: free, no key. Returns {} when Shodan has no data on the IP."""
        def fetch():
            r = self.session.get(f"https://internetdb.shodan.io/{ip}", timeout=self.timeout)
            if r.status_code == 404:
                return {}
            r.raise_for_status()
            return r.json()
        return self.cached(f"internetdb:{ip}", fetch)

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
# RDAP helpers
# --------------------------------------------------------------------------- #
RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RDAP_CACHE = os.path.join(os.path.expanduser("~"), ".cache", "webosint", "rdap_dns.json")
_rdap_lock = threading.Lock()
_rdap_map = None


def rdap_base(ctx, tld):
    """Find the registry's RDAP server for a TLD using IANA's bootstrap file (cached 7 days)."""
    global _rdap_map
    with _rdap_lock:
        if _rdap_map is None:
            data = None
            try:
                if os.path.exists(RDAP_CACHE) and time.time() - os.path.getmtime(RDAP_CACHE) < 7 * 86400:
                    with open(RDAP_CACHE, encoding="utf-8") as fh:
                        data = json.load(fh)
            except (OSError, ValueError):
                data = None
            if data is None:
                try:
                    data = ctx.get(RDAP_BOOTSTRAP).json()
                    os.makedirs(os.path.dirname(RDAP_CACHE), exist_ok=True)
                    with open(RDAP_CACHE, "w", encoding="utf-8") as fh:
                        json.dump(data, fh)
                except Exception:
                    data = {"services": []}
            _rdap_map = {}
            for tlds, urls in data.get("services", []):
                https = [u for u in urls if u.startswith("https")] or urls
                for t in tlds:
                    _rdap_map[t.lower()] = https[0]
        return _rdap_map.get(tld.lower())


def _vcard(entity):
    """Flatten an RDAP entity's jCard into a small dict."""
    out = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        name, params, _, val = (item + [None] * 4)[:4]
        if name == "fn" and val:
            out["name"] = val
        elif name == "org" and val:
            out["org"] = val if isinstance(val, str) else " ".join(map(str, val))
        elif name == "email" and val:
            out.setdefault("email", val)
        elif name == "tel" and val:
            out.setdefault("phone", str(val).replace("tel:", ""))
        elif name == "adr":
            label = (params or {}).get("label") if isinstance(params, dict) else None
            if isinstance(val, list):
                parts = [p if isinstance(p, str) else " ".join(p) for p in val if p]
                if parts:
                    out["address"] = ", ".join(x for x in parts if x)
                    if parts and len(parts[-1]) <= 3:
                        out["country"] = parts[-1]
            elif label:
                out["address"] = label.replace("\n", ", ")
    return out


def parse_rdap(d):
    out = {"domain_name": d.get("ldhName") or d.get("unicodeName")}
    for ev in d.get("events", []):
        action = ev.get("eventAction", "")
        key = {"registration": "creation_date", "expiration": "expiration_date",
               "last changed": "updated_date", "transfer": "last_transfer"}.get(action)
        if key:
            out[key] = ev.get("eventDate")
    out["status"] = d.get("status")
    out["name_servers"] = sorted(n.get("ldhName", "").lower() for n in d.get("nameservers", []) if n.get("ldhName"))
    sec = d.get("secureDNS") or {}
    if "delegationSigned" in sec:
        out["dnssec"] = "signed" if sec["delegationSigned"] else "unsigned"
    out["whois_server"] = d.get("port43")

    def walk(entities):
        for e in entities or []:
            yield e
            yield from walk(e.get("entities"))

    contacts = {}
    entities = list(walk((d.get("_registrar_rdap") or {}).get("entities"))) + list(walk(d.get("entities")))
    if d.get("_registrar_rdap_url"):
        out["registrar_rdap"] = d["_registrar_rdap_url"]
    for e in entities:
        info = _vcard(e)
        for role in e.get("roles", []):
            if role == "registrar":
                out["registrar"] = info.get("name") or info.get("org") or e.get("handle")
                iana = [p.get("identifier") for p in e.get("publicIds", []) if "IANA" in p.get("type", "")]
                if iana:
                    out["registrar_iana_id"] = iana[0]
                url = [l.get("href") for l in e.get("links", []) if l.get("rel") in ("about", "self")]
                if url:
                    out["registrar_url"] = url[0]
            elif info and role in ("registrant", "administrative", "technical", "abuse", "billing"):
                contacts.setdefault(role, info)  # registrar data first (richer), then registry
    if contacts:
        out["contacts"] = contacts
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}


# --------------------------------------------------------------------------- #
# Modules — each returns a JSON-serialisable dict
# --------------------------------------------------------------------------- #
def mod_registration(ctx):
    try:
        return {"registered": ctx.rdap() is not None, "source": "RDAP"}
    except Exception:
        pass
    try:
        w = ctx.whois()
        if w.domain_name:
            return {"registered": True, "source": "WHOIS"}
        return {"registered": False, "source": "WHOIS"}
    except SkipModule:
        raise
    except Exception as exc:
        if "no match" in str(exc).lower() or "not found" in str(exc).lower():
            return {"registered": False, "source": "WHOIS"}
    # neither source answered: say so instead of guessing "not registered"
    try:
        ctx.ips()
        return {"registered": True, "source": "DNS (domain resolves; RDAP/WHOIS unavailable)"}
    except Exception:
        return {"registered": None, "source": "unknown (RDAP and WHOIS both unavailable for this TLD)"}


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
    ip = ips[0]

    # 1) HackerTarget: free tier (20/day) or your key if config.json has one
    ht_domains, ht_error = [], None
    params = {"q": ip}
    if ctx.keys["HACKERTARGET_API_KEY"]:
        params["apikey"] = ctx.keys["HACKERTARGET_API_KEY"]
    try:
        text = ctx.get("https://api.hackertarget.com/reverseiplookup/", params=params).text.strip()
        if text.lower().startswith(("api count exceeded", "error", "no dns a records")):
            ht_error = text.splitlines()[0]
        else:
            ht_domains = [l.strip().lower() for l in text.splitlines() if l.strip()]
    except Exception as exc:
        ht_error = f"{exc.__class__.__name__}: {exc}"

    # 2) Shodan InternetDB: always queried, free, no key (backup + extra hostnames)
    sh_domains, sh_error = [], None
    try:
        sh_domains = [h.lower() for h in ctx.internetdb(ip).get("hostnames", [])]
    except Exception as exc:
        sh_error = f"{exc.__class__.__name__}: {exc}"

    domains = uniq(ht_domains + sh_domains)
    sources = []
    if ht_domains:
        sources.append("HackerTarget (API key)" if "apikey" in params else "HackerTarget (free tier)")
    if sh_domains:
        sources.append("Shodan InternetDB")
    out = {"ip": ip, "count": len(domains), "domains": domains,
           "source": " + ".join(sources) or "none"}
    extra = [d for d in sh_domains if d not in set(ht_domains)]
    if ht_domains and extra:
        out["added_by_shodan"] = len(extra)
    if ht_error:
        out["hackertarget_note"] = ht_error + ("  → Shodan used as backup" if sh_domains else "")
    if not domains:
        out["error"] = "; ".join(x for x in (ht_error, sh_error) if x) or "no co-hosted domains found"
    return out


def mod_shodan(ctx):
    """Open ports, software (CPE), tags and known CVEs per IP (Shodan InternetDB, free, no key)."""
    try:
        ips = ctx.ips()["ipv4"]
    except socket.gaierror:
        raise SkipModule("domain does not resolve")
    if not ips:
        raise SkipModule("no IPv4 address")
    hosts = {}
    for ip in ips[:3]:
        try:
            d = ctx.internetdb(ip)
        except Exception as exc:
            hosts[ip] = {"error": f"{exc.__class__.__name__}: {exc}"}
            continue
        if not d:
            hosts[ip] = {"note": "no data in Shodan for this IP"}
            continue
        vulns = sorted(d.get("vulns", []), reverse=True)
        hosts[ip] = {k: v for k, v in {
            "ports": sorted(d.get("ports", [])),
            "hostnames": d.get("hostnames", []),
            "tags": d.get("tags", []),
            "software": d.get("cpes", []),
            "vulns_count": len(vulns),
            "vulns": vulns,
            "url": f"https://www.shodan.io/host/{ip}",
        }.items() if v not in ([], None)}
    return {"hosts": hosts, "source": "Shodan InternetDB (free, non-commercial use)"}


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
    errors = []
    try:
        d = ctx.rdap()
        if d is None:
            return {"error": "Domain not registered (RDAP 404)"}
        out = parse_rdap(d)
        if len(out) > 1:
            out["source"] = "RDAP (registry" + (" + registrar)" if d.get("_registrar_rdap") else ")")
            if "registrant" not in out.get("contacts", {}):
                try:  # owner details are sometimes only in classic WHOIS
                    legacy = _whois_legacy(ctx)
                    owner = {k: legacy[k] for k in ("name", "org", "emails", "address", "city", "state",
                                                    "zipcode", "country") if legacy.get(k)}
                    if owner:
                        out.setdefault("contacts", {})["registrant (WHOIS)"] = owner
                        out["source"] += " + WHOIS"
                except Exception:
                    pass
            privacy = _privacy_flag(out.get("contacts", {}))
            if privacy:
                out["privacy"] = privacy
            return out
    except Exception as exc:
        errors.append(f"RDAP: {exc}")
    try:
        out = _whois_legacy(ctx)
        out["source"] = "WHOIS (port 43)"
        return out
    except SkipModule as exc:
        errors.append(f"WHOIS: {exc}")
    except Exception as exc:
        errors.append(f"WHOIS: {exc.__class__.__name__}: {exc}")
    raise RuntimeError(" | ".join(errors) or "no data")


PRIVACY_MARKERS = ("redacted", "privacy", "withheld", "data protected", "not disclosed", "whoisguard",
                   "domains by proxy", "contact privacy", "gdpr", "proxy")


def _privacy_flag(contacts):
    reg = {k: v for k, v in contacts.items() if k.startswith("registrant")}
    if not reg:
        return "no registrant published (GDPR redaction is the norm since 2018)"
    blob = json.dumps(reg).lower()
    if any(m in blob for m in PRIVACY_MARKERS):
        return "registrant hidden behind a privacy/proxy service or redacted"
    return None


def _whois_legacy(ctx):
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
        raise RuntimeError("no WHOIS data returned")
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
        rec = {k: v for k, v in {
            "query_time": r.get("query_time"),
            "registrar": (r.get("domain_registrar") or {}).get("registrar_name"),
            "created": r.get("create_date"),
            "updated": r.get("update_date"),
            "expires": r.get("expiry_date"),
            "status": r.get("domain_status"),
            "name_servers": r.get("name_servers"),
        }.items() if v}
        # every *_contact block (registrant, administrative, technical, billing...), all fields
        for ck, cv in r.items():
            if ck.endswith("_contact") and isinstance(cv, dict):
                fields = {f: v for f, v in cv.items() if v not in (None, "", [], {})}
                if fields:
                    rec[ck.replace("_contact", "")] = fields
        hist.append(rec)
    # owner changes over time are the interesting part: list distinct registrants
    owners = uniq(json.dumps({k: v for k, v in (h.get("registrant") or {}).items()
                              if k in ("name", "company", "email_address")}, sort_keys=True)
                  for h in hist if h.get("registrant"))
    owners = [json.loads(o) for o in owners if o != "{}"]
    out = {"total_records": d.get("total_records", len(hist))}
    if owners:
        out["distinct_registrants"] = owners
    out["records"] = hist
    return out


EXPOSURE_POLL = 5        # seconds between polls
EXPOSURE_MAX_WAIT = 90   # give up after this many seconds


def mod_exposure(ctx):
    """Lunar Domain Exposure API (free, no key) — infostealer / breach exposure (issue #5)."""
    # Lunar builds the report on demand: the first call returns GENERATING_REPORT,
    # so poll the same endpoint until it is REPORT_READY (or we give up).
    deadline = time.time() + EXPOSURE_MAX_WAIT
    while True:
        d = ctx.get("https://api.lunarcyber.com/domain-exposure", params={"domain": ctx.domain},
                    timeout=max(ctx.timeout, 30)).json()
        data = d.get("data", d) if isinstance(d, dict) else {}
        report = data.get("report") or {}
        status = str(data.get("status") or "").upper()
        if report.get("summary") or status == "REPORT_READY" or "GENERAT" not in status \
                or time.time() + EXPOSURE_POLL > deadline:
            break
        time.sleep(EXPOSURE_POLL)
    if not report.get("summary") and "GENERAT" in status:
        return {"status": data.get("status"),
                "note": f"Lunar is still generating the report after {EXPOSURE_MAX_WAIT}s. "
                        f"Run again in a minute: webosint.py {ctx.domain} -m exposure"}
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
    ("registration", "Domain Registration", mod_registration, "Is the domain registered? (RDAP/WHOIS)"),
    ("ip",           "IP Address & Geolocation", mod_ip, "A/AAAA + ipinfo.io / ipapi.co data"),
    ("shodan",       "Shodan (ports & CVEs)", mod_shodan, "Open ports, software, known CVEs (Shodan, free)"),
    ("reverse_ip",   "Reverse IP (shared hosting)", mod_reverse_ip, "Other domains on the same IP (HackerTarget + Shodan)"),
    ("dns",          "DNS Records", mod_dns, "A, AAAA, MX, NS, TXT, SOA, CAA, DMARC"),
    ("whois",        "WHOIS / RDAP", mod_whois, "Registrar, dates, contacts (RDAP, WHOIS fallback)"),
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
            if d["registered"] is None:
                print(f"    {C.Y}? unknown{C.X}  {C.D}{d.get('source', '')}{C.X}")
            else:
                print((f"    {C.G}✅ registered" if d["registered"] else f"    {C.R}❌ not registered")
                      + f"{C.X}  {C.D}({d.get('source', '')}){C.X}")
        elif key == "reverse_ip" and "domains" in d:
            print(f"    {C.D}{d['count']} domain(s) on {d['ip']} — {d['source']}{C.X}")
            if d.get("hackertarget_note"):
                print(f"    {C.Y}HackerTarget: {d['hackertarget_note']}{C.X}")
            if d.get("added_by_shodan"):
                print(f"    {C.D}(+{d['added_by_shodan']} hostname(s) only seen by Shodan){C.X}")
            print_list(d["domains"], limit)
        elif key == "shodan":
            for ip, h in d["hosts"].items():
                print(f"    {C.B}{ip}{C.X}")
                if "note" in h or "error" in h:
                    print(f"      {C.D}{h.get('note') or h.get('error')}{C.X}")
                    continue
                for label, field in (("ports", "ports"), ("hostnames", "hostnames"), ("tags", "tags"),
                                     ("software", "software")):
                    if h.get(field):
                        print(f"      {C.D}{label:<10}{C.X} {C.G}{_fmt(h[field])}{C.X}")
                if h.get("vulns"):
                    shown = h["vulns"] if full else h["vulns"][:15]
                    more = "" if full or len(h["vulns"]) <= 15 else f" … +{len(h['vulns']) - 15}"
                    print(f"      {C.D}{'CVEs':<10}{C.X} {C.R}{h['vulns_count']}: {', '.join(shown)}{more}{C.X}")
                print(f"      {C.D}{h['url']}{C.X}")
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
# HTML report (self-contained, works offline)
# --------------------------------------------------------------------------- #
HTML_CSS = r"""
:root{--bg:#05060b;--panel:#0b0d17cc;--line:#1d2140;--txt:#d7dcff;--dim:#7a80a8;
--neon:#b04cff;--neon2:#39ffb0;--warn:#ffcc4d;--bad:#ff4d6d;--mono:ui-monospace,"SF Mono",
"JetBrains Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.55 var(--mono);
background-image:linear-gradient(#b04cff0d 1px,transparent 1px),linear-gradient(90deg,#b04cff0d 1px,transparent 1px),
radial-gradient(ellipse at top,#2a0f4a 0%,transparent 60%);background-size:32px 32px,32px 32px,100% 100%;
background-attachment:fixed}
body:after{content:"";position:fixed;inset:0;pointer-events:none;
background:repeating-linear-gradient(0deg,#ffffff05 0 1px,transparent 1px 3px)}
a{color:var(--neon2);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1180px;margin:0 auto;padding:28px 16px 60px}
header{border:1px solid var(--line);background:var(--panel);backdrop-filter:blur(6px);
padding:22px 24px;position:relative;clip-path:polygon(0 0,calc(100% - 22px) 0,100% 22px,100% 100%,22px 100%,0 calc(100% - 22px))}
header:before{content:"";position:absolute;left:0;top:0;height:2px;width:100%;
background:linear-gradient(90deg,var(--neon),var(--neon2),transparent);animation:scan 4s linear infinite}
@keyframes scan{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}
.brand{color:var(--neon);letter-spacing:.35em;font-size:12px;text-transform:uppercase}
h1{margin:6px 0 4px;font-size:clamp(22px,4vw,34px);letter-spacing:.04em;color:#fff;
text-shadow:0 0 12px #b04cff99,0 0 30px #b04cff55;word-break:break-all}
.meta{color:var(--dim);font-size:12px}.meta b{color:var(--neon2);font-weight:400}
nav{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}
nav a{border:1px solid var(--line);padding:4px 10px;font-size:12px;color:var(--dim);background:#0b0d17}
nav a:hover{border-color:var(--neon);color:#fff;text-decoration:none}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0 26px}
.kpi{border:1px solid var(--line);background:var(--panel);padding:14px 16px;position:relative}
.kpi:after{content:"";position:absolute;right:8px;top:8px;width:6px;height:6px;background:var(--neon2);
box-shadow:0 0 8px var(--neon2)}
.kpi .v{font-size:26px;color:#fff;text-shadow:0 0 10px #39ffb066}.kpi .l{color:var(--dim);font-size:11px;
text-transform:uppercase;letter-spacing:.15em}
.kpi.bad .v{color:var(--bad);text-shadow:0 0 10px #ff4d6d66}.kpi.bad:after{background:var(--bad);box-shadow:0 0 8px var(--bad)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,520px),1fr));gap:16px;align-items:start}
details.card{border:1px solid var(--line);background:var(--panel);backdrop-filter:blur(6px)}
details.card[open]{border-color:#b04cff55;box-shadow:0 0 0 1px #b04cff22,0 0 40px -20px var(--neon)}
summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:10px;padding:12px 16px;
border-bottom:1px solid transparent}summary::-webkit-details-marker{display:none}
details[open] summary{border-bottom-color:var(--line)}
summary .n{color:var(--neon);font-size:11px}summary .t{flex:1;color:#fff;letter-spacing:.05em}
summary .s{font-size:11px;color:var(--dim)}
.pill{font-size:10px;padding:2px 8px;letter-spacing:.12em;text-transform:uppercase;border:1px solid}
.ok{color:var(--neon2);border-color:#39ffb066}.skipped{color:var(--warn);border-color:#ffcc4d66}
.error{color:var(--bad);border-color:#ff4d6d66}
.body{padding:12px 16px 16px;overflow-x:auto}
table{width:100%;border-collapse:collapse}td,th{padding:5px 8px;border-bottom:1px dashed #1d214099;
vertical-align:top;text-align:left;word-break:break-word}
th{color:var(--dim);font-weight:400;white-space:nowrap;width:1%;padding-right:18px}
td{color:var(--txt)}.tag{color:var(--neon);white-space:nowrap}
.note{color:var(--dim);margin:0 0 10px;font-size:12px}.err{color:var(--bad)}.warn{color:var(--warn)}
ul.list{list-style:none;margin:0;padding:0;max-height:420px;overflow:auto;columns:2 260px;column-gap:24px}
ul.list li{padding:2px 0;break-inside:avoid;word-break:break-all}ul.list li:before{content:"› ";color:var(--neon)}
input.filter{width:100%;background:#05060b;border:1px solid var(--line);color:#fff;padding:7px 10px;
font:inherit;margin-bottom:10px;outline:none}input.filter:focus{border-color:var(--neon);box-shadow:0 0 12px -4px var(--neon)}
.big{font-size:18px}.yes{color:var(--neon2)}.no{color:var(--bad)}
footer{margin-top:40px;color:var(--dim);font-size:11px;text-align:center;letter-spacing:.1em}
footer b{color:var(--neon)}
.domain{margin-top:34px}
@media (max-width:640px){table,tbody,tr,th,td{display:block;width:auto}th{padding:6px 0 0;border:0}
td{padding:0 0 6px 12px}.wrap{padding:16px 12px 40px}}
@media print{body{background:#fff;color:#000}body:after,header:before{display:none}
details.card{break-inside:avoid}ul.list{max-height:none}}
"""

HTML_JS = r"""
document.querySelectorAll('input.filter').forEach(function(inp){
  inp.addEventListener('input',function(){
    var q=inp.value.toLowerCase(),list=inp.nextElementSibling,shown=0;
    list.querySelectorAll('li').forEach(function(li){
      var m=li.textContent.toLowerCase().indexOf(q)>-1;li.style.display=m?'':'none';if(m)shown++;});
    inp.setAttribute('data-count',shown);
  });
});
document.getElementById('toggle').addEventListener('click',function(e){
  e.preventDefault();var cards=document.querySelectorAll('details.card');
  var open=[].some.call(cards,function(c){return !c.open});
  cards.forEach(function(c){c.open=open});
});
"""


def _h(v):
    import html as _html
    return _html.escape(str(v), quote=True)


def _html_value(v):
    if isinstance(v, dict):
        return _html_table(v)
    if isinstance(v, list):
        if v and isinstance(v[0], dict):
            return "".join(f'<div style="margin:6px 0 10px">{_html_table(i)}</div>' for i in v)
        return "<br>".join(_h(x) for x in v)
    s = str(v)
    if s.startswith(("http://", "https://")):
        return f'<a href="{_h(s)}" target="_blank" rel="noopener noreferrer">{_h(s)}</a>'
    return _h(s)


def _html_table(d):
    rows = "".join(f"<tr><th>{_h(k.replace('_', ' '))}</th><td>{_html_value(v)}</td></tr>"
                   for k, v in d.items() if v not in (None, "", [], {}))
    return f"<table>{rows}</table>"


def _html_list(items, label):
    lis = "".join(f"<li>{_h(i)}</li>" for i in items)
    return (f'<input class="filter" placeholder="filter {len(items)} {label}…" aria-label="filter">'
            f'<ul class="list">{lis}</ul>')


def _html_module(key, res):
    if res["status"] == "skipped":
        return f'<p class="warn">Skipped: {_h(res["reason"])}</p>'
    if res["status"] == "error" and "reason" in res:
        return f'<p class="err">Error: {_h(res["reason"])}</p>'
    d = res["data"]
    if key == "registration":
        src = f'<p class="note">source: {_h(d.get("source", ""))}</p>'
        if d["registered"] is None:
            return '<p class="big warn">● UNKNOWN</p>' + src
        return ('<p class="big yes">● REGISTERED</p>' if d["registered"]
                else '<p class="big no">● NOT REGISTERED</p>') + src
    if key == "reverse_ip" and "domains" in d:
        notes = ""
        if d.get("hackertarget_note"):
            notes += f'<p class="warn" style="font-size:12px">HackerTarget: {_h(d["hackertarget_note"])}</p>'
        if d.get("added_by_shodan"):
            notes += f'<p class="note">+{d["added_by_shodan"]} hostname(s) only seen by Shodan</p>'
        return f'<p class="note">{d["count"]} domain(s) on {_h(d["ip"])} · {_h(d["source"])}</p>' + notes + \
            _html_list(d["domains"], "domains")
    if key == "shodan":
        out = f'<p class="note">{_h(d["source"])}</p>'
        for ip, h in d["hosts"].items():
            if "note" in h or "error" in h:
                out += f'<p><span class="tag">{_h(ip)}</span> <span class="note">{_h(h.get("note") or h.get("error"))}</span></p>'
                continue
            rows = ""
            if h.get("ports"):
                rows += "<tr><th>ports</th><td>" + " ".join(
                    f'<span class="pill ok" style="margin:0 4px 4px 0;display:inline-block">{_h(p)}</span>'
                    for p in h["ports"]) + "</td></tr>"
            for f in ("hostnames", "tags", "software"):
                if h.get(f):
                    rows += f"<tr><th>{f}</th><td>{'<br>'.join(_h(x) for x in h[f])}</td></tr>"
            if h.get("vulns"):
                links = " ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{_h(v)}" target="_blank" '
                                 f'rel="noopener noreferrer" style="color:var(--bad)">{_h(v)}</a>' for v in h["vulns"])
                rows += f'<tr><th>CVEs ({h["vulns_count"]})</th><td>{links}</td></tr>'
            rows += (f'<tr><th>shodan</th><td><a href="{_h(h["url"])}" target="_blank" '
                     f'rel="noopener noreferrer">{_h(h["url"])}</a></td></tr>')
            out += f'<p class="tag" style="margin:10px 0 4px">{_h(ip)}</p><table>{rows}</table>'
        return out
    if key == "subdomains":
        return f'<p class="note">{d["count"]} unique hostname(s) · {_h(d["source"])}</p>' + \
            _html_list(d["subdomains"], "subdomains")
    if key == "dns":
        rows = "".join(f'<tr><th class="tag">{_h(t)}</th><td>{"<br>".join(_h(v) for v in vals)}</td></tr>'
                       for t, vals in d["records"].items())
        return f'<p class="note">source: {_h(d["source"])}</p><table>{rows}</table>'
    if key == "certs":
        head = (f'<p class="note">{d["total"]} certificate(s) · first seen {_h(d["first_seen"])}</p>'
                + _html_table({"issuers": {k: v for k, v in d["issuers"].items()}}))
        rows = "".join(
            f'<tr><th>{_h((c["logged_at"] or "?")[:10])}</th><td>{"<br>".join(_h(n) for n in c["names"][:6])}'
            f'<br><a href="{_h(c["url"])}" target="_blank" rel="noopener noreferrer">crt.sh #{_h(c["id"])}</a></td></tr>'
            for c in d["latest"])
        return head + f'<p class="note" style="margin-top:12px">Latest certificates</p><table>{rows}</table>'
    return _html_table(d)


def _kpis(rep):
    m = rep["modules"]

    def data(k):
        r = m.get(k)
        return r["data"] if r and r["status"] == "ok" else None

    tiles = []
    if data("registration") is not None:
        reg = data("registration")["registered"]
        tiles.append(("Registered", "?" if reg is None else ("YES" if reg else "NO"), not reg))
    if data("ip") and "ipv4" in data("ip"):
        tiles.append(("IP addresses", len(data("ip")["ipv4"]) + len(data("ip").get("ipv6", [])), False))
    if data("subdomains"):
        tiles.append(("Subdomains", data("subdomains")["count"], False))
    if data("certs"):
        tiles.append(("Certificates", data("certs")["total"], False))
    if data("reverse_ip") and "count" in data("reverse_ip"):
        tiles.append(("Co-hosted domains", data("reverse_ip")["count"], False))
    if data("shodan"):
        hosts = [h for h in data("shodan")["hosts"].values() if "ports" in h or "vulns" in h]
        if hosts:
            tiles.append(("Open ports", len({p for h in hosts for p in h.get("ports", [])}), False))
            cves = len({v for h in hosts for v in h.get("vulns", [])})
            tiles.append(("Known CVEs", cves, cves > 0))
    if data("exposure") and data("exposure").get("summary"):
        t = data("exposure")["summary"].get("total_events")
        if t is not None:
            tiles.append(("Exposure events", t, bool(t)))
    if data("reputation") and data("reputation").get("reputation_score") is not None:
        s = data("reputation")["reputation_score"]
        tiles.append(("Reputation", s, isinstance(s, (int, float)) and s < 70))
    ok = sum(1 for r in m.values() if r["status"] == "ok")
    tiles.append(("Modules OK", f"{ok}/{len(m)}", ok < len(m)))
    return "".join(f'<div class="kpi{" bad" if bad else ""}"><div class="v">{_h(v)}</div>'
                   f'<div class="l">{_h(l)}</div></div>' for l, v, bad in tiles)


def to_html(reports):
    multi = len(reports) > 1
    title = "WebOSINT report — " + (reports[0]["domain"] if not multi else f"{len(reports)} domains")
    parts = []
    for i, rep in enumerate(reports):
        cards = []
        for n, (key, res) in enumerate(rep["modules"].items(), 1):
            st = res["status"]
            cards.append(
                f'<details class="card" id="d{i}-{key}" open><summary><span class="n">[{n:02d}]</span>'
                f'<span class="t">{_h(MOD_INDEX[key][1])}</span><span class="s">{res["elapsed"]}s</span>'
                f'<span class="pill {st}">{st}</span></summary>'
                f'<div class="body">{_html_module(key, res)}</div></details>')
        nav = "".join(f'<a href="#d{i}-{k}">{_h(k)}</a>' for k in rep["modules"])
        parts.append(
            f'<section class="domain" id="dom{i}"><header><div class="brand">W3b0s1nt // domain intelligence</div>'
            f'<h1>{_h(rep["domain"])}</h1><div class="meta">generated <b>{_h(rep["generated_at"])}</b> · '
            f'scan time <b>{rep["elapsed"]}s</b> · {len(rep["modules"])} modules · passive recon</div></header>'
            f'<nav>{nav}<a href="#" id="toggle" style="margin-left:auto">expand / collapse all</a></nav>'
            .replace('id="toggle"', 'id="toggle"' if i == 0 else 'class="tg"')
            + f'<div class="kpis">{_kpis(rep)}</div><div class="grid">{"".join(cards)}</div></section>')
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="generator" content="WebOSINT {VERSION}"><title>{_h(title)}</title>'
            f'<style>{HTML_CSS}</style></head><body><div class="wrap">{"".join(parts)}'
            f'<footer>generated by <b>WebOSINT v{VERSION}</b> · '
            f'<a href="https://github.com/C3n7ral051nt4g3ncy/WebOSINT">github.com/C3n7ral051nt4g3ncy/WebOSINT</a>'
            f' · passive OSINT — verify before acting</footer></div><script>{HTML_JS}</script></body></html>')

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
    ap.add_argument("--html", nargs="?", const="auto", metavar="FILE",
                    help="save a self-contained HTML report (default name: webosint_<domain>_<date>.html)")
    ap.add_argument("--open", action="store_true", help="open the HTML report in your browser when done")
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

    asked_html = False
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
        asked_html = True
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
    if asked_html and reports and not args.html:
        try:
            ans = input(f"{C.P}{C.B}Save an HTML report? [Y/n]: {C.X}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans in ("", "y", "yes", "o", "oui"):
            args.html, args.open = "auto", True
    if args.html and reports:
        path = args.html
        if path == "auto":
            stem = reports[0]["domain"] if len(reports) == 1 else "multi"
            path = f"webosint_{stem}_{datetime.now():%Y%m%d_%H%M}.html"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_html(reports))
        print(f"{C.G}HTML report saved → {os.path.abspath(path)}{C.X}", file=sys.stderr)
        if args.open:
            import webbrowser
            webbrowser.open("file://" + os.path.abspath(path))


if __name__ == "__main__":
    main()
