#!/usr/bin/env python3
import argparse
import dns.resolver
import requests
import whois
import socket
import ssl
import re
import json
import sys
import os
from urllib.parse import urljoin, urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init(autoreset=True)

class Out:
    @staticmethod
    def info(m): print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {m}")
    @staticmethod
    def good(m): print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {m}")
    @staticmethod
    def warn(m): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {m}")
    @staticmethod
    def bad(m): print(f"{Fore.RED}[-]{Style.RESET_ALL} {m}")

class SpecterCore:
    def __init__(self, domain, wordlist=None):
        self.domain = domain
        self.wordlist = wordlist
        self.data = {
            "target": domain,
            "timestamp": datetime.now().isoformat(),
            "dns": {},
            "whois": {},
            "subdomains": set(),
            "web": {},
            "ssl": {},
            "archive": [],
            "emails": set(),
            "tech": set(),
            "security_headers": {}
        }

    def run_all(self):
        Out.info("Initiating full OSINT cycle...")
        DNSModule(self).execute()
        WHOISModule(self).execute()
        SubdomainModule(self).execute()
        WebModule(self).execute()
        SSLModule(self).execute()
        ArchiveModule(self).execute()
        ReportModule(self).export()

class DNSModule:
    def __init__(self, core): self.core = core
    def execute(self):
        Out.info("DNS Enumeration...")
        types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        for qtype in types:
            try:
                ans = dns.resolver.resolve(self.core.domain, qtype)
                self.core.data['dns'][qtype] = [str(r) for r in ans]
                for r in ans: Out.good(f"{qtype}: {r}")
            except Exception as e:
                self.core.data['dns'][qtype] = []

class WHOISModule:
    def __init__(self, core): self.core = core
    def execute(self):
        Out.info("WHOIS Lookup...")
        try:
            w = whois.whois(self.core.domain)
            self.core.data['whois'] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "org": w.org,
                "emails": w.emails
            }
            Out.good(f"Registrar: {w.registrar}")
        except Exception as e:
            Out.bad(f"WHOIS failed: {e}")

class SubdomainModule:
    def __init__(self, core): self.core = core
    def execute(self):
        Out.info("Subdomain Discovery...")
        self._crtsh()
        self._brute()
        Out.good(f"Total subdomains found: {len(self.core.data['subdomains'])}")

    def _crtsh(self):
        try:
            url = f"https://crt.sh/?q=%.{self.core.domain}&output=json"
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                for entry in r.json():
                    name = entry.get('name_value')
                    if name:
                        for sub in name.split('\n'):
                            if '*' not in sub:
                                self.core.data['subdomains'].add(sub.strip())
        except Exception as e:
            Out.bad(f"CRT.SH error: {e}")

    def _brute(self):
        wordlist = []
        if self.core.wordlist and os.path.exists(self.core.wordlist):
            with open(self.core.wordlist) as f:
                wordlist = [x.strip() for x in f.readlines()]
        else:
            wordlist = ["www","mail","ftp","localhost","webmail","admin","portal","api","test","dev","staging","vpn","dns","mx","pop","imap","cpanel","webdisk","ns1","ns2","autodiscover","autoconfig","blog","shop","forum","webdav","smtp"]
        
        def check(sub):
            host = f"{sub}.{self.core.domain}"
            try:
                dns.resolver.resolve(host, 'A')
                self.core.data['subdomains'].add(host)
                Out.good(f"Subdomain: {host}")
            except:
                pass

        with ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(check, wordlist))

class WebModule:
    def __init__(self, core): self.core = core
    def execute(self):
        Out.info("Web Reconnaissance...")
        url = f"http://{self.core.domain}"
        try:
            r = requests.get(url, timeout=15, headers={"User-Agent":"Mozilla/5.0"})
            headers = r.headers
            body = r.text
            
            # Headers
            self.core.data['web']['server'] = headers.get('Server')
            self.core.data['web']['powered_by'] = headers.get('X-Powered-By')
            Out.good(f"Server: {headers.get('Server')}")

            # Security Headers
            sec_headers = ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options",
                           "X-Content-Type-Options","Referrer-Policy","Permissions-Policy"]
            for h in sec_headers:
                self.core.data['security_headers'][h] = headers.get(h, "MISSING")
                if headers.get(h):
                    Out.good(f"Security Header {h}: Present")
                else:
                    Out.warn(f"Security Header {h}: MISSING")

            # Tech Detection
            sigs = {
                "WordPress": ["wp-content","wp-includes"],
                "Drupal": ["drupal.js","/sites/default"],
                "Joomla": ["Joomla","/media/system/js/"],
                "React": ["reactroot","__REACT_"],
                "Angular": ["ng-app","angular"],
                "jQuery": ["jquery"],
                "PHP": [".php"],
                "Apache": ["Apache"],
                "Nginx": ["nginx"],
                "IIS": ["IIS"],
                "Cloudflare": ["cloudflare"]
            }
            for tech, patterns in sigs.items():
                if any(p in body or p in str(headers) for p in patterns):
                    self.core.data['tech'].add(tech)
                    Out.good(f"Technology: {tech}")

            # Email Extraction
            emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body))
            self.core.data['emails'].update(emails)
            for e in emails: Out.good(f"Email found: {e}")

            # Robots & Sitemap
            for path in ["/robots.txt","/sitemap.xml"]:
                try:
                    rr = requests.get(urljoin(url, path), timeout=10)
                    if rr.status_code == 200:
                        self.core.data['web'][path.strip('/')] = rr.text[:2000]
                        Out.good(f"{path} retrieved")
                except:
                    pass

        except Exception as e:
            Out.bad(f"Web recon failed: {e}")

class SSLModule:
    def __init__(self, core): self.core = core
    def execute(self):
        Out.info("SSL/TLS Analysis...")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.core.domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.core.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    self.core.data['ssl'] = {
                        "subject": cert.get('subject'),
                        "issuer": cert.get('issuer'),
                        "not_after": cert.get('notAfter'),
                        "not_before": cert.get('notBefore'),
                        "serial": cert.get('serialNumber'),
                        "alt_names": cert.get('subjectAltName'),
                        "tls_version": ssock.version(),
                        "cipher": cipher[0]
                    }
                    Out.good(f"TLS Version: {ssock.version()}")
                    Out.good(f"Cipher: {cipher[0]}")
        except Exception as e:
            Out.bad(f"SSL error: {e}")

class ArchiveModule:
    def __init__(self, core): self.core = core
    def execute(self):
        Out.info("Wayback Machine Enumeration...")
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.core.domain}/*&output=json&fl=original&collapse=urlkey"
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                data = r.json()
                self.core.data['archive'] = [x[0] for x in data[1:101]]  # Top 100
                Out.good(f"Wayback URLs: {len(self.core.data['archive'])}")
        except Exception as e:
            Out.bad(f"Archive error: {e}")

class ReportModule:
    def __init__(self, core): self.core = core

    def export(self):
        self._json()
        self._html()

    def _json(self):
        fname = f"{self.core.domain}_report.json"
        with open(fname, 'w') as f:
            d = self.core.data.copy()
            d['subdomains'] = list(d['subdomains'])
            d['emails'] = list(d['emails'])
            d['tech'] = list(d['tech'])
            json.dump(d, f, indent=2)
        Out.good(f"JSON Report: {fname}")

    def _html(self):
        fname = f"{self.core.domain}_report.html"
        d = self.core.data
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>OSINT: {d['target']}</title>
<style>
body{{font-family:monospace;background:#0a0a0a;color:#00ff41;margin:20px}}
h1,h2{{color:#fff;border-bottom:1px solid #333;padding-bottom:5px}}
.section{{background:#111;padding:15px;margin-bottom:15px;border-left:3px solid #00ff41}}
.missing{{color:#ff4444}} .good{{color:#00ff41}} .warn{{color:#ffaa00}}
</style></head><body>
<h1>SPECTER-OSINT REPORT</h1>
<div class="section"><h2>TARGET</h2><p>{d['target']}<br>Scan Time: {d['timestamp']}</p></div>

<div class="section"><h2>DNS RECORDS</h2><pre>{json.dumps(d['dns'], indent=2)}</pre></div>

<div class="section"><h2>WHOIS</h2><pre>{json.dumps(d['whois'], indent=2)}</pre></div>

<div class="section"><h2>SUBDOMAINS ({len(d['subdomains'])})</h2><ul>{''.join(f'<li>{s}</li>' for s in d['subdomains'])}</ul></div>

<div class="section"><h2>TECHNOLOGIES</h2><p>{', '.join(d['tech']) or 'None detected'}</p></div>

<div class="section"><h2>SECURITY HEADERS</h2><ul>
{''.join(f'<li class="{"missing" if v=="MISSING" else "good"}">{k}: {v}</li>' for k,v in d['security_headers'].items())}
</ul></div>

<div class="section"><h2>EMAILS</h2><ul>{''.join(f'<li>{e}</li>' for e in d['emails']) or '<li>None</li>'}</ul></div>

<div class="section"><h2>SSL/TLS</h2><pre>{json.dumps(d['ssl'], indent=2)}</pre></div>

<div class="section"><h2>WAYBACK URLS (Top 100)</h2><ul>{''.join(f'<li><a href="{u}" style="color:#00ff41">{u}</a></li>' for u in d['archive'][:50])}</ul></div>

<div class="section"><h2>RAW WEB DATA</h2><pre>{json.dumps(d['web'], indent=2)}</pre></div>
</body></html>"""
        with open(fname, 'w', encoding='utf-8') as f:
            f.write(html)
        Out.good(f"HTML Report: {fname}")

def main():
    parser = argparse.ArgumentParser(description="SPECTER-OSINT v1.0")
    parser.add_argument("-d","--domain", required=True, help="Target domain")
    parser.add_argument("--dns", action="store_true", help="DNS enumeration only")
    parser.add_argument("--whois", action="store_true", help="WHOIS lookup only")
    parser.add_argument("--subs", action="store_true", help="Subdomain discovery only")
    parser.add_argument("--web", action="store_true", help="Web recon only")
    parser.add_argument("--ssl", action="store_true", help="SSL analysis only")
    parser.add_argument("--archive", action="store_true", help="Wayback only")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("-w","--wordlist", help="Subdomain wordlist")
    args = parser.parse_args()

    core = SpecterCore(args.domain, args.wordlist)

    if args.all or not any([args.dns, args.whois, args.subs, args.web, args.ssl, args.archive]):
        core.run_all()
    else:
        if args.dns: DNSModule(core).execute()
        if args.whois: WHOISModule(core).execute()
        if args.subs: SubdomainModule(core).execute()
        if args.web: WebModule(core).execute()
        if args.ssl: SSLModule(core).execute()
        if args.archive: ArchiveModule(core).execute()
        ReportModule(core).export()

if __name__ == "__main__":
    main()
