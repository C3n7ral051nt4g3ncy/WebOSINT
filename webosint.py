#!/usr/bin/env python3
# File name   : webosint.py
# Tool name   : W3b0s1nt (WebOSINT)
# Author      : @C3n7ral051nt4g3ncy
# Version     : V2.1
# Licence     : MIT
# Script Info : WebOSINT is a passive Domain Intelligence recon tool, a Swiss army knife with 8 modules


# Py Libs
import re
import whois
import socket
import requests
import time
import sys
# import readline
import json
from pprint import pprint
from pycrtsh import Crtsh
from dateutil.parser import parse
from requests import get


class MyCrtsh:
    def search(self, query, timeout=None):
        """
        Search crt.sh with the give query
        Query can be domain, sha1, sha256...
        """
        r = requests.get('https://crt.sh/', params={'q': query, 'output': 'json'}, timeout=timeout)
        nameparser = re.compile("([a-zA-Z]+)=(\"[^\"]+\"|[^,]+)")
        certs = []
        try:
            for c in r.json():
                if not c['entry_timestamp']:
                    continue
                certs.append({
                    'id': c['id'],
                    'logged_at': parse(c['entry_timestamp']),
                    'not_before': parse(c['not_before']),
                    'not_after': parse(c['not_after']),
                    'name': c['name_value'],
                    'ca': {
                        'caid': c['issuer_ca_id'],
                        'name': c['issuer_name'],
                        'parsed_name': dict(nameparser.findall(c['issuer_name']))
                    }
                })
        except json.decoder.JSONDecodeError:
            pass
        return certs


# W3b0s1nt Banner
print("""\033[0;35m
*═════════════════════════════════════════════════════════════════════*                                                               
█  ██╗    ██╗██████╗ ██████╗  ██████╗ ███████╗ ██╗███╗   ██╗████████╗ █
█  ██║    ██║╚════██╗██╔══██╗██╔═████╗██╔════╝███║████╗  ██║╚══██╔══╝ █
█  ██║ █╗ ██║ █████╔╝██████╔╝██║██╔██║███████╗╚██║██╔██╗ ██║   ██║    █
█  ██║███╗██║ ╚═══██╗██╔══██╗████╔╝██║╚════██║ ██║██║╚██╗██║   ██║    █
█  ╚███╔███╔╝██████╔╝██████╔╝╚██████╔╝███████║ ██║██║ ╚████║   ██║    █
█   ╚══╝╚══╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝    █
█ V1.1.4                                                              █
█ W3b0s1nt: Domain Intelligence                                       █                                                         
*═════════════════════════════════════════════════════════════════════*\033[0m\033[0;32m 
  ╔═══════════════════════════════════════════════════════════════╗
  ║ by C3n7ral051nt4g3ncy                                         ║      
  ║ Github.com/C3n7ral051nt4g3ncy                                 ║                                                                            
  ║ Contributions(BTC):bc1q66awg48m2hvdsrf62pvev78z3vkamav7chusde ║
  ║ Licence:MIT                                                   ║
  ╚═══════════════════════════════════════════════════════════════╝
  \033[0m""")
time.sleep(3)

# What the script does (Sequence)
print("[1]Domain Registration Check"
      "\n[2]Get Domain IP + Data"
      "\n[3]Reverse IP Search -extract Domains with same IP (HackerTarget API)"
      "\n[4]Get DNS Records (HackerTarget API)"
      "\n[5]Whois Domain Information"
      "\n[6]Domain CERT search (CRT.SH)"
      "\n[7]Domain Reputation search WhoisXML"
      "\n[8]Subdomain scan"
      "\n[9]Historical Whois")

with open('config.json', 'r') as f:
    config = json.load(f)

WHOIS_XML_API_KEY = config['WHOIS_XML_API_KEY']
HACKERTARGET_API_KEY = config['HACKERTARGET_API_KEY']
WHOIS_FREAKS_API_KEY = config['WHOIS_FREAKS_API_KEY']


# Checking if the domain is registered
def registrationstatus(domain_name):
    """
    Checking whether the domain is registered or not
    """

    try:
        dn = whois.whois(domain_name)
    except Exception:
        return False
    else:
        return bool(dn.domain_name)


print("\nLet's start by checking if the domain is registered!")
query = input("\n\033[0;35m\033[1mDomain Name: \033[0m")
domain = query
print(domain, "\033[0;32m...searching for domain registration\n")
print(domain, "\033[0;32m\033[1m is registered ✅ \033[0m" if registrationstatus(
    domain) else "\033[0;31m\033[1m is not registered ❌ \033[0m")


# Get domain IP Address
def domain_ip():
    """
    Find Domain ip address
    """

    website = query
    try:
        domain_ip = socket.gethostbyname(website)

    except Exception as e:
        return


    print("\n\033[0;35m\033[1mDomain IP: \033[1m\033[0;32m\n")
    print(domain_ip)

    ip_address = domain_ip
    response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()
    print("\n\033[0;35m\033[1mIP Data:\n\033[0m\033[0;32m")
    pprint(response)

    print("\n\n\033[0;35m\033[1mDouble IP verification using IPinfo.io")
    print("\n\033[0;35m\033[1mResults:\033[0m\033[0;32m")

    response = requests.get(f'https://ipinfo.io/{ip_address}/json')
    data = json.loads(response.text)

    ip = data['ip']
    organization = data['org']
    city = data['city']
    region = data['region']
    country = data['country']
    location = data['loc']
    postal = data['postal']
    timezone = data['timezone']

    print("ip:", ip)
    print("organization:", organization)
    print("city:", city)
    print("region:", region),\
    print("country:", country)
    print("postal:", postal)
    print("location:", location)
    print("timezone", timezone)

    choice = input("\n\n\033[0;35m\033[1mExtract domains with the same IP?\033[0m y/n: ")
    if choice == "y" or choice == "Y":
        rev_ip(domain_ip, website)
    if choice == "n" or choice == "N":
        dns_records(website)
    else:
        print("You pressed the wrong key; choose Y or N, please start again")
        sys.exit(1)


# Reverse IP lookup intro - choice of limited free search or API Key
def rev_ip(domain_ip, domain):
    """
    Choose Reverse ip for free or with your API
    """

    print(
        "\n\n\033[1m!!! Hacker Target will give you a few tries for free, then you will need to change your ip or to use your API Key!!!\033[0m")

    choice = input(
        """\n\033[0;35m\033[1mType -F for Free Search, or Type -API for usage with your own API Key: \033[0m""")
    if choice == "-F" or choice == "-f" or choice == "F" or choice == "f":
        rev_ip_free(domain_ip, domain)
    if choice == "-API" or choice == "-api" or choice == "API" or choice == "api":
        rev_ip_api(domain_ip, domain)

    else:
        print(
            "You pressed the wrong key; choose -F for free search or -API for usage with your API Key, please start again")
        sys.exit(1)


# Reverse IP lookup using limited searches with the Hacker Target free test API to extract all domains using the same IP
def rev_ip_free(domain_ip, domain):
    """
    Reverse IP search for Free
    """

    # Returning and printing the status code
    print("\n\033[0;32mOne moment ...checking Hackertarget.com status\033[0m")
    URL = 'http://api.hackertarget.com/reverseiplookup'
    request = requests.get(URL)

    if request.status_code == 200:
        print(
            "\n\033[0;32mstatus code 200!\033[0m Hacker Target is \033[0;32m\033[1monline\033[0m\033[0;35m\033[1m\n\nReverse IP search results:\033[0m\033[0;32m\n")
    else:
        print('\033[0;32mResponse Failed, try again later')

    # Free Hacker Target API with limited searches
    ht_api = "http://api.hackertarget.com/reverseiplookup"
    domain_ip = {"q": domain_ip}
    response = requests.request("GET", ht_api, params=domain_ip)
    print(response.text)

    choice = input("\n\n\033[0;35m\033[1mContinue to DNS Records search?\033[0m y/n: ")
    if choice == "y" or choice == "Y":
        dns_records(domain)
    if choice == "n" or choice == "N":
        whois_search()

    else:
        print("You pressed the wrong key; choose Y or N, please start again")
        sys.exit(1)


# Reverse IP lookup using Hacker Target API to extract all domains using the same IP address
def rev_ip_api(domain_ip, domain):
    """
    Reverse IP search with API
    """

    # Returning and printing the status code (200 means the server was reached).
    print("\n\033[0;32mOne moment ...checking Hackertarget.com status\033[0m")
    URL = 'http://api.hackertarget.com/reverseiplookup'

    request = requests.get(URL)
    if request.status_code == 200:
        print(
            "\n\n\033[0;32mstatus code 200!\033[0m Hacker Target is \033[0;32m\033[1monline\033[0m\033[0;35m\033[1m\n\nReverse IP search results:\033[0m\033[0;32m\n")

    else:
        print('\033[0;32mResponse Failed, try again later')

    # Using your own Hacker Target API to avoid restrictions
    query = domain_ip
    domain_ip = {"q": query}
    api = f"https://api.hackertarget.com/reverseiplookup/?q={query}&apikey={HACKERTARGET_API_KEY}"
    response = requests.request("GET", api, params=domain_ip)
    print(response.text)

    choice = input("\n\n\033[0;35m\033[1mContinue to DNS Records search?\033[0m y/n: ")

    if choice == "y" or choice == "Y":
        dns_records(domain)
    if choice == "n" or choice == "N":
        whois_search()

    else:
        print("You pressed the wrong key; choose Y or N, please start again")
        sys.exit(1)


# Search DNS Records (choose Free Search or using Hacker Target API KEY)
def dns_records(domain):
    """
    Choose Free Search or API
    """

    choice = input(
        """\n\033[0;35m\033[1mType -F for Free Search, or Type -API for usage with your own API Key: \033[0m""")
    if choice == "-F" or choice == "-f" or choice == "F" or choice == "f":
        dns_records_free(domain)
    if choice == "-API" or choice == "-api" or choice == "API" or choice == "api":
        dns_records_api(domain)

    else:
        print(
            "You pressed the wrong key; choose -F for free search or -API for usage with your API Key, please start again")
        sys.exit(1)


# Search DNS Records free
def dns_records_free(domain):
    """
    DNS Records check
    """

    print("\n\033[0;35m\033[1mDNS Records search results:\033[0m\033[0;32m\n")
    dnsrecords_api = "https://api.hackertarget.com/dnslookup/"

    dns_records = {"q": domain}
    response = requests.request("GET", dnsrecords_api, params=dns_records)
    print(response.text)

    choice = input("\n\n\033[0;35m\033[1mDo a Whois scan? y/n: \033[0m")
    if choice == "y" or choice == "Y":
        whois_search()
    if choice == "n" or choice == "N":
        sys.exit(1)

    else:
        print("You pressed the wrong key; choose Y or N, please start again")
        sys.exit(1)


# Using your own Hacker Target API to avoid restrictions
def dns_records_api(domain):
    """
    DNS Records check with API
    """
    print("\n\033[0;35m\033[1mDNS Records search results:\033[0m\033[0;32m\n")
    dns_records = {"q": domain}
    api = f"https://api.hackertarget.com/dnslookup/?q={domain}&apikey={HACKERTARGET_API_KEY}"
    response = requests.request("GET", api, params=dns_records)
    print(response.text)

    choice = input("\n\n\033[0;35m\033[1mDo a Whois scan? y/n: \033[0m")
    if choice == "y" or choice == "Y":
        whois_search()
    if choice == "n" or choice == "N":
        sys.exit(1)

    else:
        print("You pressed the wrong key; choose Y or N, please start again")
        sys.exit(1)


# Search further domain information with the Whois module
def whois_search():
    """
    WHOis information search
    """

    print("\n\n\033[0;35m\033[1mLet's try and find more domain information!\033[0m")
    webdomain = query
    domain_name = webdomain
    whois_information = whois.whois(domain_name)

    # WHOis results easy to read.
    print("\n\033[0;32mDomain Name:", whois_information.domain_name)
    print("\nDomain registrar:", whois_information.registrar)
    print("\nWHOis server:", whois_information.whois_server)
    print("\nDomain creation date:", whois_information.creation_date)
    print("\nExpiration date:", whois_information.expiration_date)
    print("\nUpdated Date:", whois_information.updated_date)
    print("\nServers:", whois_information.name_servers)
    print("\nStatus:", whois_information.status)
    print("\nEmail Addresses:", whois_information.emails)
    print("\nName:", whois_information.name)
    print("\nOrg:", whois_information.org)
    print("\nAddress:", whois_information.address)
    print("\nCity:", whois_information.city)
    print("\nState:", whois_information.state)
    print("\nZipcode:", whois_information.zipcode)
    print("\nCountry:", whois_information.country)

    # Sleeping time so the user can view the results without the script moving too fast
    time.sleep(3)

    choice = input("\n\n\033[0;35m\033[1mCheck domain CERT (Certificate)?\033[0m y/n: ")
    if choice == "Y" or choice == "y":
        crt_sh(domain_name)
    if choice == "N" or choice == "n":
        domain_reputation(domain_name)

    else:
        print("You pressed the wrong key; choose Y or N, please start again")
        sys.exit(1)


# Site Certificate search with CRT.SH
def crt_sh(domain_name):
    c = MyCrtsh()
    certs = c.search(domain_name)
    print("\n\033[0;35m\033[1mWebsite cert. search results:\033[0m\n\033[0;32m")
    pprint(certs[:6])

    time.sleep(3)

    choice = input("\n\n\033[0;35m\033[1mDomain reputation scan?\033[0m y/n: ")
    if choice == "Y" or choice == "y":
        domain_reputation(domain_name)
    if choice == "N" or choice == "n":
        print("\n\n\n\033[0;35m\033[1mBye Bye 😈 !!! You have reached the end of the W3b0s1nt Python script...")
        sys.exit(1)

    else:
        print("You pressed the wrong key; choose Y or N, please start again")
        sys.exit(1)


# Domain Reputation Scan
def domain_reputation(domain_name):
    """
    Domain reputation scan
    """

    print("\n\033[0;35m\033[1mOK! Let's check domain reputation using WhoisXML API\n\033[0m")

    query = domain_name
    reputation = {"q": query}
    api = f"https://domain-reputation.whoisxmlapi.com/api/v2?apiKey={WHOIS_XML_API_KEY}&domainName={query}"
    response = requests.request("GET", api, params=reputation)

    print("\n\n\033[0;35m\033[1mDomain Reputation check results:\n\n\033[0;32m")
    pprint(response.text)

    time.sleep(3)

    choice = input("\n\n\033[0;35m\033[1mLet's do a subdomain scan?\033[0m y/n: ")
    if choice == "Y" or choice == "y":
        subdomain_scanner(domain_name)
    if choice == "N" or choice == "n":
        whois_history(domain_name)


# WebOSINT Subscan (Subdomain Scanner)
def subdomain_scanner(domain_name):
    """
    Subdomain scan
    """

    subdomains_found = []

    sdsreq = requests.get(f'https://crt.sh/?q={domain_name}&output=json')

    if sdsreq.status_code == 200:
        print('\033[0;32m\033[1m\n\nScanning for subdomains now...')

    else:
        print("\033[0;32mThe subdomain scanner tool is currently offline, please try again in a few minutes!\033[0m")
        sys.exit(1)

    for (key, value) in enumerate(sdsreq.json()):
        subdomains_found.append(value['name_value'])

    print(
        f"\n\n\033[0;35m\033[1mYour chosen targeted Domain for the Subdomain scan:\033[0;32m{domain_name}\033[0m\033[0;32m\n")

    subdomains = sorted(set(subdomains_found))

    for sub_link in subdomains:
        print(f'\033[1m[✅ Subdomain Found]\033[0m\033[0;32m -->{sub_link}')

    print("\n\033[1m\033[0;35m\033[1mSubdomain Scan Completed ✔️  -\033[0;32m\033[1mALL Subdomains have been Found")

    time.sleep(3)

    choice = input("\n\n\033[0;35m\033[1mDo you want to finish with a Whois History search?\033[0m y/n: ")
    if choice == "Y" or choice == "y":
        whois_history(domain_name)
    if choice == "N" or choice == "n":
        print("\n\n\n\033[0;35m\033[1mBye Bye 😈 !!! You have reached the end of the W3b0s1nt Python script...")
        sys.exit(1)


# Whois History using your WhoisFreaks API Key
def whois_history(domain_name):
    """
    Whois History search
    """

    print("\n\033[0;35m\033[1mOK Let's do this and check Historical Whois using your Whois Freaks API ;-)\n\033[0m")

    time.sleep(2)

    print("\n\033[0;35m\033[1mHistorical Whois results:\n\n\033[0;32m")

    query = domain_name
    whoishistory = {"q": query}
    api = f"https://api.whoisfreaks.com/v1.0/whois?apiKey={WHOIS_FREAKS_API_KEY}&whois=historical&domainName={query}"
    response = requests.request("GET", api, params=whoishistory)
    pprint(response.text)

    time.sleep(3)

    # Farewell Goodbye End of Script Message
    print("\n\n\n\033[0;35m\033[1mBye Bye 😈 !!! You have reached the end of the W3b0s1nt Python script...")
    sys.exit(1)


# Choice to use Dig
choice = input("""\n\n\033[0;35m\033[1mFind domain IP?\033[0m  y/n: """)
if choice == "Y" or choice == "y":
    domain_ip()
if choice == "N" or choice == "n":
    dns_records(query)
else:
    print("\n\nDomain IP not found for:")
    print(domain)
    print("This means that you will now be taken straight to the Reverse DNS search module...")
    dns_records(domain)


# Main.
def main():
    registrationstatus()
    domain_ip()
    rev_ip()
    rev_ip_free()
    rev_ip_api()
    dns_records()
    dns_records_free()
    dns_records_api()
    whois_search()
    crt_sh()
    domain_reputation()
    subdomain_scanner()
    whois_history()


if __name__ == '__main__':
    main()
