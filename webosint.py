#!/usr/bin/env python3
# File name          : webosint.py
# Tool name          : W3b0s1nt
# Author             : @C3n7ral051nt4g3ncy
# Version            : V1.1.2
# Licence            : MIT
# Script release     : July 2022


# Py Libs
import whois
import socket
import requests
import time
import sys
from pprint import pprint



# W3b0s1nt Banner.
print("""\033[0;35m
*═════════════════════════════════════════════════════════════════════*                                                               
█  ██╗    ██╗██████╗ ██████╗  ██████╗ ███████╗ ██╗███╗   ██╗████████╗ █
█  ██║    ██║╚════██╗██╔══██╗██╔═████╗██╔════╝███║████╗  ██║╚══██╔══╝ █
█  ██║ █╗ ██║ █████╔╝██████╔╝██║██╔██║███████╗╚██║██╔██╗ ██║   ██║    █
█  ██║███╗██║ ╚═══██╗██╔══██╗████╔╝██║╚════██║ ██║██║╚██╗██║   ██║    █
█  ╚███╔███╔╝██████╔╝██████╔╝╚██████╔╝███████║ ██║██║ ╚████║   ██║    █
█   ╚══╝╚══╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝    █
█ V1.1.2                                                              █
█ W3b0s1nt: Domain Intelligence                                       █                                                         
*═════════════════════════════════════════════════════════════════════*\033[0m\033[0;32m 
  ╔═══════════════════════════════════════════════════════════════╗
  ║ by C3n7ral051nt4g3ncy                                         ║      
  ║ Github.com/C3n7ral051nt4g3ncy                                 ║                                                                            
  ║ Contributions(₿TC):bc1q66awg48m2hvdsrf62pvev78z3vkamav7chusde ║
  ║ Licence:MIT                                                   ║
  ║ Code:Python                                                   ║
  ╚═══════════════════════════════════════════════════════════════╝
  \033[0m""")
time.sleep(3)

# What the script does (in order)
print("[1]Domain Registration Check"
      "\n[2]Get Domain IP"
      "\n[3]Reverse IP Search -extract Domains with same IP (HackerTarget API)"
      "\n[4]Get DNS Records (HackerTarget API)"
      "\n[5]Whois Domain Information"
      "\n[6]Domain Reputation WhoisXML")



# Checking if the domain is registered.
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
query = input("\nDomain Name: ")
domain = query
print(domain, "...searching for domain registration\n\n")
print(domain, "\033[0;32m\033[1m is registered ✅ \033[0m" if registrationstatus(domain) else "\033[0;31m\033[1m is not registered ❌ \033[0m")



# Get domain IP Address.
def domain_ip():
    """
    Find Domain ip address
    """
    website = query
    domain_ip = socket.gethostbyname(website)
    print("\n\nDomain IP: \033[0;32m")
    print(domain_ip)

    ip_address = domain_ip
    response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()
    print("\nIP Location Data/ORG/ASN/Version:\n")
    print(("City:")+ response['city'])
    print(("Country:")+ response['country_name'])
    print(("Country Capital:")+ response['country_capital'])
    print(("Country Code:")+ response['country_code'])
    print(("Continent Code:") + response['continent_code'])
    print(("Organization:")+ response['org'])
    print(("ASN:")+ response['asn'])
    print(("Version:")+ response['version'])

    choice = input("\n\nReverse Search ip using HackerTarget API? y/n: ")
    if choice == "y" or choice == "Y":
        rev_ip()
    if choice == "n" or choice == "N":
        dns_records()



# Reverse IP lookup intro - choice of limited free search or API Key usage.
def rev_ip():
    """
    Choose Reverse ip for free or with API
    """
    print("\n\033[0;31m\U0001F6AB \033[1mHacker Target will give you a few tries, then you will need to change ip or to use an API Key!!!\033[0m")

    choice = input("""\nChoose "F" for Free Search, or "API" for usage with your own API Key: """)
    if choice == "F" or choice == "f":
        rev_ip_free()
    if choice == "API" or choice == "api":
        rev_ip_api()



# Reverse IP lookup using limited searches with the Hacker Target free test API to extract all domains using the same IP.
def rev_ip_free():
    """
    Reverse IP search for Free
    """

# Returning and printing the status code.
    print("\n\033[0;32mOne moment ...checking Hacker Target status\033[0m")
    URL = 'http://api.hackertarget.com/reverseiplookup'
    request = requests.get(URL)
    if request.status_code == 200:
        print("\n\033[0;32mstatus code 200\033[0m: Hacker Target is \033[0;32m\033[1monline\033[0m\n")
    else:
        print ('Response Failed, try again later')



# Free Hacker Target API with limited searches, user will need to regularly change IP address in order to make many daily searches !or to purchase the annual Hacker Target API Key).
    ht_api = "http://api.hackertarget.com/reverseiplookup"
    query = input("Type or paste the target IP: ")
    domain_ip = {"q":query}
    response = requests.request("GET", ht_api, params=domain_ip)
    print(response.text)

    choice = input("\n\ncontinue to DNS Records check? y/n: ")
    if choice == "y" or choice == "Y":
        dns_records()
    if choice == "n" or choice =="N":
        whois_search()



# Reverse IP lookup using Hacker Target API to extract all domains using the same IP address.
def rev_ip_api():
    """
    Reverse IP search with API
    """
# Returning and printing the status code (200 means the server was reached).
    print("\n\033[0;32mOne moment ...checking Hacker Target status\033[0m")
    URL = 'http://api.hackertarget.com/reverseiplookup'

    request = requests.get(URL)
    if request.status_code == 200:
        print("\n\033[0;32mstatus code 200\033[0m: Hacker Target is \033[0;32m\033[1monline\033[0m\n")
    else:
        print('Response Failed, try again later')

# Using your own Hacker Target API to avoid restrictions.
    query = input("Type or paste IP: ")
    apikey = input("Paste Hacker Target API: ")
    domain_ip = {"q": query}
    api = f"https://api.hackertarget.com/reverseiplookup/?q={query}&apikey={apikey}"
    response = requests.request("GET", api, params=domain_ip)
    print(response.text)

    choice = input("\n\n\033[0;32m\033[1mcontinue to DNS RECORDS search? y/n: \033[0m")

    if choice == "y" or choice == "Y":
        dns_records()
    if choice == "n" or choice == "N":
        whois_search()



# Search DNS Records (choose Free Search or using Hacker Target API KEY)
def dns_records():
    """
    Choose Free Search or API
    """

    print("\n\033[0;31m\U0001F6AB \033[1mHacker Target will give you a few tries, then you will need to change ip or to use your API Key!!!\033[0m")
    choice = input("""\nChoose "F" for Free Search, or "API" for usage with your own API Key: """)
    if choice == "F" or choice == "f":
        dns_records_free()
    if choice == "API" or choice == "api":
        dns_records_api()



# Search DNS Records free.
def dns_records_free():
    """
    DNS Records check
    """

    dnsrecords_api = "https://api.hackertarget.com/dnslookup/"

    dns_records = {"q": query}
    response = requests.request("GET", dnsrecords_api, params=dns_records)
    print(response.text)

    choice = input("\n\n\033[0;32m\033[1mcontinue to WHOis Search? y/n: \033[0m")
    if choice == "y" or choice == "Y":
        whois_search()
    if choice == "n" or choice == "N":
        sys.exit(1)




# Using your own Hacker Target API to avoid restrictions.
def dns_records_api ():
    """
    DNS Records check with API
    """
    query = input("""Domain name to check DNS RECORDS (for example "google.com" !!!Do not put www. before the domain): """)
    apikey = input("Paste your Hacker Target API: ")
    dns_records = {"q": query}
    api = f"https://api.hackertarget.com/dnslookup/?q={query}&apikey={apikey}"
    response = requests.request("GET", api, params=dns_records)
    print(response.text)

    choice = input("\n\n\033[0;32m\033[1mContinue to WHOIS Search? y/n: \033[0m")
    if choice == "y" or choice == "Y":
        whois_search()
    if choice == "n" or choice == "N":
        sys.exit(1)



# Search further domain information with the Whois module.
def whois_search():
    """
    WHOis information search
    """

    print("\n\nLet's try and find more domain information!")
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
    print("\nCountry:\033[0m", whois_information.country)

# Sleeping time so the user can view the results without the script moving too fast.
    time.sleep(3)

    choice = input("\n\nDo you want to run a domain reputation scan? y/n: ")
    if choice == "Y" or choice == "y":
        domain_reputation()
    if choice =="N" or choice == "n":
        print("\n\n\n\033[0;35m\033[1mBye Bye 😈 you have reached the end of the W3b0s1nt Python script...")
        sys.exit(1)

def domain_reputation():
    """
    Domain reputation search
    """
    print("\nOK! Let's finish with a domain reputation check with WhoisXML 👾 🔎 \n")
    query = input("""Type domain you want to check: """)
    yourapi = input("Paste your WhoisXML Api Key: ")
    reputation = {"q": query}
    api = f"https://domain-reputation.whoisxmlapi.com/api/v2?apiKey={yourapi}&domainName={query}"
    response = requests.request("GET", api, params=reputation)
    print("\nDomain Reputation check results:\n")
    pprint(response.text)
    time.sleep(12)

# Farewell Goodbye End of Script Message.
    print("\n\n\n\033[0;35m\033[1mBye Bye 😈 you have reached the end of the W3b0s1nt Python script...")
    sys.exit(1)


# Choice to use Dig.
choice = input("""\nFind domain IP address? y/n: """)
if choice == "Y" or choice == "y":
    domain_ip()
if choice == "N" or choice == "n":
    dns_records()




# Main.
def main():
    registrationstatus()
    domain_ip()
    rev_ip()
    rev_ip_free()
    rev_ip_api ()
    dns_records()
    dns_records_free()
    dns_records_api()
    whois_search()
    domain_reputation()




if __name__ == '__main__':
    main()