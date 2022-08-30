import sys
import shodan
from termcolor import colored
import requests
import json

# Insert your own API keys here:
SHODAN_API_KEY = "YOUR_API_KEY"
ABUSEIPDB_API_KEY = "YOUR_API_KEY"
VIRUSTOTAL_API_KEY = "YOUR_API_KEY"

# Shodan IP check
def shodan_check(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    
    # Lookup the host
    host = api.host(ip)

    # Print general info
    print(colored("""
  ___ _            _           
 / __| |_  ___  __| |__ _ _ _  
 \__ \ ' \/ _ \/ _` / _` | ' \ 
 |___/_||_\___/\__,_\__,_|_||_|


IP: {}
Organization: {}
Operating System: {}

    """, "red").format(host["ip_str"], host.get("org", "n/a"), host.get("os", "n/a")))

    # Print all banners
    for item in host["data"]:
        print(colored("""
Port: {}
Banner: {}
        """, "red").format(item["port"], item["data"]))

# AbuseIPDB check
def abuseipdb_check(ip):
    
    # Define API endpoint
    url = "https://api.abuseipdb.com/api/v2/check"

    # Define API parameters
    querystring = {
        "ipAddress": ip
        # "verbose": true
    }

    # Define headers
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    # Make the request
    response = requests.request("GET", url=url, headers=headers, params=querystring)
    response = json.loads(response.text)
    data = response["data"]

    # Print data from query
    print(colored("""
    _   _                 ___ ___ ___  ___ 
   /_\ | |__ _  _ ___ ___|_ _| _ \   \| _ )
  / _ \| '_ \ || (_-</ -_)| ||  _/ |) | _ )
 /_/ \_\_.__/\_,_/__/\___|___|_| |___/|___/
                                                                                 

IP: {}
Abuse Score: {}
Usage Type: {}
ISP: {}
Domain: {}
Number of Reports: {}
    """, "green").format(data["ipAddress"], data["abuseConfidenceScore"], data["usageType"], data["isp"], data["domain"], data["totalReports"]))


# VirusTotal check
def virustotal_check(ip):

    # Define API endpoint
    url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(ip)

    # Define headers
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    # Make the request
    response = requests.request("GET", url=url, headers=headers)
    response = json.loads(response.text)
    data = response["data"]

    print(colored("""
 __   ___             _____    _        _ 
 \ \ / (_)_ _ _  _ __|_   _|__| |_ __ _| |
  \ V /| | '_| || (_-< | |/ _ \  _/ _` | |
   \_/ |_|_|  \_,_/__/ |_|\___/\__\__,_|_|
                                          

IP: {}
Country: {}
Latest Reports:
    Harmless: {}
    Malicious: {}
    Suspicious: {}
    Undetected: {}
    Timeout: {}
    """, "blue").format(data["id"], data["attributes"]["country"], data["attributes"]["last_analysis_stats"]["harmless"], data["attributes"]["last_analysis_stats"]["malicious"], data["attributes"]["last_analysis_stats"]["suspicious"], data["attributes"]["last_analysis_stats"]["undetected"], data["attributes"]["last_analysis_stats"]["timeout"]))

# Check input is in the correct format
if len(sys.argv) != 2:
    print("Usage: %s <IP>" % sys.argv[0])
    sys.exit(1)

if SHODAN_API_KEY != "YOUR_API_KEY" and SHODAN_API_KEY != "":
    shodan_check(sys.argv[1])

if ABUSEIPDB_API_KEY != "YOUR_API_KEY" and ABUSEIPDB_API_KEY != "":
    abuseipdb_check(sys.argv[1])

if VIRUSTOTAL_API_KEY != "YOUR_API_KEY" and VIRUSTOTAL_API_KEY != "":
    virustotal_check(sys.argv[1])
