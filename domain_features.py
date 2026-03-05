import base64
import pandas as pd
import csv
from pyexpat import features
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse


def get_domain(url):
    """Extracts the base domain name for WHOIS lookups."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
        # Remove 'www.' for cleaner WHOIS queries
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except:
        return ""


def extract_domain_features(url):
    domain = get_domain(url)

    # Initialize defaults. We assume -1 (Phishing) if WHOIS fails,
    # but default to 1 for the APIs we aren't querying yet.
    features = {
        "age_of_domain": -1, "DNSRecord": -1,
        "Domain_registeration_length": -1, "Abnormal_URL": -1,
        "web_traffic": 1, "Page_Rank": 1,
        "Google_Index": 1, "Links_pointing_to_page": 1,
        "Statistical_report": 1
    }

    try:
        # Query the WHOIS database
        domain_info = whois.whois(domain)

        # 1. DNS Record [cite: 138-141]
        # Rule: IF no DNS Record For The Domain -> Phishing (-1) Otherwise -> Legitimate (1) [cite: 140-141]
        if domain_info.domain_name == None:
            features["DNSRecord"] = -1
        else:
            features["DNSRecord"] = 1

        # 2. Age of Domain [cite: 134-137]
        # Rule: IF Age Of Domain >= 6 months -> Legitimate (1) Otherwise -> Phishing (-1) [cite: 137]
        creation_date = domain_info.creation_date
        if type(creation_date) is list:
            # Take the first date if multiple exist
            creation_date = creation_date[0]

        if creation_date:
            today = datetime.now()
            age_in_days = (today - creation_date).days
            age_in_months = age_in_days / 30

            if age_in_months >= 6:
                features["age_of_domain"] = 1
            else:
                features["age_of_domain"] = -1
        else:
            features["age_of_domain"] = -1

        # 3. Domain Registration Length
        # Rule: IF Domains Expires on <= 1 years -> Phishing (-1) Otherwise -> Legitimate (1) [cite: 57]
        expiration_date = domain_info.expiration_date
        if type(expiration_date) is list:
            expiration_date = expiration_date[0]

        if expiration_date:
            today = datetime.now()
            days_to_expire = (expiration_date - today).days
            if days_to_expire <= 365:
                features["Domain_registeration_length"] = -1
            else:
                features["Domain_registeration_length"] = 1
        else:
            features["Domain_registeration_length"] = -1

        # 4. Abnormal URL
        # Rule: IF The Host Name Is Not Included In URL -> Phishing (-1) Otherwise -> Legitimate (1) [cite: 108]
        if domain_info.domain_name:
            # Domain name could be a list in some WHOIS responses
            host_name = domain_info.domain_name[0] if type(
                domain_info.domain_name) is list else domain_info.domain_name
            if host_name.lower() not in url.lower():
                features["Abnormal_URL"] = -1
            else:
                features["Abnormal_URL"] = 1
        else:
            features["Abnormal_URL"] = -1

    except Exception as e:
        # If the WHOIS lookup crashes (domain doesn't exist, is blocked, etc.),
        # the defaults remain -1 for the WHOIS-based features.
        pass

    # 5. Website Traffic [cite: 142-148]
    # Rule: <100,000 -> 1, >100,000 -> 0, Otherwise -> -1
    try:
        # Read the CSV using pandas (much faster optimized C backend)
        # We only need the rank (index) and the domain string
        df_tranco = pd.read_csv(
            "tranco_6GPNX-1m.csv/top-1m.csv", header=None, names=['rank', 'domain'])

        # Check if our target domain exists in the 'domain' column
        match = df_tranco[df_tranco['domain'] == domain]

        if not match.empty:
            # Get the rank integer
            rank = match['rank'].values[0]

            if rank < 100000:
                features["web_traffic"] = 1
            else:
                features["web_traffic"] = 0
        else:
            # Not in the top 1 million
            features["web_traffic"] = -1

    except Exception as e:
        print(f"[WARNING] Tranco list failed to load: {e}")
        features["web_traffic"] = -1

    # 6. PageRank [cite: 149-154]
    # Rule: PageRank < 0.2 -> -1, Otherwise -> 1 [cite: 154]
    try:
        url = "https://openpagerank.com/api/v1.0/getPageRank"
        headers = {"API-OPR": "8ogow0s80wgcswk84gg0wckwcckcggccgo8swos4"}
        params = {"domains[]": domain}

        r = requests.get(url, headers=headers, params=params)
        data = r.json()

        rank = data["response"][0]["page_rank_decimal"]

        if rank < 0.2:
            features["Page_Rank"] = -1
        else:
            features["Page_Rank"] = 1
    except:
        features["Page_Rank"] = -1

    # 7. Google Index [cite: 155-159]
    # Rule: Indexed by Google -> 1, Otherwise -> -1 [cite: 159]
    try:
        API_KEY = "36c23eba506df82f1e801a4b474893a0ca2070e48d57905ad714125b433758e0"

        headers = {
            "x-apikey": API_KEY
        }

        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers
        )

        data = r.json()

        if data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            features["Google_Index"] = -1
        else:
            features["Google_Index"] = 1
    except:
        features["Google_Index"] = -1

    # 8. Links Pointing to Page [cite: 160-164]
    # Rule: 0 -> -1, >0 and <=2 -> 0, Otherwise -> 1 [cite: 164]
    try:
        r = requests.get(f"https://api.hackertarget.com/pagelinks/?q={domain}")
        links = r.text.split("\n")
        count = len([l for l in links if l.strip() != ""])

        if count == 0:
            features["Links_pointing_to_page"] = -1
        elif count <= 2:
            features["Links_pointing_to_page"] = 0
        else:
            features["Links_pointing_to_page"] = 1
    except:
        features["Links_pointing_to_page"] = -1

   # 9. Statistical Report [cite: 165-168]
    # Rule: Belongs to Top Phishing IPs/Domains -> -1, Otherwise -> 1
    try:
        # Insert your actual VirusTotal API key here
        vt_api_key = "36c23eba506df82f1e801a4b474893a0ca2070e48d57905ad714125b433758e0"

        # VirusTotal v3 API requires the URL to be base64 encoded to act as the ID
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        headers = {
            "accept": "application/json",
            "x-apikey": vt_api_key
        }

        response = requests.get(vt_endpoint, headers=headers, timeout=5)

        if response.status_code == 200:
            result = response.json()
            # Get the number of security vendors that flagged this URL as malicious/phishing
            malicious_votes = result["data"]["attributes"]["last_analysis_stats"]["malicious"]

            # If even 1 security vendor (like PhishTank or Kaspersky) flags it, we mark as Phishing
            if malicious_votes > 0:
                features["Statistical_report"] = -1
            else:
                features["Statistical_report"] = 1
        else:
            # If the URL hasn't been scanned by VT yet, or API limit reached
            features["Statistical_report"] = 1

    except Exception as e:
        print(f"[WARNING] Statistical Report API failed: {e}")
        features["Statistical_report"] = 1

    # Return exactly 9 features in an ordered list
    return [
        features["age_of_domain"],
        features["DNSRecord"],
        features["Domain_registeration_length"],
        features["Abnormal_URL"],
        features["web_traffic"],
        features["Page_Rank"],
        features["Google_Index"],
        features["Links_pointing_to_page"],
        features["Statistical_report"]
    ]
