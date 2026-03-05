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

    # ==========================================
    # API PLACEHOLDERS FOR REMAINING FEATURES
    # ==========================================

    # 5. Website Traffic [cite: 142-148]
    # Rule: <100,000 -> 1, >100,000 -> 0, Otherwise -> -1 [cite: 148]
    features["web_traffic"] = 1

    # 6. PageRank [cite: 149-154]
    # Rule: PageRank < 0.2 -> -1, Otherwise -> 1 [cite: 154]
    features["Page_Rank"] = 1

    # 7. Google Index [cite: 155-159]
    # Rule: Indexed by Google -> 1, Otherwise -> -1 [cite: 159]
    features["Google_Index"] = 1

    # 8. Links Pointing to Page [cite: 160-164]
    # Rule: 0 -> -1, >0 and <=2 -> 0, Otherwise -> 1 [cite: 164]
    features["Links_pointing_to_page"] = 1

    # 9. Statistical Report [cite: 165-168]
    # Rule: Belongs to Top Phishing IPs/Domains -> -1, Otherwise -> 1 [cite: 168]
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
