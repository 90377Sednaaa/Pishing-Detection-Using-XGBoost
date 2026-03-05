import re
from urllib.parse import urlparse


def get_domain(url):
    """Extracts the domain from the URL."""
    try:
        parsed = urlparse(url)
        # Handle cases where url doesn't have a scheme (e.g., just 'www.google.com')
        domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
        return domain
    except:
        return ""


def having_IP_Address(url):
    # Rule: IF The Domain Part has an IP Address -> Phishing (-1) Otherwise -> Legitimate (1)
    domain = get_domain(url)
    ip_pattern = re.compile(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])|(0x[0-9a-fA-F]{2}\.){3}0x[0-9a-fA-F]{2})')
    if ip_pattern.search(domain):
        return -1
    return 1


def URL_Length(url):
    # Rule: IF URL length < 54 -> Legitimate (1), >= 54 and <= 75 -> Suspicious (0), otherwise -> Phishing (-1)
    length = len(url)
    if length < 54:
        return 1
    elif 54 <= length <= 75:
        return 0
    else:
        return -1


def Shortining_Service(url):
    # Rule: IF TinyURL -> Phishing (-1) Otherwise -> Legitimate (1)
    # Checks against a list of common shortener domains
    domain = get_domain(url)
    shorteners = r"bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bit\.do|looptube\.in"
    if re.search(shorteners, domain, flags=re.IGNORECASE):
        return -1
    return 1


def having_At_Symbol(url):
    # Rule: IF Url Having @ Symbol -> Phishing (-1) Otherwise -> Legitimate (1)
    if '@' in url:
        return -1
    return 1


def double_slash_redirecting(url):
    # Rule: IF The Position of the Last Occurrence of "//" in the URL > 7 -> Phishing (-1) Otherwise -> Legitimate (1)
    pos = url.rfind('//')
    if pos > 7:
        return -1
    return 1


def Prefix_Suffix(url):
    # Rule: IF Domain Name Part Includes (-) Symbol -> Phishing (-1) Otherwise -> Legitimate (1)
    domain = get_domain(url)
    if '-' in domain:
        return -1
    return 1


def having_Sub_Domain(url):
    # Rule: IF Dots In Domain Part = 1 -> Legitimate (1), = 2 -> Suspicious (0), Otherwise -> Phishing (-1)
    domain = get_domain(url)
    # Remove 'www.' to isolate the core domain and subdomains
    clean_domain = re.sub(r'^www\.', '', domain)
    dot_count = clean_domain.count('.')

    if dot_count == 1:
        return 1
    elif dot_count == 2:
        return 0
    else:
        return -1


def HTTPS_token(url):
    # Rule: IF Using HTTP Token in Domain Part of The URL -> Phishing (-1) Otherwise -> Legitimate (1)
    domain = get_domain(url)
    if 'https' in domain or 'http' in domain:
        return -1
    return 1

# Placeholders


def SSLfinal_State(url):
    # Rule: IF Use https and Issuer Is Trusted & Age >= 1 Years -> 1, Otherwise -> -1/0 [cite: 53]
    # (Note: This is a placeholder. Real implementation requires the 'ssl' and 'socket' libraries)
    if url.startswith("https"):
        return 1
    return -1


def port_status(url):
    # Rule: IF Port # is of the Preferred Status -> Phishing (-1), Otherwise -> Legitimate (1) [cite: 68-69]
    # (Note: Real implementation requires 'socket' library to scan ports 21, 22, 80, etc.)
    return 1


def extract_address_features(url):
    """Runs all address-based checks and returns a list of features."""
    return [
        having_IP_Address(url),
        URL_Length(url),
        Shortining_Service(url),
        having_At_Symbol(url),
        double_slash_redirecting(url),
        Prefix_Suffix(url),
        having_Sub_Domain(url),
        HTTPS_token(url),
        SSLfinal_State(url),
        port_status(url)
    ]
