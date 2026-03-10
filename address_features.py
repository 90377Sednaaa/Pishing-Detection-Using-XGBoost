import ssl
import socket
from datetime import datetime
import re
from urllib.parse import urlparse
import ipaddress
from cryptography import x509
from cryptography.hazmat.backends import default_backend


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

    # 1. First, check if it's a valid IPv4 or IPv6 address using Python's native library
    try:
        ipaddress.ip_address(domain)
        return -1  # It is exactly an IP address
    except ValueError:
        pass  # Not a standard IP, continue to regex fallback

    # 2. Fallback Regex to catch obfuscated Hex/Decimal IPs hidden in the domain string
    # This covers standard IPv4, Hex (0x...), and Decimal obfuscation
    obfuscated_ip_pattern = re.compile(
        # Standard IPv4
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])'
        r'|(0x[0-9a-fA-F]{2}\.){3}0x[0-9a-fA-F]{2}'  # Hexadecimal
        r'|^\d+$)'  # Pure Decimal IP (e.g., 2103511411)
    )

    if obfuscated_ip_pattern.search(domain):
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
    """
    Checks HTTPS usage, issuer trust, and certificate age using strict X.509 parsing.
    Requires: pip install cryptography
    """
    if not url.startswith("https"):
        return -1  # Phishing if no HTTPS

    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split(
            '/')[0]

        # Remove www. if present
        if domain.startswith("www."):
            domain = domain[4:]

        # Expanded list of modern trusted issuers
        trusted_issuers = [
            "GeoTrust", "GoDaddy", "Network Solutions", "Thawte", "Comodo",
            "Doster", "VeriSign", "Let's Encrypt", "DigiCert", "GlobalSign",
            "Cloudflare", "Google Trust Services", "Amazon", "Sectigo",
            "IdenTrust", "ZeroSSL", "RapidSSL", "Entrust", "Gandi"
        ]

        # Connect to the server and pull the raw binary certificate
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # binary_form=True is the key! It gets the uncorrupted, raw cert data
                der_cert = ssock.getpeercert(binary_form=True)

        # Parse the binary certificate using cryptography
        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # Extract all issuer attributes (Organization Name, Common Name, etc.) safely
        issuer_name = ""
        for attribute in cert.issuer:
            issuer_name += str(attribute.value) + " "

        # Check if any of our trusted names are in the issuer string
        is_trusted = any(trusted in issuer_name for trusted in trusted_issuers)

        # Safely extract the exact dates (cryptography returns naive UTC datetime objects)
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        now = datetime.utcnow()  # Use UTC to match the certificate's standard time

        # 1. Is the certificate currently valid right now?
        is_valid_now = not_before <= now <= not_after

        # 2. How many days has this certificate been active?
        current_age_days = (now - not_before).days

        # Modern Rule Logic
        if is_trusted and is_valid_now:
            if current_age_days >= 30:
                # Legitimate: Trusted, valid, and established (> 1 month old)
                return 1
            else:
                return 0  # Suspicious: Trusted and valid, but very recently created
        elif not is_trusted and is_valid_now:
            return 0      # Suspicious: Valid, but unknown/unlisted issuer
        else:
            return -1     # Phishing: Expired or not yet valid

    except Exception as e:
        # Fails safely if the site is dead, times out, or certificate is completely invalid
        return -1


def port_status(url):
    """
    Natively scans the domain to check if specific ports match their preferred status.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split(
            '/')[0]
        if domain.startswith("www."):
            domain = domain[4:]

        # Define the ports and their preferred status (True = Open, False = Close)
        ports_to_check = {
            21: False,   # FTP
            22: False,   # SSH
            23: False,   # Telnet
            80: True,    # HTTP
            443: True,   # HTTPS
            445: False,  # SMB
            1433: False,  # MSSQL
            1521: False,  # ORACLE
            3306: False,  # MySQL
            3389: False  # Remote Desktop
        }

        # Scan the ports
        for port, preferred_open in ports_to_check.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Extremely short timeout for speed
            result = sock.connect_ex((domain, port))
            sock.close()

            is_open = (result == 0)

            # If the actual status doesn't match the preferred secure status, flag it
            if is_open != preferred_open:
                return -1  # Phishing

        return 1  # Legitimate (All ports match preferred status)

    except Exception:
        # If we can't resolve the host at all
        return -1


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
