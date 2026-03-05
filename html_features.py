# pip install requests beautifulsoup4

import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse


def get_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
    except:
        return ""


def extract_html_features(url):
    """
    Fetches the webpage and extracts HTML/JS features.
    If the webpage is dead or blocks the request, it returns -1 (Phishing) 
    for these features, as phishing sites often have short lifespans.
    """
    domain = get_domain(url)

    # Initialize default features (assuming failure/phishing)
    features = {
        "Request_URL": -1, "URL_of_Anchor": -1, "Links_in_tags": -1,
        "SFH": -1, "Submitting_to_email": -1, "Redirect": -1,
        "on_mouseover": -1, "RightClick": -1, "popUpWindow": -1, "Iframe": -1, "Favicon": -1
    }

    try:
        # Fetch the webpage with a strict timeout so your app doesn't freeze
        response = requests.get(url, timeout=5, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        html_text = response.text.lower()

        # 1. Website Forwarding (Redirect) [cite: 110-114]
        # Rule: <=1 -> 1, 2 or 3 -> 0, else -> -1
        redirect_count = len(response.history)
        if redirect_count <= 1:
            features["Redirect"] = 1
        elif 2 <= redirect_count < 4:
            features["Redirect"] = 0
        else:
            features["Redirect"] = -1

        # 2. Submitting Information to Email [cite: 100-105]
        # Rule: Using mail() or mailto: -> -1, Otherwise -> 1
        if "mail()" in html_text or "mailto:" in html_text:
            features["Submitting_to_email"] = -1
        else:
            features["Submitting_to_email"] = 1

        # 3. Status Bar Customization (onMouseOver) [cite: 115-118]
        # Rule: onMouseOver changes status bar -> -1, Otherwise -> 1
        if "onmouseover" in html_text and "window.status" in html_text:
            features["on_mouseover"] = -1
        else:
            features["on_mouseover"] = 1

        # 4. Disabling Right Click [cite: 119-123]
        # Rule: event.button==2 -> -1, Otherwise -> 1
        if "event.button==2" in html_text.replace(" ", ""):
            features["RightClick"] = -1
        else:
            features["RightClick"] = 1

        # 5. IFrame Redirection [cite: 128-132]
        # Rule: Using iframe -> -1, Otherwise -> 1
        if soup.find_all('iframe'):
            features["Iframe"] = -1
        else:
            features["Iframe"] = 1

        # 6. Using Pop-up Window [cite: 124-127]
        # Rule: popup window contains text fields -> -1, Otherwise -> 1
        # (Simplified check: looking for window.open commonly used for popups)
        if "window.open" in html_text:
            features["popUpWindow"] = -1
        else:
            features["popUpWindow"] = 1

        # 7. Server Form Handler (SFH) [cite: 96-99]
        # Rule: "about:blank" or empty -> -1, Different domain -> 0, Otherwise -> 1
        forms = soup.find_all('form', action=True)
        sfh_feature = 1
        for form in forms:
            action = form['action'].strip()
            if action == "" or action == "about:blank":
                sfh_feature = -1
                break
            elif action.startswith("http") and domain not in action:
                sfh_feature = 0
        features["SFH"] = sfh_feature

        # 8. URL of Anchor [cite: 81-90]
        # Rule: % < 31% -> 1, >= 31% And <= 67% -> 0, Otherwise -> -1
        anchors = soup.find_all('a', href=True)
        bad_anchors = 0
        for a in anchors:
            href = a['href'].lower()
            if href in ["#", "#content", "#skip", "javascript::void(0)"] or (href.startswith("http") and domain not in href):
                bad_anchors += 1

        if len(anchors) > 0:
            anchor_percentage = (bad_anchors / len(anchors)) * 100
            if anchor_percentage < 31:
                features["URL_of_Anchor"] = 1
            elif 31 <= anchor_percentage <= 67:
                features["URL_of_Anchor"] = 0
            else:
                features["URL_of_Anchor"] = -1
        else:
            features["URL_of_Anchor"] = 1  # No anchors found

        # 9. Favicon
        # Rule: IF Favicon Loaded From External Domain -> -1, Otherwise -> 1 [cite: 61-62]
        favicon_link = soup.find(
            "link", rel=lambda x: x and "icon" in x.lower())
        if favicon_link and favicon_link.get('href', '').startswith('http') and domain not in favicon_link['href']:
            features["Favicon"] = -1
        else:
            features["Favicon"] = 1

    except requests.exceptions.RequestException:
        # If the page fails to load, it returns the default -1 values
        pass

    # Return as an ordered list to match your dataset format
    # Return exactly 11 features in an ordered list
    return [
        features["Request_URL"],
        features["URL_of_Anchor"],
        features["Links_in_tags"],
        features["SFH"],
        features["Submitting_to_email"],
        features["Redirect"],
        features["on_mouseover"],
        features["RightClick"],
        features["popUpWindow"],
        features["Iframe"],
        features["Favicon"]
    ]
