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
    domain = get_domain(url)

    # DEFAULT TO 0 (Suspicious/Neutral) instead of -1 if the scrape fails.
    # This prevents the AI from aggressively flagging sites that block bots.
    features = {
        "Request_URL": 0, "URL_of_Anchor": 0, "Links_in_tags": 0,
        "SFH": 0, "Submitting_to_email": 0, "Redirect": 0,
        "on_mouseover": 0, "RightClick": 0, "popUpWindow": 0, "Iframe": 0, "Favicon": 0
    }

    try:
        # ADDED: A standard User-Agent so legitimate websites don't block your script
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers,
                                timeout=5, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        html_text = response.text.lower()

        # 1. Redirect
        redirect_count = len(response.history)
        if redirect_count <= 1:
            features["Redirect"] = 1
        elif 2 <= redirect_count < 4:
            features["Redirect"] = 0
        else:
            features["Redirect"] = -1

        # 2. Submitting to email
        if "mail()" in html_text or "mailto:" in html_text:
            features["Submitting_to_email"] = -1
        else:
            features["Submitting_to_email"] = 1

        # 3. onMouseOver
        if "onmouseover" in html_text and "window.status" in html_text:
            features["on_mouseover"] = -1
        else:
            features["on_mouseover"] = 1

        # 4. RightClick
        if "event.button==2" in html_text.replace(" ", ""):
            features["RightClick"] = -1
        else:
            features["RightClick"] = 1

        # 5. Iframe
        if soup.find_all('iframe'):
            features["Iframe"] = -1
        else:
            features["Iframe"] = 1

        # 6. popUpWindow
        if "window.open" in html_text:
            features["popUpWindow"] = -1
        else:
            features["popUpWindow"] = 1

        # 7. SFH
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

        # 8. URL of Anchor
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
            features["URL_of_Anchor"] = 1

        # 9. Favicon
        favicon_link = soup.find(
            "link", rel=lambda x: x and "icon" in x.lower())
        if favicon_link and favicon_link.get('href', '').startswith('http') and domain not in favicon_link['href']:
            features["Favicon"] = -1
        else:
            features["Favicon"] = 1

        # 10. Request_URL (Images/Video/Audio loaded from outside domains)
        media_tags = soup.find_all(['img', 'audio', 'embed', 'iframe'])
        bad_media = sum(1 for tag in media_tags if tag.get(
            'src', '').startswith('http') and domain not in tag.get('src', ''))
        if len(media_tags) > 0:
            req_percentage = (bad_media / len(media_tags)) * 100
            if req_percentage < 22:
                features["Request_URL"] = 1
            elif 22 <= req_percentage <= 61:
                features["Request_URL"] = 0
            else:
                features["Request_URL"] = -1
        else:
            features["Request_URL"] = 1

        # 11. Links_in_tags (Scripts, Meta, and Link tags from outside domains)
        meta_tags = soup.find_all(['meta', 'script', 'link'])
        bad_tags = 0
        for tag in meta_tags:
            link = tag.get('href', tag.get('src', ''))
            if link.startswith('http') and domain not in link:
                bad_tags += 1
        if len(meta_tags) > 0:
            tag_percentage = (bad_tags / len(meta_tags)) * 100
            if tag_percentage < 17:
                features["Links_in_tags"] = 1
            elif 17 <= tag_percentage <= 81:
                features["Links_in_tags"] = 0
            else:
                features["Links_in_tags"] = -1
        else:
            features["Links_in_tags"] = 1

    except Exception as e:
        print(f"[WARNING] Scraper blocked or failed: {e}")

    return [
        features["Request_URL"], features["URL_of_Anchor"], features["Links_in_tags"],
        features["SFH"], features["Submitting_to_email"], features["Redirect"],
        features["on_mouseover"], features["RightClick"], features["popUpWindow"],
        features["Iframe"], features["Favicon"]
    ]
