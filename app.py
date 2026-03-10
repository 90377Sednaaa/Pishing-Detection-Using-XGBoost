from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
from main import process_url_for_ml

app = Flask(__name__)

print("[INFO] Loading ML models into Flask...")
scaler = joblib.load('minmax_scaler.pkl')
xgb_model = joblib.load('xgboost_phishing_model.pkl')

feature_names = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
    "Statistical_report"
]


@app.route('/', methods=['GET'])
def index():
    # Only load the visual interface when they visit the site
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    # This acts as the API endpoint for the JavaScript frontend
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url.startswith("http"):
        url = "http://" + url

    try:
        # Extract features
        features = process_url_for_ml(url)

        # Scale and Predict
        input_df = pd.DataFrame([features], columns=feature_names)
        scaled_input = scaler.transform(input_df)
        scaled_df = pd.DataFrame(scaled_input, columns=feature_names)

        # Use predict_proba to get the exact percentages
        probabilities = xgb_model.predict_proba(scaled_df)[0]

        # Class 0 is Phishing, Class 1 is Legitimate
        phish_prob = float(probabilities[0])
        legit_prob = float(probabilities[1])

        is_phishing = bool(phish_prob > legit_prob)

        # Calculate how confident the AI is in its final answer (e.g., 98.5%)
        confidence_score = round(max(phish_prob, legit_prob) * 100, 2)

        # Calculate a threat score from 0 to 100 for the UI Needle
        threat_score = round(phish_prob * 100, 2)

        # Send the JSON response back to the JavaScript
        return jsonify({
            'isPhishing': is_phishing,
            'features': features,
            'confidence': confidence_score,
            'threatScore': threat_score
        })

    except Exception as e:
        print(f"[ERROR] API failed: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860)
