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

        # 0 is Phishing based on your training mapping
        prediction = int(xgb_model.predict(scaled_df)[0])
        is_phishing = (prediction == 0)

        # Send the JSON response back to the JavaScript
        return jsonify({
            'isPhishing': is_phishing,
            'features': features
        })

    except Exception as e:
        print(f"[ERROR] API failed: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
