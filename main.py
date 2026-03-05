import time
import joblib
import pandas as pd
import numpy as np

# Import our custom feature extraction modules
from address_features import extract_address_features
from html_features import extract_html_features
from domain_features import extract_domain_features


def process_url_for_ml(raw_url):
    """
    Orchestrates the feature extraction process and returns 
    the ordered array ready for the ML model.
    """
    print(f"\n[INFO] Starting analysis for: {raw_url}")
    start_time = time.time()

    # 1. Extract Features from the 3 modules
    print("[1/3] Extracting Lexical & Address features...")
    address_data = extract_address_features(raw_url)

    print("[2/3] Fetching webpage and extracting HTML/JS features...")
    html_data = extract_html_features(raw_url)

    print("[3/3] Querying WHOIS and third-party databases...")
    domain_data = extract_domain_features(raw_url)

    # 2. Reorder exactly to your XGBoost Training Columns
    # We map the specific indexes from our 3 lists into the exact order your model expects.
    ordered_features = [
        address_data[0],   # 1. having_IP_Address
        address_data[1],   # 2. URL_Length
        address_data[2],   # 3. Shortining_Service
        address_data[3],   # 4. having_At_Symbol
        address_data[4],   # 5. double_slash_redirecting
        address_data[5],   # 6. Prefix_Suffix
        address_data[6],   # 7. having_Sub_Domain
        address_data[8],   # 8. SSLfinal_State
        domain_data[2],    # 9. Domain_registeration_length
        html_data[10],     # 10. Favicon
        address_data[9],   # 11. port
        address_data[7],   # 12. HTTPS_token
        html_data[0],      # 13. Request_URL
        html_data[1],      # 14. URL_of_Anchor
        html_data[2],      # 15. Links_in_tags
        html_data[3],      # 16. SFH
        html_data[4],      # 17. Submitting_to_email
        domain_data[3],    # 18. Abnormal_URL
        html_data[5],      # 19. Redirect
        html_data[6],      # 20. on_mouseover
        html_data[7],      # 21. RightClick
        # 22. popUpWidnow (Note: spelled exactly as your column name)
        html_data[8],
        html_data[9],      # 23. Iframe
        domain_data[0],    # 24. age_of_domain
        domain_data[1],    # 25. DNSRecord
        domain_data[4],    # 26. web_traffic
        domain_data[5],    # 27. Page_Rank
        domain_data[6],    # 28. Google_Index
        domain_data[7],    # 29. Links_pointing_to_page
        domain_data[8]     # 30. Statistical_report
    ]

    end_time = time.time()
    print(
        f"[INFO] Extraction complete in {round(end_time - start_time, 2)} seconds.")

    return ordered_features


if __name__ == "__main__":
    print("=========================================")
    print("   PHISHING URL DETECTOR - ML PIPELINE   ")
    print("=========================================")

    # 1. Get URL from user
    user_input = input("Please paste a URL to analyze: ").strip()
    if not user_input.startswith("http"):
        print("Adding 'http://' to the raw URL...")
        user_input = "http://" + user_input

    # 2. Extract and perfectly order the features
    final_ordered_array = process_url_for_ml(user_input)

    print(
        f"\nExtracted & Ordered exactly {len(final_ordered_array)} features.")

    # Define exact column names for XGBoost/Pandas
    feature_names = [
        "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
        "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
        "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
        "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
        "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
        "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
        "Statistical_report"
    ]

    # Create DataFrame (XGBoost often requires feature names to match training data)
    input_df = pd.DataFrame([final_ordered_array], columns=feature_names)

    try:
        # 3. Load the Saved MinMaxScaler and XGBoost Model
        # (Make sure these .pkl files are in the same folder as this script!)
        print("[INFO] Loading MinMaxScaler and XGBoost model...")
        scaler = joblib.load('minmax_scaler.pkl')
        xgb_model = joblib.load('xgboost_phishing_model.pkl')

        # 4. Apply the MinMaxScaler to the input
        # We transform the data using the exact rules learned during your training phase
        scaled_input = scaler.transform(input_df)

        # XGBoost requires a DataFrame if it was trained on one, so we wrap it back up
        scaled_df = pd.DataFrame(scaled_input, columns=feature_names)

        # 5. Make the Prediction
        prediction = xgb_model.predict(scaled_df)

        print("\n=========================================")
        print("             XGBOOST PREDICTION          ")
        print("=========================================")

        # Interpret the result (-1 = Phishing, 1 = Legitimate typically for this dataset)
        if prediction[0] == 0:  # <--- Change this from -1 to 0
            print("🚨 WARNING: This is classified as a PHISHING Website!")
        else:
            print("✅ SAFE: This website appears to be LEGITIMATE.")

    except FileNotFoundError as e:
        print(f"\n[ERROR] File missing: {e}")
        print("Make sure you saved BOTH your XGBoost model AND your MinMaxScaler during training!")
