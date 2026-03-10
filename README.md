# Phishing URL Detector (XGBoost & Flask)

An Machine Learning pipeline that detects whether a given URL is **Phishing** or **Legitimate**. This project extracts a 30-feature vector from any given link using lexical analysis, live DOM scraping, and third-party threat intelligence APIs, evaluating it with a pre-trained XGBoost model.

## Features

- Tri-Modal Feature Extraction (Address/Lexical, HTML/JS Content, Domain Reputation)
- Live Threat Intelligence integration (VirusTotal API and HackerTarget)
- Precise threat probabilities using an XGBoost Inference Engine and MinMax Scaler
- Modern, animated web UI with AI confidence scores
- Detailed breakdown of all 30 extracted features

## Prerequisites

Before running this project, make sure you have:

- **Python 3.8+** installed
- Active internet connection (for WHOIS, HTML scraping, and API lookups)
- Tranco Dataset folder (`tranco_6GPNX-1m.csv`) present in the directory
- A modern web browser

## Installation & Setup

### Step 1: Clone/Download the Project

Place the project folder on your local machine and open a terminal or command prompt inside the project directory.

### Step 2: Install Dependencies

Install the required Python libraries using pip. It is highly recommended to strictly use `scikit-learn==1.6.1` to ensure compatibility with the pre-trained model files.

```bash
pip install Flask xgboost pandas scikit-learn==1.6.1 joblib beautifulsoup4 requests python-whois
```

### Step 3: Project Structure

```text
Phishing-Detection-Using-XGBoost/
├── app.py                      # Flask backend and API bridge
├── main.py                     # Orchestrator for feature aggregation
├── address_features.py         # Lexical properties and SSL validation
├── html_features.py            # DOM scraping (iframes, right-clicks, etc.)
├── domain_features.py          # WHOIS, Tranco, and VirusTotal APIs
├── xgboost_phishing_model.pkl  # Pre-trained XGBoost model
├── minmax_scaler.pkl           # Mathematical scaler for input normalization
├── templates/
│   └── index.html              # Custom frontend user interface
└── tranco_6GPNX-1m.csv/
    └── top-1m.csv              # Local web traffic analysis database
```

### Step 4: Start the Flask Server

1. Open your terminal or command prompt.
2. Ensure you are in the project directory.
3. Start the application by running:

```bash
python app.py
```

### Step 5: Access the Application

Open your browser and navigate to the local server address provided in the terminal:

```
http://127.0.0.1:5000/
```

## How to Use

1. Access the web interface via your browser.
2. Paste the target URL you want to analyze into the input box (e.g., `https://www.google.com`).
3. Click the **SCAN** button to initialize the pipeline.
4. Wait for the scanning animation to complete as the backend orchestrates the lexical, HTML, and domain feature extraction.
5. Review the final verdict (**Legitimate** or **Phishing**), the AI's percentage-based confidence score, and the color-coded feature breakdown grid.
