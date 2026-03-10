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

- Python **3.8 or higher**
- Internet connection (for WHOIS and webpage requests)

---

## Installation

Install the required dependencies using `pip`.

### 1. Web Requests and HTML Parsing

pip install requests beautifulsoup4

### 2. Domain Information Lookup

pip install python-whois

### 3. Data Processing and Machine Learning

pip install pandas scipy scikit-learn joblib

### 4. XGBoost Model

pip install xgboost

### 5. Required Scikit-Learn Version

pip install scikit-learn==1.6.1

---

## Running the Project

After installing the required dependencies, run the main program:

python main.py
