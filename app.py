from flask import Flask, request, jsonify
import requests
import re
import tldextract
from flask_cors import CORS
import os
import logging
import validators

app = Flask(__name__)
CORS(app)  # Permettre les requêtes depuis le front-end

# Clé API Google Safe Browsing (remplace par ta clé)
API_KEY = API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

SUSPICIOUS_KEYWORDS = ["free", "login", "bank", "verify", "click", "update", "secure", "paypal", "win", "prize"]

def check_google_safe_browsing(url):
    payload = {
        "client": {"clientId": "malware-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    response = requests.post(f"{SAFE_BROWSING_URL}?key={API_KEY}", json=payload)
    result = response.json()
    return result.get("matches", [])

def check_suspicious_patterns(url):
    score = 0
    if re.search(r"(bit\.ly|tinyurl\.com|goo\.gl|shorte\.st|adf\.ly|t\.co)", url):
        score += 2
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 1
    extracted = tldextract.extract(url)
    if extracted.subdomain and extracted.subdomain not in ["www", ""]:
        score += 1
    return score

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/scan', methods=['GET', 'POST'])
def scan_url():
    logger.info("Received request to scan URL")
    logger.info(f"Request method: {request.method}")
    logger.info(f"Request headers: {request.headers}")
    logger.info(f"Request data: {request.data}")

    if request.method == 'GET':
        url = request.args.get("url")
        if not url:
            logger.error("No URL provided in GET request")
            return jsonify({"error": "Aucune URL fournie"}), 400

    elif request.method == 'POST':
        if not request.is_json:
            logger.error("Content-Type must be application/json")
            return jsonify({"error": "Content-Type must be application/json"}), 415
        data = request.get_json()
        logger.info(f"Received JSON data: {data}")
        url = data.get("url")
        if not url:
            logger.error("No URL provided in POST request")
            return jsonify({"error": "Aucune URL fournie"}), 400

    else:
        logger.error(f"Unsupported method: {request.method}")
        return jsonify({"error": "Method not allowed"}), 405

    if not validators.url(url):
        logger.error(f"Invalid URL: {url}")
        return jsonify({"error": "URL invalide"}), 400

    logger.info(f"Scanning URL: {url}")
    google_safe = check_google_safe_browsing(url)
    threat_score = check_suspicious_patterns(url)

    risk_level = "Safe"
    if google_safe:
        risk_level = "Malicious"
    elif threat_score >= 3:
        risk_level = "High Risk"
    elif threat_score == 2:
        risk_level = "Moderate Risk"
    elif threat_score == 1:
        risk_level = "Low Risk"

    logger.info(f"Scan result for {url}: Risk Level = {risk_level}")
    return jsonify({
        "url": url,
        "risk_level": risk_level,
        "safe_browsing": bool(google_safe)
    })

if __name__ == '__main__':
    app.run(debug=True)
