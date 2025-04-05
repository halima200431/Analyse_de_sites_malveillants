from flask import Flask, request, jsonify
import requests
import re
import tldextract
from flask_cors import CORS
import os
import logging
import validators
import socket
import whois
from datetime import datetime
import ssl
import dns.resolver
import urllib.parse
from bs4 import BeautifulSoup
from functools import wraps
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration - API key now from environment variables
API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
REQUEST_TIMEOUT = 10  # seconds

# Detection lists
SUSPICIOUS_KEYWORDS = ["free", "login", "bank", "verify", "account", "secure", "paypal"]
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "shorte.st", "adf.ly", "t.co"]
SQL_KEYWORDS = ["select", "union", "insert", "delete", "drop", "update", "alter", "1=1"]
XSS_PATTERNS = ["<script>", "javascript:", "onload=", "onerror=", "alert("]

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(_name_)

def calculate_security_score(results):
    """Calculate overall security score (0-100%)"""
    weights = {
        'safe_browsing': 0.3,
        'suspicious_patterns': 0.25,
        'sql_injection': 0.2,
        'xss': 0.15,
        'ssl': 0.05,
        'dns': 0.03,
        'whois': 0.02
    }
    
    total_score = 0
    
    # Safe Browsing contributes 30% (all or nothing)
    total_score += 30 if not results['findings']['safe_browsing'] else 0
    
    # Suspicious patterns (max 20%)
    suspicious_score = max(0, 20 - (results['threat_score'] * 4))
    total_score += suspicious_score
    
    # SQL Injection (max 20%)
    sql_score = 20 if not results['findings']['sql_injection'] else 0
    total_score += sql_score
    
    # XSS (max 15%)
    xss_score = 15 if not results['findings']['xss'] else 0
    total_score += xss_score
    
    # SSL (max 5%)
    ssl_score = max(0, 5 - (len(results['findings']['ssl']) * 1.25))
    total_score += ssl_score
    
    # DNS (max 8%)
    dns_score = max(0, 8 - (len(results['findings']['dns']) * 1.6))
    total_score += dns_score
    
    # WHOIS (max 2%)
    whois_score = max(0, 2 - (len(results['findings']['whois']) * 0.4))
    total_score += whois_score
    
    return round(total_score, 2)

def timeout_handling(max_time):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            if time.time() - start_time > max_time:
                logger.warning(f"Function {func._name_} took too long")
                return []
            return result
        return wrapper
    return decorator

@timeout_handling(5)
def check_google_safe_browsing(url):
    """Check URL with Google Safe Browsing API"""
    if not API_KEY:
        logger.warning("Google Safe Browsing API key not configured")
        return []
    
    try:
        payload = {
            "client": {"clientId": "malware-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        response = requests.post(
            f"{SAFE_BROWSING_URL}?key={API_KEY}",
            json=payload,
            timeout=REQUEST_TIMEOUT
        )
        return response.json().get("matches", [])
    except Exception as e:
        logger.error(f"Google Safe Browsing error: {str(e)}")
        return []

def check_suspicious_patterns(url):
    """Detect suspicious patterns in URL"""
    score = 0
    findings = []
    
    # URL shorteners
    if any(shortener in url.lower() for shortener in SHORTENERS):
        score += 2
        findings.append("URL raccourcie détectée")
    
    # Suspicious keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if found_keywords:
        score += len(found_keywords)
        findings.append(f"Mots-clés suspects: {', '.join(found_keywords)}")
    
    return score, findings

def check_sql_injection(url):
    """Detect potential SQL injections"""
    findings = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    
    for param, values in params.items():
        for value in values:
            if any(sql_kw in value.lower() for sql_kw in SQL_KEYWORDS):
                findings.append(f"Possible injection SQL dans le paramètre: {param}")
    
    return findings

def check_xss(url):
    """Detect potential XSS vulnerabilities"""
    findings = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    
    for param, values in params.items():
        for value in values:
            if any(xss_pattern in value.lower() for xss_pattern in XSS_PATTERNS):
                findings.append(f"Possible XSS dans le paramètre: {param}")
    
    return findings

def check_ssl_certificate(domain):
    """Check SSL certificate in depth"""
    findings = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check validity
                expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if expire_date < datetime.now():
                    findings.append("Certificat SSL expiré")
                
                # Check domain match
                common_name = next((v for k, v in cert['subject'][0] if k == 'commonName'), '')
                if not common_name or common_name != domain:
                    findings.append(f"Nom de certificat ne correspond pas: {common_name}")
                
                # Check cipher strength
                cipher = ssock.cipher()
                if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                    findings.append(f"Chiffrement faible détecté: {cipher[0]}")
    
    except ssl.SSLError as e:
        findings.append(f"Erreur SSL: {str(e)}")
    except Exception as e:
        findings.append(f"Erreur de connexion SSL: {str(e)}")
    
    return findings

def check_dns_records(domain):
    """Analyze DNS records for anomalies"""
    findings = []
    try:
        # MX records check
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            if not answers:
                findings.append("Aucun enregistrement MX trouvé (peut indiquer un site factice)")
        except:
            findings.append("Aucun enregistrement MX trouvé")
        
        # SPF records check
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            spf_found = any('v=spf1' in str(r) for r in answers)
            if not spf_found:
                findings.append("Aucun enregistrement SPF trouvé (risque de phishing)")
        except:
            findings.append("Aucun enregistrement SPF trouvé")
        
        # DMARC check
        try:
            dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        except:
            findings.append("Aucun enregistrement DMARC trouvé")
    
    except Exception as e:
        findings.append(f"Erreur DNS: {str(e)}")
    
    return findings

def check_whois(domain):
    """Analyze WHOIS information"""
    findings = []
    try:
        w = whois.whois(domain)
        
        # Domain age check
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            
            domain_age = (datetime.now() - creation_date).days
            if domain_age < 30:
                findings.append(f"Domaine récent ({domain_age} jours) - risque potentiel")
        
        # Registrant check
        if not w.name and not w.org:
            findings.append("Informations du propriétaire masquées (WHOIS privé)")
        
        # Country check
        if w.country:
            high_risk_countries = ['CN', 'RU', 'UA', 'TR', 'BR']
            if w.country in high_risk_countries:
                findings.append(f"Domaine enregistré dans un pays à risque: {w.country}")
    
    except Exception as e:
        findings.append(f"Erreur WHOIS: {str(e)}")
    
    return findings

@app.route('/scan', methods=['POST'])
def scan_url():
    """Main endpoint for URL scanning"""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    
    data = request.get_json()
    url = data.get("url")
    
    if not url:
        return jsonify({"error": "Aucune URL fournie"}), 400
    
    if not validators.url(url):
        return jsonify({"error": "URL invalide"}), 400
    
    logger.info(f"Analyse de l'URL: {url}")
    
    try:
        # Extract domain
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        # Run checks
        safe_browsing = check_google_safe_browsing(url)
        threat_score, suspicious_findings = check_suspicious_patterns(url)
        sql_findings = check_sql_injection(url)
        xss_findings = check_xss(url)
        ssl_findings = check_ssl_certificate(domain)
        dns_findings = check_dns_records(domain)
        whois_findings = check_whois(domain)
        
        # Prepare results
        results = {
            "url": url,
            "threat_score": threat_score,
            "findings": {
                "safe_browsing": bool(safe_browsing),
                "suspicious_patterns": suspicious_findings,
                "sql_injection": sql_findings,
                "xss": xss_findings,
                "ssl": ssl_findings,
                "dns": dns_findings,
                "whois": whois_findings
            }
        }
        
        # Calculate security score and risk level
        results['security_score'] = calculate_security_score(results)
        
        if results['security_score'] >= 90:
            risk_level = "Safe"
        elif results['security_score'] >= 70:
            risk_level = "Low Risk"
        elif results['security_score'] >= 50:
            risk_level = "Moderate Risk"
        elif results['security_score'] >= 30:
            risk_level = "High Risk"
        else:
            risk_level = "Malicious"
        
        results['risk_level'] = risk_level
        
        return jsonify(results)
    
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur est survenue lors de l'analyse"}), 500

<<<<<<< HEAD
if _name_ == '_main_':
    app.run(host='0.0.0.0', port=5000, debug=True)



    from flask import render_template

@app.route('/help', methods=['GET'])
def help_page():
    """Affiche la page d'aide avec un formulaire."""
    return render_template('help.html')

@app.route('/submit-question', methods=['POST'])
def submit_question():
    """Traite la question soumise par le client."""
    question = request.form.get('question')
    if not question:
        return jsonify({"error": "Aucune question fournie"}), 400
    
    # Vous pouvez enregistrer la question dans un fichier ou une base de données
    logger.info(f"Question reçue : {question}")
    
    # Réponse de confirmation
    return jsonify({"message": "Votre question a été envoyée avec succès !"})
=======
if __name__ == '__main__':
    # Verify API key is loaded
    if not API_KEY:
        logger.warning("Safe Browsing API key not configured - this feature will be disabled")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
>>>>>>> 8daab7013569e9ebd31023cb184c8097037b5249
