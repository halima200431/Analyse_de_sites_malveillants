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
import ssl
import socket
from datetime import datetime
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import certifi

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration - API key now from environment variables
API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
REQUEST_TIMEOUT = 10  # seconds

# Detection lists
SUSPICIOUS_KEYWORDS = [
    "free", "login", "log-in", "signin", "sign-in", "bank", "verify",
    "account", "secure", "paypal", "password", "credit", "card", "update",
    "promo", "gift", "win", "winner", "prize", "offer", "deal", "discount",
    "urgent", "alert", "warning", "confirm", "validate", "billing", "payment",
    "amazon", "google", "microsoft", "apple", "facebook", "twitter", "instagram"
]
SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "shorte.st", "adf.ly", "t.co",
    "is.gd", "ow.ly", "rebrand.ly", "rb.gy", "clck.ru", "u.to", "tiny.cc",
    "lnkd.in", "buff.ly", "s.id", "cutt.ly", "shorturl.at", "kutt.it"
]
SQL_KEYWORDS = [
    "select", "union", "insert", "delete", "drop", "update", "alter", "1=1",
    "or", "and", "--", "#", "/*", "*/", ";", "exec", "xp_", "sp_", "sleep",
    "benchmark", "waitfor", "delay", "information_schema", "table_name",
    "column_name", "sysobjects", "syscolumns", "password", "user"
]
XSS_PATTERNS = [
        # HTML tags
        "<script>", "<img", "<svg", "<iframe", "<object", "<embed", "<a ",
        "<div", "<span", "<input", "<form", "<body", "<html",
        # JavaScript protocols and keywords
        "javascript:", "vbscript:", "data:", "eval(", "document.cookie",
        "window.location", "document.write", "settimeout(", "setinterval(",
        "alert(", "confirm(", "prompt(",
        # Event handlers
        "onload=", "onerror=", "onmouseover=", "onmouseout=", "onclick=",
        "onfocus=", "onblur=", "onchange=", "onsubmit=", "onkeydown=",
        "onkeypress=", "onkeyup=",
        # Encoded characters and special patterns
        "&#", "%3c", "%3e", "<%", "%0a", "%0d", "expression("
    ]
# Suspicious patterns (e.g., quotes, encoded characters, JavaScript fragments)
SUSPICIOUS_XSS_PATTERNS = [
        "';", "'; ", "' ", '" ', "< ", "> ", "=\"", "='", "/>", "</",
        "javascript", "script", "onload", "onerror", "alert", "eval"
    ]

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def calculate_security_score(results):
    """Calculate a 100% correct security score based on findings (0-100)"""
    score = 100
    
    # Safe Browsing: Critical threat detection (25 points)
    if results['findings']['safe_browsing']:
        score -= 25
    
    # Suspicious Patterns: Proportional to threat_score (max 20 points)
    suspicious_deduction = min(20, results['threat_score'] * 4)
    score -= suspicious_deduction
    
    # SQL Injection: Significant vulnerability (20 points)
    if results['findings']['sql_injection']:
        score -= 20
    
    # XSS: Common vulnerability (15 points)
    if results['findings']['xss']:
        score -= 15
    
    # SSL: Security foundation (max 30 points, increased due to criticality)
    ssl_issues = 0
    for finding in results['findings']['ssl']:
        if any(keyword in finding.lower() for keyword in ["expired", "handshake failed", "domain mismatch", "weak", "insecure", "ssl analysis error"]):
            ssl_issues += 1
        elif "expires soon" in finding.lower():
            ssl_issues += 0.5
    ssl_deduction = min(30, ssl_issues * 10)  # 10 points per critical issue, 5 for expires soon
    score -= ssl_deduction
    
    # DNS: Basic validation (max 8 points)
    dns_issues = len(results['findings']['dns'])
    dns_deduction = min(8, dns_issues * 2)
    score -= dns_deduction
    
    # WHOIS: Supplementary info (max 2 points)
    whois_issues = len(results['findings']['whois'])
    whois_deduction = min(2, whois_issues * 0.5)
    score -= whois_deduction
    
    return max(0, round(score, 2))

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

# Add the improved check_sql_injection function
def check_sql_injection(url):
    """Detect potential SQL injections with improved detection"""
    findings = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    
    # Suspicious patterns (e.g., quotes, equals, comments)
    SUSPICIOUS_PATTERNS = [
        "'='", "''", "1=1", "' OR", "OR '", "-- ", "# ", "/* ", " */",
        "; ", "=1", "='", "' '", " -", "+"
    ]
    
    # Check query parameters
    for param, values in params.items():
        for value in values:
            decoded_value = urllib.parse.unquote(value).lower()
            for sql_kw in SQL_KEYWORDS:
                if sql_kw in decoded_value:
                    findings.append(f"Possible injection SQL dans le paramètre: {param} (mot-clé: {sql_kw})")
                    break
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in decoded_value:
                    findings.append(f"Possible injection SQL dans le paramètre: {param} (motif suspect: {pattern})")
                    break
    
    # Check URL path
    path = urllib.parse.unquote(parsed.path).lower()
    for sql_kw in SQL_KEYWORDS:
        if sql_kw in path:
            findings.append(f"Possible injection SQL dans le chemin de l'URL (mot-clé: {sql_kw})")
            break
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in path:
            findings.append(f"Possible injection SQL dans le chemin de l'URL (motif suspect: {pattern})")
            break
    
    # Check URL fragment
    fragment = urllib.parse.unquote(parsed.fragment).lower()
    if fragment:
        for sql_kw in SQL_KEYWORDS:
            if sql_kw in fragment:
                findings.append(f"Possible injection SQL dans le fragment de l'URL (mot-clé: {sql_kw})")
                break
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in fragment:
                findings.append(f"Possible injection SQL dans le fragment de l'URL (motif suspect: {pattern})")
                break
    
    # Remove duplicates
    findings = list(dict.fromkeys(findings))
    
    return findings

def check_xss(url):
    """Detect potential XSS vulnerabilities with improved detection"""
    findings = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    # Check query parameters
    for param, values in params.items():
        for value in values:
            # Decode URL-encoded characters (e.g., %3C -> <)
            decoded_value = urllib.parse.unquote(value).lower()
            
            # Check for XSS patterns
            for xss_pattern in XSS_PATTERNS:
                if xss_pattern in decoded_value:
                    findings.append(f"Potential XSS in param: {param} (pattern: {xss_pattern})")
                    break  # Avoid duplicate findings for the same parameter
            
            # Check for suspicious patterns
            for pattern in SUSPICIOUS_XSS_PATTERNS:
                if pattern in decoded_value:
                    findings.append(f"Potential XSS in param: {param} (suspicious pattern: {pattern})")
                    break  # Avoid duplicate findings for the same parameter
    
    # Check URL path for XSS patterns
    path = urllib.parse.unquote(parsed.path).lower()
    for xss_pattern in XSS_PATTERNS:
        if xss_pattern in path:
            findings.append(f"Potential XSS in URL path (pattern: {xss_pattern})")
            break
    for pattern in SUSPICIOUS_XSS_PATTERNS:
        if pattern in path:
            findings.append(f"Potential XSS in URL path (suspicious pattern: {pattern})")
            break
    
    # Check URL fragment (if present)
    fragment = urllib.parse.unquote(parsed.fragment).lower()
    if fragment:
        for xss_pattern in XSS_PATTERNS:
            if xss_pattern in fragment:
                findings.append(f"Potential XSS in URL fragment (pattern: {xss_pattern})")
                break
        for pattern in SUSPICIOUS_XSS_PATTERNS:
            if pattern in fragment:
                findings.append(f"Potential XSS in URL fragment (suspicious pattern: {pattern})")
                break
    
    # Remove duplicates while preserving order
    findings = list(dict.fromkeys(findings))
    
    return findings

import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import certifi
import fnmatch

def check_ssl_certificate(domain):
    findings = []
    
    # Create a secure SSL context
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_ciphers('HIGH:!aNULL:!eNULL:!MD5:!3DES:!CAMELLIA:!PSK:!SRP')
    
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            try:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Get the certificate in dictionary form (strings)
                    cert = ssock.getpeercert(binary_form=False)
                    # Get the certificate in binary form for cryptography
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_binary)
                    cert_crypto = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                    
                    # Certificate validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    current_time = datetime.utcnow()
                    if current_time > not_after:
                        findings.append(f"Certificate expired on {not_after}")
                    elif (not_after - current_time).days < 30:
                        findings.append(f"Certificate expires soon: {not_after}")
                    if current_time < not_before:
                        findings.append(f"Certificate not yet valid: {not_before}")
                    
                    # Domain validation with wildcard support
                    # Extract CN from subject (tuple of tuples)
                    common_name = None
                    for attr in cert.get('subject', ()):
                        for key, value in attr:
                            if key == 'commonName':
                                common_name = value
                                break
                        if common_name:
                            break
                    
                    san_list = []
                    if 'subjectAltName' in cert:
                        san_list = [entry[1] for entry in cert['subjectAltName'] if entry[0] == 'DNS']
                    
                    domain_matches = False
                    if common_name and (common_name == domain or fnmatch.fnmatch(domain, common_name)):
                        domain_matches = True
                    else:
                        for san in san_list:
                            if san == domain or fnmatch.fnmatch(domain, san):
                                domain_matches = True
                                break
                    if not domain_matches:
                        findings.append(f"Domain mismatch - CN: {common_name}, SAN: {', '.join(san_list)}")
                    
                    # Chain validation (implicitly handled by successful handshake)
                    findings.append("Certificate chain validated successfully (Python SSL)")
                    
                    # Security configuration
                    protocol = ssock.version()
                    if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        findings.append(f"Insecure protocol version: {protocol}")
                    
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name, version, bits = cipher
                        if bits < 128:
                            findings.append(f"Weak cipher strength: {bits} bits")
                        if any(weak in cipher_name for weak in ['RC4', 'DES', '3DES', 'MD5']):
                            findings.append(f"Insecure cipher detected: {cipher_name}")
                    
                    # Signature algorithm (from cryptography)
                    sig_algo = cert_crypto.signature_algorithm_oid._name
                    if sig_algo in ['md5WithRSAEncryption', 'sha1WithRSAEncryption']:
                        findings.append(f"Weak signature algorithm used: {sig_algo}")
                    
                    # Issuer verification
                    issuer = None
                    for attr in cert.get('issuer', ()):
                        for key, value in attr:
                            if key == 'commonName':
                                issuer = value
                                break
                        if issuer:
                            break
                    if not issuer:
                        findings.append("Missing issuer information")
                    
                    # Certificate Transparency (SCT)
                    try:
                        sct_ext = cert_crypto.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps)
                        if not sct_ext.value:
                            findings.append("No valid SCTs found in Certificate Transparency extension")
                        else:
                            findings.append(f"Found {len(sct_ext.value)} valid SCTs")
                    except x509.ExtensionNotFound:
                        findings.append("No Certificate Transparency information (SCT missing)")
                    except Exception as e:
                        findings.append(f"SCT check error: {str(e)}")
            
            except ssl.SSLError as e:
                findings.append(f"SSL handshake failed: {str(e)}")
                # Fallback to unverified context
                unverified_context = ssl._create_unverified_context()
                with unverified_context.wrap_socket(sock, server_hostname=domain) as unverified_ssock:
                    cert_binary = unverified_ssock.getpeercert(binary_form=True)
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_binary)
                    cert_crypto = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                    findings.append("Certificate retrieved without verification due to handshake failure")
                    
    except socket.gaierror:
        findings.append("Domain resolution failed")
    except socket.timeout:
        findings.append("SSL connection timeout")
    except Exception as e:
        findings.append(f"SSL analysis error: {str(e)}")
    
    if not findings:
        findings.append("No SSL/TLS issues detected")
    
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
    
if __name__ == '__main__':
    # Verify API key is loaded
    if not API_KEY:
        logger.warning("Safe Browsing API key not configured - this feature will be disabled")
    
    app.run(host='0.0.0.0', port=5000, debug=True)