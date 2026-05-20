"""
predict_url.py
--------------
This script is called by the WhatsTrust Java simulator to classify a URL.
Java calls it like: python predict_url.py "https://example.com/path?q=1"
Returns: 1 (Legitimate) or 0 (Phishing)

URL Feature Extraction is done here — no need to visit the page.
All features are extracted purely from the URL string itself.
"""

import sys
import re
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse

# =============================================================
# LOAD MODEL (only once when script starts)
# =============================================================
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE_DIR, 'url_classifier_model.pkl'), 'rb') as f:
    model = pickle.load(f)
with open(os.path.join(BASE_DIR, 'url_features.pkl'), 'rb') as f:
    feature_names = pickle.load(f)

# Known legitimate TLDs and their probability scores
LEGIT_TLDS = {
    'com': 0.522907, 'org': 0.079963, 'net': 0.079963,
    'edu': 0.079963, 'gov': 0.079963, 'uk': 0.035,
    'de': 0.033, 'in': 0.005, 'io': 0.01, 'co': 0.02
}

# =============================================================
# FEATURE EXTRACTION FROM URL STRING
# =============================================================
def extract_features(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc or ''
    path   = parsed.path or ''
    query  = parsed.query or ''
    full   = url

    # Remove port from domain if present
    domain_clean = domain.split(':')[0]
    subdomains = domain_clean.split('.')
    tld = subdomains[-1] if subdomains else ''
    domain_no_tld = '.'.join(subdomains[:-1]) if len(subdomains) > 1 else domain_clean

    # Count characters
    letters   = sum(c.isalpha() for c in full)
    digits    = sum(c.isdigit() for c in full)
    equals    = full.count('=')
    qmarks    = full.count('?')
    ampersand = full.count('&')
    special   = sum(1 for c in full if not c.isalnum() and c not in ['/', '.', '-', '_', ':', '?', '=', '&', '#', '%'])

    url_len   = len(full)
    dom_len   = len(domain_clean)
    tld_len   = len(tld)

    # Is domain an IP address?
    is_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain_clean) else 0

    # Subdomains count
    num_subdomains = max(0, len(subdomains) - 2)

    # Obfuscation: hex encoding, @ symbol, double slashes
    obfuscated_chars = len(re.findall(r'%[0-9a-fA-F]{2}', full))
    has_obfuscation  = 1 if obfuscated_chars > 0 or '@' in full else 0
    obfuscation_ratio = obfuscated_chars / url_len if url_len > 0 else 0

    # IsHTTPS
    is_https = 1 if url.startswith('https') else 0

    # TLD legitimacy probability
    tld_prob = LEGIT_TLDS.get(tld.lower(), 0.001)

    # URL char probability (ratio of alphanumeric)
    url_char_prob = (letters + digits) / url_len if url_len > 0 else 0

    # Character continuation rate (longest run of same char type / length)
    def char_continuation(s):
        if not s:
            return 0
        max_run = run = 1
        for i in range(1, len(s)):
            if s[i].isalpha() == s[i-1].isalpha():
                run += 1
                max_run = max(max_run, run)
            else:
                run = 1
        return max_run / len(s)

    char_cont = char_continuation(full)

    # URL similarity index (check for common legitimate domains misspelled)
    common_domains = ['google', 'facebook', 'amazon', 'paypal', 'apple', 'microsoft', 'netflix']
    url_sim = 100  # default: assume similar to legitimate
    for legit in common_domains:
        if legit in domain_clean.lower() and domain_clean.lower() != f'www.{legit}.com':
            url_sim = 50  # suspicious similarity

    features = {
        'URLLength':                   url_len,
        'DomainLength':                dom_len,
        'IsDomainIP':                  is_ip,
        'URLSimilarityIndex':          url_sim,
        'CharContinuationRate':        char_cont,
        'TLDLegitimateProb':           tld_prob,
        'URLCharProb':                 url_char_prob,
        'TLDLength':                   tld_len,
        'NoOfSubDomain':               num_subdomains,
        'HasObfuscation':              has_obfuscation,
        'NoOfObfuscatedChar':          obfuscated_chars,
        'ObfuscationRatio':            obfuscation_ratio,
        'NoOfLettersInURL':            letters,
        'LetterRatioInURL':            letters / url_len if url_len > 0 else 0,
        'NoOfDegitsInURL':             digits,
        'DegitRatioInURL':             digits / url_len if url_len > 0 else 0,
        'NoOfEqualsInURL':             equals,
        'NoOfQMarkInURL':              qmarks,
        'NoOfAmpersandInURL':          ampersand,
        'NoOfOtherSpecialCharsInURL':  special,
        'SpacialCharRatioInURL':       special / url_len if url_len > 0 else 0,
        'IsHTTPS':                     is_https,
    }
    return features

# =============================================================
# PREDICT
# =============================================================
def predict(url: str) -> int:
    features = extract_features(url)
    # Change this line:
    X = np.array([[features[f] for f in feature_names]])
    # To this:
    X = pd.DataFrame([[features[f] for f in feature_names]], columns=feature_names)
    return int(model.predict(X)[0])

# =============================================================
# MAIN — called by Java
# Usage: python predict_url.py "https://example.com"
# Output: 1 (Legitimate) or 0 (Phishing)
# =============================================================
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python predict_url.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    result = predict(url)
    print(result)  # Java reads this output