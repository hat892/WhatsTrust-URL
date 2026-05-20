"""
classify_urls_batch.py
-----------------------
Classifies ALL URLs in one call using the EXACT SAME
feature extraction as predict_url.py.

Usage: python classify_urls_batch.py <input_file> <output_file>
  input_file:  one URL per line
  output_file: one result per line (0=phishing, 1=legitimate)
"""

import sys
import re
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import os

# =============================================================
# LOAD MODEL
# =============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE_DIR, 'url_classifier_model.pkl'), 'rb') as f:
    model = pickle.load(f)
with open(os.path.join(BASE_DIR, 'url_features.pkl'), 'rb') as f:
    feature_names = pickle.load(f)

# Known legitimate TLDs (same as predict_url.py)
LEGIT_TLDS = {
    'com': 0.522907, 'org': 0.079963, 'net': 0.079963,
    'edu': 0.079963, 'gov': 0.079963, 'uk': 0.035,
    'de': 0.033, 'in': 0.005, 'io': 0.01, 'co': 0.02
}

# =============================================================
# FEATURE EXTRACTION — identical to predict_url.py
# =============================================================
def extract_features(url: str) -> dict:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or ''
        full   = url
        domain_clean = domain.split(':')[0]
        subdomains = domain_clean.split('.')
        tld = subdomains[-1] if subdomains else ''

        letters   = sum(c.isalpha() for c in full)
        digits    = sum(c.isdigit() for c in full)
        equals    = full.count('=')
        qmarks    = full.count('?')
        ampersand = full.count('&')
        special   = sum(1 for c in full if not c.isalnum() and c not in ['/', '.', '-', '_', ':', '?', '=', '&', '#', '%'])
        url_len   = len(full)
        dom_len   = len(domain_clean)
        tld_len   = len(tld)
        is_ip     = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain_clean) else 0
        num_sub   = max(0, len(subdomains) - 2)
        obf_chars = len(re.findall(r'%[0-9a-fA-F]{2}', full))
        has_obf   = 1 if obf_chars > 0 or '@' in full else 0
        obf_ratio = obf_chars / url_len if url_len > 0 else 0
        is_https  = 1 if url.startswith('https') else 0
        tld_prob  = LEGIT_TLDS.get(tld.lower(), 0.001)
        url_char_prob = (letters + digits) / url_len if url_len > 0 else 0

        def char_cont(s):
            if not s: return 0
            max_run = run = 1
            for i in range(1, len(s)):
                if s[i].isalpha() == s[i-1].isalpha():
                    run += 1
                    max_run = max(max_run, run)
                else:
                    run = 1
            return max_run / len(s)

        common = ['google', 'facebook', 'amazon', 'paypal', 'apple', 'microsoft', 'netflix']
        url_sim = 100
        for legit in common:
            if legit in domain_clean.lower() and domain_clean.lower() != f'www.{legit}.com':
                url_sim = 50

        return {
            'URLLength':                  url_len,
            'DomainLength':               dom_len,
            'IsDomainIP':                 is_ip,
            'URLSimilarityIndex':         url_sim,
            'CharContinuationRate':       char_cont(full),
            'TLDLegitimateProb':          tld_prob,
            'URLCharProb':                url_char_prob,
            'TLDLength':                  tld_len,
            'NoOfSubDomain':              num_sub,
            'HasObfuscation':             has_obf,
            'NoOfObfuscatedChar':         obf_chars,
            'ObfuscationRatio':           obf_ratio,
            'NoOfLettersInURL':           letters,
            'LetterRatioInURL':           letters / url_len if url_len > 0 else 0,
            'NoOfDegitsInURL':            digits,
            'DegitRatioInURL':            digits / url_len if url_len > 0 else 0,
            'NoOfEqualsInURL':            equals,
            'NoOfQMarkInURL':             qmarks,
            'NoOfAmpersandInURL':         ampersand,
            'NoOfOtherSpecialCharsInURL': special,
            'SpacialCharRatioInURL':      special / url_len if url_len > 0 else 0,
            'IsHTTPS':                    is_https,
        }
    except Exception:
        return {f: 0 for f in feature_names}

# =============================================================
# MAIN
# =============================================================
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python classify_urls_batch.py <input_file> <output_file>")
        sys.exit(1)

    input_file  = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    # Extract features for ALL URLs
    features_list = [extract_features(url) for url in urls]
    X = pd.DataFrame(features_list, columns=feature_names)

    # Classify all at once (vectorized)
    predictions = model.predict(X)

    # Write results
    with open(output_file, 'w') as f:
        for pred in predictions:
            f.write(str(int(pred)) + '\n')

    legit   = sum(predictions)
    phishing = len(predictions) - legit
    print(f"Classified {len(urls)} URLs: {int(legit)} legitimate, {int(phishing)} phishing.")
