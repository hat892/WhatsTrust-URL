"""
classify_realtime.py
---------------------
Called ONCE by Java at startup to classify all URLs in the
simulation pools (test_phishing_urls.txt + test_legit_urls.txt).

Extracts 3 features from URL string only — no network access needed:
  NoOfSubDomain  : count of subdomains
  DegitRatioInURL: ratio of digits in URL
  IsHTTPS        : 1 if https, 0 if http

Output format (one line per URL):
  url<TAB>label<TAB>p_phishing

Usage: python classify_realtime.py <input_urls.txt> <output_results.txt>
"""

import sys
import re
import pickle
import numpy as np
from urllib.parse import urlparse

# Load model
import os
BASE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE, 'url_classifier_3f.pkl'), 'rb') as f:
    model = pickle.load(f)
with open(os.path.join(BASE, 'url_features_3f.pkl'), 'rb') as f:
    features = pickle.load(f)

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc or ''
    domain_clean = domain.split(':')[0]
    parts = domain_clean.split('.')
    
    # NoOfSubDomain: number of subdomains (parts beyond domain + TLD)
    num_sub = max(0, len(parts) - 2)
    
    # DegitRatioInURL: ratio of digits in full URL
    digits = sum(c.isdigit() for c in url)
    digit_ratio = digits / len(url) if len(url) > 0 else 0
    
    # IsHTTPS
    is_https = 1 if url.startswith('https') else 0
    
    feat_map = {
        'NoOfSubDomain':   num_sub,
        'DegitRatioInURL': digit_ratio,
        'IsHTTPS':         is_https
    }
    return [feat_map[f] for f in features]

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python classify_realtime.py <input> <output>")
        sys.exit(1)
    
    input_file  = sys.argv[1]
    output_file = sys.argv[2]
    
    urls = []
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                urls.append(line)
    
    print(f"Classifying {len(urls)} URLs...")
    
    X = np.array([extract_features(u) for u in urls])
    labels = model.predict(X)
    probas = model.predict_proba(X)[:, 0]  # P(phishing) = P(class 0)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# url\tlabel\tp_phishing\n")
        for url, label, p in zip(urls, labels, probas):
            f.write(f"{url}\t{int(label)}\t{p:.6f}\n")
    
    print(f"Done. Written to {output_file}")
