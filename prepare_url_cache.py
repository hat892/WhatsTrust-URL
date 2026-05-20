"""
prepare_url_cache.py  —  Updated version
-----------------------------------------
Run this ONCE after training to pre-classify all URLs.

Key addition: splits phishing URLs into two groups:
  phishing_caught.txt  — phishing the classifier correctly flagged
  phishing_missed.txt  — phishing the classifier got WRONG (labelled legit)

The simulation uses both lists so M2 is a real measurement:
  - phishing_caught URLs → URL gate blocks them (correct detection)
  - phishing_missed URLs → URL gate MISSES them (genuine false negatives)
  → M2 = caught / (caught + missed) = real classifier performance

Run: python prepare_url_cache.py
"""

import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import os

BASE = os.path.dirname(os.path.abspath(__file__))

print("Loading model and features...")
with open(os.path.join(BASE, 'url_classifier_model.pkl'), 'rb') as f:
    model = pickle.load(f)
with open(os.path.join(BASE, 'url_features.pkl'), 'rb') as f:
    feature_names = pickle.load(f)

print(f"Features: {feature_names}")

DATA_PATH = os.path.join(BASE, "PhiUSIIL_Phishing_URL_Dataset.csv")
print(f"Loading dataset...")
df = pd.read_csv(DATA_PATH)
df = df.drop_duplicates(subset=['URL']).reset_index(drop=True)
print(f"Total unique URLs: {len(df)}")

# Train/test split — same seed as training
train_df, test_df = train_test_split(
    df, test_size=0.2, random_state=42, stratify=df['label'])

print("Classifying all URLs with probabilities...")
X = df[feature_names]
proba  = model.predict_proba(X)
labels = model.predict(X)

# P(phishing) = P(class=0) since label 0 = phishing
p_phishing = proba[:, 0]

# ── Write full url_cache.txt ──────────────────────────────────────
cache_path = os.path.join(BASE, "url_cache.txt")
with open(cache_path, 'w', encoding='utf-8') as f:
    f.write("# url\tpredicted_label\tp_phishing\n")
    for url, label, p in zip(df['URL'], labels, p_phishing):
        url = str(url).strip()
        if url and url != 'nan':
            f.write(f"{url}\t{int(label)}\t{p:.6f}\n")
print(f"Written url_cache.txt ({len(df)} URLs)")

# ── Split test-set URLs by ground truth and classifier result ─────
# We use the TEST SPLIT only for simulation (model never saw these)

test_legit_urls    = test_df[test_df['label'] == 1]['URL'].dropna().tolist()
test_phishing_urls = test_df[test_df['label'] == 0]['URL'].dropna().tolist()

# Classify test phishing URLs
X_phi = test_df[test_df['label'] == 0][feature_names]
phi_pred  = model.predict(X_phi)
phi_proba = model.predict_proba(X_phi)[:, 0]

phishing_caught = []  # classifier correctly said phishing (pred=0)
phishing_missed = []  # classifier WRONG — said legit (pred=1) but actually phishing

for url, pred, p in zip(test_phishing_urls, phi_pred, phi_proba):
    if pred == 0:
        phishing_caught.append((url, p))
    else:
        phishing_missed.append((url, p))

print(f"\nTest phishing URLs:    {len(test_phishing_urls)}")
print(f"  Correctly caught:    {len(phishing_caught)} ({len(phishing_caught)*100/max(1,len(test_phishing_urls)):.1f}%)")
print(f"  Missed (false neg):  {len(phishing_missed)} ({len(phishing_missed)*100/max(1,len(test_phishing_urls)):.1f}%)")

# ── Write simulation URL files ────────────────────────────────────

def write_urls(path, url_list):
    with open(path, 'w', encoding='utf-8') as f:
        for item in url_list:
            if isinstance(item, tuple):
                f.write(item[0].strip() + '\n')
            else:
                f.write(str(item).strip() + '\n')

write_urls(os.path.join(BASE, 'test_legit_urls.txt'),     test_legit_urls)
write_urls(os.path.join(BASE, 'test_phishing_urls.txt'),  test_phishing_urls)
write_urls(os.path.join(BASE, 'phishing_caught.txt'),     phishing_caught)
write_urls(os.path.join(BASE, 'phishing_missed.txt'),     phishing_missed)

print(f"\ntest_legit_urls.txt:    {len(test_legit_urls)}")
print(f"test_phishing_urls.txt: {len(test_phishing_urls)}")
print(f"phishing_caught.txt:    {len(phishing_caught)}")
print(f"phishing_missed.txt:    {len(phishing_missed)}")
print("\nDone! Now run your simulation.")