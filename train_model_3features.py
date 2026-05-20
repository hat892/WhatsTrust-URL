"""
train_model_3features.py
-------------------------
Retrains the model using ONLY 3 features extractable from URL string:
  - NoOfSubDomain
  - DegitRatioInURL
  - IsHTTPS

These 3 features require NO webpage visit — pure string parsing.
This allows real-time classification during simulation.

Run: python train_model_3features.py
Outputs: url_classifier_3f.pkl, url_features_3f.pkl
"""

import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import warnings
warnings.filterwarnings('ignore')

DATA_PATH = "PhiUSIIL_Phishing_URL_Dataset.csv"

print("Loading dataset...")
df = pd.read_csv(DATA_PATH)
df = df.drop_duplicates(subset=['URL']).reset_index(drop=True)
print(f"Dataset shape: {df.shape}")

FEATURES = ['NoOfSubDomain', 'DegitRatioInURL', 'IsHTTPS']

available = [f for f in FEATURES if f in df.columns]
print(f"Using features: {available}")

train_df, test_df = train_test_split(
    df, test_size=0.2, random_state=42, stratify=df['label'])

X_train = train_df[available]
y_train = train_df['label']
X_test  = test_df[available]
y_test  = test_df['label']

print("\nTraining Random Forest (3 features)...")
rf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

pred = rf.predict(X_test)
acc  = accuracy_score(y_test, pred)
print(f"Accuracy: {acc:.4f}")
print(classification_report(y_test, pred, target_names=['Phishing','Legitimate']))

# Save
with open('url_classifier_3f.pkl', 'wb') as f:
    pickle.dump(rf, f)
with open('url_features_3f.pkl', 'wb') as f:
    pickle.dump(available, f)

print("\nSaved: url_classifier_3f.pkl, url_features_3f.pkl")
print(f"Accuracy with 3 string-only features: {acc:.4f}")
print("Done!")
