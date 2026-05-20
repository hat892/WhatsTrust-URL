import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
import pickle
import warnings
warnings.filterwarnings('ignore')

# =============================================================
# STEP 1: LOAD DATA
# =============================================================
DATA_PATH = r"C:\Users\Hatna\OneDrive\Desktop\selected project\Our Code\PhiUSIIL_Phishing_URL_Dataset.csv"

print("Loading dataset...")
df = pd.read_csv(DATA_PATH)
print(f"Dataset shape: {df.shape}")
print(f"Label distribution:\n{df['label'].value_counts()}")

# =============================================================
# STEP 2: SPLIT FIRST — save test URLs before dropping URL column
# This prevents data leakage in the simulation
# =============================================================
train_df, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['label'])
print(f"\nTraining set: {len(train_df)} | Test set: {len(test_df)}")

# Save test set URLs — these will be used in simulation messages
# The model has NEVER seen these URLs during training
test_legit    = test_df[test_df['label'] == 1]['URL'].dropna().tolist()
test_phishing = test_df[test_df['label'] == 0]['URL'].dropna().tolist()

print(f"Test legitimate URLs saved: {len(test_legit)}")
print(f"Test phishing URLs saved:   {len(test_phishing)}")

with open('test_legit_urls.txt', 'w', encoding='utf-8') as f:
    for url in test_legit:
        f.write(url + '\n')

with open('test_phishing_urls.txt', 'w', encoding='utf-8') as f:
    for url in test_phishing:
        f.write(url + '\n')

print("Saved: test_legit_urls.txt and test_phishing_urls.txt")

# =============================================================
# STEP 3: SELECT FEATURES
# Using these 15 specific features from the dataset
# =============================================================
SELECTED_FEATURES = [
    'URLSimilarityIndex',
    'NoOfSubDomain',
    'DegitRatioInURL',
    'IsHTTPS',
    'DomainTitleMatchScore',
    'URLTitleMatchScore',
    'HasFavicon',
    'Robots',
    'IsResponsive',
    'HasDescription',
    'HasSocialNet',
    'HasSubmitButton',
    'HasHiddenFields',
    'Pay',
    'HasCopyrightInfo'
]

# Keep only features that exist in the dataset
available = [f for f in SELECTED_FEATURES if f in df.columns]
missing   = [f for f in SELECTED_FEATURES if f not in df.columns]

if missing:
    print(f"\nWARNING: These features not found: {missing}")

print(f"\nUsing {len(available)} features: {available}")

X_train = train_df[available]
y_train = train_df['label']
X_test  = test_df[available]
y_test  = test_df['label']

print(f"Training: {X_train.shape[0]} | Test: {X_test.shape[0]}")

# =============================================================
# STEP 4: TRAIN MODELS
# =============================================================
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

print("\nTraining Logistic Regression...")
lr = LogisticRegression(max_iter=1000, random_state=42)
lr.fit(X_train_scaled, y_train)
lr_acc = accuracy_score(y_test, lr.predict(X_test_scaled))
print(f"LR Accuracy: {lr_acc:.4f}")
print(classification_report(y_test, lr.predict(X_test_scaled),
      target_names=['Phishing', 'Legitimate']))

print("\nTraining Random Forest (50 trees)...")
rf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
rf_acc = accuracy_score(y_test, rf.predict(X_test))
print(f"RF Accuracy: {rf_acc:.4f}")
print(classification_report(y_test, rf.predict(X_test),
      target_names=['Phishing', 'Legitimate']))

# Feature importance
feat_imp = pd.Series(rf.feature_importances_, index=available)
print("\nFeature Importance (Random Forest):")
print(feat_imp.sort_values(ascending=False).to_string())

# =============================================================
# STEP 5: SAVE MODELS
# =============================================================
print("\nSaving models...")

with open('url_classifier_model.pkl', 'wb') as f:
    pickle.dump(rf, f)
with open('url_classifier_lr.pkl', 'wb') as f:
    pickle.dump(lr, f)
with open('url_scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)
with open('url_features.pkl', 'wb') as f:
    pickle.dump(available, f)

print("Saved:")
print("  url_classifier_model.pkl  (Random Forest)")
print("  url_classifier_lr.pkl     (Logistic Regression)")
print("  url_scaler.pkl")
print("  url_features.pkl")
print(f"\nBest model: Random Forest ({rf_acc:.4f})")
print("\nDone! Now run prepare_messages.py to create 6000 message files.")