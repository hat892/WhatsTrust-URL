import pandas as pd
import numpy as np
import pickle
import warnings
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import (
    RandomForestClassifier,
    AdaBoostClassifier
)
from sklearn.metrics import (
    classification_report,
    accuracy_score
)
from sklearn.preprocessing import StandardScaler

from xgboost import XGBClassifier

warnings.filterwarnings('ignore')

# =============================================================
# STEP 1: LOAD DATA
# =============================================================

DATA_PATH = "PhiUSIIL_Phishing_URL_Dataset.csv"

print("Loading dataset...")

df = pd.read_csv(DATA_PATH)

# Remove duplicate URLs
df = df.drop_duplicates(subset=['URL']).reset_index(drop=True)

print(f"Dataset shape: {df.shape}")
print(f"Label distribution:\n{df['label'].value_counts()}")

# =============================================================
# STEP 2: TRAIN / TEST SPLIT
# =============================================================

train_df, test_df = train_test_split(
    df,
    test_size=0.2,
    random_state=42,
    stratify=df['label']
)

print(f"\nTraining set: {len(train_df)}")
print(f"Test set: {len(test_df)}")

# =============================================================
# STEP 3: FEATURE SELECTION
# =============================================================

SELECTED_FEATURES = [
    'NoOfSubDomain',
    'DegitRatioInURL',
    'IsHTTPS',
    'HasFavicon',
    'Robots',
    'IsResponsive',
    'HasSubmitButton',
    'HasHiddenFields',
    'Pay'
]

available = [f for f in SELECTED_FEATURES if f in df.columns]
missing = [f for f in SELECTED_FEATURES if f not in df.columns]

if missing:
    print(f"\nMissing features: {missing}")

print(f"\nUsing features: {available}")

X_train = train_df[available]
y_train = train_df['label']

X_test = test_df[available]
y_test = test_df['label']

# =============================================================
# STEP 4: SCALING
# =============================================================

scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# =============================================================
# STEP 5: LOGISTIC REGRESSION
# =============================================================

print("\nTraining Logistic Regression...")

lr_model = LogisticRegression(
    max_iter=1000,
    random_state=42
)

lr_model.fit(X_train_scaled, y_train)

lr_pred = lr_model.predict(X_test_scaled)

lr_acc = accuracy_score(y_test, lr_pred)

print(f"Logistic Regression Accuracy: {lr_acc:.4f}")

print(classification_report(
    y_test,
    lr_pred,
    target_names=['Phishing', 'Legitimate']
))

# =============================================================
# STEP 6: RANDOM FOREST
# =============================================================

print("\nTraining Random Forest...")

rf_model = RandomForestClassifier(
    n_estimators=50,
    random_state=42,
    n_jobs=-1
)

rf_model.fit(X_train, y_train)

rf_pred = rf_model.predict(X_test)

rf_acc = accuracy_score(y_test, rf_pred)

print(f"Random Forest Accuracy: {rf_acc:.4f}")

print(classification_report(
    y_test,
    rf_pred,
    target_names=['Phishing', 'Legitimate']
))

# =============================================================
# STEP 7: XGBOOST
# =============================================================

print("\nTraining XGBoost...")

xgb_model = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=6,
    random_state=42,
    use_label_encoder=False,
    eval_metric='logloss'
)

xgb_model.fit(X_train, y_train)

xgb_pred = xgb_model.predict(X_test)

xgb_acc = accuracy_score(y_test, xgb_pred)

print(f"XGBoost Accuracy: {xgb_acc:.4f}")

print(classification_report(
    y_test,
    xgb_pred
))

# =============================================================
# STEP 8: ADABOOST
# =============================================================

print("\nTraining AdaBoost...")

ada_model = AdaBoostClassifier(
    n_estimators=100,
    random_state=42
)

ada_model.fit(X_train, y_train)

ada_pred = ada_model.predict(X_test)

ada_acc = accuracy_score(y_test, ada_pred)

print(f"AdaBoost Accuracy: {ada_acc:.4f}")

print(classification_report(
    y_test,
    ada_pred
))

# =============================================================
# STEP 9: CORRELATION MATRIX
# =============================================================

print("\nCalculating Correlation Matrix...")

corr_matrix = df.select_dtypes(include=[np.number]).corr()

target_corr = corr_matrix['label'].sort_values(ascending=False)

print("\n--- Feature Correlation with Label ---")
print(target_corr)

plt.figure(figsize=(10, 8))

sns.heatmap(
    corr_matrix,
    annot=False,
    cmap='coolwarm'
)

plt.title("Correlation Matrix")

plt.show()

# =============================================================
# STEP 10: INDIVIDUAL FEATURE CORRELATION
# =============================================================

print("\nFeature Correlation Scores:")

for col in available:
    score = abs(df[col].corr(df['label']))
    print(f"{col}: {score:.4f}")

# =============================================================
# STEP 11: SINGLE FEATURE RANDOM FOREST TEST
# =============================================================

print("\nTesting Features Individually...")

for feature in available:

    Xtr = train_df[[feature]]
    Xte = test_df[[feature]]

    model = RandomForestClassifier(random_state=42)

    model.fit(Xtr, y_train)

    pred = model.predict(Xte)

    acc = accuracy_score(y_test, pred)

    print(f"{feature}: {acc:.4f}")

# =============================================================
# STEP 12: FEATURE IMPORTANCE
# =============================================================

feat_imp = pd.Series(
    rf_model.feature_importances_,
    index=available
)

print("\nFeature Importance (Random Forest):")

print(feat_imp.sort_values(ascending=False))

# =============================================================
# STEP 13: SAVE MODELS
# =============================================================

print("\nSaving models...")

with open('url_classifier_model.pkl', 'wb') as f:
    pickle.dump(rf_model, f)

with open('url_classifier_lr.pkl', 'wb') as f:
    pickle.dump(lr_model, f)

with open('url_scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)

with open('url_features.pkl', 'wb') as f:
    pickle.dump(available, f)

print("\nSaved:")
print("  url_classifier_model.pkl")
print("  url_classifier_lr.pkl")
print("  url_scaler.pkl")
print("  url_features.pkl")

print("\nDone!")