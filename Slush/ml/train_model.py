import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

df = pd.read_csv("dataset.csv")

FEATURES = ["packet_count", "byte_count", "flow_duration", "bytes_per_packet"]
X = df[FEATURES]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")
clf.fit(X_train, y_train)

print(classification_report(
    y_test, clf.predict(X_test),
    target_names=["ddos", "benign", "exfiltration"]
))

joblib.dump(clf, "../controller/model_RF.pkl")
print("Saved model to ../controller/model_RF.pkl")
