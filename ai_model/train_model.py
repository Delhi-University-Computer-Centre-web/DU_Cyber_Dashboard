# ai_model/train_model.py

from models import db, LogEntry
from ai_model.features import extract_features
from flask import Flask
from config import Config
from sklearn.ensemble import IsolationForest
import joblib
import os

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

def train_ai_model():
    with app.app_context():
        entries = LogEntry.query.all()
        if not entries:
            print("⚠️ No log entries found to train the model.")
            return

        X = [extract_features(entry) for entry in entries]
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        model.fit(X)

        joblib.dump(model, Config.MODEL_PATH)
        print(f"✅ Model trained and saved to: {Config.MODEL_PATH}")

if __name__ == "__main__":
    train_ai_model()
