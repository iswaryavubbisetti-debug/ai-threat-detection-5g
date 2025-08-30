numpy
pandas
scikit-learn
tensorflow
matplotlib
streamlit
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from tensorflow.keras import layers, models

class AutoencoderModel:
    def __init__(self, input_dim):
        inp = layers.Input(shape=(input_dim,))
        enc = layers.Dense(64, activation="relu")(inp)
        enc = layers.Dense(32, activation="relu")(enc)
        dec = layers.Dense(64, activation="relu")(enc)
        out = layers.Dense(input_dim, activation="linear")(dec)
        self.model = models.Model(inp, out)
        self.model.compile(optimizer="adam", loss="mse")

    def train(self, X, epochs=5, batch_size=128):
        self.model.fit(X, X, epochs=epochs, batch_size=batch_size, verbose=0)

    def score(self, X):
        recon = self.model.predict(X, verbose=0)
        return ((X - recon)**2).mean(axis=1)

class IsolationForestModel:
    def __init__(self):
        self.model = IsolationForest(contamination=0.01, random_state=42)

    def train(self, X):
        self.model.fit(X)

    def score(self, X):
        return -self.model.decision_function(X)
import json

def block_ip(ip):
    print(f"[ACTION] Blocking IP: {ip}")

def isolate_container(container_id):
    print(f"[ACTION] Isolating container: {container_id}")

def send_alert(msg):
    print(f"[ALERT] {msg}")

def automated_response(alerts_file):
    with open(alerts_file, 'r') as f:
        alerts = json.load(f)
    for alert in alerts:
        if alert["type"] == "ddos":
            block_ip(alert.get("src_ip", "unknown"))
        elif alert["type"] == "compromise":
            isolate_container(alert.get("container", "unknown"))
        send_alert(f"Incident handled: {alert}")
import streamlit as st
import pandas as pd
import numpy as np
import json
from sklearn.preprocessing import StandardScaler
from src.model import AutoencoderModel, IsolationForestModel
from src.response import automated_response

st.title("🔐 AI Threat Detection in 5G Cloud Networks")

st.sidebar.header("⚙️ Settings")
model_choice = st.sidebar.selectbox("Choose Model", ["Autoencoder", "Isolation Forest"])

uploaded_file = st.file_uploader("Upload Network Flow CSV", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.write("📊 Uploaded Data", df.head())

    scaler = StandardScaler()
    X = scaler.fit_transform(df.select_dtypes(include=[np.number]))

    if model_choice == "Autoencoder":
        model = AutoencoderModel(input_dim=X.shape[1])
        model.train(X)
        scores = model.score(X)
    else:
        model = IsolationForestModel()
        model.train(X)
        scores = model.score(X)

    threshold = np.percentile(scores, 95)
    anomalies = (scores >= threshold).astype(int)
    df["anomaly"] = anomalies

    st.subheader("🚨 Detection Results")
    st.write(df["anomaly"].value_counts())

    alerts = [{"type": "ddos", "src_ip": "192.168.0.1"} for i in range(df["anomaly"].sum())]
    with open("alerts.json", "w") as f:
        json.dump(alerts, f)

    st.download_button("⬇️ Download Alerts", json.dumps(alerts), "alerts.json")

    if st.button("⚡ Trigger Automated Response"):
        automated_response("alerts.json")
        st.success("Automated Response Executed ✅")
