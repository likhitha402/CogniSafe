from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
from sklearn.ensemble import IsolationForest

app = Flask(__name__)
CORS(app)

user_profile = []
model = IsolationForest(contamination=0.1)
login_attempts_count = 0

def extract_features(data):
    ks = data.get("keystrokes", [])
    mouse = data.get("mouse", [])

    intervals = [ks[i]['t'] - ks[i-1]['t'] for i in range(1, len(ks))]
    typing_speed = np.mean(intervals) if intervals else 0

    speeds = []
    for i in range(1, len(mouse)):
        dx = mouse[i]['x'] - mouse[i-1]['x']
        dy = mouse[i]['y'] - mouse[i-1]['y']
        dt = mouse[i]['t'] - mouse[i-1]['t']
        if dt > 0:
            speeds.append(((dx**2 + dy**2)**0.5) / dt)
    mouse_speed = np.mean(speeds) if speeds else 0

    idle = data.get("idle", 0)
    return [typing_speed, mouse_speed, idle]

def behavior_score(features):
    user_profile.append(features)
    if len(user_profile) > 10:
        model.fit(user_profile)
        result = model.predict([features])[0]
        return 0.9 if result == -1 else 0.1
    return 0.1

def phishing_score(text):
    keywords = ["urgent", "blocked", "verify", "act now",
                "gift card", "wire", "offshore"]
    score = sum(0.15 for k in keywords if k in text.lower())
    return min(score, 1.0)

def login_score(attempts):
    return min(attempts * 0.2, 1.0)

def risk_engine(b, p, l):
    return int((b * 0.4 + p * 0.35 + l * 0.25) * 100)

def decision(risk):
    if risk > 70:
        return "BLOCK"
    elif risk > 40:
        return "VERIFY"
    return "ALLOW"

@app.route("/analyze", methods=["POST"])
def analyze():
    global login_attempts_count
    data = request.json
    event_type = data.get("event")

    if event_type == "reset":
        login_attempts_count = 0
        user_profile.clear()
        return jsonify({"status": "reset"})

    if event_type == "login_attempt":
        login_attempts_count += 1

    features = extract_features(data)
    b = behavior_score(features)
    note = data.get("note", "")
    p = phishing_score(note)
    l = login_score(login_attempts_count)

    risk = risk_engine(b, p, l)
    action = decision(risk)

    reasons = []
    if b > 0.5:
        reasons.append("Typing pattern mismatch")
    if p > 0.3:
        reasons.append("Phishing keywords detected")
    if l > 0.4:
        reasons.append("Multiple failed logins")

    return jsonify({
        "risk": risk,
        "action": action,
        "behavior": round(b, 2),
        "phishing": round(p, 2),
        "login": round(l, 2),
        "reasons": reasons
    })

if __name__ == "__main__":
    app.run(debug=True)