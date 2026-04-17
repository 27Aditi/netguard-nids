# NetGuard NIDS
### Network Intrusion Detection System

A machine learning powered network intrusion detection system that analyzes PCAP files and detects malicious traffic using an ensemble of classifiers combined with anomaly detection via Bayesian combination.

---

## Features

- **PCAP file analysis** — upload any `.pcap` or `.pcapng` file for instant analysis
- **Ensemble classification** — Random Forest, LightGBM, and XGBoost working together
- **Anomaly detection** — Isolation Forest for unsupervised anomaly scoring
- **Bayesian combination** — 50/50 weighted combination of ensemble and anomaly scores
- **32 flow-level features** — manually extracted using NFStream and Scapy
- **Real-time dashboard** — live threat score chart, session history, model info
- **User-friendly verdict** — risk level, network status, threat intensity, traffic behavior
- **Session history** — past sessions stored and displayed in sidebar
- **Live capture** *(coming in Phase 2)* — real-time network interface monitoring

---

## Project Structure

```
netguard-nids/
│
├── backend/
│   ├── main.py                         ← FastAPI app (API endpoints)
│   ├── requirements.txt                ← Backend dependencies
│   │
│   ├── models/
│   │   ├── classifiers/
│   │   │   ├── final_rf.pkl            ← Random Forest model
│   │   │   ├── final_lgbm.pkl          ← LightGBM model
│   │   │   └── final_xgb.pkl           ← XGBoost model
│   │   ├── anomaly/
│   │   │   └── isolation_forest.pkl    ← Isolation Forest model
│   │   ├── scalers/
│   │   │   ├── nidss_scaler.pkl        ← Ensemble scaler
│   │   │   └── if_scaler.pkl           ← Isolation Forest scaler
│   │   ├── encoders/
│   │   │   └── nidss_encoders.pkl      ← Label encoders (proto, service, state)
│   │   ├── feature_order/
│   │   │   ├── nidss_features.pkl      ← Feature order for ensemble
│   │   │   └── if_feature_order.pkl    ← Feature order for Isolation Forest
│   │   └── threshold/
│   │       └── final_threshold.pkl     ← Decision threshold
│   │
│   └── pipelines/
│       ├── feature_extraction.py       ← NFStream + Scapy feature extraction
│       └── prediction.py               ← Prediction pipeline + verdict logic
│
├── frontend/
│   ├── app.py                          ← Flask app
│   └── templates/
│       └── dashboard.html              ← Full dashboard UI
│
├── Dockerfile                          ← Docker deployment config
├── start.sh                            ← Startup script for deployment
├── requirements.txt                    ← Full project dependencies
└── README.md
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend API | FastAPI |
| Frontend | Flask + HTML/CSS/JS |
| Packet capture | NFStream + Scapy |
| ML models | scikit-learn, XGBoost, LightGBM |
| Charts | Chart.js |
| Deployment | Docker |

---

## ML Pipeline

```
PCAP file
    ↓
NFStream → flow-level dataframe
    ↓
Scapy → raw packet features (TTL, window size, RTT, payload)
    ↓
32 features extracted
    ↓
Label encoding + MinMax scaling
    ↓
Ensemble (RF + LightGBM + XGBoost) → attack probability
    ↓
Isolation Forest → anomaly score
    ↓
Bayesian combination (50/50) → combined score
    ↓
Threshold comparison → NORMAL / ATTACK verdict
```

---

## Features Extracted (32)

`dur`, `proto`, `service`, `state`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `sttl`, `dttl`, `sload`, `dload`, `sloss`, `dloss`, `sinpkt`, `swin`, `dwin`, `tcprtt`, `synack`, `smean`, `dmean`, `trans_depth`, `response_body_len`, `ct_srv_src`, `ct_state_ttl`, `ct_src_dport_ltm`, `ct_dst_sport_ltm`, `ct_dst_src_ltm`, `is_ftp_login`, `ct_flw_http_mthd`, `ct_srv_dst`, `is_sm_ips_ports`

---

## Dataset

Trained on **UNSW-NB15** — a comprehensive network intrusion dataset containing modern attack types including Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, and Worms.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/analyze` | Upload PCAP and get verdict |

---

## Running Locally

### Prerequisites
- Python 3.10+
- Npcap (Windows) or libpcap (Linux)
- NIDS virtual environment with all dependencies

### Backend
```bash
cd backend
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
python app.py
```

Open `http://localhost:5000` in your browser.

---

## Dashboard

- **Upload PCAP** — analyze any captured network traffic file
- **Threat score chart** — rolling average line chart of Bayesian scores per flow
- **Session safety score** — how safe the current session is out of 100%
- **Risk level** — Low / Medium / High
- **Network status** — Safe / Suspicious / Danger
- **Threat intensity** — percentage threat level
- **Traffic behavior** — Stable / Unstable / Erratic
- **Analyst note** — auto-generated plain English summary
- **Model info** — details about the ML pipeline
- **Session history** — past analysis sessions

---

## Author

Aditi Bhatnagar  
B.Tech — [Your Branch]  
[Your College]
