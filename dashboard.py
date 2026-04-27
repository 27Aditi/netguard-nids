
import os
import sys
import time
import subprocess
import threading
import tempfile
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
from scapy.all import AsyncSniffer, wrpcap

st.set_page_config(
    page_title="NetGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
            
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600;700&display=swap');


:root {
    --bg:         #0b0f1a;
    --bg2:        #111827;
    --bg3:        #1a2235;
    --border:     #1e2d45;
    --accent:     #00d4ff;
    --accent2:    #7c3aed;
    --green:      #10b981;
    --yellow:     #f59e0b;
    --red:        #ef4444;
    --text:       #e2e8f0;
    --text-muted: #64748b;
    --mono:       'Space Mono', monospace;
    --sans:       'DM Sans', sans-serif;
}

html, body, [class*="css"] {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--sans) !important;
}

#MainMenu, footer { visibility: hidden; }
.block-container { padding-top: 3rem !important; padding-bottom: 2rem !important; }

[data-testid="stSidebar"] {
    background: var(--bg2) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text) !important; }

.ng-topbar {
    background: linear-gradient(135deg, var(--bg2) 0%, #0d1525 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.4rem 2rem;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: relative;
    overflow: hidden;
}
.ng-topbar::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent2), var(--accent), var(--green));
}
.ng-logo { display: flex; align-items: center; gap: 1rem; }
.ng-logo-icon {
    width: 44px; height: 44px;
    background: linear-gradient(135deg, var(--accent2), var(--accent));
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.3rem;
}
.ng-logo-text h1 {
    font-family: var(--mono) !important;
    font-size: 1.3rem !important;
    font-weight: 700 !important;
    color: var(--accent) !important;
    margin: 0 !important; padding: 0 !important;
    letter-spacing: 0.05em;
}
.ng-logo-text p {
    font-size: 0.75rem !important;
    color: var(--text-muted) !important;
    margin: 0 !important;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}
.ng-status-pill {
    font-family: var(--mono);
    font-size: 0.72rem;
    padding: 0.35rem 0.85rem;
    border-radius: 20px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}
.ng-status-pill.ready {
    background: rgba(16,185,129,0.12);
    color: var(--green);
    border: 1px solid rgba(16,185,129,0.3);
}
.ng-status-pill.scanning {
    background: rgba(0,212,255,0.12);
    color: var(--accent);
    border: 1px solid rgba(0,212,255,0.3);
    animation: pulse-glow 1.5s ease-in-out infinite;
}
.ng-status-pill.alert {
    background: rgba(239,68,68,0.12);
    color: var(--red);
    border: 1px solid rgba(239,68,68,0.3);
}
@keyframes pulse-glow {
    0%, 100% { box-shadow: 0 0 4px rgba(0,212,255,0.3); }
    50%       { box-shadow: 0 0 12px rgba(0,212,255,0.6); }
}

.ng-metric {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem 1.4rem;
    position: relative;
    overflow: hidden;
    transition: transform 0.2s, border-color 0.2s;
}
.ng-metric:hover { transform: translateY(-2px); border-color: var(--accent); }
.ng-metric::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 3px;
    border-radius: 0 0 12px 12px;
}
.ng-metric.blue::after   { background: var(--accent); }
.ng-metric.purple::after { background: var(--accent2); }
.ng-metric.green::after  { background: var(--green); }
.ng-metric.red::after    { background: var(--red); }
.ng-metric.yellow::after { background: var(--yellow); }
.ng-metric-label {
    font-size: 0.7rem !important;
    color: var(--text-muted) !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.4rem;
    font-weight: 600;
}
.ng-metric-value {
    font-family: var(--mono) !important;
    font-size: 2rem !important;
    font-weight: 700 !important;
    line-height: 1.1;
    margin-bottom: 0.3rem;
}
.ng-metric-value.blue   { color: var(--accent) !important; }
.ng-metric-value.purple { color: var(--accent2) !important; }
.ng-metric-value.green  { color: var(--green) !important; }
.ng-metric-value.red    { color: var(--red) !important; }
.ng-metric-value.yellow { color: var(--yellow) !important; }
.ng-metric-sub {
    font-size: 0.72rem !important;
    color: var(--text-muted) !important;
}
.ng-metric-icon {
    position: absolute; top: 1rem; right: 1rem;
    font-size: 1.4rem; opacity: 0.15;
}

[data-testid="stVerticalBlockBorderWrapper"] {
    background: var(--bg2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    padding: 0.4rem 0.6rem !important;
    margin-bottom: 1.2rem !important;
}

.ng-panel-title {
    font-family: var(--mono) !important;
    font-size: 0.78rem !important;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text-muted) !important;
    font-weight: 700 !important;
    margin-bottom: 1rem;
    display: flex; align-items: center; gap: 0.5rem;
}
.ng-panel-title span { color: var(--accent); font-size: 1rem; }

.ng-verdict {
    display: inline-flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.6rem 1.4rem;
    border-radius: 8px;
    font-family: var(--mono);
    font-size: 1.1rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    margin-bottom: 0.5rem;
}
.ng-verdict.safe {
    background: rgba(16,185,129,0.12);
    color: var(--green);
    border: 1px solid rgba(16,185,129,0.4);
}
.ng-verdict.attack {
    background: rgba(239,68,68,0.12);
    color: var(--red);
    border: 1px solid rgba(239,68,68,0.4);
    animation: threat-pulse 2s ease-in-out infinite;
}
@keyframes threat-pulse {
    0%, 100% { box-shadow: 0 0 6px rgba(239,68,68,0.2); }
    50%       { box-shadow: 0 0 20px rgba(239,68,68,0.5); }
}

[data-testid="stFileUploader"] {
    background: var(--bg3) !important;
    border: 2px dashed var(--border) !important;
    border-radius: 12px !important;
    transition: border-color 0.2s;
}
[data-testid="stFileUploader"]:hover {
    border-color: var(--accent) !important;
}
[data-testid="stFileUploader"] * { color: var(--text) !important; }

.stButton > button {
    background: linear-gradient(135deg, var(--accent2), var(--accent)) !important;
    color: #fff !important;
    border: none !important;
    border-radius: 8px !important;
    font-family: var(--mono) !important;
    font-weight: 700 !important;
    font-size: 0.82rem !important;
    letter-spacing: 0.06em !important;
    text-transform: uppercase !important;
    padding: 0.6rem 1.4rem !important;
    transition: opacity 0.2s, transform 0.15s !important;
    width: 100%;
}
.stButton > button:hover {
    opacity: 0.88 !important;
    transform: translateY(-1px) !important;
}
.stButton > button:active { transform: translateY(0px) !important; }

.stop-btn .stButton > button {
    background: linear-gradient(135deg, #7f1d1d, var(--red)) !important;
}

.stSpinner > div { border-top-color: var(--accent) !important; }
.stProgress > div > div > div {
    background: linear-gradient(90deg, var(--accent2), var(--accent)) !important;
}

.js-plotly-plot .plotly { background: transparent !important; }

.ng-analyst-note {
    background: rgba(0,212,255,0.05);
    border-left: 3px solid var(--accent);
    border-radius: 0 8px 8px 0;
    padding: 0.8rem 1.2rem;
    font-size: 0.88rem;
    color: var(--text);
    margin-top: 0.8rem;
}

.ng-callout {
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.2rem;
    font-size: 0.85rem;
    line-height: 1.7;
    color: var(--text);
}
.ng-callout b { color: var(--accent); }

.stSelectbox > div > div, .stSlider { background: transparent !important; }
[data-baseweb="select"] > div {
    background: var(--bg3) !important;
    border-color: var(--border) !important;
    color: var(--text) !important;
}

[data-testid="stExpander"] {
    background: var(--bg3) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
}
[data-testid="stExpander"] summary { color: var(--text) !important; }

hr { border-color: var(--border) !important; }

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg2); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent); }
</style>
""", unsafe_allow_html=True)


def panel_title(icon, text):
    st.markdown(
        f'<div class="ng-panel-title"><span>{icon}</span> {text}</div>',
        unsafe_allow_html=True,
    )

def html_panel(icon, title, content):
    panel_html = f"""
    <div class="ng-panel">
        <div class="ng-panel-title">{icon} {title}</div>
        {content}
    </div>
    """
    st.markdown(panel_html, unsafe_allow_html=True)



def html_panel(icon, title, body_html):
    st.markdown(f"""
    <div style="background:#111827;border:1px solid #1e2d45;border-radius:12px;
                padding:1.4rem 1.6rem;margin-bottom:1.2rem;">
      <div class="ng-panel-title"><span>{icon}</span> {title}</div>
      {body_html}
    </div>
    """, unsafe_allow_html=True)


def _plotly_layout(title="", height=320):
    return dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="DM Sans, sans-serif", color="#e2e8f0", size=11),
        title=dict(text=title, font=dict(size=13, color="#64748b",
                                          family="Space Mono, monospace")),
        margin=dict(l=10, r=10, t=40 if title else 10, b=10),
        height=height,
        showlegend=True,
        legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor="rgba(0,0,0,0)",
                    font=dict(size=10)),
        xaxis=dict(gridcolor="#1e2d45", zerolinecolor="#1e2d45",
                   tickfont=dict(size=10)),
        yaxis=dict(gridcolor="#1e2d45", zerolinecolor="#1e2d45",
                   tickfont=dict(size=10)),
    )


def render_topbar(status="ready"):
    status_map = {
        "ready":    ("SYSTEM READY",      "ready"),
        "scanning": ("ANALYZING...",      "scanning"),
        "attack":   ("⚠ THREAT DETECTED", "alert"),
        "normal":   ("ALL CLEAR",         "ready"),
    }
    label, cls = status_map.get(status, ("READY", "ready"))
    ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    st.markdown(f"""
    <div class="ng-topbar">
      <div class="ng-logo">
        <div class="ng-logo-icon">🛡️</div>
        <div class="ng-logo-text">
          <h1>NetGuard AI</h1>
          <p>Network Threat Intelligence Platform</p>
        </div>
      </div>
      <div style="text-align:right">
        <div class="ng-status-pill {cls}">{label}</div>
        <div style="font-size:0.68rem;color:#334155;margin-top:0.3rem;
                    font-family:'Space Mono',monospace;">{ts}</div>
      </div>
    </div>
    """, unsafe_allow_html=True)


def render_metric(label, value, sub, color="blue", icon=""):
    st.markdown(f"""
    <div class="ng-metric {color}">
      <div class="ng-metric-icon">{icon}</div>
      <div class="ng-metric-label">{label}</div>
      <div class="ng-metric-value {color}">{value}</div>
      <div class="ng-metric-sub">{sub}</div>
    </div>
    """, unsafe_allow_html=True)


def human_bytes(n):
    for unit in ['B','KB','MB','GB']:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def plain_english_risk(risk, verdict, note):
    if verdict == "NORMAL":
        headline = "✅ Your network looks healthy"
        body = ("Our AI scanned every connection in this file and found no signs of "
                "hacking, data theft, or unusual activity. Think of it like a security "
                "guard who watched every person enter and leave a building — nobody "
                "suspicious was spotted.")
    else:
        headline = "⚠️ Suspicious activity was detected"
        body = ("Our AI found patterns in this network traffic that look like they could "
                "be an attack — similar to noticing someone trying every door handle in "
                "a building. This doesn't mean damage has been done, but it's worth "
                "asking your IT team to take a closer look.")
    return headline, body


MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

@st.cache_resource(show_spinner=False)
def load_artifacts_cached():
    try:
        from prediction import load_artifacts
        return load_artifacts(MODELS_DIR), None
    except Exception as e:
        return None, str(e)


def run_full_analysis(pcap_path):
    try:
        from feature_extraction import extract_all_features
        from prediction import load_artifacts, run_prediction

        with st.spinner(""):
            st.markdown("""
            <div class="ng-callout">
              <b>Step 1 / 3</b> — Reading PCAP file and extracting network flows…
            </div>""", unsafe_allow_html=True)
            raw_df = extract_all_features(pcap_path)

        with st.spinner(""):
            st.markdown("""
            <div class="ng-callout">
              <b>Step 2 / 3</b> — Running AI threat detection models…
            </div>""", unsafe_allow_html=True)
            artifacts, err = load_artifacts_cached()
            if err:
                raise RuntimeError(err)
            result = run_prediction(raw_df, artifacts)

        st.markdown("""
        <div class="ng-callout">
          <b>Step 3 / 3</b> — Generating report… done ✓
        </div>""", unsafe_allow_html=True)
        time.sleep(0.4)
        return result, raw_df, None

    except Exception as e:
        return None, None, str(e)


def mock_result(seed=42):
    rng = np.random.default_rng(seed)
    n = rng.integers(80, 300)
    scores = rng.beta(2, 5, n).tolist()
    attack_count = int(sum(s > 0.5 for s in scores))
    ratio = attack_count / n
    verdict = "ATTACK" if ratio >= 0.3 else "NORMAL"
    mean_score = float(np.mean(scores))
    return {
        "verdict":           verdict,
        "total_flows":       n,
        "risk_level":        "High" if verdict == "ATTACK" else ("Medium" if mean_score > 0.35 else "Low"),
        "network_status":    "Danger" if verdict == "ATTACK" else "Safe",
        "threat_intensity":  round(mean_score * 100, 1),
        "traffic_behavior":  "Erratic" if verdict == "ATTACK" else "Stable",
        "peak_flow_index":   int(np.argmax(scores)) + 1,
        "analyst_note":      ("High threat intensity detected. Immediate action recommended."
                              if verdict == "ATTACK" else
                              "Traffic appears normal. No immediate action required."),
        "all_flow_scores":   [round(s, 4) for s in scores],
        "confidence":        round(min(abs(mean_score - 0.4) * 250, 100), 1),
    }


def mock_raw_df(n):
    rng = np.random.default_rng(0)
    protos   = rng.choice(['TCP','UDP','ICMP'], n, p=[0.7,0.25,0.05])
    services = rng.choice(['http','https','dns','-','ssh','ftp'], n, p=[0.25,0.35,0.15,0.15,0.07,0.03])
    return pd.DataFrame({
        'proto':   protos,
        'service': services,
        'sbytes':  rng.integers(100, 50000, n),
        'dbytes':  rng.integers(50, 30000, n),
        'spkts':   rng.integers(1, 200, n),
        'dpkts':   rng.integers(1, 100, n),
        'dur':     rng.uniform(0.001, 60, n).round(4),
        'state':   rng.choice(['CON','FIN','RST','INT'], n, p=[0.5,0.3,0.15,0.05]),
    })


def render_results(result, raw_df, filename="uploaded.pcap"):
    scores       = np.array(result["all_flow_scores"])
    n            = result["total_flows"]
    attack_flows = int(sum(scores >= 0.5))
    safe_flows   = n - attack_flows


    v_cls   = "attack" if result["verdict"] == "ATTACK" else "safe"
    v_icon  = "⚠️"    if result["verdict"] == "ATTACK" else "✅"
    v_label = "THREAT DETECTED" if result["verdict"] == "ATTACK" else "NETWORK SAFE"
    headline, body = plain_english_risk(result["risk_level"], result["verdict"], result["analyst_note"])
    st.markdown(f"""
    <div style="background:#111827;border:1px solid #1e2d45;border-radius:12px;
                padding:1.4rem 1.6rem;margin-bottom:1rem;">
      <div class="ng-panel-title"><span>📋</span> Analysis Result — {filename}</div>
      <div class="ng-verdict {v_cls}">{v_icon} &nbsp; {v_label}</div>
      <div style="font-size:1.05rem;font-weight:600;margin:0.6rem 0 0.3rem;color:#e2e8f0;">
        {headline}
      </div>
      <div style="font-size:0.88rem;color:#94a3b8;line-height:1.7;">{body}</div>
      <div class="ng-analyst-note">
        <b>AI Note:</b> {result["analyst_note"]}
      </div>
    </div>
    """, unsafe_allow_html=True)

    cols = st.columns(4)
    metric_data = [
        ("Total Connections", str(n),              "network flows analyzed",               "blue",   "🌐"),
        ("Threat Level",      result["risk_level"], f"{result['threat_intensity']}% intensity",
         "red" if result["risk_level"] == "High" else ("yellow" if result["risk_level"] == "Medium" else "green"), "🎯"),
        ("Suspicious Flows",  str(attack_flows),   f"{round(attack_flows/n*100,1)}% of traffic",
         "red" if attack_flows > 0 else "green", "⚠️"),
        ("AI Confidence",     f"{result['confidence']}%", "model certainty",              "purple", "🤖"),
    ]
    for col, (lbl, val, sub, clr, ico) in zip(cols, metric_data):
        with col:
            render_metric(lbl, val, sub, clr, ico)

    st.markdown("<br>", unsafe_allow_html=True)


    col1, col2 = st.columns([1.6, 1])

    with col1:
        with st.container(border=True):
            panel_title("📈", "Per-Flow Threat Score")
            x         = list(range(1, n + 1))
            color_arr = ["#ef4444" if s >= 0.5 else "#10b981" for s in scores]
            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=x, y=scores.tolist(),
                marker_color=color_arr,
                hovertemplate="Flow %{x}<br>Score: %{y:.3f}<extra></extra>",
            ))
            fig.add_hline(y=0.5, line_dash="dash", line_color="#f59e0b",
                          annotation_text="Risk Threshold",
                          annotation_font_color="#f59e0b",
                          annotation_font_size=10)
            layout = _plotly_layout(height=280)
            layout.update(bargap=0.1)
            fig.update_layout(**layout)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with col2:
        with st.container(border=True):
            panel_title("🍩", "Traffic Breakdown")
            fig2 = go.Figure(go.Pie(
                labels=["Safe Flows", "Suspicious Flows"],
                values=[safe_flows, attack_flows],
                hole=0.62,
                marker_colors=["#10b981", "#ef4444"],
                textfont_size=11,
                hovertemplate="%{label}: %{value} flows (%{percent})<extra></extra>",
            ))
            fig2.add_annotation(
                text=f"{round(safe_flows/n*100)}%<br><span style='font-size:10px'>Safe</span>",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16, color="#10b981", family="Space Mono"))
            layout2 = _plotly_layout(height=280)
            layout2.update(showlegend=True)
            fig2.update_layout(**layout2)
            st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})

    if raw_df is not None:
        col3, col4 = st.columns(2)

        with col3:
            with st.container(border=True):
                panel_title("📡", "Protocol Distribution")
                proto_col    = 'proto' if 'proto' in raw_df.columns else raw_df.columns[0]
                proto_counts = raw_df[proto_col].value_counts().head(8)
                fig3 = go.Figure(go.Bar(
                    x=proto_counts.index.tolist(),
                    y=proto_counts.values.tolist(),
                    marker=dict(
                        color=proto_counts.values.tolist(),
                        colorscale=[[0, "#7c3aed"], [0.5, "#00d4ff"], [1, "#10b981"]],
                        showscale=False,
                    ),
                    hovertemplate="%{x}: %{y} flows<extra></extra>",
                ))
                fig3.update_layout(**_plotly_layout(height=250))
                st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})

        with col4:
            with st.container(border=True):
                panel_title("🔗", "Top Services Contacted")
                svc_col = 'service' if 'service' in raw_df.columns else None
                if svc_col:
                    svc_counts = raw_df[svc_col].value_counts().head(8)
                    fig4 = go.Figure(go.Bar(
                        x=svc_counts.values.tolist(),
                        y=svc_counts.index.tolist(),
                        orientation='h',
                        marker=dict(
                            color=svc_counts.values.tolist(),
                            colorscale=[[0, "#1a2235"], [1, "#00d4ff"]],
                            showscale=False,
                        ),
                        hovertemplate="%{y}: %{x} flows<extra></extra>",
                    ))
                    fig4.update_layout(**_plotly_layout(height=250))
                    st.plotly_chart(fig4, use_container_width=True, config={"displayModeBar": False})
                else:
                    st.info("Service data not available in this capture.")

    with st.container(border=True):
        panel_title("📊", "Threat Score Distribution — How Risky Are the Connections?")
        st.markdown("""
        <div style="font-size:0.8rem;color:#64748b;margin-bottom:0.8rem;">
          Each bar shows how many connections fall into a threat-score range.
          Bars to the <b style="color:#10b981">left (green)</b> = safe.
          Bars to the <b style="color:#ef4444">right (red)</b> = suspicious.
        </div>
        """, unsafe_allow_html=True)
        bins = np.linspace(0, 1, 21)
        hist, edges = np.histogram(scores, bins=bins)
        bar_colors  = ["#10b981" if (e + edges[i+1])/2 < 0.5 else "#ef4444"
                       for i, e in enumerate(edges[:-1])]
        fig5 = go.Figure(go.Bar(
            x=[(edges[i]+edges[i+1])/2 for i in range(len(hist))],
            y=hist.tolist(),
            marker_color=bar_colors,
            width=0.045,
            hovertemplate="Score %.2f-%.2f: %%{y} flows<extra></extra>",
        ))
        fig5.add_vline(x=0.5, line_dash="dash", line_color="#f59e0b",
                       annotation_text="Risk boundary",
                       annotation_font_color="#f59e0b",
                       annotation_font_size=10)
        l5 = _plotly_layout(height=200)
        l5["xaxis"]["title"] = "Threat Score (0 = safe, 1 = dangerous)"
        l5["yaxis"]["title"] = "# Connections"
        fig5.update_layout(**l5)
        st.plotly_chart(fig5, use_container_width=True, config={"displayModeBar": False})

    if raw_df is not None and 'sbytes' in raw_df.columns:
        with st.container(border=True):
            panel_title("📦", "Data Volume per Connection")
            st.markdown("""
            <div style="font-size:0.8rem;color:#64748b;margin-bottom:0.8rem;">
              Shows how much data was sent and received in each connection.
              Unusually large transfers might indicate data theft.
            </div>
            """, unsafe_allow_html=True)
            sample_n  = min(150, len(raw_df))
            sample_df = raw_df.head(sample_n)
            fig6 = go.Figure()
            fig6.add_trace(go.Scatter(
                y=sample_df['sbytes'].tolist(), name="Sent (bytes)",
                fill='tozeroy', line=dict(color="#7c3aed", width=1.5),
                fillcolor="rgba(124,58,237,0.15)",
                hovertemplate="Flow %{x}<br>Sent: %{y:,.0f} bytes<extra></extra>",
            ))
            if 'dbytes' in raw_df.columns:
                fig6.add_trace(go.Scatter(
                    y=sample_df['dbytes'].tolist(), name="Received (bytes)",
                    fill='tozeroy', line=dict(color="#00d4ff", width=1.5),
                    fillcolor="rgba(0,212,255,0.1)",
                    hovertemplate="Flow %{x}<br>Received: %{y:,.0f} bytes<extra></extra>",
                ))
            fig6.update_layout(**_plotly_layout(height=220))
            st.plotly_chart(fig6, use_container_width=True, config={"displayModeBar": False})

    with st.expander("📖  What do these terms mean? (Click to expand)"):
        st.markdown("""
        <div class="ng-callout">
        <b>Network Flow</b> — A single conversation between two devices (like a phone call between two people).<br><br>
        <b>Threat Score</b> — A number from 0 to 1 our AI assigns to each connection.
        Near 0 = safe. Near 1 = suspicious.<br><br>
        <b>Protocol</b> — The "language" two devices use to communicate.
        TCP = reliable (like a registered letter); UDP = fast but unverified (like a postcard).<br><br>
        <b>Service</b> — The type of activity in a connection.
        HTTPS = secure web browsing; DNS = looking up website names; SSH = remote computer access.<br><br>
        <b>Isolation Forest</b> — One of our AI models. It looks for connections that are
        unusually different from normal traffic — like spotting someone wearing a costume at a business meeting.<br><br>
        <b>Ensemble Model</b> — Three separate AI classifiers (XGBoost, LightGBM, Random Forest) that vote on
        whether each connection is safe or suspicious. Majority rules.<br><br>
        <b>PCAP File</b> — A recording of all network traffic, like a CCTV tape for your internet connection.
        </div>
        """, unsafe_allow_html=True)

    if raw_df is not None:
        with st.expander("🔬  Raw Flow Data (for technical users)"):
            show_cols = [c for c in ['proto','service','state','sbytes','dbytes','spkts','dpkts','dur','sttl']
                         if c in raw_df.columns]
            st.dataframe(
                raw_df[show_cols].head(200).style.set_properties(**{
                    'background-color': '#111827',
                    'color': '#e2e8f0',
                    'border': '1px solid #1e2d45'
                }),
                use_container_width=True,
            )


def render_live_capture_tab():
    html_panel("🎙️", "Live Network Capture", """
    <div class="ng-callout">
      <b>Live capture is not available on the cloud version.</b><br><br>
      This feature requires direct access to your machine's network interface and
      administrator privileges — which cloud servers don't support.
    </div>
    """)

    st.markdown("""
    <div style="background:#111827;border:1px solid #1e2d45;border-radius:12px;
                padding:2rem;text-align:center;margin-top:1rem;">
      <div style="font-size:3rem;margin-bottom:1rem;">🖥️</div>
      <div style="font-family:'Space Mono',monospace;font-size:1.1rem;
                  color:#00d4ff;font-weight:700;margin-bottom:0.5rem;">
        Run Locally for Live Capture
      </div>
      <div style="font-size:0.88rem;color:#94a3b8;line-height:1.8;margin-bottom:1.5rem;">
        To capture live network traffic, run NetGuard AI on your own machine.<br>
        It takes less than 2 minutes to set up.
      </div>

      <div style="background:#0b0f1a;border:1px solid #1e2d45;border-radius:10px;
                  padding:1.2rem;text-align:left;margin-bottom:1.5rem;max-width:500px;margin-left:auto;margin-right:auto;">
        <div style="font-family:'Space Mono',monospace;font-size:0.7rem;
                    color:#475569;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:0.8rem;">
          Setup Instructions
        </div>
        <div style="font-family:'Space Mono',monospace;font-size:0.82rem;color:#e2e8f0;line-height:2;">
          <span style="color:#7c3aed">#</span> 1. Clone the repo<br>
          <span style="color:#10b981">$</span> git clone https://github.com/yourrepo/netguard<br><br>
          <span style="color:#7c3aed">#</span> 2. Install dependencies<br>
          <span style="color:#10b981">$</span> pip install -r requirements.txt<br><br>
          <span style="color:#7c3aed">#</span> 3. Run with admin privileges<br>
          <span style="color:#10b981">$</span> sudo streamlit run app.py &nbsp;&nbsp;<span style="color:#475569"># Linux/Mac</span><br>
          <span style="color:#10b981">$</span> streamlit run app.py &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#475569"># Windows (as Admin)</span>
        </div>
      </div>

      <div style="font-size:0.8rem;color:#475569;">
        💡 On Windows? Use <b style="color:#e2e8f0">Wireshark</b> to save a .pcap file,
        then upload it in the <b style="color:#00d4ff">Upload &amp; Analyze</b> tab above.
      </div>
    </div>
    """, unsafe_allow_html=True)



def main():
    with st.sidebar:
        st.markdown("""
        <div style="padding:1rem 0.5rem 0.5rem">
          <div style="font-family:'Space Mono',monospace;font-size:0.65rem;
                      color:#334155;text-transform:uppercase;letter-spacing:0.12em;
                      margin-bottom:1.2rem">Navigation</div>
        </div>
        """, unsafe_allow_html=True)

        page = st.radio(
            "", ["📁  Upload & Analyze", "🎙️  Live Capture", "ℹ️  About"],
            label_visibility="collapsed"
        )

        st.markdown("---")
        st.markdown("""
        <div style="font-size:0.72rem;color:#334155;line-height:1.8;padding:0 0.3rem">
          <div style="font-family:'Space Mono',monospace;font-size:0.62rem;
                      color:#475569;text-transform:uppercase;letter-spacing:0.1em;
                      margin-bottom:0.6rem">AI Models</div>
          🤖 XGBoost Classifier<br>
          🌲 Random Forest<br>
          💡 LightGBM<br>
          🔍 Isolation Forest<br>
          ⚖️ Bayesian Combiner
        </div>
        """, unsafe_allow_html=True)
        st.markdown("---")
        st.markdown("""
        <div style="font-size:0.72rem;color:#334155;line-height:1.8;padding:0 0.3rem">
          <div style="font-family:'Space Mono',monospace;font-size:0.62rem;
                      color:#475569;text-transform:uppercase;letter-spacing:0.1em;
                      margin-bottom:0.6rem">Dataset</div>
          Trained on UNSW-NB15<br>
          2.5M+ network flows<br>
          Covers 9 attack categories
        </div>
        """, unsafe_allow_html=True)

    

    if "📁" in page:
        
        if "upload_result" in st.session_state:
            verdict       = st.session_state.upload_result.get("verdict", "NORMAL")
            topbar_status = "attack" if verdict == "ATTACK" else "normal"
        else:
            topbar_status = "ready"
        render_topbar(topbar_status)

        
        st.markdown("""
        <div class="ng-callout" style="margin-bottom:1rem">
          <b>What is a PCAP file?</b> It's a recording of network traffic — like a security camera
          recording for your internet connection. You can create one using tools like
          <b>Wireshark</b> (free, Windows/Mac/Linux) or <b>tcpdump</b> (Linux/Mac terminal).
          Upload it here and our AI will check it for threats in seconds.
        </div>
        """, unsafe_allow_html=True)

        
        uploaded = st.file_uploader(
            "Drag & drop your .pcap or .pcapng file here",
            type=["pcap", "pcapng", "cap"],
            label_visibility="collapsed",
        )

        if uploaded is not None:
            file_size = len(uploaded.getvalue())
            st.markdown(f"""
            <div style="font-size:0.8rem;color:#64748b;margin:-0.5rem 0 1rem;
                        font-family:'Space Mono',monospace;">
              📎 {uploaded.name} &nbsp;·&nbsp; {human_bytes(file_size)}
            </div>
            """, unsafe_allow_html=True)

            if st.button("🔍  Analyze File"):
                with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                    tmp.write(uploaded.getvalue())
                    pcap_path = tmp.name

                progress_placeholder = st.empty()
                steps = [
                    ("📡  Parsing packet headers…",          0.15),
                    ("🔬  Extracting flow features…",        0.40),
                    ("🤖  Running ensemble classifiers…",    0.70),
                    ("🔍  Isolation Forest anomaly scan…",   0.85),
                    ("📊  Building your report…",            1.00),
                ]

                with progress_placeholder.container():
                    bar = st.progress(0)
                    msg = st.empty()

                    result, raw_df, err = None, None, None
                    models_available    = os.path.isdir(MODELS_DIR)

                    def _run():
                        nonlocal result, raw_df, err
                        if models_available:
                            result, raw_df, err = run_full_analysis(pcap_path)
                        else:
                            time.sleep(3.5)
                            result = mock_result(seed=abs(hash(uploaded.name)) % 9999)
                            raw_df = mock_raw_df(result["total_flows"])

                    t = threading.Thread(target=_run, daemon=True)
                    t.start()

                    step_idx = 0
                    while t.is_alive():
                        if step_idx < len(steps):
                            label, prog = steps[step_idx]
                            msg.markdown(f"""
                            <div style="font-family:'Space Mono',monospace;
                                        font-size:0.78rem;color:#00d4ff;
                                        padding:0.4rem 0;animation:pulse-glow 1s infinite">
                              {label}
                            </div>""", unsafe_allow_html=True)
                            bar.progress(prog)
                            step_idx = (step_idx + 1) % len(steps)
                        time.sleep(0.9)

                    t.join()
                    bar.progress(1.0)
                    msg.empty()

                progress_placeholder.empty()

                if not models_available and err is None:
                    st.info("ℹ️ Models folder not found — showing a **demo analysis** "
                            "with simulated data. To use your real models, place them "
                            f"in `{MODELS_DIR}`.")

                if err:
                    st.error(f"❌ Analysis error: {err}")
                else:
                    st.session_state.upload_result = result
                    st.session_state.upload_raw_df = raw_df
                    st.session_state.upload_name   = uploaded.name
                    st.rerun()  

        if "upload_result" in st.session_state:
            render_results(
                st.session_state.upload_result,
                st.session_state.upload_raw_df,
                filename=st.session_state.get("upload_name", "capture.pcap"),
            )

    elif "🎙️" in page:
        render_topbar("ready")
        render_live_capture_tab()

    elif "ℹ️" in page:
        render_topbar("ready")
        st.markdown('<div class="ng-panel">', unsafe_allow_html=True)
        st.markdown('<div class="ng-panel-title"><span>🛡️</span> About NetGuard AI</div>',
                    unsafe_allow_html=True)
        
        st.markdown("""
        <div class="ng-callout">
          <b>NetGuard AI</b> is a network intrusion detection system that uses machine learning
          to automatically detect attacks and anomalies in network traffic.<br><br>

          <b>How the AI works (in plain English):</b><br>
          Imagine you have a very experienced security guard who has watched millions of security
          camera recordings. They've seen exactly what normal, everyday activity looks like —
          and they've also seen every type of break-in attempt. When you hand them a new
          recording, they can immediately spot anything that "doesn't look right."<br><br>
          That's exactly what our AI does with network traffic. It was trained on a massive
          dataset of both normal internet usage and real cyber attacks, so it learned the
          difference. Now it checks every connection in your network recording and flags
          anything suspicious.<br><br>

          <b>The 5 AI models working together:</b><br>
          ① <b>XGBoost</b> — Very fast, great at spotting known attack patterns<br>
          ② <b>LightGBM</b> — Handles large amounts of data efficiently<br>
          ③ <b>Random Forest</b> — Stable and hard to fool<br>
          ④ <b>Isolation Forest</b> — Detects strange, one-of-a-kind anomalies<br>
          ⑤ <b>Bayesian Combiner</b> — Weighs all four votes and makes the final call<br><br>

          <b>Training dataset:</b> UNSW-NB15 — a standard academic benchmark with over
          2.5 million network flows covering 9 attack types: Fuzzers, Analysis, Backdoors,
          DoS, Exploits, Generic, Reconnaissance, Shellcode, and Worms.
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown('<div class="ng-panel">', unsafe_allow_html=True)
            st.markdown('<div class="ng-panel-title"><span>⚙️</span> Feature Pipeline</div>',
                        unsafe_allow_html=True)
            st.markdown("""
            <div class="ng-callout">
              <b>Step 1</b> — PCAP file is read by NFStream<br>
              <b>Step 2</b> — 42 statistical features extracted per flow<br>
              <b>Step 3</b> — Categorical features encoded<br>
              <b>Step 4</b> — Data normalized by StandardScaler<br>
              <b>Step 5</b> — Isolation Forest scores anomalies<br>
              <b>Step 6</b> — Ensemble classifiers predict attacks<br>
              <b>Step 7</b> — Bayesian combination → final verdict
            </div>
            """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
        with col_b:
            st.markdown('<div class="ng-panel">', unsafe_allow_html=True)
            st.markdown('<div class="ng-panel-title"><span>📦</span> Requirements</div>',
                        unsafe_allow_html=True)
            st.markdown("""
            <div class="ng-callout">
              <code>pip install streamlit plotly nfstream scapy</code><br>
              <code>pip install xgboost lightgbm scikit-learn joblib</code><br><br>
              For live capture:<br>
              <code>sudo apt install tcpdump</code> (Linux)<br>
              <code>brew install tcpdump</code> (macOS)<br><br>
              Place trained model files in <code>./models/</code>
            </div>
            """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)


if __name__ == "__main__":
    main()
