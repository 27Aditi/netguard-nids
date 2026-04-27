# ─────────────────────────────────────────────────────
# live_capture.py
# Run this file locally for live packet capture:
#   sudo streamlit run live_capture.py   (Linux/Mac)
#   streamlit run live_capture.py        (Windows Admin)
# ─────────────────────────────────────────────────────

import os, time, tempfile
import streamlit as st
from scapy.all import AsyncSniffer, wrpcap
from prediction import load_artifacts, run_prediction
from feature_extraction import extract_all_features


def render_live_capture_tab():
    
    html_panel("🎙️", "Live Network Capture", """
    <div class="ng-callout">
      <b>How it works:</b> Click <b>Start Capture</b> to begin recording live network traffic from your machine.
      When you're done, click <b>Stop &amp; Analyze</b> — the recording will be saved and automatically analyzed.
      <br><br>
      ⚠️ <b>Note:</b> Live capture requires administrator/root privileges and the
      <code>tcpdump</code> tool installed on your system. This feature works on Linux and macOS.
      On Windows, use Wireshark to save a PCAP file and upload it in the <b>Upload &amp; Analyze</b> tab.
    </div>
    """)

    if "capture_proc" not in st.session_state:
        st.session_state.capture_proc  = None
        st.session_state.capture_file  = None
        st.session_state.capturing     = False
        st.session_state.capture_start = None

    col_iface, col_dur = st.columns(2)
    with col_iface:
        iface = st.text_input("Network Interface", value="Wi-Fi",
                              help="e.g. eth0, en0, wlan0 — the name of your network card")
    with col_dur:
        max_dur = st.slider("Max capture duration (seconds)", 5, 120, 30)

    col_start, col_stop = st.columns(2)

    with col_start:
        if st.button("▶  Start Capture", disabled=st.session_state.capturing):
            try:
                tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
                st.session_state.capture_file = tmp.name
                tmp.close()
                sniffer = AsyncSniffer(iface=iface, store=True)
                sniffer.start()
                st.session_state.capture_proc  = sniffer
                st.session_state.capturing     = True
                st.session_state.capture_start = time.time()
                st.rerun()
            except FileNotFoundError:
                st.error("❌ tcpdump not found. Please install it: `sudo apt install tcpdump`")
            except Exception as e:
                st.error(f"❌ Could not start capture: {e}")

    with col_stop:
        st.markdown('<div class="stop-btn">', unsafe_allow_html=True)
        if st.button("⏹  Stop & Analyze", disabled=not st.session_state.capturing):
            sniffer = st.session_state.capture_proc
            if sniffer is not None:
                sniffer.stop()
                packets = sniffer.results
                if packets:
                    wrpcap(st.session_state.capture_file, packets)
            st.session_state.capturing = False
            pcap_path = st.session_state.capture_file
            if pcap_path and os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0:
                st.success("✅ Capture saved. Starting analysis…")
                with st.spinner("🔍 Running AI threat analysis on captured traffic…"):
                    result, raw_df, err = run_full_analysis(pcap_path)
                if err:
                    st.error(f"Analysis failed: {err}")
                else:
                    st.session_state.live_result = result
                    st.session_state.live_raw_df = raw_df
                    st.rerun()
            else:
                st.warning("⚠️ No data was captured. Make sure the interface name is correct "
                           "and you have permission to capture packets.")
        st.markdown('</div>', unsafe_allow_html=True)

    if st.session_state.capturing:
        elapsed  = int(time.time() - st.session_state.capture_start)
        progress = min(elapsed / max_dur, 1.0)
        st.markdown(f"""
        <div style="margin-top:1rem">
          <div style="font-family:'Space Mono',monospace;font-size:0.8rem;
                      color:#00d4ff;margin-bottom:0.4rem;animation:pulse-glow 1s infinite">
            🔴 CAPTURING — {elapsed}s elapsed on <b>{iface}</b>
          </div>
        </div>
        """, unsafe_allow_html=True)
        st.progress(progress)
        if elapsed >= max_dur:
            proc = st.session_state.capture_proc
            if proc and proc.poll() is None:
                proc.terminate()
            st.session_state.capturing = False
            st.info("⏱️ Max duration reached. Click **Stop & Analyze** to process the capture.")
        time.sleep(1)
        st.rerun()

    if "live_result" in st.session_state:
        st.markdown("---")
        render_results(st.session_state.live_result,
                       st.session_state.live_raw_df,
                       filename="live_capture.pcap")

render_live_capture_tab()
