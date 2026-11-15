import os, json
from datetime import datetime
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from cyberrakshak.detector import analyze_transcript
from cyberrakshak.gnani_client import GnaniService, GnaniConfigError
from cyberrakshak.evon import EvonAnalyzer
from cyberrakshak.evaluation import evaluate_dataset, load_dataset
from cyberrakshak.store import log_event, read_events, clear_events, export_csv
from cyberrakshak.i18n import supported_languages

load_dotenv()
st.set_page_config(page_title="CyberRakshak AI", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
/* CyberRakshak AI — clean light dashboard */
:root {
    --cr-ink: #172033;
    --cr-muted: #64748B;
    --cr-blue: #2563EB;
    --cr-border: #E2E8F0;
    --cr-panel: #FFFFFF;
    --cr-soft: #F5F8FC;
}
.stApp,
[data-testid="stAppViewContainer"],
[data-testid="stMain"] {
    background: #FFFFFF !important;
    color: var(--cr-ink) !important;
}
[data-testid="stHeader"] {
    background: rgba(247,249,252,.92) !important;
}
[data-testid="stSidebar"],
[data-testid="stSidebarContent"] {
    background: #FFFFFF !important;
}
[data-testid="stSidebar"] {
    border-right: 1px solid var(--cr-border);
}
.block-container {
    padding-top: 1.6rem;
    padding-bottom: 2.5rem;
    max-width: 1480px;
}
h1, h2, h3, h4 {
    color: #14213D !important;
    letter-spacing: -0.025em;
}
p, li, label, [data-testid="stMarkdownContainer"] {
    color: #334155;
}
[data-testid="stCaptionContainer"] {
    color: var(--cr-muted) !important;
}
[data-testid="stMetric"] {
    background: #FFFFFF;
    border: 1px solid var(--cr-border);
    border-radius: 15px;
    padding: 16px 18px;
    box-shadow: 0 2px 8px rgba(15,23,42,.035);
}
[data-testid="stMetricLabel"] {
    color: #64748B !important;
}
[data-testid="stMetricValue"] {
    color: #14213D !important;
    font-weight: 750;
}
.stTextInput input,
.stTextArea textarea,
[data-baseweb="select"] > div {
    background: #FFFFFF !important;
    color: #172033 !important;
    border: 1px solid #CBD5E1 !important;
    border-radius: 10px !important;
}
.stTextArea textarea::placeholder,
.stTextInput input::placeholder {
    color: #94A3B8 !important;
}
.stButton > button,
.stDownloadButton > button {
    background: #3B82F6 !important;
    color: #FFFFFF !important;
    -webkit-text-fill-color: #FFFFFF !important;
    border: 1px solid #2563EB !important;
    border-radius: 10px !important;
    font-weight: 700 !important;
    min-height: 2.65rem;
    transition: all .15s ease;
}
/* Streamlit may render button labels inside nested paragraph/span elements. */
.stButton > button *,
.stDownloadButton > button * {
    color: #FFFFFF !important;
    -webkit-text-fill-color: #FFFFFF !important;
    font-weight: 700 !important;
}
.stButton > button:hover,
.stDownloadButton > button:hover {
    background: #2563EB !important;
    border-color: #1D4ED8 !important;
    color: #FFFFFF !important;
    -webkit-text-fill-color: #FFFFFF !important;
}
.stButton > button:hover *,
.stDownloadButton > button:hover * {
    color: #FFFFFF !important;
    -webkit-text-fill-color: #FFFFFF !important;
}
.stButton > button:focus,
.stDownloadButton > button:focus {
    box-shadow: 0 0 0 3px rgba(37,99,235,.18) !important;
}
[data-testid="stAlert"] {
    border-radius: 12px !important;
    border: 1px solid var(--cr-border) !important;
}
[data-testid="stAlert"] p,
[data-testid="stAlert"] span {
    color: #243247 !important;
}
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    border-bottom: 1px solid var(--cr-border);
}
.stTabs [data-baseweb="tab"] {
    color: #475569 !important;
    padding: 12px 15px;
    border-radius: 9px 9px 0 0;
}
.stTabs [aria-selected="true"] {
    color: #1D4ED8 !important;
}
div[data-testid="stProgressBar"] > div > div {
    background: #2563EB !important;
}
hr {
    border-color: var(--cr-border) !important;
}
.cr-hero {
    background: linear-gradient(120deg, #FFFFFF 0%, #EFF6FF 100%);
    border: 1px solid #DBEAFE;
    border-radius: 20px;
    padding: 25px 28px;
    margin: 4px 0 18px 0;
}
.cr-kicker {
    color: #2563EB;
    font-size: .78rem;
    font-weight: 750;
    text-transform: uppercase;
    letter-spacing: .11em;
}
.cr-subtitle {
    color: #64748B;
    font-size: 1rem;
    margin-top: 5px;
}
.cr-panel {
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 15px;
    padding: 18px 20px;
    margin: 8px 0 14px 0;
}
.cr-muted {
    color: #64748B;
    font-size: .9rem;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="cr-hero">
  <div class="cr-kicker">Multilingual voice security</div>
  <h1 style="margin:5px 0 0 0;font-size:2.45rem;">🛡️ CyberRakshak AI</h1>
  <div class="cr-subtitle">Understand the conversation. Recognise the risk. Stay protected.</div>
  <div style="margin-top:14px;color:#475569;font-size:.88rem;">
    <b>Gnani Prisma STT</b> &nbsp;·&nbsp; Explainable threat analysis &nbsp;·&nbsp; Practical safety guidance &nbsp;·&nbsp; Optional contextual review
  </div>
</div>
""", unsafe_allow_html=True)
st.warning("Decision-support prototype — not a caller identity verifier or a guarantee of safety. Use only with informed consent. Do not rely on it as the sole basis for financial or emergency decisions.")

with st.sidebar:
    st.header("System settings")
    lang_label = st.selectbox("Speech language", list(supported_languages().keys()), index=0)
    lang_code = supported_languages()[lang_label]
    st.toggle("Enable optional Evon contextual analysis", key="evon_enabled", value=False)
    st.toggle("Enable Timbre spoken alerts", key="tts_enabled", value=False)
    st.selectbox("Timbre voice", ["Nalini", "Pranav"], key="tts_voice")
    st.divider()
    st.caption("Privacy: this app keeps session event summaries only. Audio is not stored by the app.")
    if st.button("Clear session history", use_container_width=True):
        clear_events()
        st.rerun()

tab_overview, tab_live, tab_text, tab_dash, tab_eval, tab_about = st.tabs([
    "Overview", "🎙️ Live monitor", "🧪 Analyse sample",
    "Threat history", "📈 Evaluation", "📘 Project"
])

def render_safety_guidance(result):
    """Show practical next steps based on the risk indicators actually detected."""
    signals = result.get("signals", [])
    signal_keys = {item.get("key", "") for item in signals}
    evidence_text = " ".join(
        f'{item.get("title", "")} {item.get("evidence", "")}'
        for item in signals
    ).lower()

    steps = []
    if "credential" in signal_keys or any(term in evidence_text for term in ("otp", "one-time", "password", "pin", "credential", "cvv")):
        steps.append("Do not share the requested OTP, UPI PIN, password, CVV, or screen-lock code. End the call and verify the request using the organisation's official app or a phone number you obtain independently.")
    if any(term in evidence_text for term in ("upi", "payment", "transfer", "refund", "bank account", "money")):
        steps.append("Do not approve an unexpected collect request or transfer money to 'verify', 'unlock', or 'receive' a refund.")
    if any(term in evidence_text for term in ("anydesk", "remote", "screen share", "access code", "install")):
        steps.append("Do not install remote-access apps or share screen-control codes with an unsolicited caller. If already installed, disconnect and seek help from the app's official support.")
    if any(term in evidence_text for term in ("police", "court", "arrest", "authority", "government", "impersonat")):
        steps.append("Do not act on threats from the caller. End the call and independently contact the relevant organization using a number from its official website or app.")
    if any(term in evidence_text for term in ("link", "url", "website", "delivery", "kyc")):
        steps.append("Do not open links or enter personal or payment details from the message or caller. Open the official app or type the organization's known website yourself.")
    if any(term in evidence_text for term in ("urgent", "urgency", "immediately", "threat", "isolation", "secret", "don't tell")):
        steps.append("Pause. Pressure, secrecy, and threats are reasons to stop and verify independently. Speak to someone you trust before taking action.")

    if not steps and result.get("level") in ("HIGH", "CRITICAL"):
        steps.append("End the interaction for now. Do not share sensitive information or send money; verify the caller through an independently obtained official contact.")
    elif not steps and result.get("level") == "MEDIUM":
        steps.append("Be cautious. Avoid sharing sensitive information or making payments until you have independently verified the request.")
    elif not steps:
        steps.append("No configured warning pattern was detected. That does not prove the conversation is safe; continue to protect passwords, OTPs, PINs, and payment details.")

    st.markdown("### Your next safest steps")
    if "credential" in signal_keys:
        st.warning("An OTP or credential request was detected. Do not share the code. End the call and verify through the organisation's official app or published phone number.")
    elif "remote" in signal_keys:
        st.warning("A remote-access or screen-sharing request was detected. Do not install the app or share access codes.")
    elif result.get("level") in ("HIGH", "CRITICAL"):
        st.error("Pause the conversation. Do not share information or transfer money while you verify the request.")
    elif result.get("level") == "MEDIUM":
        st.warning("Take a moment to verify the request independently before proceeding.")
    else:
        st.info("Stay alert. A low detector score is not a guarantee of safety.")

    for step in steps:
        st.markdown(f"- {step}")

    st.caption("These are precautionary suggestions generated from detected transcript indicators, not proof of fraud or a substitute for official advice.")


def render_result(transcript, result, evon_result=None):
    st.markdown("### Threat assessment")
    c1,c2,c3 = st.columns(3)
    c1.metric("Risk score", f'{result["score"]}/100')
    c2.metric("Risk level", result["level"])
    c3.metric("Signals", len(result["signals"]))
    st.progress(result["score"]/100)
    st.markdown("**Recognised transcript**")
    st.info(transcript)
    if result["signals"]:
        st.markdown("**Explainable indicators**")
        for item in result["signals"]:
            st.markdown(f'- **{item["title"]}** (+{item["points"]}) — {item["evidence"]}')
    else:
        st.success("No configured indicators found. This is not proof that the conversation is safe.")
    st.markdown(f'**Detector recommendation:** {result["advice"]}')
    render_safety_guidance(result)
    if evon_result:
        st.markdown("**Evon contextual assessment**")
        st.write(evon_result.get("summary", ""))
        if evon_result.get("concerns"):
            for concern in evon_result["concerns"]:
                st.write(f'• {concern}')
        st.caption("Evon output is advisory and is not used to lower the deterministic risk score.")
    if st.session_state.get("tts_enabled") and result["level"] in ("HIGH","CRITICAL"):
        if st.button("Generate spoken warning with Timbre"):
            try:
                with st.spinner("Generating voice alert..."):
                    audio = GnaniService().speak(result["warning"], lang_code, st.session_state["tts_voice"])
                st.audio(audio, format="audio/wav")
            except Exception as e:
                st.error(f"Timbre unavailable: {e}")


with tab_overview:
    st.markdown("## Security overview")
    st.caption("A live summary of analyses you have explicitly saved. Metrics are based only on recorded sessions.")
    refresh_col, _ = st.columns([1, 5])
    with refresh_col:
        if st.button("↻ Refresh dashboard", key="refresh_overview"):
            st.rerun()

    overview_events = read_events()
    overview_df = pd.DataFrame(overview_events) if overview_events else pd.DataFrame()

    if not overview_df.empty:
        latest_score = int(overview_df.iloc[-1].get("score", 0))
        latest_level = str(overview_df.iloc[-1].get("level", "UNKNOWN"))
        total_sessions = len(overview_df)
        high_count = int(overview_df["level"].isin(["HIGH", "CRITICAL"]).sum())
        total_signals = int(overview_df["signal_count"].fillna(0).sum()) if "signal_count" in overview_df else 0
        average_score = float(overview_df["score"].mean())
    else:
        latest_score, latest_level = 0, "NO DATA"
        total_sessions, high_count, total_signals, average_score = 0, 0, 0, 0.0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Latest risk score", f"{latest_score}/100", latest_level)
    m2.metric("Sessions analysed", total_sessions)
    m3.metric("High / critical flags", high_count)
    m4.metric("Signals detected", total_signals)

    st.markdown("### Threat detection and activity")
    left_chart, right_chart = st.columns(2, gap="large")

    with left_chart:
        with st.container(border=True):
            st.markdown("#### Risk activity")
            if not overview_df.empty and "timestamp" in overview_df:
                trend = overview_df.copy()
                trend["_time"] = pd.to_datetime(trend["timestamp"], errors="coerce")
                trend = trend.dropna(subset=["_time"]).sort_values("_time")
                if not trend.empty:
                    trend = trend.set_index("_time")[["score"]]
                    st.line_chart(trend, height=245)
                    st.caption("Risk score by saved analysis time.")
                else:
                    st.info("Saved analyses do not contain readable timestamps yet.")
            else:
                st.info("Risk activity will appear after you analyse a transcript or save a live session.")
                st.caption("No sample activity is fabricated.")

    with right_chart:
        with st.container(border=True):
            st.markdown("#### Risk-level distribution")
            if not overview_df.empty and "level" in overview_df:
                level_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                counts = overview_df["level"].value_counts().reindex(level_order, fill_value=0)
                st.bar_chart(counts, height=245)
                st.caption("Count of saved sessions by detector risk level.")
            else:
                st.info("Risk-level distribution will appear when session results are saved.")

    st.markdown("### Recent activity")
    if not overview_df.empty:
        show_cols = [c for c in ["timestamp", "source", "level", "score", "signal_count"] if c in overview_df.columns]
        st.dataframe(overview_df[show_cols].tail(5).iloc[::-1], use_container_width=True, hide_index=True)
    else:
        st.markdown("""
        <div class="cr-panel">
          <div class="cr-kicker">Ready when you are</div>
          <h3 style="margin:7px 0;color:#14213D;">Your security activity will appear here</h3>
          <p class="cr-muted">Start a live microphone session or analyse a consented transcript to populate this overview.</p>
        </div>
        """, unsafe_allow_html=True)

    st.caption("CyberRakshak AI is a decision-support prototype. A low score does not prove that a conversation is safe.")

with tab_live:
    st.subheader("🎙️ Live protection monitor")
    st.markdown(
        "Speak for a few seconds, then pause briefly. Prisma uses voice activity detection, "
        "so a transcript segment may appear after a phrase rather than word-by-word."
    )
    st.info(
        "This captures the selected microphone only. It does not automatically access both "
        "sides of an ordinary cellular call. Use only with informed consent."
    )

    from cyberrakshak.live_capture import LiveAudioProcessor, LivePrismaBridge
    # Read the key from local .env OR Streamlit Cloud's Secrets panel.
    gnani_key = os.getenv("GNANI_API_KEY", "").strip()
    if not gnani_key:
        try:
            gnani_key = str(st.secrets.get("GNANI_API_KEY", "")).strip()
        except Exception:
            gnani_key = ""

    if (
        "live_prisma_bridge" not in st.session_state
        or st.session_state["live_prisma_bridge"].language_code != lang_code
    ):
        old_bridge = st.session_state.get("live_prisma_bridge")
        if old_bridge is not None:
            old_bridge.stop()
        st.session_state["live_prisma_bridge"] = LivePrismaBridge(lang_code, api_key=gnani_key)
    bridge = st.session_state["live_prisma_bridge"]

    try:
        from streamlit_webrtc import webrtc_streamer, WebRtcMode
        ctx = webrtc_streamer(
            key="cyberrakshak-prisma-live",
            mode=WebRtcMode.SENDONLY,
            audio_processor_factory=lambda: LiveAudioProcessor(bridge),
            media_stream_constraints={"video": False, "audio": True},
            async_processing=True,
        )

        @st.fragment(run_every=1)
        def live_results_panel():
            state = bridge.snapshot()
            st.markdown(f"**Prisma connection:** {state['status']}")
            if state["error"]:
                st.error(state["error"])
            if state["segments"]:
                reset_col, note_col = st.columns([1, 3])
                with reset_col:
                    if st.button("Start new analysis", key="reset_live_analysis"):
                        bridge.clear_transcript()
                        st.rerun()
                with note_col:
                    st.caption("Risk is cumulative within the current analysis session. Start a new analysis to clear prior transcript evidence.")
                st.markdown("#### Live transcript")
                for segment in state["segments"][-8:]:
                    st.markdown(
                        f'`{segment["time"]} · {segment["language"]}`  '
                        f'{segment["text"]}'
                    )
                joined = state["transcript"]
                current = analyze_transcript(joined)
                c1, c2, c3 = st.columns(3)
                c1.metric("Risk score", f'{current["score"]}/100')
                c2.metric("Risk level", current["level"])
                c3.metric("Signals", len(current["signals"]))
                st.progress(current["score"] / 100)
                if current["signals"]:
                    st.markdown("**Why it was flagged**")
                    for item in current["signals"]:
                        st.markdown(
                            f'- **{item["title"]}** (+{item["points"]}) — {item["evidence"]}'
                        )
                st.markdown(f'**Detector recommendation:** {current["advice"]}')
                render_safety_guidance(current)
                already_saved_live = st.session_state.get("last_saved_live_transcript") == joined
                if st.button(
                    "✓ Saved to dashboard" if already_saved_live else "＋ Save live analysis to dashboard",
                    key="save_live_analysis",
                    disabled=already_saved_live,
                    use_container_width=True
                ):
                    try:
                        log_event(joined, current, {"source": "live microphone"})
                        st.session_state["last_saved_live_transcript"] = joined
                        st.success("Saved successfully. Open Overview or Threat history to see this session.")
                        st.rerun()
                    except Exception as save_error:
                        st.error(f"Could not save the live analysis: {save_error}")
            else:
                st.caption(
                    "No transcript segment yet. Check that START is active, your browser "
                    "has microphone permission, GNANI_API_KEY is configured, and Prisma "
                    "streaming is enabled for your API key. Speak a full sentence and pause."
                )
            if state["dropped_frames"]:
                st.caption(f'Audio frames dropped to control latency: {state["dropped_frames"]}')

        live_results_panel()
    except Exception as e:
        st.error(f"Live microphone could not start: {e}")
        st.caption("Use Analyse sample with a transcript or uploaded recording while resolving this issue.")

with tab_text:
    st.subheader("🧪 Conversation analysis")
    method = st.radio("Input method", ["Paste transcript","Upload audio"], horizontal=True)
    transcript = ""
    uploaded = None
    if method == "Paste transcript":
        transcript = st.text_area("Conversation transcript", height=170, placeholder="Paste a consented call transcript...")
    else:
        uploaded = st.file_uploader("Upload a consented recording", type=["wav","mp3","flac","ogg","m4a"])
        if uploaded:
            st.audio(uploaded)
    if st.button("Analyse conversation", type="primary", use_container_width=True):
        try:
            if uploaded:
                with st.spinner("Transcribing with Gnani Prisma..."):
                    transcript = GnaniService().transcribe(uploaded.getvalue(), uploaded.name, lang_code)
            if not transcript.strip():
                st.error("Provide a transcript or upload an audio recording.")
            else:
                result = analyze_transcript(transcript)
                evon_result = None
                if st.session_state.get("evon_enabled"):
                    with st.spinner("Requesting optional Evon contextual analysis..."):
                        evon_result = EvonAnalyzer().analyse(transcript, result)
                st.session_state["last_transcript"] = transcript
                st.session_state["last_result"] = result
                st.session_state["last_evon"] = evon_result
                st.session_state["last_analysis_saved"] = False
        except Exception as e:
            st.error(str(e))
    if "last_result" in st.session_state:
        render_result(st.session_state["last_transcript"], st.session_state["last_result"], st.session_state.get("last_evon"))

        if st.session_state.get("last_analysis_saved", False):
            st.success("This analysis is saved in Threat history and the Overview dashboard.")
        else:
            if st.button("＋ Save this analysis to dashboard", key="save_sample_analysis", use_container_width=True):
                try:
                    log_event(
                        st.session_state["last_transcript"],
                        st.session_state["last_result"],
                        {
                            "source": "upload/transcript",
                            "evon_used": bool(st.session_state.get("last_evon"))
                        }
                    )
                    st.session_state["last_analysis_saved"] = True
                    st.success("Saved successfully. Open Overview or Threat history to see this analysis.")
                    st.rerun()
                except Exception as save_error:
                    st.error(f"Could not save this analysis: {save_error}")

with tab_dash:
    st.subheader("📚 Saved threat history")
    events = read_events()
    if not events:
        st.info("Your dashboard is ready. Analyse a transcript or save a live microphone session to see session insights here.")
        st.markdown("""
        <div class="cr-panel">
          <div class="cr-kicker">Getting started</div>
          <h3 style="margin:6px 0;color:#14213D;">Your security activity will appear here</h3>
          <p class="cr-muted">Run a sample analysis or save a live session. This dashboard reports activity from the current session history.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        df = pd.DataFrame(events)
        a,b,c = st.columns(3)
        a.metric("Sessions analysed", len(df))
        b.metric("High / critical", int(df["level"].isin(["HIGH","CRITICAL"]).sum()))
        c.metric("Average risk", f'{df["score"].mean():.1f}/100')
        st.bar_chart(df.groupby("level").size())
        st.dataframe(df[["timestamp","source","level","score","signal_count"]], use_container_width=True)
        st.download_button("Export CSV report", export_csv(), "cyberrakshak_session_report.csv", "text/csv")

with tab_eval:
    st.subheader("📈 Model evaluation")
    st.write("Runs the detector against the included, explicitly synthetic labelled test set. These results measure this small test set only; they are not real-world accuracy claims.")
    if st.button("Run evaluation"):
        rows = load_dataset()
        report = evaluate_dataset(rows)
        st.session_state["evaluation"] = report
    if "evaluation" in st.session_state:
        r = st.session_state["evaluation"]
        x,y,z,w = st.columns(4)
        x.metric("Precision", f'{r["precision"]:.2f}')
        y.metric("Recall", f'{r["recall"]:.2f}')
        z.metric("F1", f'{r["f1"]:.2f}')
        w.metric("Accuracy", f'{r["accuracy"]:.2f}')
        st.write("Confusion matrix (positive = scam-like)")
        st.dataframe(pd.DataFrame(r["confusion_matrix"], index=["Actual benign","Actual suspicious"], columns=["Predicted benign","Predicted suspicious"]))
        st.caption(f'{r["count"]} synthetic labelled examples. Replace or extend with consented, human-labelled data before making performance claims.')

with tab_about:
    st.subheader("📘 How CyberRakshak works")
    st.code("""
Audio input (consented microphone / file)
             |
             v
       Gnani Prisma STT
             |
             v
  Language-aware normalisation
             |
             v
  Explainable multi-signal engine
  ├─ credential / OTP extraction
  ├─ impersonation and authority cues
  ├─ urgency / coercion
  ├─ payment / UPI requests
  ├─ remote-access instructions
  └─ multi-signal sequence bonuses
             |
       +-----+------+
       |            |
       v            v
   Dashboard    Optional Evon analysis
       |            |
       +-----+------+
             |
       Gnani Timbre warning
""", language="text")
    st.markdown("""
**Project novelty:** focuses on conversational attack patterns rather than a single suspicious keyword; surfaces the evidence behind each alert; supports a multilingual speech workflow; and separates deterministic scoring from optional LLM reasoning.

**Responsible-use design:** no caller identification, no automatic call termination, no hidden recording, no raw audio retention by default, and no claim that a low score means safe.
""")
