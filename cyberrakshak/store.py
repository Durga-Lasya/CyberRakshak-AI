import csv, io, json
from pathlib import Path
from datetime import datetime
import streamlit as st

def _init():
    if "cyber_events" not in st.session_state: st.session_state["cyber_events"]=[]
def log_event(transcript,result,meta=None):
    _init()
    st.session_state["cyber_events"].append({"timestamp":datetime.now().isoformat(timespec="seconds"),
       "source":(meta or {}).get("source","unknown"),"level":result["level"],"score":result["score"],
       "signal_count":result["signal_count"],"transcript_preview":transcript[:180]})
def read_events(): _init(); return st.session_state["cyber_events"]
def clear_events(): st.session_state["cyber_events"]=[]
def export_csv():
    out=io.StringIO(); rows=read_events()
    fields=["timestamp","source","level","score","signal_count","transcript_preview"]
    w=csv.DictWriter(out,fieldnames=fields); w.writeheader(); w.writerows(rows)
    return out.getvalue()
