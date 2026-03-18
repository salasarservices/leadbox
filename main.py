from __future__ import annotations

from datetime import datetime, timezone, date as date_type
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo
import base64
import hmac
import hashlib
import html
import json
import os
import re
import secrets
import string

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
from bson.objectid import ObjectId
from pymongo import MongoClient, ASCENDING, DESCENDING, UpdateOne
from pymongo.errors import BulkWriteError, DuplicateKeyError


# -----------------------
# App config
# -----------------------
st.set_page_config(
    page_title="LeadBox",
    layout="wide",
    initial_sidebar_state="expanded",
)

IST = ZoneInfo("Asia/Kolkata")
MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]

DB_NAME = "sal-leads"
COLL_LEADS = "leads"
COLL_USERS = "leadbox-users"
SECRET_KEY_LEADS = "mongo_uri_leads"  # Streamlit secrets key
LOGO_URL = "https://ik.imagekit.io/salasarservices/Salasar-Logo-new.png?updatedAt=1771587668127"

LEAD_ID_PREFIX = "SL"
SUPER_ADMIN_USERNAME = "sallead"
INACTIVITY_TIMEOUT_SECONDS = 30 * 60


# -----------------------
# LOGIN (simple gate)
# -----------------------
def _get_login_creds() -> tuple[str, str]:
    user = st.secrets.get("app_user") or os.environ.get("APP_USER") or SUPER_ADMIN_USERNAME
    pwd = st.secrets.get("app_password") or os.environ.get("APP_PASSWORD") or ""

    user = str(user).strip() or SUPER_ADMIN_USERNAME
    pwd = str(pwd)

    if not pwd:
        st.error("Login is not configured.")
        st.info(
            "Streamlit Cloud → App → Settings → Secrets. Add:\n\n"
            'app_password = "your-password"\n'
        )
        st.stop()

    return user, pwd


APP_USER, APP_PASSWORD = _get_login_creds()




def check_legacy_login(username: str, password: str) -> bool:
    return hmac.compare_digest((username or "").strip(), APP_USER) and hmac.compare_digest(password or "", APP_PASSWORD)

def check_super_admin(username: str, password: str) -> bool:
    user = (username or "").strip()
    if not user:
        return False
    user_match = hmac.compare_digest(user.lower(), SUPER_ADMIN_USERNAME)
    pwd_match = hmac.compare_digest(password or "", APP_PASSWORD)
    return user_match and pwd_match


def users_col_for_login() -> Optional[Any]:
    uri = st.secrets.get(SECRET_KEY_LEADS)
    if not uri:
        return None
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=1800)
        return client[DB_NAME][COLL_USERS]
    except Exception:
        return None


def hash_password(password: str) -> str:
    return hashlib.sha256((password or "").encode("utf-8")).hexdigest()


def check_db_user_login(username: str, password: str) -> bool:
    uname = (username or "").strip().lower()
    pwd = password or ""
    if not uname or not pwd:
        return False

    col = users_col_for_login()
    if col is None:
        return False

    doc = col.find_one({"username": uname, "isActive": {"$ne": False}}, {"passwordHash": 1})
    if not doc:
        return False

    stored = str(doc.get("passwordHash") or "")
    return bool(stored) and hmac.compare_digest(stored, hash_password(pwd))


def logout_user(reason: str = "You have been logged out.") -> None:
    st.session_state.clear()
    st.session_state["logout_notice"] = reason
    st.rerun()


def track_session_activity() -> None:
    if st.session_state.get("authenticated") is not True:
        return

    now_ts = datetime.now(timezone.utc).timestamp()
    last_ts = float(st.session_state.get("last_activity_ts") or now_ts)
    if now_ts - last_ts >= INACTIVITY_TIMEOUT_SECONDS:
        logout_user("Logged out due to 30 minutes of inactivity.")

    st.session_state["last_activity_ts"] = now_ts


def login_gate() -> None:
    notice = st.session_state.pop("logout_notice", None)
    if notice:
        st.warning(notice)

    if st.session_state.get("authenticated") is True:
        track_session_activity()
        return

    st.markdown(
        """
        <style>
          .block-container{max-width: 520px !important;}
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.image(LOGO_URL, width=200)
    st.markdown(
        "<div style='font-size:1.4rem;font-weight:900;color:#2d448d;margin-top:0.6rem;'>LEADBOX LOGIN</div>",
        unsafe_allow_html=True,
    )
    st.caption("Please sign in to access the dashboard.")

    with st.form("login_form"):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        ok = st.form_submit_button("Login")

    if ok:
        username = u.strip()
        if check_super_admin(username, p):
            st.session_state["authenticated"] = True
            st.session_state["logged_in_user"] = username.lower()
            st.session_state["is_super_admin"] = True
            st.session_state["last_activity_ts"] = datetime.now(timezone.utc).timestamp()
            st.rerun()
        elif check_legacy_login(username, p):
            st.session_state["authenticated"] = True
            st.session_state["logged_in_user"] = username.lower()
            st.session_state["is_super_admin"] = username.lower() == SUPER_ADMIN_USERNAME
            st.session_state["last_activity_ts"] = datetime.now(timezone.utc).timestamp()
            st.rerun()
        elif check_db_user_login(username, p):
            st.session_state["authenticated"] = True
            st.session_state["logged_in_user"] = username.lower()
            st.session_state["is_super_admin"] = False
            st.session_state["last_activity_ts"] = datetime.now(timezone.utc).timestamp()
            st.rerun()
        else:
            st.error("Invalid username or password.")

    st.stop()


login_gate()


# -----------------------
# Domain choices
# -----------------------
LEAD_STATUS_OPTIONS = ["Fresh", "Allocated", "Interested", "Lost", "Closed"]

DEFAULT_PRODUCT_TYPES: list[str] = [
    "Property",
    "Loss Of Profit & Contingent BI",
    "Speciality",
    "Aircraft & Hull",
    "Employee Benefits",
    "Liability",
    "Miscellaneous",
    "Mega Property",
    "Industrial All Risks",
    "Engineering",
    "Marine",
    "Liability",
    "Miscellaneous",
    "Reinsurance Broking",
    "Aviation & Aerospace Insurance",
    "Crop- Weather Insurance",
    "Cattle- Livestock Insurance",
    "Fishery- Aquaculture Insurance",
    "Senior Citizen Health Insurance",
    "Family Floater Health Insurance",
    "Individual Health Insurance",
    "Super Top-Up policy",
    "Personal Accident Policy",
    "Cancer Insurance",
    "Critical Illness Policy",
    "Health Insurance Policy Audit (HIPA)",
    "Term Life Insurance",
    "Whole Life Insurance",
    "Endowment Policy",
    "Money Back Insurance Policy",
    "Pension Plans",
    "Gratuity Plan",
    "Home Insurance",
    "Goods Carrying Vehicle",
    "Private Car Insurance",
    "Two-Wheeler Insurance",
    "Passenger Carrying Vehicle",
    "Misc-D",
    "Travel Insurance",
]


def normalize_lead_status(label: str) -> str:
    s = (label or "").strip().lower()
    if s in {"not-interested", "not interested", "not_interested"}:
        return "lost"
    if s == "lost":
        return "lost"
    return s


def denormalize_lead_status(value: Optional[str]) -> str:
    v = (value or "").strip().lower()
    if v in {"not interested", "lost"}:
        return "Lost"
    if not v:
        return "Fresh"
    return v.title()


# -----------------------
# THEME / UI
# -----------------------
st.markdown(
    """
<style>
:root{
  --navy:#2d448d;
  --lime:#a6ce39;
  --cyan:#00aeef;

  --bg:#F7F9FC;
  --card:#FFFFFF;

  --pastel-navy:#EEF2FF;
  --pastel-lime:#F3FAE6;
  --pastel-cyan:#E6F8FF;

  --text:#0f172a;
  --muted:#64748b;
  --border: rgba(15, 23, 42, 0.08);
  --shadow: 0 8px 20px rgba(15, 23, 42, 0.06);
}

.stApp { background: var(--bg); color: var(--text); }
.block-container { padding-top: 1.0rem; padding-bottom: 1.5rem; max-width: 1200px; }

.lb-card{
  background: var(--card);
  border: 1px solid var(--border);
  box-shadow: var(--shadow);
  border-radius: 14px;
  padding: 14px 14px 10px 14px;
  margin-bottom: 12px;
}
.lb-card-header{
  display:flex;
  align-items:center;
  gap:10px;
  margin-bottom: 10px;
}
.lb-dot{
  width:10px;height:10px;border-radius:999px;flex:0 0 10px;
}
.lb-title{
  font-weight: 700;
  color: var(--navy);
  font-size: 0.98rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.lb-subtitle{
  color: var(--muted);
  font-size: 0.88rem;
  margin-top: -2px;
}

.lb-navy{ background: linear-gradient(180deg, var(--pastel-navy), #fff); }
.lb-lime{ background: linear-gradient(180deg, var(--pastel-lime), #fff); }
.lb-cyan{ background: linear-gradient(180deg, var(--pastel-cyan), #fff); }

.stButton>button{
  border-radius: 10px;
  border: 1px solid var(--border);
  padding: 0.55rem 0.85rem;
  font-weight: 650;
}

div[data-baseweb="select"] > div,
.stTextInput input, .stTextArea textarea, .stNumberInput input {
  border-radius: 10px !important;
}

label, .stMarkdown p { font-size: 0.92rem; }
div[data-baseweb="select"] * { text-transform: uppercase; }

#MainMenu { visibility: hidden; }
footer { visibility: hidden; }

/* KPI boxes */
.kpi-row{
  display:flex;
  gap:18px;
  flex-wrap:wrap;
  padding: 10px 2px 6px 2px;
  align-items: flex-start;
}
.kpi-wrap{
  width: 170px;
  display:flex;
  flex-direction: column;
  align-items: center;
}
.kpi{
  width: 170px;
  height: 108px;
  border-radius: 14px;
  border: 1px solid var(--border);
  box-shadow: var(--shadow);
  display:flex;
  align-items:center;
  justify-content:center;
  transition: transform 180ms ease, box-shadow 180ms ease;
}
.kpi:hover{
  transform: translateY(-3px) scale(1.02);
  box-shadow: 0 14px 30px rgba(15, 23, 42, 0.10);
}
.kpi-inner{
  text-align:center;
  padding: 12px;
}
.kpi-number{
  font-size: 2.2rem;
  font-weight: 900;
  line-height: 1.05;
  color: var(--text);
}
.kpi-number.navy{ color: var(--navy); }
.kpi-number.cyan{ color: var(--cyan); }
.kpi-number.lime{ color: #5a7f11; }

.kpi-sub{
  margin-top: 4px;
  font-size: 0.78rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  font-weight: 900;
}
.kpi-title-below{
  margin-top: 10px;
  text-align:center;
  font-size: 0.82rem;
  color: var(--muted);
  font-weight: 900;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

/* DB status pill */
.db-pill{
  display:flex; align-items:center; gap:8px;
  padding:8px 10px; border-radius:12px;
  border:1px solid rgba(15,23,42,0.08);
  background:#fff;
}
.db-dot{
  width:10px;height:10px;border-radius:999px;
}
.db-text{
  font-size:0.88rem;color:#0f172a;font-weight:800;
}
.db-sub{
  font-size:0.78rem;color:#64748b;margin-top:-2px;
}

/* Scrollable dataframe container */
.lb-table-wrap{
  border: 1px solid rgba(15,23,42,0.08);
  border-radius: 14px;
  box-shadow: 0 8px 20px rgba(15, 23, 42, 0.06);
  padding: 10px;
  background: #fff;
}

/* Lead picker heading (avoid wrapper artifacts above dropdown) */
.lb-lead-picker-title{
  margin: 8px 0 6px 0;
  font-weight: 900;
  color: var(--navy);
  letter-spacing: 0.02em;
}

/* Read-only comments section */
.lb-comments-view{
  background: var(--pastel-lime);
  border: 1px solid rgba(90, 127, 17, 0.22);
  border-radius: 14px;
  padding: 10px 12px;
}
.lb-comment-item{
  padding: 8px 0;
}
.lb-comment-meta{
  color: #4d7c0f;
  font-size: 0.80rem;
  font-weight: 800;
  margin-bottom: 4px;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}
.lb-comment-text{
  color: #1f2937;
  font-size: 0.92rem;
  white-space: pre-wrap;
  word-break: break-word;
}
.lb-comment-divider{
  border-top: 1px solid rgba(90, 127, 17, 0.24);
  margin: 2px 0;
}

/* Filtered leads table header styling */
div[data-testid="stDataFrame"] [role="columnheader"] {
  background: linear-gradient(180deg, #f1f5f9 0%, #e2e8f0 100%) !important;
}

div[data-testid="stDataFrame"] [role="columnheader"] * {
  font-weight: 800 !important;
  text-align: center !important;
  justify-content: center !important;
}

/* Make dataframe toolbar and tooltips more prominent */
div[data-testid="stElementToolbar"] {
  background: linear-gradient(135deg, rgba(45, 68, 141, 0.16), rgba(0, 174, 239, 0.14)) !important;
  border: 1px solid rgba(45, 68, 141, 0.22) !important;
  border-radius: 12px !important;
  box-shadow: 0 8px 20px rgba(45, 68, 141, 0.18) !important;
  padding: 4px 6px !important;
}

div[data-testid="stElementToolbar"] button {
  background: rgba(255, 255, 255, 0.78) !important;
  border-radius: 9px !important;
}

div[data-testid="stElementToolbar"] button:hover {
  background: rgba(255, 255, 255, 0.95) !important;
}

div[role="tooltip"] {
  background: linear-gradient(135deg, #2d448d 0%, #00aeef 100%) !important;
  color: #ffffff !important;
  border: 1px solid rgba(255, 255, 255, 0.28) !important;
  border-radius: 10px !important;
  box-shadow: 0 10px 24px rgba(15, 23, 42, 0.24) !important;
}

div[role="tooltip"] * {
  color: #ffffff !important;
}

</style>
""",
    unsafe_allow_html=True,
)


# -----------------------
# UI helpers
# -----------------------
def card_open(title: str, variant: str, dot_color: str, subtitle: str | None = None):
    sub = f'<div class="lb-subtitle">{subtitle}</div>' if subtitle else ""
    st.markdown(
        f"""
<div class="lb-card {variant}">
  <div class="lb-card-header">
    <div class="lb-dot" style="background:{dot_color};"></div>
    <div>
      <div class="lb-title">{title}</div>
      {sub}
    </div>
  </div>
""",
        unsafe_allow_html=True,
    )


def card_close():
    st.markdown("</div>", unsafe_allow_html=True)


def db_status_pill(ok: bool, detail: str = ""):
    color = "#22c55e" if ok else "#ef4444"
    text = "DB STATUS: OK" if ok else "DB STATUS: ERROR"
    sub = detail or ("Connected • indexes OK" if ok else "Check MongoDB URI / permissions / cluster")
    st.markdown(
        f"""
<div class="db-pill">
  <div class="db-dot" style="background:{color};"></div>
  <div>
    <div class="db-text">{text}</div>
    <div class="db-sub">{sub}</div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


def encode_uploaded_file(uploaded_file: Any) -> Optional[dict]:
    if uploaded_file is None:
        return None

    data = uploaded_file.getvalue()
    if not data:
        return None

    mime_type = str(getattr(uploaded_file, "type", "") or "application/octet-stream").strip() or "application/octet-stream"
    return {
        "name": str(getattr(uploaded_file, "name", "") or "policy-copy").strip() or "policy-copy",
        "mimeType": mime_type,
        "data": base64.b64encode(data).decode("utf-8"),
        "uploadedAt": now_utc(),
        "uploadedBy": current_username() or None,
    }


def parse_money(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if not s:
        return None
    s = re.sub(r"[^0-9.\-]", "", s)
    if not s or s in {"-", ".", "-."}:
        return None
    try:
        return float(s)
    except Exception:
        return None


def format_inr_compact(amount: float) -> str:
    try:
        x = float(amount)
    except Exception:
        return "₹0"

    sign = "-" if x < 0 else ""
    x = abs(x)

    def fmt(value: float, suffix: str) -> str:
        if abs(value - round(value)) < 1e-9:
            return f"{sign}₹{int(round(value))}{suffix}"
        return f"{sign}₹{value:.1f}{suffix}"

    if x >= 1e7:
        return fmt(x / 1e7, "Cr")
    if x >= 1e5:
        return fmt(x / 1e5, "L")
    if x >= 1e3:
        return fmt(x / 1e3, "K")
    return f"{sign}₹{int(round(x))}"


def format_note_datetime_ist(value: Any) -> str:
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        dt_ist = dt.astimezone(IST)
        return dt_ist.strftime("%d %b %Y • %I:%M %p IST")
    return "Unknown timestamp"


def policy_copy_present(lead: dict) -> bool:
    policy_copy = lead.get("policyCopy") or {}
    return bool(isinstance(policy_copy, dict) and str(policy_copy.get("data") or "").strip())


def dedupe_notes(notes: list[dict]) -> list[dict]:
    deduped: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for note in notes:
        if not isinstance(note, dict):
            continue
        text = str((note or {}).get("text") or "").strip()
        author = str((note or {}).get("createdBy") or "").strip().lower()
        key = (text, author)
        if not text or key in seen:
            continue
        seen.add(key)
        deduped.append(note)
    return deduped


@st.dialog("Policy Copy")
def show_policy_copy_dialog(lead: dict) -> None:
    policy_copy = lead.get("policyCopy") or {}
    encoded = str(policy_copy.get("data") or "").strip()
    if not encoded:
        st.info("No policy copy uploaded for this lead.")
        return

    mime_type = str(policy_copy.get("mimeType") or "application/pdf").strip() or "application/pdf"
    file_name = str(policy_copy.get("name") or "policy-copy").strip() or "policy-copy"
    uploaded_meta: list[str] = []
    if policy_copy.get("uploadedBy"):
        uploaded_meta.append(f"Uploaded by {policy_copy.get('uploadedBy')}")
    if policy_copy.get("uploadedAt"):
        uploaded_meta.append(format_note_datetime_ist(policy_copy.get("uploadedAt")))
    if uploaded_meta:
        st.caption(" • ".join(uploaded_meta))

    file_bytes = base64.b64decode(encoded)
    if mime_type == "application/pdf":
        file_name_html = html.escape(file_name, quote=True)
        pdf_data_url = f"data:application/pdf;base64,{encoded}#toolbar=1&navpanes=0&scrollbar=1"
        components.html(
            f"""
            <div style="height:640px;width:100%;overflow:hidden;border-radius:12px;background:#fff;">
              <object
                data="{pdf_data_url}"
                type="application/pdf"
                aria-label="{file_name_html}"
                style="width:100%;height:100%;border:0;display:block;"
              >
                <embed
                  src="{pdf_data_url}"
                  type="application/pdf"
                  style="width:100%;height:100%;border:0;display:block;"
                />
              </object>
            </div>
            """,
            height=640,
        )
    elif mime_type.startswith("image/"):
        st.image(file_bytes, caption=file_name, use_container_width=True)
    else:
        st.info(f"Preview is not available for {file_name}. You can download the file below.")

    st.download_button(
        "Download Policy Copy",
        data=file_bytes,
        file_name=file_name,
        mime=mime_type,
        use_container_width=True,
        key=f"download_policy_copy_{lead.get('leadId')}",
    )


def comments_view_html(notes: list[dict]) -> str:
    if not notes:
        return '<div class="lb-comments-view"><div class="lb-comment-text">No comments available for this lead.</div></div>'

    rows: list[str] = ['<div class="lb-comments-view">']
    for i, note in enumerate(notes):
        text = str((note or {}).get("text") or "").strip() or "(empty comment)"
        ts = format_note_datetime_ist((note or {}).get("createdAt"))
        author = str((note or {}).get("createdBy") or "Unknown user").strip() or "Unknown user"
        rows.append('<div class="lb-comment-item">')
        rows.append(f'<div class="lb-comment-meta">{author} • {ts}</div>')
        rows.append(f'<div class="lb-comment-text">{text}</div>')
        rows.append('</div>')
        if i < len(notes) - 1:
            rows.append('<div class="lb-comment-divider"></div>')
    rows.append('</div>')
    return "".join(rows)


def allocation_chain(lead: dict) -> list[str]:
    history = [h for h in (lead.get("allocationHistory") or []) if isinstance(h, dict)]
    ordered = sorted(
        history,
        key=lambda h: h.get("editedAt") if isinstance(h.get("editedAt"), datetime) else datetime.min.replace(tzinfo=timezone.utc),
    )

    chain: list[str] = []
    for item in ordered:
        first_alloc = str(item.get("from") or "").strip()
        reassigned_to = str(item.get("to") or "").strip()
        if first_alloc and (not chain or chain[-1].lower() != first_alloc.lower()):
            chain.append(first_alloc)
        if reassigned_to and (not chain or chain[-1].lower() != reassigned_to.lower()):
            chain.append(reassigned_to)

    if not chain:
        current = str(safe_get(lead, "allocatedTo.displayName") or "").strip()
        if current:
            chain.append(current)

    return chain


def allocation_chain_text(lead: dict) -> str:
    chain = allocation_chain(lead)
    return " -> ".join(chain) if chain else "—"


def kpi_circles_html(total: int, interested: int, not_interested: int, closed: int, total_brokerage: float):
    brok = format_inr_compact(total_brokerage)
    return f"""
<div class="kpi-row">
  <div class="kpi-wrap">
    <div class="kpi" style="background: linear-gradient(180deg, var(--pastel-navy), #fff);">
      <div class="kpi-inner">
        <div class="kpi-number navy">{total}</div>
        <div class="kpi-sub">Total Leads</div>
      </div>
    </div>
    <div class="kpi-title-below"></div>
  </div>

  <div class="kpi-wrap">
    <div class="kpi" style="background: linear-gradient(180deg, var(--pastel-lime), #fff);">
      <div class="kpi-inner">
        <div class="kpi-number lime">{interested}</div>
        <div class="kpi-sub">Interested</div>
      </div>
    </div>
    <div class="kpi-title-below"></div>
  </div>

  <div class="kpi-wrap">
    <div class="kpi" style="background: linear-gradient(180deg, #FFF1F2, #fff);">
      <div class="kpi-inner">
        <div class="kpi-number" style="color:#be123c;">{not_interested}</div>
        <div class="kpi-sub">Lost</div>
      </div>
    </div>
    <div class="kpi-title-below"></div>
  </div>

  <div class="kpi-wrap">
    <div class="kpi" style="background: linear-gradient(180deg, var(--pastel-cyan), #fff);">
      <div class="kpi-inner">
        <div class="kpi-number cyan">{closed}</div>
        <div class="kpi-sub">Closed</div>
      </div>
    </div>
    <div class="kpi-title-below"></div>
  </div>

  <div class="kpi-wrap">
    <div class="kpi" style="background: linear-gradient(180deg, #FFF7ED, #fff);">
      <div class="kpi-inner">
        <div class="kpi-number" style="color:#9a3412;">{brok}</div>
        <div class="kpi-sub">Total Brokerage</div>
      </div>
    </div>
    <div class="kpi-title-below"></div>
  </div>
</div>
"""


# -----------------------
# Mongo helpers
# -----------------------
@st.cache_resource
def mongo_client() -> MongoClient:
    uri = st.secrets.get(SECRET_KEY_LEADS)
    if not uri:
        st.error(f"Missing Streamlit secret: {SECRET_KEY_LEADS}")
        st.stop()
    return MongoClient(uri)


def clear_db_cache() -> None:
    st.cache_resource.clear()


def leads_col():
    return mongo_client()[DB_NAME][COLL_LEADS]


def users_col():
    return mongo_client()[DB_NAME][COLL_USERS]


def current_username() -> str:
    return str(st.session_state.get("logged_in_user") or "").strip().lower()


def can_manage_deletions() -> bool:
    return current_username() == SUPER_ADMIN_USERNAME


def generate_strong_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(ch.islower() for ch in pwd)
            and any(ch.isupper() for ch in pwd)
            and any(ch.isdigit() for ch in pwd)
            and any(ch in "!@#$%^&*()-_=+" for ch in pwd)
        ):
            return pwd
