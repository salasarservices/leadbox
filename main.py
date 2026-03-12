from __future__ import annotations

from datetime import datetime, timezone, date as date_type
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo
import hmac
import hashlib
import os
import re
import secrets
import string

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
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
LEAD_STATUS_OPTIONS = ["Fresh", "Allocated", "Interested", "Not-Interested", "Closed"]

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
        return "not interested"
    return s


def denormalize_lead_status(value: Optional[str]) -> str:
    v = (value or "").strip().lower()
    if v == "not interested":
        return "Not-Interested"
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


def comments_view_html(notes: list[dict]) -> str:
    if not notes:
        return '<div class="lb-comments-view"><div class="lb-comment-text">No comments available for this lead.</div></div>'

    rows: list[str] = ['<div class="lb-comments-view">']
    for i, note in enumerate(notes):
        text = str((note or {}).get("text") or "").strip() or "(empty comment)"
        ts = format_note_datetime_ist((note or {}).get("createdAt"))
        rows.append('<div class="lb-comment-item">')
        rows.append(f'<div class="lb-comment-meta">{ts}</div>')
        rows.append(f'<div class="lb-comment-text">{text}</div>')
        rows.append('</div>')
        if i < len(notes) - 1:
            rows.append('<div class="lb-comment-divider"></div>')
    rows.append('</div>')
    return "".join(rows)


def kpi_circles_html(total: int, interested: int, not_interested: int, closed: int, total_brokerage: float):
    brok = format_inr_compact(total_brokerage)
    return f"""
<div class="kpi-row">
  <div class="kpi-wrap">
    <div class="kpi" style="background: linear-gradient(90deg, #5b6bdc 0%, #4f8fd8 50%, #46c1d9 100%);">
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
        <div class="kpi-sub">Not Interested</div>
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


def create_dashboard_user(username: str, password: str, created_by: str | None = None) -> tuple[bool, str]:
    uname = (username or "").strip().lower()
    if not uname:
        return False, "Username is required."
    if not re.fullmatch(r"[a-z0-9._-]{3,40}", uname):
        return False, "Username must be 3-40 chars: lowercase letters, numbers, dot, underscore, hyphen."
    if not password:
        return False, "Password is required."

    col = users_col()
    doc = {
        "username": uname,
        "passwordHash": hash_password(password),
        "passwordPlain": password,
        "createdAt": now_utc(),
        "updatedAt": now_utc(),
        "createdBy": (created_by or "").strip().lower() or None,
        "isActive": True,
        "role": "user",
    }

    try:
        col.insert_one(doc)
        return True, f"User '{uname}' created successfully."
    except DuplicateKeyError:
        return False, f"User '{uname}' already exists."


def list_dashboard_users() -> List[dict]:
    col = users_col()
    return list(
        col.find(
            {},
            {
                "username": 1,
                "passwordPlain": 1,
                "isActive": 1,
                "createdAt": 1,
                "updatedAt": 1,
            },
        ).sort([("username", ASCENDING)])
    )


def set_dashboard_user_password(username: str, password: str, updated_by: str | None = None) -> tuple[bool, str]:
    uname = (username or "").strip().lower()
    if not uname:
        return False, "Select a valid user."
    if not password:
        return False, "Password is required."

    res = users_col().update_one(
        {"username": uname},
        {
            "$set": {
                "passwordHash": hash_password(password),
                "passwordPlain": password,
                "updatedAt": now_utc(),
                "updatedBy": (updated_by or "").strip().lower() or None,
            }
        },
    )
    if res.matched_count == 0:
        return False, f"User '{uname}' not found."
    return True, f"Password updated for '{uname}'."


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def safe_get(d: dict, path: str, default=None):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def month_bounds_utc(year: int, month: int) -> Tuple[datetime, datetime]:
    start_ist = datetime(year, month, 1, 0, 0, 0, tzinfo=IST)
    if month == 12:
        end_ist = datetime(year + 1, 1, 1, 0, 0, 0, tzinfo=IST)
    else:
        end_ist = datetime(year, month + 1, 1, 0, 0, 0, tzinfo=IST)
    return start_ist.astimezone(timezone.utc), end_ist.astimezone(timezone.utc)


# -----------------------
# LeadId helpers (prefix SL)
# -----------------------
def make_lead_id(serial: int, lead_date_ist: datetime) -> str:
    nn = str(int(serial)).zfill(2)
    mmm = MONTHS[lead_date_ist.month - 1]
    yy = str(lead_date_ist.year)[-2:]
    return f"{LEAD_ID_PREFIX}{nn}{mmm}{yy}"


def next_serial_for_month(lead_date_ist: datetime) -> int:
    col = leads_col()
    start_utc, end_utc = month_bounds_utc(lead_date_ist.year, lead_date_ist.month)

    arr = list(
        col.find({"leadDate": {"$gte": start_utc, "$lt": end_utc}}, {"legacyNumber": 1})
        .sort([("legacyNumber", DESCENDING)])
        .limit(1)
    )
    if not arr:
        return 1

    try:
        return int(arr[0].get("legacyNumber")) + 1
    except Exception:
        return 1


def lead_id_from_existing_or_new(target_lead_date_ist: datetime, existing_lead_id: Optional[str]) -> tuple[str, int]:
    if not existing_lead_id:
        serial = next_serial_for_month(target_lead_date_ist)
        return make_lead_id(serial, target_lead_date_ist), serial

    mmm = MONTHS[target_lead_date_ist.month - 1]
    yy = str(target_lead_date_ist.year)[-2:]
    suffix = f"{mmm}{yy}".upper()

    if existing_lead_id.upper().endswith(suffix):
        return existing_lead_id, -1

    serial = next_serial_for_month(target_lead_date_ist)
    return make_lead_id(serial, target_lead_date_ist), serial


# -----------------------
# DB init + indexes
# -----------------------
def ensure_indexes():
    col = leads_col()
    existing = col.index_information()
    if "uniq_leadId" not in existing:
        col.create_index([("leadId", ASCENDING)], unique=True, name="uniq_leadId")
    if "idx_leadDate" not in existing:
        col.create_index([("leadDate", ASCENDING)], name="idx_leadDate")
    if "idx_leadStatus" not in existing:
        col.create_index([("leadStatus", ASCENDING)], name="idx_leadStatus")
    if "idx_allocatedTo" not in existing:
        col.create_index([("allocatedTo.displayName", ASCENDING)], name="idx_allocatedTo")

    ucol = users_col()
    users_existing = ucol.index_information()
    if "uniq_username" not in users_existing:
        ucol.create_index([("username", ASCENDING)], unique=True, name="uniq_username")


def check_db_and_init() -> tuple[bool, str]:
    try:
        mongo_client().admin.command("ping")
        ensure_indexes()
        return True, "Connected • indexes OK"
    except Exception as e:
        return False, str(e)




# -----------------------
# Suggestions
# -----------------------
def product_suggestions() -> list[str]:
    col = leads_col()
    db_values = [p for p in col.distinct("productType") if isinstance(p, str) and p.strip()]

    merged: list[str] = []
    seen: set[str] = set()
    for item in (DEFAULT_PRODUCT_TYPES + sorted(db_values, key=lambda x: x.lower())):
        key = item.strip().lower()
        if key and key not in seen:
            seen.add(key)
            merged.append(item.strip())
    return merged


def allocated_to_suggestions() -> list[str]:
    col = leads_col()
    names = [a for a in col.distinct("allocatedTo.displayName") if isinstance(a, str) and a.strip()]
    return sorted({n.strip() for n in names}, key=lambda x: x.lower())


def month_lead_counts(year: int) -> dict[int, int]:
    col = leads_col()

    start_ist = datetime(year, 1, 1, 0, 0, 0, tzinfo=IST)
    end_ist = datetime(year + 1, 1, 1, 0, 0, 0, tzinfo=IST)

    pipeline = [
        {"$match": {"leadDate": {"$gte": start_ist.astimezone(timezone.utc), "$lt": end_ist.astimezone(timezone.utc)}}},
        {"$addFields": {"leadDateIST": {"$dateToParts": {"date": "$leadDate", "timezone": "Asia/Kolkata"}}}},
        {"$group": {"_id": "$leadDateIST.month", "count": {"$sum": 1}}},
    ]
    res = list(col.aggregate(pipeline))
    return {int(r["_id"]): int(r["count"]) for r in res if r.get("_id")}


# -----------------------
# Continuous month chart (Plotly)
# -----------------------
def first_month_in_db() -> datetime:
    col = leads_col()
    doc = list(col.find({}, {"leadDate": 1}).sort([("leadDate", ASCENDING)]).limit(1))
    if not doc:
        now = datetime.now(IST)
        return datetime(now.year, now.month, 1, 0, 0, 0, tzinfo=IST)

    dt = doc[0].get("leadDate")
    if isinstance(dt, datetime):
        dt_ist = dt.astimezone(IST)
        return datetime(dt_ist.year, dt_ist.month, 1, 0, 0, 0, tzinfo=IST)

    now = datetime.now(IST)
    return datetime(now.year, now.month, 1, 0, 0, 0, tzinfo=IST)


def month_series_counts_df() -> pd.DataFrame:
    col = leads_col()

    start_m = first_month_in_db()
    now_ist = datetime.now(IST)
    end_m = datetime(now_ist.year, now_ist.month, 1, 0, 0, 0, tzinfo=IST)

    start_utc = start_m.astimezone(timezone.utc)

    if end_m.month == 12:
        end_excl_ist = datetime(end_m.year + 1, 1, 1, 0, 0, 0, tzinfo=IST)
    else:
        end_excl_ist = datetime(end_m.year, end_m.month + 1, 1, 0, 0, 0, tzinfo=IST)
    end_utc = end_excl_ist.astimezone(timezone.utc)

    pipeline = [
        {"$match": {"leadDate": {"$gte": start_utc, "$lt": end_utc}}},
        {"$addFields": {"leadDateIST": {"$dateToParts": {"date": "$leadDate", "timezone": "Asia/Kolkata"}}}},
        {"$group": {"_id": {"y": "$leadDateIST.year", "m": "$leadDateIST.month"}, "count": {"$sum": 1}}},
    ]
    res = list(col.aggregate(pipeline))
    counts = {(int(r["_id"]["y"]), int(r["_id"]["m"])): int(r["count"]) for r in res if r.get("_id")}

    rows: List[Dict[str, Any]] = []
    y, m = start_m.year, start_m.month
    while True:
        label = f"{MONTHS[m-1]} {str(y)[-2:]}"
        month_start_ist = datetime(y, m, 1, 0, 0, 0, tzinfo=IST)
        rows.append({"label": label, "month_start": month_start_ist, "count": int(counts.get((y, m), 0))})

        if y == end_m.year and m == end_m.month:
            break

        if m == 12:
            y += 1
            m = 1
        else:
            m += 1

    return pd.DataFrame(rows).sort_values("month_start", ascending=True)


def plot_month_series(df: pd.DataFrame) -> go.Figure:
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=df["label"],
            y=df["count"],
            mode="lines+markers",
            line=dict(color="#00aeef", width=3),
            marker=dict(size=7, color="#2d448d", line=dict(width=1, color="white")),
            hovertemplate="<b>%{x}</b><br>Leads: %{y}<extra></extra>",
        )
    )
    fig.update_layout(
        height=300,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial", size=12, color="#0f172a"),
        xaxis=dict(title="", tickangle=-35, showgrid=False, zeroline=False, tickfont=dict(color="#475569")),
        yaxis=dict(title="", gridcolor="rgba(15, 23, 42, 0.08)", zeroline=False, tickfont=dict(color="#475569")),
        showlegend=False,
    )
    return fig


# -----------------------
# CRUD
# -----------------------
def build_query(filters: dict) -> Dict[str, Any]:
    q: Dict[str, Any] = {}
    if filters.get("status") and filters["status"] != "all":
        q["leadStatus"] = normalize_lead_status(filters["status"])
    if filters.get("allocatedTo") and filters["allocatedTo"] != "all":
        q["allocatedTo.displayName"] = filters["allocatedTo"]
    if filters.get("month_mode") == "month":
        start_utc, end_utc = month_bounds_utc(filters["month_year"], filters["month_num"])
        q["leadDate"] = {"$gte": start_utc, "$lt": end_utc}
    return q


def fetch_leads(filters: dict) -> list[dict]:
    col = leads_col()
    q = build_query(filters)
    docs = list(col.find(q).sort([("leadDate", DESCENDING)]))

    search = (filters.get("search") or "").strip().lower()
    if search:

        def match(d: dict) -> bool:
            fields = [
                d.get("leadId"),
                d.get("contactName"),
                d.get("companyName"),
                d.get("contactEmail"),
                d.get("contactPhone"),
                d.get("productType"),
                safe_get(d, "allocatedTo.displayName"),
                d.get("leadStatus"),
            ]
            return any(search in str(v).lower() for v in fields if v is not None)

        docs = [d for d in docs if match(d)]

    return docs


def compute_kpis_from_docs(docs: list[dict]) -> dict:
    total = len(docs)
    interested = sum(1 for d in docs if (d.get("leadStatus") or "").lower() == "interested")
    not_interested = sum(1 for d in docs if (d.get("leadStatus") or "").lower() == "not interested")
    closed = sum(1 for d in docs if (d.get("leadStatus") or "").lower() == "closed")
    total_brokerage = 0.0
    for d in docs:
        v = d.get("brokerageReceived")
        if isinstance(v, (int, float)):
            total_brokerage += float(v)
    return {
        "total": total,
        "interested": interested,
        "not_interested": not_interested,
        "closed": closed,
        "total_brokerage": total_brokerage,
    }


def fetch_kpis_from_db(q: Dict[str, Any]) -> dict:
    col = leads_col()
    total = col.count_documents(q)
    interested = col.count_documents({**q, "leadStatus": "interested"})
    not_interested = col.count_documents({**q, "leadStatus": "not interested"})
    closed = col.count_documents({**q, "leadStatus": "closed"})

    pipeline = [
        {"$match": q},
        {"$group": {"_id": None, "sum": {"$sum": {"$cond": [{"$isNumber": "$brokerageReceived"}, "$brokerageReceived", 0]}}}},
    ]
    agg = list(col.aggregate(pipeline))
    total_brokerage = float(agg[0]["sum"]) if agg else 0.0

    return {
        "total": total,
        "interested": interested,
        "not_interested": not_interested,
        "closed": closed,
        "total_brokerage": total_brokerage,
    }


def update_lead(_id: ObjectId, updates: dict):
    col = leads_col()
    updates["updatedAt"] = now_utc()
    col.update_one({"_id": _id}, {"$set": updates})


def add_note(_id: ObjectId, text: str, created_by: Optional[str] = None):
    col = leads_col()
    note = {"text": text.strip(), "createdAt": now_utc(), "createdBy": created_by}
    col.update_one({"_id": _id}, {"$push": {"notes": note}, "$set": {"updatedAt": now_utc()}})


def create_lead(payload: dict) -> ObjectId:
    col = leads_col()

    lead_date: date_type = payload["leadDate"]
    lead_date_local = datetime(lead_date.year, lead_date.month, lead_date.day, 0, 0, 0, tzinfo=IST)

    serial = next_serial_for_month(lead_date_local)
    lead_id = make_lead_id(serial, lead_date_local)

    initial_comment = (payload.get("comment") or "").strip() or None

    doc = {
        "leadId": lead_id,
        "legacyNumber": serial,
        "leadDate": lead_date_local.astimezone(timezone.utc),
        "companyName": payload.get("companyName") or None,
        "contactName": payload.get("contactName") or None,
        "contactEmail": payload.get("contactEmail") or None,
        "contactPhone": payload.get("contactPhone") or None,
        "productType": payload.get("productType") or None,
        "allocatedTo": {"displayName": payload.get("allocatedToDisplayName") or None, "userId": None, "email": None},
        "leadStatus": normalize_lead_status(payload.get("leadStatus") or "Fresh") or "fresh",
        "brokerageReceived": payload.get("brokerageReceived", None),
        "notes": ([{"text": initial_comment, "createdAt": now_utc(), "createdBy": None}] if initial_comment else []),
        "emailRecipients": [],
        "messageText": None,
        "schemaVersion": 3,
        "createdAt": now_utc(),
        "updatedAt": now_utc(),
    }

    try:
        res = col.insert_one(doc)
        return res.inserted_id
    except DuplicateKeyError:
        serial = next_serial_for_month(lead_date_local)
        doc["legacyNumber"] = serial
        doc["leadId"] = make_lead_id(serial, lead_date_local)
        res = col.insert_one(doc)
        return res.inserted_id


# -----------------------
# Auto-run DB init + status
# -----------------------
db_ok, db_detail = check_db_and_init()

# -----------------------
# Header with logo
# -----------------------
header_l, header_r = st.columns([0.25, 0.75], vertical_alignment="center")
with header_l:
    st.image(LOGO_URL, width=165)
with header_r:
    st.markdown(
        "<div style='font-size:1.35rem;font-weight:800;color:#2d448d;letter-spacing:-0.02em;'>LEADBOX DASHBOARD</div>"
        "<div style='color:#64748b;margin-top:-4px;'>Leads • Notes • Month-wise filtering</div>",
        unsafe_allow_html=True,
    )

st.write("")

# -----------------------
# Sidebar
# -----------------------
with st.sidebar:
    db_status_pill(db_ok, db_detail)

    logged_in_user = st.session_state.get("logged_in_user") or "unknown"
    st.caption(f"Signed in as: `{logged_in_user}`")
    if st.button("Logout", use_container_width=True):
        logout_user("You have been logged out.")

    if st.button("Refresh DB", use_container_width=True):
        clear_db_cache()
        st.success("DB cache cleared. Data will refresh on next interaction.")

    # ❌ Removed: Admin: Lead ID migration (no longer shown in sidebar)

    card_open("Navigation", "lb-navy", "#2d448d", subtitle="Switch between modules")
    page = st.radio("Go to", ["Leads", "Create Lead"], index=0, label_visibility="collapsed")
    card_close()

    allocs = allocated_to_suggestions()

    card_open("Filters", "lb-cyan", "#00aeef", subtitle="Search and segment leads")
    status = st.selectbox("Status", ["all"] + LEAD_STATUS_OPTIONS, index=0)
    allocatedTo = st.selectbox("Allocated to", ["all"] + allocs, index=0)
    search = st.text_input("Search", value="", placeholder="Lead ID, contact, company, email, phone...")
    card_close()

    card_open("Month Filters", "lb-lime", "#a6ce39", subtitle="View lead activity month-wise (IST)")
    month_mode = st.selectbox("Filter by", ["all", "month"], index=0)

    month_year = datetime.now(IST).year
    month_num = datetime.now(IST).month

    if month_mode == "month":
        month_year = st.number_input("Year", min_value=2020, max_value=2100, value=month_year, step=1)
        counts = month_lead_counts(int(month_year))
        month_num = st.selectbox(
            "Month",
            options=list(range(1, 13)),
            index=month_num - 1,
            format_func=lambda m: f"{MONTHS[m-1]} ({counts.get(m, 0)})",
        )
    card_close()

    if st.session_state.get("is_super_admin") is True:
        card_open("User Management", "lb-navy", "#2d448d", subtitle="Add users, manage passwords, and reveal current user credentials")

        if "generated_password_create" not in st.session_state:
            st.session_state["generated_password_create"] = generate_strong_password(16)

        with st.form("create_user_form"):
            new_username = st.text_input("New Username", placeholder="e.g. team.member")
            generated_password = st.session_state.get("generated_password_create") or generate_strong_password(16)
            selected_password = st.text_input(
                "Generated Strong Password",
                value=generated_password,
                help="Editable for super-admin: keep generated value or enter your own password.",
            )
            create_cols = st.columns(2)
            with create_cols[0]:
                refresh_generated = st.form_submit_button("Regenerate Password")
            with create_cols[1]:
                create_user_btn = st.form_submit_button("Add User")

        if refresh_generated:
            st.session_state["generated_password_create"] = generate_strong_password(16)
            st.rerun()

        if create_user_btn:
            ok_user, msg_user = create_dashboard_user(
                username=new_username,
                password=selected_password,
                created_by=st.session_state.get("logged_in_user"),
            )
            if ok_user:
                st.success(f"{msg_user} Current password: {selected_password}")
                st.session_state["generated_password_create"] = generate_strong_password(16)
            else:
                st.error(msg_user)

        users = list_dashboard_users()
        usernames = [u.get("username") for u in users if u.get("username")]
        with st.form("change_user_password_form"):
            st.markdown("**Change Existing User Password**")
            selected_user = st.selectbox("Select User", options=usernames) if usernames else None
            generated_update_password = generate_strong_password(16)
            updated_password = st.text_input(
                "New Password (Editable Generated Password)",
                value=generated_update_password,
                help="Use generated password or enter your preferred password.",
            )
            update_password_btn = st.form_submit_button("Update Password")

        if update_password_btn:
            if not selected_user:
                st.error("No users available to update.")
            else:
                ok_upd, msg_upd = set_dashboard_user_password(
                    username=selected_user,
                    password=updated_password,
                    updated_by=st.session_state.get("logged_in_user"),
                )
                if ok_upd:
                    st.success(msg_upd)
                else:
                    st.error(msg_upd)

        with st.expander("Click to reveal current users and passwords"):
            users = list_dashboard_users()
            if not users:
                st.info("No users found.")
            else:
                reveal_rows = []
                for user_doc in users:
                    reveal_rows.append(
                        {
                            "Username": user_doc.get("username") or "—",
                            "Current Password": user_doc.get("passwordPlain") or "(legacy/unknown)",
                            "Active": "Yes" if user_doc.get("isActive", True) else "No",
                        }
                    )
                st.dataframe(pd.DataFrame(reveal_rows), use_container_width=True, hide_index=True)

        card_close()

filters = {
    "status": status,
    "allocatedTo": allocatedTo,
    "search": search,
    "month_mode": month_mode,
    "month_year": int(month_year),
    "month_num": int(month_num),
}

# -----------------------
# Pages
# -----------------------
if page == "Leads":
    leads = fetch_leads(filters)
    is_filtered = (
        filters.get("status") != "all"
        or filters.get("allocatedTo") != "all"
        or filters.get("month_mode") == "month"
        or bool(filters.get("search"))
    )

    kpis = compute_kpis_from_docs(leads)
    st.markdown(
        kpi_circles_html(kpis["total"], kpis["interested"], kpis["not_interested"], kpis["closed"], kpis["total_brokerage"]),
        unsafe_allow_html=True,
    )

    if is_filtered and leads:
        card_open("Filtered Leads", "lb-lime", "#a6ce39", subtitle="Matching leads")
        df_table = pd.DataFrame([
            {
                "Number": idx + 1,
                "Lead ID": d.get("leadId") or "—",
                "Name": d.get("contactName") or "—",
                "Company": d.get("companyName") or "—",
                "Allocated To": safe_get(d, "allocatedTo.displayName") or "—",
                "Status": denormalize_lead_status(d.get("leadStatus")) or "—",
                "Brokerage Received": format_inr_compact(parse_money(d.get("brokerageReceived")) or 0),
            }
            for idx, d in enumerate(leads)
        ])

        df_download = pd.DataFrame([
            {
                "Number": idx + 1,
                "Lead ID": d.get("leadId") or "",
                "Name": d.get("contactName") or "",
                "Company": d.get("companyName") or "",
                "Allocated To": safe_get(d, "allocatedTo.displayName") or "",
                "Status": denormalize_lead_status(d.get("leadStatus")) or "",
                "Brokerage Received": parse_money(d.get("brokerageReceived")) or 0,
                "Phone Number": d.get("contactPhone") or "",
                "Email": d.get("contactEmail") or "",
                "Comments": " | ".join(
                    [
                        str((n or {}).get("text") or "").strip()
                        for n in (d.get("notes") or [])
                        if isinstance(n, dict) and str((n or {}).get("text") or "").strip()
                    ]
                ),
            }
            for idx, d in enumerate(leads)
        ])

        st.download_button(
            "Download Filtered Leads CSV",
            data=df_download.to_csv(index=False).encode("utf-8"),
            file_name=f"filtered_leads_{datetime.now(IST).strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
            key="download_filtered_leads_csv",
        )

        selection_event = st.dataframe(
            df_table,
            use_container_width=True,
            hide_index=True,
            height=390,
            column_config={
                "Number": st.column_config.NumberColumn("Number", width="small"),
                "Lead ID": st.column_config.TextColumn("Lead ID", width="small"),
                "Name": st.column_config.TextColumn("Name", width="medium"),
                "Company": st.column_config.TextColumn("Company", width="medium"),
                "Allocated To": st.column_config.TextColumn("Allocated To", width="medium"),
                "Status": st.column_config.TextColumn("Status", width="small"),
                "Brokerage Received": st.column_config.TextColumn("Brokerage Received", width="small"),
            },
            on_select="rerun",
            selection_mode="single-row",
            key="filtered_leads_table",
        )

        selected_rows = selection_event.get("selection", {}).get("rows", [])
        if selected_rows:
            selected_idx = selected_rows[0]
            if 0 <= selected_idx < len(leads):
                st.session_state["selected_lead_id"] = leads[selected_idx].get("leadId")
        card_close()

    left, right = st.columns([0.45, 0.55])

    with left:
        card_open("Details", "lb-navy", "#2d448d", subtitle="Select a lead to view or edit")

        def lead_label(d: dict) -> str:
            lid = d.get("leadId") or "?"
            name = (d.get("contactName") or "").strip()
            status = denormalize_lead_status(d.get("leadStatus") or "") or "—"
            return f"{lid} — {name} [{status}]"

        lead_options = [lead_label(d) for d in leads]
        lead_map = {lead_label(d): d for d in leads}
        lead_index_by_id = {str(d.get("leadId") or ""): idx for idx, d in enumerate(leads)}

        st.markdown('<div class="lb-lead-picker-title">Select a lead</div>', unsafe_allow_html=True)
        if lead_options:
            default_idx = 0
            selected_lead_id = str(st.session_state.get("selected_lead_id") or "")
            if selected_lead_id and selected_lead_id in lead_index_by_id:
                default_idx = lead_index_by_id[selected_lead_id]
            selected_label = st.selectbox(
                "Select a lead",
                lead_options,
                index=default_idx,
                label_visibility="collapsed",
            )
        else:
            selected_label = st.selectbox("Select a lead", ["(no leads found)"], index=0, label_visibility="collapsed")

        selected_lead = lead_map.get(selected_label)
        if selected_lead:
            st.session_state["selected_lead_id"] = selected_lead.get("leadId")

        if selected_lead:
            lead = selected_lead
            lead_oid = lead["_id"]

            existing_dt = lead.get("leadDate")
            if isinstance(existing_dt, datetime):
                existing_date_ist = existing_dt.astimezone(IST).date()
            else:
                existing_date_ist = datetime.now(IST).date()

            existing_notes = lead.get("notes") or []
            existing_comment_default = (existing_notes[-1].get("text") if existing_notes else "") or ""

            save = False
            with st.form("edit_lead_form"):
                c1, c2 = st.columns(2)

                with c1:
                    leadDateEdit = st.date_input("Lead date (IST)", value=existing_date_ist)
                    companyName = st.text_input("Company", value=lead.get("companyName") or "")
                    contactName = st.text_input("Contact person", value=lead.get("contactName") or "")
                    contactEmail = st.text_input("Email id", value=lead.get("contactEmail") or "")
                    contactPhone = st.text_input("Phone number", value=lead.get("contactPhone") or "")

                with c2:
                    current_status_label = denormalize_lead_status(lead.get("leadStatus"))
                    status_index = LEAD_STATUS_OPTIONS.index(current_status_label) if current_status_label in LEAD_STATUS_OPTIONS else 0
                    leadStatusLabel = st.selectbox("Lead status", LEAD_STATUS_OPTIONS, index=status_index)

                    alloc_opts = allocated_to_suggestions()
                    current_alloc = (safe_get(lead, "allocatedTo.displayName") or "").strip()

                    alloc_options = ["None", "(TYPE NEW)"] + alloc_opts
                    if current_alloc and current_alloc.lower() not in {a.lower() for a in alloc_options}:
                        alloc_options.insert(2, current_alloc)

                    alloc_index = 0
                    if current_alloc:
                        try:
                            alloc_index = [a.lower() for a in alloc_options].index(current_alloc.lower())
                        except ValueError:
                            alloc_index = 0

                    allocPick = st.selectbox("Allocated to (choose)", alloc_options, index=alloc_index)
                    allocTyped = st.text_input("Or type allocated to (adds new)", value="", placeholder="Type a new name here...")
                    allocatedToDisplayName = (allocTyped.strip() or (allocPick if allocPick not in {"None", "(TYPE NEW)"} else "")).strip() or None

                brokerage = st.text_input(
                    "Brokerage received",
                    value="" if lead.get("brokerageReceived") is None else str(lead.get("brokerageReceived")),
                )

                comment_edit = st.text_area(
                    "Comments (optional)",
                    value=existing_comment_default,
                    height=90,
                    placeholder="Update comment for this lead...",
                    help="Saving will add this as a new note entry (keeps history).",
                )

                st.caption("If you change the month/year in Lead Date, the Lead ID will be regenerated to match that month.")
                save = st.form_submit_button("Save changes")

            if save:
                # ---- Brokerage parsing ----
                brokerage_val: Any = brokerage.strip()
                if brokerage_val == "":
                    brokerage_val = None
                else:
                    try:
                        brokerage_val = float(brokerage_val)
                    except ValueError:
                        st.error("Brokerage must be a number (or empty).")
                        st.stop()

                # ---- Lead date / Lead ID regeneration ----
                new_lead_dt_ist = datetime(
                    leadDateEdit.year,
                    leadDateEdit.month,
                    leadDateEdit.day,
                    0,
                    0,
                    0,
                    tzinfo=IST,
                )

                current_lead_id = lead.get("leadId")
                new_lead_id, new_serial = lead_id_from_existing_or_new(new_lead_dt_ist, current_lead_id)

                # ---- Updates ----
                updates: dict = {
                    "leadDate": new_lead_dt_ist.astimezone(timezone.utc),
                    "companyName": companyName.strip() or None,
                    "contactName": contactName.strip() or None,
                    "contactEmail": contactEmail.strip() or None,
                    "contactPhone": contactPhone.strip() or None,
                    "leadStatus": normalize_lead_status(leadStatusLabel),
                    "allocatedTo": {"displayName": allocatedToDisplayName, "userId": None, "email": None},
                    "brokerageReceived": brokerage_val,
                }

                if new_lead_id != current_lead_id:
                    updates["leadId"] = new_lead_id
                    updates["legacyNumber"] = new_serial

                try:
                    update_lead(lead_oid, updates)
                except DuplicateKeyError:
                    st.error("Lead ID collision occurred. Try saving again.")
                    st.stop()

                if (comment_edit or "").strip():
                    add_note(lead_oid, comment_edit.strip(), created_by=None)

                st.success("Saved. Click 'Refresh DB' in sidebar to reload cached DB connection.")

        card_close()

    with right:
        try:
            df_chart = month_series_counts_df()
            if not df_chart.empty:
                card_open("Month-Wise Leads", "lb-cyan", "#00aeef", subtitle="Lead activity over time")
                st.plotly_chart(plot_month_series(df_chart), use_container_width=True)
                card_close()
        except Exception:
            pass

        if selected_lead:
            card_open("Comments", "lb-lime", "#a6ce39", subtitle="Read-only timeline from database")
            notes = [n for n in (selected_lead.get("notes") or []) if isinstance(n, dict)]
            notes_sorted = sorted(
                notes,
                key=lambda n: (
                    n.get("createdAt") if isinstance(n.get("createdAt"), datetime) else datetime.min.replace(tzinfo=timezone.utc)
                ),
                reverse=True,
            )
            st.markdown(comments_view_html(notes_sorted), unsafe_allow_html=True)
            card_close()

elif page == "Create Lead":
    card_open("Create Lead", "lb-navy", "#a6ce39", subtitle="Add a new lead (Lead ID generated from selected Lead Date)")
    product_opts = product_suggestions()
    alloc_opts = allocated_to_suggestions()

    with st.form("create_lead_form"):
        c1, c2 = st.columns(2)

        with c1:
            leadDate = st.date_input("Lead date (IST)", value=datetime.now(IST).date())
            companyName = st.text_input("Company")
            contactName = st.text_input("Contact person")
            contactEmail = st.text_input("Email id")
            contactPhone = st.text_input("Phone number")

        with c2:
            productType = st.selectbox("Product type", ["(none)"] + product_opts)
            leadStatus = st.selectbox("Lead status", LEAD_STATUS_OPTIONS)
            allocPick = st.selectbox("Allocated to (choose)", ["None", "(TYPE NEW)"] + alloc_opts)
            allocTyped = st.text_input("Or type allocated to (adds new)", value="", placeholder="Type a new name here...")
            brokerage = st.text_input("Brokerage received", value="")

        comment = st.text_area("Comments (optional)", height=90, placeholder="Initial note for this lead...")
        submitted = st.form_submit_button("Create Lead")

    if submitted:
        alloc_display = (allocTyped.strip() or (allocPick if allocPick not in {"None", "(TYPE NEW)"} else "")).strip() or None
        brokerage_val: Any = brokerage.strip()
        if brokerage_val == "":
            brokerage_val = None
        else:
            try:
                brokerage_val = float(brokerage_val)
            except ValueError:
                st.error("Brokerage must be a number (or empty).")
                st.stop()

        new_oid = create_lead({
            "leadDate": leadDate,
            "companyName": companyName.strip() or None,
            "contactName": contactName.strip() or None,
            "contactEmail": contactEmail.strip() or None,
            "contactPhone": contactPhone.strip() or None,
            "productType": None if (productType or "") == "(none)" else productType,
            "leadStatus": leadStatus,
            "allocatedToDisplayName": alloc_display,
            "brokerageReceived": brokerage_val,
            "comment": comment.strip() or None,
        })
        created_doc = leads_col().find_one({"_id": new_oid}, {"leadId": 1})
        created_lead_id = (created_doc or {}).get("leadId") or str(new_oid)
        st.success(f"Lead created: {created_lead_id}")

    card_close()
