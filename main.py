from __future__ import annotations

from datetime import datetime, timezone, date as date_type
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo
import hmac
import os
import re

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
SECRET_KEY_LEADS = "mongo_uri_leads"  # Streamlit secrets key
LOGO_URL = "https://ik.imagekit.io/salasarservices/Salasar-Logo-new.png?updatedAt=1771587668127"

LEAD_ID_PREFIX = "SL"


# -----------------------
# LOGIN (simple gate)
# -----------------------
def _get_login_creds() -> tuple[str, str]:
    user = st.secrets.get("app_user") or os.environ.get("APP_USER") or ""
    pwd = st.secrets.get("app_password") or os.environ.get("APP_PASSWORD") or ""

    user = str(user).strip()
    pwd = str(pwd)

    if not user or not pwd:
        st.error("Login is not configured.")
        st.info(
            "Streamlit Cloud → App → Settings → Secrets. Add:\n\n"
            'app_user = "your-username"\n'
            'app_password = "your-password"\n'
        )
        st.stop()

    return user, pwd


APP_USER, APP_PASSWORD = _get_login_creds()


def check_login(username: str, password: str) -> bool:
    return hmac.compare_digest(username or "", APP_USER) and hmac.compare_digest(password or "", APP_PASSWORD)


def login_gate() -> None:
    if st.session_state.get("authenticated") is True:
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
        if check_login(u.strip(), p):
            st.session_state["authenticated"] = True
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

/* KPI circles */
.kpi-row{
  display:flex;
  gap:18px;
  flex-wrap:wrap;
  padding: 10px 2px 6px 2px;
  align-items: flex-start;
}
.kpi-wrap{
  width: 150px;
  display:flex;
  flex-direction: column;
  align-items: center;
}
.kpi-circle{
  width: 112px;
  height: 112px;
  border-radius: 999px;
  display:flex;
  align-items:center;
  justify-content:center;
  box-shadow: var(--shadow);
  border: 2px solid rgba(15,23,42,0.06);
  background: #fff;
}
.kpi-val{
  font-size: 1.45rem;
  font-weight: 800;
  letter-spacing: -0.02em;
}
.kpi-label{
  margin-top: 8px;
  text-align:center;
  color: var(--muted);
  font-size: 0.82rem;
  line-height:1.2;
  text-transform: uppercase;
  letter-spacing: .03em;
}
.kpi-total .kpi-circle{ background: linear-gradient(180deg, #eaf0ff, #ffffff); border-color:#dbe5ff; }
.kpi-int .kpi-circle{ background: linear-gradient(180deg, #e9f7ee, #ffffff); border-color:#d2efdb; }
.kpi-nint .kpi-circle{ background: linear-gradient(180deg, #fff3e9, #ffffff); border-color:#ffe1c8; }
.kpi-closed .kpi-circle{ background: linear-gradient(180deg, #f4ecff, #ffffff); border-color:#e5d6ff; }
.kpi-brok .kpi-circle{ background: linear-gradient(180deg, #e8f9ff, #ffffff); border-color:#c9efff; }

/* Lead picker title */
.lb-lead-picker-title{
  font-weight:700;
  color:#2d448d;
  font-size:0.9rem;
  text-transform:uppercase;
  margin-bottom:0.25rem;
  letter-spacing:.04em;
}

/* Comments timeline */
.lb-comments-view{
  max-height: 380px;
  overflow: auto;
  padding-right: 4px;
}
.lb-comment-item{
  border:1px solid var(--border);
  border-radius:10px;
  padding:10px 12px;
  margin-bottom:8px;
  background:#fff;
}
.lb-comment-meta{
  color:var(--muted);
  font-size:0.78rem;
  margin-bottom:6px;
}
.lb-comment-text{
  color:#0f172a;
  font-size:0.9rem;
  line-height:1.35;
  white-space:pre-wrap;
  word-wrap:break-word;
}
</style>
""",
    unsafe_allow_html=True,
)


def card_open(title: str, tone: str, dot_color: str, subtitle: Optional[str] = None):
    st.markdown(
        f"""
        <div class="lb-card {tone}">
          <div class="lb-card-header">
            <div class="lb-dot" style="background:{dot_color};"></div>
            <div>
              <div class="lb-title">{title}</div>
              {"<div class='lb-subtitle'>" + subtitle + "</div>" if subtitle else ""}
            </div>
          </div>
        """,
        unsafe_allow_html=True,
    )


def card_close():
    st.markdown("</div>", unsafe_allow_html=True)


def kpi_circles_html(total: int, interested: int, not_interested: int, closed: int, brokerage: float) -> str:
    brok = f"₹{brokerage:,.0f}" if brokerage else "₹0"
    return f"""
    <div class="kpi-row">
      <div class="kpi-wrap kpi-total">
        <div class="kpi-circle"><div class="kpi-val">{total}</div></div>
        <div class="kpi-label">TOTAL LEADS</div>
      </div>
      <div class="kpi-wrap kpi-int">
        <div class="kpi-circle"><div class="kpi-val">{interested}</div></div>
        <div class="kpi-label">INTERESTED</div>
      </div>
      <div class="kpi-wrap kpi-nint">
        <div class="kpi-circle"><div class="kpi-val">{not_interested}</div></div>
        <div class="kpi-label">NOT INTERESTED</div>
      </div>
      <div class="kpi-wrap kpi-closed">
        <div class="kpi-circle"><div class="kpi-val">{closed}</div></div>
        <div class="kpi-label">CLOSED</div>
      </div>
      <div class="kpi-wrap kpi-brok">
        <div class="kpi-circle"><div class="kpi-val" style="font-size:1.08rem">{brok}</div></div>
        <div class="kpi-label">BROKERAGE RECEIVED</div>
      </div>
    </div>
    """


def comments_view_html(notes: list[dict]) -> str:
    if not notes:
        return '<div class="lb-comments-view"><div class="lb-comment-text">No comments available for this lead.</div></div>'

    rows = []
    for n in notes:
        txt = str(n.get("text") or "").strip()
        if not txt:
            continue
        created_at = n.get("createdAt")
        created_by = n.get("createdBy")
        who = "System"
        if isinstance(created_by, dict):
            who = created_by.get("displayName") or created_by.get("email") or "User"

        if isinstance(created_at, datetime):
            ts = created_at.astimezone(IST).strftime("%d %b %Y, %I:%M %p IST")
        else:
            ts = "Unknown time"

        rows.append(
            f"""
            <div class="lb-comment-item">
              <div class="lb-comment-meta">{who} • {ts}</div>
              <div class="lb-comment-text">{txt}</div>
            </div>
            """
        )

    if not rows:
        return '<div class="lb-comments-view"><div class="lb-comment-text">No comments available for this lead.</div></div>'

    return f'<div class="lb-comments-view">{"".join(rows)}</div>'


# -----------------------
# DB helpers
# -----------------------
@st.cache_resource(show_spinner=False)
def get_mongo_client() -> MongoClient:
    uri = st.secrets.get(SECRET_KEY_LEADS) or os.environ.get("MONGO_URI_LEADS")
    if not uri:
        raise RuntimeError(
            f"Missing Mongo URI. Set Streamlit secret '{SECRET_KEY_LEADS}' or env MONGO_URI_LEADS."
        )
    return MongoClient(uri, serverSelectionTimeoutMS=6000)


def db():
    return get_mongo_client()[DB_NAME]


def leads_col():
    return db()[COLL_LEADS]


def clear_db_cache():
    get_mongo_client.clear()


def db_status_pill(ok: bool, detail: str):
    color = "#16a34a" if ok else "#dc2626"
    bg = "#ecfdf3" if ok else "#fef2f2"
    txt = f"DB: {'Connected' if ok else 'Not Connected'}"
    st.markdown(
        f"""
        <div style="
            border:1px solid rgba(15,23,42,0.08);
            border-radius:10px;padding:8px 10px;margin:4px 0 10px 0;
            background:{bg};font-size:0.82rem;">
          <span style="
            display:inline-block;width:8px;height:8px;border-radius:999px;
            background:{color};margin-right:7px;vertical-align:middle;"></span>
          <span style="font-weight:700;color:#0f172a;">{txt}</span>
          <div style="color:#64748b;margin-top:3px;">{detail}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def check_db_and_init() -> tuple[bool, str]:
    try:
        client = get_mongo_client()
        client.admin.command("ping")
        ensure_indexes()
        return True, f"{DB_NAME}.{COLL_LEADS}"
    except Exception as e:
        return False, str(e)


def month_bounds_utc(year: int, month: int) -> tuple[datetime, datetime]:
    start_ist = datetime(year, month, 1, 0, 0, 0, tzinfo=IST)
    if month == 12:
        end_ist = datetime(year + 1, 1, 1, 0, 0, 0, tzinfo=IST)
    else:
        end_ist = datetime(year, month + 1, 1, 0, 0, 0, tzinfo=IST)
    return start_ist.astimezone(timezone.utc), end_ist.astimezone(timezone.utc)


def make_lead_id(serial: int, lead_date_ist: datetime) -> str:
    mmm = MONTHS[lead_date_ist.month - 1]
    yy = str(lead_date_ist.year)[-2:]
    return f"{LEAD_ID_PREFIX}{serial:02d}{mmm}{yy}"


def next_serial_for_month(lead_date_ist: datetime) -> int:
    col = leads_col()
    start_utc, end_utc = month_bounds_utc(lead_date_ist.year, lead_date_ist.month)

    docs = list(
        col.find({"leadDate": {"$gte": start_utc, "$lt": end_utc}}, {"legacyNumber": 1})
    )

    max_legacy = 0
    for d in docs:
        n = d.get("legacyNumber")
        if isinstance(n, int) and n > max_legacy:
            max_legacy = n

    return max_legacy + 1


def lead_id_from_existing_or_new(target_lead_date_ist: datetime, existing_lead_id: Optional[str]) -> tuple[str, int]:
    if not existing_lead_id:
        serial = next_serial_for_month(target_lead_date_ist)
        return make_lead_id(serial, target_lead_date_ist), serial

    mmm = MONTHS[target_lead_date_ist.month - 1]
    yy = str(target_lead_date_ist.year)[-2:]
    suffix = f"{mmm}{yy}"

    if existing_lead_id.upper().endswith(suffix):
        return existing_lead_id, -1

    serial = next_serial_for_month(target_lead_date_ist)
    return make_lead_id(serial, target_lead_date_ist), serial


def ensure_indexes():
    col = leads_col()
    existing = set(col.index_information().keys())
    if "uniq_leadId" not in existing:
        col.create_index([("leadId", ASCENDING)], unique=True, name="uniq_leadId")
    if "idx_leadDate" not in existing:
        col.create_index([("leadDate", ASCENDING)], name="idx_leadDate")
    if "idx_leadStatus" not in existing:
        col.create_index([("leadStatus", ASCENDING)], name="idx_leadStatus")


# -----------------------
# Misc utils
# -----------------------
def safe_get(d: dict, path: str, default=None):
    cur = d
    for k in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def parse_money(x: Any) -> Optional[float]:
    if x is None:
        return None
    s = str(x).strip()
    if not s:
        return None
    s = re.sub(r"[,\s₹$]", "", s)
    try:
        return float(s)
    except Exception:
        return None


@st.cache_data(show_spinner=False, ttl=60)
def product_suggestions() -> list[str]:
    col = leads_col()
    vals = col.distinct("productType")
    vals = [v.strip() for v in vals if isinstance(v, str) and v.strip()]
    merged = sorted(set(DEFAULT_PRODUCT_TYPES + vals), key=lambda s: s.lower())
    return merged


@st.cache_data(show_spinner=False, ttl=60)
def allocated_to_suggestions() -> list[str]:
    col = leads_col()
    vals = col.distinct("allocatedTo.displayName")
    vals = [v.strip() for v in vals if isinstance(v, str) and v.strip()]
    return sorted(set(vals), key=lambda s: s.lower())


@st.cache_data(show_spinner=False, ttl=30)
def month_lead_counts(year: int) -> dict[int, int]:
    col = leads_col()
    start_ist = datetime(year, 1, 1, tzinfo=IST)
    end_ist = datetime(year + 1, 1, 1, tzinfo=IST)

    pipeline = [
        {"$match": {"leadDate": {"$gte": start_ist.astimezone(timezone.utc), "$lt": end_ist.astimezone(timezone.utc)}}},
        {"$addFields": {"leadDateIST": {"$dateToParts": {"date": "$leadDate", "timezone": "Asia/Kolkata"}}}},
        {"$group": {"_id": "$leadDateIST.month", "count": {"$sum": 1}}},
    ]
    out = {m: 0 for m in range(1, 13)}
    for row in col.aggregate(pipeline):
        m = int(row["_id"])
        out[m] = int(row["count"])
    return out


@st.cache_data(show_spinner=False, ttl=60)
def earliest_year_available() -> int:
    col = leads_col()
    doc = list(col.find({}, {"leadDate": 1}).sort([("leadDate", ASCENDING)]).limit(1))
    if not doc:
        return datetime.now(IST).year
    dt = doc[0].get("leadDate")
    if not isinstance(dt, datetime):
        return datetime.now(IST).year
    return dt.astimezone(IST).year


@st.cache_data(show_spinner=False, ttl=30)
def month_series_counts_df() -> pd.DataFrame:
    col = leads_col()
    start_utc = datetime(2020, 1, 1, tzinfo=timezone.utc)
    end_utc = datetime(2101, 1, 1, tzinfo=timezone.utc)

    pipeline = [
        {"$match": {"leadDate": {"$gte": start_utc, "$lt": end_utc}}},
        {"$addFields": {"leadDateIST": {"$dateToParts": {"date": "$leadDate", "timezone": "Asia/Kolkata"}}}},
        {"$group": {"_id": {"y": "$leadDateIST.year", "m": "$leadDateIST.month"}, "count": {"$sum": 1}}},
        {"$sort": {"_id.y": 1, "_id.m": 1}},
    ]
    rows = []
    for r in col.aggregate(pipeline):
        y = int(r["_id"]["y"])
        m = int(r["_id"]["m"])
        c = int(r["count"])
        rows.append({"year": y, "month": m, "count": c})

    if not rows:
        return pd.DataFrame(columns=["date", "count", "label"])

    df = pd.DataFrame(rows)
    df["date"] = pd.to_datetime(df["year"].astype(str) + "-" + df["month"].astype(str) + "-01")
    df["label"] = df["date"].dt.strftime("%b %Y")
    return df.sort_values("date").reset_index(drop=True)


def plot_month_series(df: pd.DataFrame) -> go.Figure:
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=df["date"],
            y=df["count"],
            mode="lines+markers",
            line=dict(color="#2d448d", width=2),
            marker=dict(size=7, color="#00aeef"),
            hovertemplate="%{x|%b %Y}<br>Leads: %{y}<extra></extra>",
            name="Leads",
        )
    )
    fig.update_layout(
        margin=dict(l=20, r=20, t=20, b=20),
        height=290,
        xaxis=dict(title="", tickformat="%b\n%Y", showgrid=False),
        yaxis=dict(title="", rangemode="tozero", gridcolor="rgba(15,23,42,0.08)"),
        plot_bgcolor="white",
        paper_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
    )
    return fig


# -----------------------
# Query + transforms
# -----------------------
def build_query(filters: dict) -> dict:
    q: dict[str, Any] = {}

    if filters["status"] and filters["status"] != "all":
        q["leadStatus"] = normalize_lead_status(filters["status"])

    if filters["allocatedTo"] and filters["allocatedTo"] != "all":
        q["allocatedTo.displayName"] = filters["allocatedTo"]

    if filters["month_mode"] == "month":
        start_utc, end_utc = month_bounds_utc(filters["month_year"], filters["month_num"])
        q["leadDate"] = {"$gte": start_utc, "$lt": end_utc}

    s = (filters.get("search") or "").strip()
    if s:
        rx = re.compile(re.escape(s), re.IGNORECASE)
        q["$or"] = [
            {"leadId": rx},
            {"contactName": rx},
            {"companyName": rx},
            {"contactEmail": rx},
            {"contactPhone": rx},
            {"allocatedTo.displayName": rx},
        ]

    return q


def fetch_leads(filters: dict) -> list[dict]:
    col = leads_col()
    q = build_query(filters)
    docs = list(col.find(q).sort([("leadDate", DESCENDING)]))
    return docs


def compute_kpis_from_docs(docs: list[dict]) -> dict:
    total = len(docs)
    interested = sum(1 for d in docs if (d.get("leadStatus") or "").lower() == "interested")
    not_interested = sum(1 for d in docs if (d.get("leadStatus") or "").lower() == "not interested")
    closed = sum(1 for d in docs if (d.get("leadStatus") or "").lower() == "closed")
    total_brokerage = sum(parse_money(d.get("brokerageReceived")) or 0 for d in docs)

    return {
        "total": total,
        "interested": interested,
        "not_interested": not_interested,
        "closed": closed,
        "total_brokerage": total_brokerage,
    }


def compute_kpis_from_db(filters: dict) -> dict:
    col = leads_col()
    q = build_query(filters)
    total = col.count_documents(q)
    interested = col.count_documents({**q, "leadStatus": "interested"})
    not_interested = col.count_documents({**q, "leadStatus": "not interested"})
    closed = col.count_documents({**q, "leadStatus": "closed"})

    # brokerage sum
    docs = list(col.find(q, {"brokerageReceived": 1}))
    total_brokerage = 0.0
    for d in docs:
        total_brokerage += parse_money(d.get("brokerageReceived")) or 0.0

    return {
        "total": total,
        "interested": interested,
        "not_interested": not_interested,
        "closed": closed,
        "total_brokerage": total_brokerage,
    }


# -----------------------
# CRUD
# -----------------------
def update_lead(_id: ObjectId, updates: dict):
    col = leads_col()
    updates["updatedAt"] = datetime.now(timezone.utc)
    col.update_one({"_id": _id}, {"$set": updates})


def add_note(_id: ObjectId, text: str, created_by: Optional[dict] = None):
    col = leads_col()
    note = {
        "_id": ObjectId(),
        "text": text,
        "createdBy": created_by or {"userId": None, "displayName": "System", "email": None},
        "createdAt": datetime.now(timezone.utc),
    }
    col.update_one({"_id": _id}, {"$push": {"notes": note}, "$set": {"updatedAt": datetime.now(timezone.utc)}})


def create_lead(payload: dict) -> ObjectId:
    col = leads_col()

    lead_date: date_type = payload["leadDate"]
    lead_date_local = datetime(lead_date.year, lead_date.month, lead_date.day, 0, 0, 0, tzinfo=IST)

    serial = next_serial_for_month(lead_date_local)
    lead_id = make_lead_id(serial, lead_date_local)

    doc = {
        "leadId": lead_id,
        "legacyNumber": serial,
        "leadDate": lead_date_local.astimezone(timezone.utc),
        "companyName": payload.get("companyName"),
        "contactName": payload.get("contactName"),
        "contactEmail": payload.get("contactEmail"),
        "contactPhone": payload.get("contactPhone"),
        "productType": payload.get("productType"),
        "leadStatus": normalize_lead_status(payload.get("leadStatus") or "Fresh") or "fresh",
        "allocatedTo": {
            "displayName": payload.get("allocatedToDisplayName"),
            "userId": None,
            "email": None,
        },
        "brokerageReceived": payload.get("brokerageReceived"),
        "notes": [],
        "createdAt": datetime.now(timezone.utc),
        "updatedAt": datetime.now(timezone.utc),
    }

    initial_comment = (payload.get("comment") or "").strip()
    if initial_comment:
        doc["notes"] = [{
            "_id": ObjectId(),
            "text": initial_comment,
            "createdBy": {"userId": None, "displayName": "System", "email": None},
            "createdAt": datetime.now(timezone.utc),
        }]

    try:
        res = col.insert_one(doc)
        return res.inserted_id
    except DuplicateKeyError:
        # Retry once with next serial
        serial = next_serial_for_month(lead_date_local)
        doc["legacyNumber"] = serial
        doc["leadId"] = make_lead_id(serial, lead_date_local)
        res = col.insert_one(doc)
        return res.inserted_id


# -----------------------
# Migration utility (one-time) - KEEP, but no UI button
# -----------------------
def parse_legacy_number_from_lead_id(lead_id: str) -> Optional[int]:
    """
    Expects format like SL01JAN26
    Returns 1 for '01', etc.
    """
    if not lead_id or not isinstance(lead_id, str):
        return None
    m = re.match(rf"^{LEAD_ID_PREFIX}(\d{{2}})[A-Z]{{3}}\d{{2}}$", lead_id.strip().upper())
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def migrate_set_legacy_numbers(batch_size: int = 500) -> tuple[int, int, int]:
    """
    Backfill legacyNumber for docs where missing/null using leadId pattern.
    Returns: (matched, modified, failed)
    """
    col = leads_col()
    q = {
        "$or": [
            {"legacyNumber": {"$exists": False}},
            {"legacyNumber": None},
        ]
    }

    matched = col.count_documents(q)
    cursor = col.find(q, {"_id": 1, "leadId": 1})

    ops: list[UpdateOne] = []
    modified = 0
    failed = 0

    for d in cursor:
        lid = d.get("leadId")
        num = parse_legacy_number_from_lead_id(lid)
        if num is None:
            failed += 1
            continue
        ops.append(UpdateOne({"_id": d["_id"]}, {"$set": {"legacyNumber": num}}))
        if len(ops) >= batch_size:
            try:
                res = col.bulk_write(ops, ordered=False)
                modified += int(res.modified_count)
            except BulkWriteError:
                failed += len(ops)
            ops = []

    if ops:
        try:
            res = col.bulk_write(ops, ordered=False)
            modified += int(res.modified_count)
        except BulkWriteError:
            failed += len(ops)

    return matched, modified, failed


# -----------------------
# DB status
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
                "Phone": d.get("contactPhone") or "—",
                "Email": d.get("contactEmail") or "—",
                "Allocated To": safe_get(d, "allocatedTo.displayName") or "—",
                "Status": denormalize_lead_status(d.get("leadStatus")) or "—",
            }
            for idx, d in enumerate(leads)
        ])

        selection_event = st.dataframe(
            df_table,
            use_container_width=True,
            hide_index=True,
            height=390,
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
