from __future__ import annotations

from datetime import datetime, timezone, date as date_type
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo
import base64
import hmac
import importlib
import hashlib
from io import BytesIO
import os
import re
import secrets
import string

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as st_components
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
COLL_ARCHIVE = "lead-archive"
SECRET_KEY_LEADS = "mongo_uri_leads"  # Streamlit secrets key
LOGO_URL = "https://ik.imagekit.io/salasarservices/Salasar-Logo-new.png?updatedAt=1771587668127"

PDFIUM_AVAILABLE = importlib.util.find_spec("pypdfium2") is not None
pdfium = importlib.import_module("pypdfium2") if PDFIUM_AVAILABLE else None
APP_DIR = Path(__file__).resolve().parent


LEAD_ID_PREFIX = "SL"
SUPER_ADMIN_USERNAME = "sallead"
INACTIVITY_TIMEOUT_SECONDS = 30 * 60

# -----------------------
# RBAC
# -----------------------
ROLE_ADMIN   = "admin"
ROLE_MANAGER = "manager"
ROLE_VIEWER  = "viewer"

VALID_ROLES = [ROLE_ADMIN, ROLE_MANAGER, ROLE_VIEWER]

def current_role() -> str:
    """Return the role of the currently logged-in user."""
    if st.session_state.get("is_super_admin"):
        return ROLE_ADMIN
    return str(st.session_state.get("user_role") or ROLE_VIEWER).lower()

def is_admin() -> bool:
    return current_role() == ROLE_ADMIN

def is_manager_or_above() -> bool:
    return current_role() in {ROLE_ADMIN, ROLE_MANAGER}

def is_viewer_only() -> bool:
    return current_role() == ROLE_VIEWER

def require_role(minimum_role: str) -> None:
    """Stop execution if user doesn't meet the minimum role requirement."""
    hierarchy = {ROLE_ADMIN: 3, ROLE_MANAGER: 2, ROLE_VIEWER: 1}
    if hierarchy.get(current_role(), 0) < hierarchy.get(minimum_role, 99):
        st.error("Access denied: insufficient permissions.")
        st.stop()


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
    """Legacy SHA-256 — only used for migrating old hashes."""
    return hashlib.sha256((password or "").encode("utf-8")).hexdigest()


def hash_password_secure(password: str) -> str:
    """Industry-standard: scrypt with a random 16-byte salt, stored as salt$hash (hex)."""
    salt = secrets.token_hex(16)
    dk = hashlib.scrypt((password or "").encode("utf-8"), salt=salt.encode(), n=16384, r=8, p=1)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verify against scrypt hash (salt$hash) or fall back to legacy SHA-256."""
    if not stored:
        return False
    if "$" in stored:
        try:
            salt, dk_hex = stored.split("$", 1)
            dk = hashlib.scrypt((password or "").encode("utf-8"), salt=salt.encode(), n=16384, r=8, p=1)
            return hmac.compare_digest(dk.hex(), dk_hex)
        except Exception:
            return False
    # Legacy SHA-256 fallback
    return hmac.compare_digest(stored, hash_password(password))


def check_db_user_login(username: str, password: str) -> Optional[str]:
    """Returns the user's role string if login succeeds, else None."""
    uname = (username or "").strip().lower()
    pwd = password or ""
    if not uname or not pwd:
        return None

    col = users_col_for_login()
    if col is None:
        return None

    doc = col.find_one(
        {"username": uname, "isActive": {"$ne": False}},
        {"passwordHash": 1, "role": 1}
    )
    if not doc:
        return None

    stored = str(doc.get("passwordHash") or "")
    if not verify_password(pwd, stored):
        return None

    # Auto-migrate legacy SHA-256 hash to scrypt on successful login
    if "$" not in stored:
        col.update_one(
            {"username": uname},
            {"$set": {"passwordHash": hash_password_secure(pwd), "updatedAt": now_utc()}}
        )

    role = str(doc.get("role") or ROLE_MANAGER).lower()
    return role if role in VALID_ROLES else ROLE_MANAGER


def logout_user(reason: str = "You have been logged out.") -> None:
    st.session_state.clear()
    st.session_state["logout_notice"] = reason
    st.session_state["_clear_storage"] = True
    st.rerun()


def restore_login_from_storage() -> None:
    """Restore session from query params written by localStorage JS bridge."""
    # If already authenticated, nothing to do
    if st.session_state.get("authenticated") is True:
        return

    # Step 2: query params have been set by the JS bridge — restore session
    user = st.query_params.get("_lb_user", "")
    admin = st.query_params.get("_lb_admin", "0")
    ts = st.query_params.get("_lb_ts", "")

    if user:
        # Validate inactivity before restoring
        try:
            last_ts = float(ts)
            elapsed = datetime.now(timezone.utc).timestamp() - last_ts
            if elapsed >= INACTIVITY_TIMEOUT_SECONDS:
                st.query_params.clear()
                return
        except (ValueError, TypeError):
            st.query_params.clear()
            return

        st.session_state["authenticated"] = True
        st.session_state["logged_in_user"] = user
        st.session_state["is_super_admin"] = admin == "1"
        st.session_state["last_activity_ts"] = datetime.now(timezone.utc).timestamp()
        st.query_params.clear()
        return

    # Step 1: not authenticated, not from params — inject JS bridge to read localStorage
    # and set query params (no redirect, uses history.replaceState)
    if not st.session_state.get("_storage_checked"):
        st.session_state["_storage_checked"] = True
        st_components.html("""
<script>
(function() {
  try {
    var s = localStorage.getItem('lb_session');
    if (!s) return;
    var d = JSON.parse(s);
    if (!d.user) return;
    var ts = d.ts || '0';
    var elapsed = (Date.now() / 1000) - parseFloat(ts);
    if (elapsed >= 1800) { localStorage.removeItem('lb_session'); return; }
    var url = new URL(window.parent.location.href);
    url.searchParams.set('_lb_user', d.user);
    url.searchParams.set('_lb_admin', d.admin ? '1' : '0');
    url.searchParams.set('_lb_ts', ts);
    window.parent.location.href = url.toString();
  } catch(e) {}
})();
</script>
""", height=0)


def persist_login_to_storage() -> None:
    """Save session to localStorage on every authenticated render."""
    # Clear storage on logout
    if st.session_state.pop("_clear_storage", False):
        st_components.html(
            "<script>try{localStorage.removeItem('lb_session');}catch(e){}</script>",
            height=0,
        )
        return

    if st.session_state.get("authenticated") is not True:
        return

    user = st.session_state.get("logged_in_user", "")
    admin = "true" if st.session_state.get("is_super_admin") else "false"
    ts = str(st.session_state.get("last_activity_ts", datetime.now(timezone.utc).timestamp()))
    st_components.html(f"""
<script>
(function() {{
  try {{
    localStorage.setItem('lb_session', JSON.stringify({{
      user: '{user}',
      admin: {admin},
      ts: '{ts}'
    }}));
  }} catch(e) {{}}
}})();
</script>
""", height=0)


_LOADER_CSS = """
<style>
.loader {
  width: 24px;
  height: 80px;
  display: block;
  margin: 35px auto 0;
  border: 1px solid #FFF;
  border-radius: 0 0 50px 50px;
  position: relative;
  box-shadow: 0px 0px #FF3D00 inset;
  background-image: linear-gradient(#FF3D00 100px, transparent 0);
  background-position: 0px 0px;
  background-size: 22px 80px;
  background-repeat: no-repeat;
  box-sizing: border-box;
  animation: animloader 6s linear infinite;
}
.loader::after {
  content: '';
  box-sizing: border-box;
  top: -6px;
  left: 50%;
  transform: translateX(-50%);
  position: absolute;
  border: 1px solid #FFF;
  border-radius: 50%;
  width: 28px;
  height: 6px;
}
.loader::before {
  content: '';
  box-sizing: border-box;
  left: 0;
  bottom: -4px;
  border-radius: 50%;
  position: absolute;
  width: 6px;
  height: 6px;
  animation: animloader1 6s linear infinite;
}
@keyframes animloader {
  0%   { background-position: 0px 80px; }
  100% { background-position: 0px 0px; }
}
@keyframes animloader1 {
  0%   { box-shadow: 4px -10px rgba(255,255,255,0), 6px 0px rgba(255,255,255,0), 8px -15px rgba(255,255,255,0), 12px 0px rgba(255,255,255,0); }
  20%  { box-shadow: 4px -20px rgba(255,255,255,0), 8px -10px rgba(255,255,255,0), 10px -30px rgba(255,255,255,0.5), 15px -5px rgba(255,255,255,0); }
  40%  { box-shadow: 2px -40px rgba(255,255,255,0.5), 8px -30px rgba(255,255,255,0.4), 8px -60px rgba(255,255,255,0.5), 12px -15px rgba(255,255,255,0.5); }
  60%  { box-shadow: 4px -60px rgba(255,255,255,0.5), 6px -50px rgba(255,255,255,0.4), 10px -90px rgba(255,255,255,0.5), 15px -25px rgba(255,255,255,0.5); }
  80%  { box-shadow: 2px -80px rgba(255,255,255,0.5), 4px -70px rgba(255,255,255,0.4), 8px -120px rgba(255,255,255,0), 12px -35px rgba(255,255,255,0.5); }
  100% { box-shadow: 4px -100px rgba(255,255,255,0), 8px -90px rgba(255,255,255,0), 10px -120px rgba(255,255,255,0), 15px -45px rgba(255,255,255,0); }
}
</style>
"""

_LOADER_HTML = """
<div id="lb-db-loader" style="
  position:fixed;top:0;left:0;width:100%;height:100%;
  background:rgba(15,23,42,0.45);
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  z-index:99999;backdrop-filter:blur(2px);">
  <div class="loader"></div>
  <div style="margin-top:18px;color:#fff;font-size:0.85rem;font-weight:700;
    letter-spacing:0.08em;text-transform:uppercase;opacity:0.85;">
    {label}
  </div>
</div>
"""


from contextlib import contextmanager

@contextmanager
def db_loader(label: str = "Please wait..."):
    """Show custom CSS loader overlay while a DB operation runs, then clear it."""
    st.markdown(_LOADER_CSS, unsafe_allow_html=True)
    placeholder = st.empty()
    placeholder.markdown(_LOADER_HTML.format(label=label), unsafe_allow_html=True)
    try:
        yield
    finally:
        placeholder.empty()


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
            st.session_state["user_role"] = ROLE_ADMIN if username.lower() == SUPER_ADMIN_USERNAME else ROLE_MANAGER
            st.session_state["last_activity_ts"] = datetime.now(timezone.utc).timestamp()
            st.rerun()
        else:
            role = check_db_user_login(username, p)
            if role is not None:
                st.session_state["authenticated"] = True
                st.session_state["logged_in_user"] = username.lower()
                st.session_state["is_super_admin"] = False
                st.session_state["user_role"] = role
                st.session_state["last_activity_ts"] = datetime.now(timezone.utc).timestamp()
                st.rerun()
            else:
                st.error("Invalid username or password.")

    st.stop()


restore_login_from_storage()
login_gate()
persist_login_to_storage()



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
def load_app_styles() -> None:
    styles_path = APP_DIR / "streamlit" / "styles.css"
    css = styles_path.read_text(encoding="utf-8")
    if hasattr(st, "html"):
        st.html(f"<style>{css}</style>")
        return
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


load_app_styles()


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


def render_pdf_preview_image(file_bytes: bytes, file_name: str) -> bool:
    if not PDFIUM_AVAILABLE or pdfium is None:
        return False

    try:
        pdf = pdfium.PdfDocument(file_bytes)
        page = pdf[0]
        bitmap = page.render(scale=1.5).to_pil()
        buffer = BytesIO()
        bitmap.save(buffer, format="WEBP", quality=90)
        st.image(buffer.getvalue(), caption=f"{file_name} • preview", use_container_width=True)
        return True
    except Exception:
        return False


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
        if not render_pdf_preview_image(file_bytes, file_name):
            st.pdf(file_bytes, width="stretch", height=640)
            st.caption("Preview fallback: native PDF viewer shown because image conversion was unavailable.")
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
    conversion = f"{(closed / total * 100):.1f}%" if total > 0 else "0%"
    return f"""
<div class="kpi-row" style="display:flex;gap:12px;padding:10px 2px 6px 2px;align-items:flex-start;">
  <div class="kpi-wrap" style="flex:1;display:flex;flex-direction:column;align-items:center;">
    <div class="kpi" style="background:var(--pastel-navy);width:100%;height:95px;border-radius:1px;border:1px solid var(--border);box-shadow:var(--shadow);display:flex;align-items:center;justify-content:center;">
      <div class="kpi-inner" style="text-align:center;padding:8px;">
        <div class="kpi-number navy" data-target="{total}" data-type="int" style="font-size:1.9rem;font-weight:900;color:#fff;">0</div>
        <div class="kpi-sub" style="margin-top:4px;font-size:0.78rem;color:#fff;text-transform:uppercase;letter-spacing:0.06em;font-weight:900;">Total Leads</div>
      </div>
    </div>
  </div>

  <div class="kpi-wrap" style="flex:1;display:flex;flex-direction:column;align-items:center;">
    <div class="kpi" style="background:var(--pastel-lime);width:100%;height:95px;border-radius:1px;border:1px solid var(--border);box-shadow:var(--shadow);display:flex;align-items:center;justify-content:center;">
      <div class="kpi-inner" style="text-align:center;padding:8px;">
        <div class="kpi-number lime" data-target="{interested}" data-type="int" style="font-size:1.9rem;font-weight:900;color:#fff;">0</div>
        <div class="kpi-sub" style="margin-top:4px;font-size:0.78rem;color:#fff;text-transform:uppercase;letter-spacing:0.06em;font-weight:900;">Interested</div>
      </div>
    </div>
  </div>

  <div class="kpi-wrap" style="flex:1;display:flex;flex-direction:column;align-items:center;">
    <div class="kpi" style="background:#FF5252;width:100%;height:95px;border-radius:1px;border:1px solid var(--border);box-shadow:var(--shadow);display:flex;align-items:center;justify-content:center;">
      <div class="kpi-inner" style="text-align:center;padding:8px;">
        <div class="kpi-number" data-target="{not_interested}" data-type="int" style="font-size:1.9rem;font-weight:900;color:#fff;">0</div>
        <div class="kpi-sub" style="margin-top:4px;font-size:0.78rem;color:#fff;text-transform:uppercase;letter-spacing:0.06em;font-weight:900;">Lost</div>
      </div>
    </div>
  </div>

  <div class="kpi-wrap" style="flex:1;display:flex;flex-direction:column;align-items:center;">
    <div class="kpi" style="background:#8BBA29;width:100%;height:95px;border-radius:1px;border:1px solid var(--border);box-shadow:var(--shadow);display:flex;align-items:center;justify-content:center;">
      <div class="kpi-inner" style="text-align:center;padding:8px;">
        <div class="kpi-number cyan" data-target="{closed}" data-type="int" style="font-size:1.9rem;font-weight:900;color:#fff;">0</div>
        <div class="kpi-sub" style="margin-top:4px;font-size:0.78rem;color:#fff;text-transform:uppercase;letter-spacing:0.06em;font-weight:900;">Closed</div>
      </div>
    </div>
  </div>

  <div class="kpi-wrap" style="flex:1;display:flex;flex-direction:column;align-items:center;">
    <div class="kpi" style="background:#536DFE;width:100%;height:95px;border-radius:1px;border:1px solid var(--border);box-shadow:var(--shadow);display:flex;align-items:center;justify-content:center;">
      <div class="kpi-inner" style="text-align:center;padding:8px;">
        <div class="kpi-number" data-target="{brok}" data-type="text" style="font-size:1.9rem;font-weight:900;color:#fff;">-</div>
        <div class="kpi-sub" style="margin-top:4px;font-size:0.78rem;color:#fff;text-transform:uppercase;letter-spacing:0.06em;font-weight:900;">Total Brokerage</div>
      </div>
    </div>
  </div>

  <div class="kpi-wrap" style="flex:1;display:flex;flex-direction:column;align-items:center;">
    <div class="kpi" style="background:#7C4DFF;width:100%;height:95px;border-radius:1px;border:1px solid var(--border);box-shadow:var(--shadow);display:flex;align-items:center;justify-content:center;">
      <div class="kpi-inner" style="text-align:center;padding:8px;">
        <div class="kpi-number" data-target="{conversion}" data-type="percent" style="font-size:1.9rem;font-weight:900;color:#fff;">0%</div>
        <div class="kpi-sub" style="margin-top:4px;font-size:0.78rem;color:#fff;text-transform:uppercase;letter-spacing:0.06em;font-weight:900;">Conversion Rate</div>
      </div>
    </div>
  </div>
</div>
"""


def kpi_counter_script(total: int, interested: int, not_interested: int, closed: int, total_brokerage: float):
    brok = format_inr_compact(total_brokerage)
    conversion = f"{(closed / total * 100):.1f}%" if total > 0 else "0%"
    return f"""
<script>
(function() {{
  function animateCounters() {{
    var root = window.parent.document;
    var els = root.querySelectorAll('.kpi-number[data-target]');
    els.forEach(function(el) {{
      var type = el.getAttribute('data-type');
      var target = el.getAttribute('data-target');
      if (type === 'text') {{
        setTimeout(function() {{
          el.style.transition = 'opacity 0.6s ease';
          el.style.opacity = '0';
          setTimeout(function() {{
            el.textContent = target;
            el.style.opacity = '1';
          }}, 300);
        }}, 200);
        return;
      }}
      var endVal = parseFloat(type === 'percent' ? target.replace('%','') : target);
      var duration = 1200;
      var startTime = null;
      var suffix = type === 'percent' ? '%' : '';
      var decimals = type === 'percent' ? 1 : 0;
      function step(timestamp) {{
        if (!startTime) startTime = timestamp;
        var progress = Math.min((timestamp - startTime) / duration, 1);
        var ease = 1 - Math.pow(1 - progress, 3);
        var current = endVal * ease;
        el.textContent = current.toFixed(decimals) + suffix;
        if (progress < 1) requestAnimationFrame(step);
        else el.textContent = target;
      }}
      requestAnimationFrame(step);
    }});
  }}
  setTimeout(animateCounters, 300);
}})();
</script>
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
    """Admins can archive/delete leads. Managers can delete comments."""
    return is_admin()

def can_delete_comments() -> bool:
    return is_manager_or_above()

def can_edit_leads() -> bool:
    return is_manager_or_above()

def can_create_leads() -> bool:
    return is_manager_or_above()


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


def create_dashboard_user(username: str, password: str, role: str = ROLE_MANAGER, created_by: str | None = None) -> tuple[bool, str]:
    uname = (username or "").strip().lower()
    if not uname:
        return False, "Username is required."
    if not re.fullmatch(r"[a-z0-9._-]{3,40}", uname):
        return False, "Username must be 3-40 chars: lowercase letters, numbers, dot, underscore, hyphen."
    if not password:
        return False, "Password is required."
    if role not in VALID_ROLES:
        role = ROLE_MANAGER

    col = users_col()
    doc = {
        "username": uname,
        "passwordHash": hash_password_secure(password),
        "createdAt": now_utc(),
        "updatedAt": now_utc(),
        "createdBy": (created_by or "").strip().lower() or None,
        "isActive": True,
        "role": role,
    }
    try:
        col.insert_one(doc)
        return True, f"User '{uname}' created successfully with role '{role}'."
    except DuplicateKeyError:
        return False, f"User '{uname}' already exists."


def list_dashboard_users() -> List[dict]:
    col = users_col()
    return list(
        col.find(
            {},
            {
                "username": 1,
                "isActive": 1,
                "role": 1,
                "createdAt": 1,
                "updatedAt": 1,
            },
        ).sort([("username", ASCENDING)])
    )


def set_user_role(username: str, role: str, updated_by: str | None = None) -> tuple[bool, str]:
    uname = (username or "").strip().lower()
    if not uname:
        return False, "Select a valid user."
    if role not in VALID_ROLES:
        return False, f"Invalid role. Must be one of: {', '.join(VALID_ROLES)}."
    if uname == SUPER_ADMIN_USERNAME:
        return False, "Cannot change role of super admin."
    res = users_col().update_one(
        {"username": uname},
        {"$set": {"role": role, "updatedAt": now_utc(), "updatedBy": (updated_by or "").strip().lower() or None}},
    )
    if res.matched_count == 0:
        return False, f"User '{uname}' not found."
    return True, f"Role updated to '{role}' for '{uname}'."


def deactivate_user(username: str, updated_by: str | None = None) -> tuple[bool, str]:
    uname = (username or "").strip().lower()
    if not uname:
        return False, "Select a valid user."
    if uname == SUPER_ADMIN_USERNAME:
        return False, "Cannot deactivate the super admin."
    res = users_col().update_one(
        {"username": uname},
        {"$set": {"isActive": False, "updatedAt": now_utc(), "deactivatedBy": (updated_by or "").strip().lower() or None}},
    )
    if res.matched_count == 0:
        return False, f"User '{uname}' not found."
    return True, f"User '{uname}' deactivated."


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
                "passwordHash": hash_password_secure(password),
                "updatedAt": now_utc(),
                "updatedBy": (updated_by or "").strip().lower() or None,
            },
            "$unset": {"passwordPlain": ""},
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
    suffix = f"{MONTHS[lead_date_ist.month - 1]}{str(lead_date_ist.year)[-2:]}"
    id_pattern = re.compile(rf"^{re.escape(LEAD_ID_PREFIX)}(\d+){suffix}$", re.IGNORECASE)

    max_serial = 0
    seen_ids: set[str] = set()

    docs_in_month = col.find({"leadDate": {"$gte": start_utc, "$lt": end_utc}}, {"legacyNumber": 1, "leadId": 1})
    docs_by_suffix = col.find({"leadId": {"$regex": rf"^{re.escape(LEAD_ID_PREFIX)}\d+{suffix}$", "$options": "i"}}, {"legacyNumber": 1, "leadId": 1})

    for docs in (docs_in_month, docs_by_suffix):
        for doc in docs:
            lead_id = str(doc.get("leadId") or "").upper()
            if lead_id in seen_ids:
                continue
            seen_ids.add(lead_id)

            legacy_number = doc.get("legacyNumber")
            if isinstance(legacy_number, int):
                max_serial = max(max_serial, legacy_number)

            match = id_pattern.fullmatch(lead_id)
            if match:
                max_serial = max(max_serial, int(match.group(1)))

    return max_serial + 1


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

    acol = mongo_client()[DB_NAME][COLL_ARCHIVE]
    archive_existing = acol.index_information()
    if "idx_archive_leadId" not in archive_existing:
        acol.create_index([("leadId", ASCENDING)], name="idx_archive_leadId")
    if "idx_archive_archivedAt" not in archive_existing:
        acol.create_index([("archivedAt", DESCENDING)], name="idx_archive_archivedAt")


def migrate_status_terms() -> None:
    col = leads_col()
    col.update_many({"leadStatus": {"$in": ["not interested", "not-interested", "not_interested"]}}, {"$set": {"leadStatus": "lost", "updatedAt": now_utc()}})


def check_db_and_init() -> tuple[bool, str]:
    try:
        mongo_client().admin.command("ping")
        ensure_indexes()
        migrate_status_terms()
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


def date_range_bounds_utc(start_date: date_type, end_date: date_type) -> tuple[datetime, datetime]:
    start_ist = datetime(start_date.year, start_date.month, start_date.day, 0, 0, 0, tzinfo=IST)
    end_exclusive_ist = datetime(end_date.year, end_date.month, end_date.day, 0, 0, 0, tzinfo=IST)
    end_exclusive_ist = end_exclusive_ist.replace(hour=0, minute=0, second=0, microsecond=0)
    end_exclusive_ist = end_exclusive_ist + pd.Timedelta(days=1)
    return start_ist.astimezone(timezone.utc), end_exclusive_ist.astimezone(timezone.utc)


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
    elif filters.get("month_mode") == "date range":
        start_utc, end_utc = date_range_bounds_utc(filters["range_start"], filters["range_end"])
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


def filters_are_active(filters: dict) -> bool:
    return (
        filters.get("status") != "all"
        or filters.get("allocatedTo") != "all"
        or filters.get("month_mode") in {"month", "date range"}
        or bool((filters.get("search") or "").strip())
    )


LEAD_STATUS_BADGE_STYLES: dict[str, dict[str, str]] = {
    "fresh":     {"text": "#ffffff", "bg": "#448AFF", "border": "#448AFF"},
    "allocated": {"text": "#ffffff", "bg": "#536DFE", "border": "#536DFE"},
    "interested":{"text": "#ffffff", "bg": "#11C15B", "border": "#11C15B"},
    "lost":      {"text": "#ffffff", "bg": "#FF5252", "border": "#FF5252"},
    "closed":    {"text": "#ffffff", "bg": "#8BBA29", "border": "#8BBA29"},
}


def lead_status_badge_style(value: object) -> str:
    normalized = normalize_lead_status(str(value or ""))
    palette = LEAD_STATUS_BADGE_STYLES.get(
        normalized,
        {"text": "#475569", "bg": "#e2e8f0", "border": "#cbd5e1"},
    )
    return (
        f"background-color: {palette['bg']}; "
        f"color: {palette['text']}; "
        f"border: 1px solid {palette['border']}; "
        "border-radius: 999px; "
        "font-weight: 700; "
        "text-align: center; "
        "padding: 0.45rem 0.75rem;"
    )


def style_leads_table(df_table: pd.DataFrame) -> Any:
    styler = df_table.style
    styler = styler.set_properties(
        **{
            "background-color": "#ffffff",
            "color": "#334e68",
            "border-bottom": "1px solid #e5e7eb",
            "font-size": "0.95rem",
        }
    )
    styler = styler.map(
        lambda _value: "background-color: #f8fbff;",
        subset=pd.IndexSlice[:, df_table.columns],
    )
    styler = styler.map(lead_status_badge_style, subset=["Status"])
    styler = styler.set_properties(
        subset=["Number", "Status", "Brokerage Received"],
        **{"text-align": "center"},
    )
    return styler
def build_leads_table_frames(leads: list[dict]) -> tuple[pd.DataFrame, pd.DataFrame]:
    df_table = pd.DataFrame([
        {
            "Number": idx + 1,
            "Lead ID": d.get("leadId") or "—",
            "Name": d.get("contactName") or "—",
            "Company": d.get("companyName") or "—",
            "Allocated To": allocation_chain_text(d),
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
            "Allocated To": allocation_chain_text(d).replace("—", ""),
            "Status": denormalize_lead_status(d.get("leadStatus")) or "",
            "Brokerage Received": parse_money(d.get("brokerageReceived")) or 0,
            "Net Premium": parse_money(d.get("netPremium")) or 0,
            "Phone Number": d.get("contactPhone") or "",
            "Email": d.get("contactEmail") or "",
            "Comments": " | ".join(
                [
                    str((n or {}).get("text") or "").strip()
                    for n in dedupe_notes(d.get("notes") or [])
                    if isinstance(n, dict) and str((n or {}).get("text") or "").strip()
                ]
            ),
        }
        for idx, d in enumerate(leads)
    ])
    return df_table, df_download


def render_leads_table(leads: list[dict], *, table_key: str, download_key: str, download_label: str) -> None:
    if not leads:
        st.info("No leads found.")
        return

    df_table, df_download = build_leads_table_frames(leads)
    st.download_button(
        download_label,
        data=df_download.to_csv(index=False).encode("utf-8"),
        file_name=f"{download_key}_{datetime.now(IST).strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        use_container_width=True,
        key=f"{download_key}_btn",
    )

    selection_event = st.dataframe(
        style_leads_table(df_table),
        use_container_width=True,
        hide_index=True,
        height=390,
        column_config={
            "Number": st.column_config.NumberColumn("NUMBER", width="small"),
            "Lead ID": st.column_config.TextColumn("LEAD ID", width="small"),
            "Name": st.column_config.TextColumn("NAME", width="medium"),
            "Company": st.column_config.TextColumn("COMPANY", width="medium"),
            "Allocated To": st.column_config.TextColumn("ALLOCATED TO", width="medium"),
            "Status": st.column_config.TextColumn("STATUS", width="small"),
            "Brokerage Received": st.column_config.TextColumn("BROKERAGE", width="small"),
        },
        on_select="rerun",
        selection_mode="single-row",
        key=table_key,
    )

    selected_rows = selection_event.get("selection", {}).get("rows", [])
    if selected_rows:
        selected_idx = selected_rows[0]
        if 0 <= selected_idx < len(leads):
            st.session_state["selected_lead_id"] = leads[selected_idx].get("leadId")


def compute_kpis_from_docs(docs: list[dict]) -> dict:
    total = len(docs)
    interested = sum(1 for d in docs if (d.get("leadStatus") or "").lower() == "interested")
    not_interested = sum(1 for d in docs if (d.get("leadStatus") or "").lower() in {"not interested", "lost"})
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
    not_interested = col.count_documents({**q, "leadStatus": {"$in": ["lost", "not interested"]}})
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


def update_lead(_id: ObjectId, updates: dict, push_ops: Optional[dict] = None):
    col = leads_col()
    updates["updatedAt"] = now_utc()
    update_doc: dict = {"$set": updates}
    if push_ops:
        update_doc["$push"] = push_ops
    col.update_one({"_id": _id}, update_doc)


def add_note(_id: ObjectId, text: str, created_by: Optional[str] = None):
    col = leads_col()
    note = {"text": text.strip(), "createdAt": now_utc(), "createdBy": created_by}
    col.update_one({"_id": _id}, {"$push": {"notes": note}, "$set": {"updatedAt": now_utc()}})


def archive_lead(_id: ObjectId) -> None:
    """Soft delete: copy lead to lead-archive collection, mark as archived in leads."""
    col = leads_col()
    archive_col = mongo_client()[DB_NAME][COLL_ARCHIVE]
    doc = col.find_one({"_id": _id})
    if doc:
        archived_doc = {
            **doc,
            "archivedAt": now_utc(),
            "archivedBy": current_username(),
            "originalId": doc["_id"],
        }
        archived_doc.pop("_id", None)
        archive_col.insert_one(archived_doc)
    col.update_one({"_id": _id}, {"$set": {"isArchived": True, "archivedAt": now_utc(), "archivedBy": current_username()}})


def restore_lead(archive_id: ObjectId) -> None:
    """Restore a lead from the archive back to active leads."""
    archive_col = mongo_client()[DB_NAME][COLL_ARCHIVE]
    doc = archive_col.find_one({"_id": archive_id})
    if not doc:
        return
    col = leads_col()
    original_id = doc.get("originalId")
    if original_id:
        col.update_one(
            {"_id": original_id},
            {"$unset": {"isArchived": "", "archivedAt": "", "archivedBy": ""}, "$set": {"updatedAt": now_utc()}}
        )
    archive_col.delete_one({"_id": archive_id})


def fetch_archived_leads() -> list[dict]:
    archive_col = mongo_client()[DB_NAME][COLL_ARCHIVE]
    return list(archive_col.find({}).sort([("archivedAt", DESCENDING)]))


def delete_note(_id: ObjectId, note: dict) -> None:
    col = leads_col()
    col.update_one({"_id": _id}, {"$pull": {"notes": note}, "$set": {"updatedAt": now_utc()}})


def create_lead(payload: dict) -> ObjectId:
    col = leads_col()

    lead_date: date_type = payload["leadDate"]
    lead_date_local = datetime(lead_date.year, lead_date.month, lead_date.day, 0, 0, 0, tzinfo=IST)

    initial_comment = (payload.get("comment") or "").strip() or None
    allocation_name = (payload.get("allocatedToDisplayName") or "").strip() or None
    created_by = current_username()

    doc_base = {
        "leadDate": lead_date_local.astimezone(timezone.utc),
        "companyName": payload.get("companyName") or None,
        "contactName": payload.get("contactName") or None,
        "contactEmail": payload.get("contactEmail") or None,
        "contactPhone": payload.get("contactPhone") or None,
        "productType": payload.get("productType") or None,
        "allocatedTo": {"displayName": allocation_name, "userId": None, "email": None},
        "leadStatus": normalize_lead_status(payload.get("leadStatus") or "Fresh") or "fresh",
        "brokerageReceived": payload.get("brokerageReceived", None),
        "netPremium": payload.get("netPremium", None),
        "policyCopy": payload.get("policyCopy") if normalize_lead_status(payload.get("leadStatus") or "Fresh") == "closed" else None,
        "notes": ([{"text": initial_comment, "createdAt": now_utc(), "createdBy": created_by}] if initial_comment else []),
        "allocationHistory": ([{"from": allocation_name, "to": None, "editedAt": now_utc(), "editedBy": created_by}] if allocation_name else []),
        "emailRecipients": [],
        "messageText": None,
        "schemaVersion": 4,
        "createdAt": now_utc(),
        "updatedAt": now_utc(),
    }

    for _ in range(5):
        serial = next_serial_for_month(lead_date_local)
        doc = {
            **doc_base,
            "leadId": make_lead_id(serial, lead_date_local),
            "legacyNumber": serial,
        }
        try:
            res = col.insert_one(doc)
            return res.inserted_id
        except DuplicateKeyError:
            continue

    raise DuplicateKeyError("Could not generate a unique leadId after multiple attempts.")


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
        "<div style='font-size:2rem;font-weight:800;color:#2d448d;letter-spacing:-0.02em;'>LEADBOX DASHBOARD</div>"
        "<div style='color:#64748b;margin-top:-4px;'>Lead Management System</div>",
        unsafe_allow_html=True,
    )

st.write("")

# -----------------------
# Sidebar
# -----------------------
with st.sidebar:
    db_status_pill(db_ok, db_detail)

    logged_in_user = st.session_state.get("logged_in_user") or "unknown"
    st.caption(f"Signed in as: `{logged_in_user}` · Role: `{current_role().upper()}`")
    if st.button("Logout", use_container_width=True):
        logout_user("You have been logged out.")

    if st.button("Refresh DB", use_container_width=True):
        clear_db_cache()
        st.success("DB cache cleared. Data will refresh on next interaction.")

    # ❌ Removed: Admin: Lead ID migration (no longer shown in sidebar)

    card_open("Navigation", "lb-navy", "#2d448d", subtitle="Switch between modules")
    _nav_pages = ["Leads"]
    if can_create_leads():
        _nav_pages.append("Create Lead")
    if is_admin():
        _nav_pages.append("Archived Leads")
    page = st.radio("Go to", _nav_pages, index=0, label_visibility="collapsed")
    card_close()

    allocs = allocated_to_suggestions()

    card_open("Filters", "lb-cyan", "#00aeef", subtitle="Search and segment leads")
    status = st.selectbox("Status", ["all"] + LEAD_STATUS_OPTIONS, index=0)
    allocatedTo = st.selectbox("Allocated to", ["all"] + allocs, index=0)
    search = st.text_input("Search", value="", placeholder="Lead ID, contact, company, email, phone...")
    card_close()

    card_open("Month Filters", "lb-lime", "#a6ce39", subtitle="View lead activity month-wise (IST)")
    month_mode = st.selectbox("Filter by", ["all", "month", "date range"], index=0)

    month_year = datetime.now(IST).year
    month_num = datetime.now(IST).month
    date_range_default = (datetime.now(IST).date().replace(day=1), datetime.now(IST).date())
    range_start, range_end = date_range_default

    if month_mode == "month":
        month_year = st.number_input("Year", min_value=2020, max_value=2100, value=month_year, step=1)
        counts = month_lead_counts(int(month_year))
        month_num = st.selectbox(
            "Month",
            options=list(range(1, 13)),
            index=month_num - 1,
            format_func=lambda m: f"{MONTHS[m-1]} ({counts.get(m, 0)})",
        )
    elif month_mode == "date range":
        selected_range = st.date_input(
            "Date range (IST)",
            value=date_range_default,
            help="Select a start and end date to view leads created within that IST date range.",
        )
        if isinstance(selected_range, tuple) and len(selected_range) == 2:
            range_start, range_end = selected_range
        elif isinstance(selected_range, list) and len(selected_range) == 2:
            range_start, range_end = selected_range[0], selected_range[1]
        else:
            range_start = range_end = selected_range if not isinstance(selected_range, (tuple, list)) else datetime.now(IST).date()

        if range_start > range_end:
            range_start, range_end = range_end, range_start
    card_close()
    if is_admin():
        card_open("User Management", "lb-navy", "#2d448d", subtitle="Manage users, roles and passwords")

        # --- Create New User ---
        st.markdown("**Create New User**")
        if "generated_password_create" not in st.session_state:
            st.session_state["generated_password_create"] = generate_strong_password(16)

        with st.form("create_user_form"):
            new_username = st.text_input("New Username", placeholder="e.g. team.member")
            new_role = st.selectbox("Role", [ROLE_MANAGER, ROLE_VIEWER], index=0)
            generated_password = st.session_state.get("generated_password_create") or generate_strong_password(16)
            selected_password = st.text_input(
                "Generated Strong Password",
                value=generated_password,
                help="Keep generated value or enter your own strong password.",
            )
            create_cols = st.columns(2)
            with create_cols[0]:
                refresh_generated = st.form_submit_button("Regenerate")
            with create_cols[1]:
                create_user_btn = st.form_submit_button("Add User")

        if refresh_generated:
            st.session_state["generated_password_create"] = generate_strong_password(16)
            st.rerun()

        if create_user_btn:
            ok_user, msg_user = create_dashboard_user(
                username=new_username,
                password=selected_password,
                role=new_role,
                created_by=st.session_state.get("logged_in_user"),
            )
            if ok_user:
                st.success(f"{msg_user}\n\nShare this password securely: `{selected_password}`")
                st.session_state["generated_password_create"] = generate_strong_password(16)
            else:
                st.error(msg_user)

        st.divider()

        # --- Manage Existing Users ---
        users = list_dashboard_users()
        usernames = [u.get("username") for u in users if u.get("username") and u.get("username") != SUPER_ADMIN_USERNAME]

        st.markdown("**Update Password**")
        with st.form("change_user_password_form"):
            selected_user_pwd = st.selectbox("Select User", options=usernames, key="pwd_user_select") if usernames else None
            new_pwd = st.text_input(
                "New Password",
                value=generate_strong_password(16),
                help="Use generated password or enter a custom strong password.",
            )
            update_password_btn = st.form_submit_button("Update Password")

        if update_password_btn:
            if not selected_user_pwd:
                st.error("No users available.")
            else:
                ok_upd, msg_upd = set_dashboard_user_password(
                    username=selected_user_pwd,
                    password=new_pwd,
                    updated_by=st.session_state.get("logged_in_user"),
                )
                st.success(msg_upd) if ok_upd else st.error(msg_upd)

        st.divider()

        st.markdown("**Assign Role**")
        with st.form("assign_role_form"):
            selected_user_role = st.selectbox("Select User", options=usernames, key="role_user_select") if usernames else None
            assign_role = st.selectbox("New Role", [ROLE_MANAGER, ROLE_VIEWER], key="assign_role_select")
            assign_role_btn = st.form_submit_button("Update Role")

        if assign_role_btn:
            if not selected_user_role:
                st.error("No users available.")
            else:
                ok_r, msg_r = set_user_role(
                    username=selected_user_role,
                    role=assign_role,
                    updated_by=st.session_state.get("logged_in_user"),
                )
                st.success(msg_r) if ok_r else st.error(msg_r)

        st.divider()

        st.markdown("**Deactivate User**")
        with st.form("deactivate_user_form"):
            selected_user_del = st.selectbox("Select User", options=usernames, key="del_user_select") if usernames else None
            deactivate_btn = st.form_submit_button("Deactivate User")

        if deactivate_btn:
            if not selected_user_del:
                st.error("No users available.")
            else:
                ok_d, msg_d = deactivate_user(
                    username=selected_user_del,
                    updated_by=st.session_state.get("logged_in_user"),
                )
                st.success(msg_d) if ok_d else st.error(msg_d)

        st.divider()

        # --- User List (no passwords) ---
        st.markdown("**Active Users**")
        if users:
            st.dataframe(
                pd.DataFrame([
                    {
                        "Username": u.get("username") or "—",
                        "Role": str(u.get("role") or ROLE_MANAGER).upper(),
                        "Active": "Yes" if u.get("isActive", True) else "No",
                    }
                    for u in users
                ]),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No users found.")

        card_close()

filters = {
    "status": status,
    "allocatedTo": allocatedTo,
    "search": search,
    "month_mode": month_mode,
    "month_year": int(month_year),
    "month_num": int(month_num),
    "range_start": range_start,
    "range_end": range_end,
}

# -----------------------
# Pages
# -----------------------
if page == "Leads":
    with db_loader("Fetching leads..."):
        leads = fetch_leads(filters)
    is_filtered = filters_are_active(filters)

    kpis = compute_kpis_from_docs(leads)
    st.markdown(
        kpi_circles_html(kpis["total"], kpis["interested"], kpis["not_interested"], kpis["closed"], kpis["total_brokerage"]),
        unsafe_allow_html=True,
    )
    st_components.html(
        kpi_counter_script(kpis["total"], kpis["interested"], kpis["not_interested"], kpis["closed"], kpis["total_brokerage"]),
        height=0,
    )

    table_title = "Filtered Leads" if is_filtered else "Leads"
    if filters.get("month_mode") == "date range":
        start_label = filters["range_start"].strftime("%d %b %Y")
        end_label = filters["range_end"].strftime("%d %b %Y")
        table_subtitle = f"Leads in selected range ({start_label} - {end_label}): {len(leads)}"
    else:
        table_subtitle = f"Matching leads: {len(leads)}" if is_filtered else f"Showing all leads: {len(leads)}"
    download_label = "Download Filtered Leads CSV" if is_filtered else "Download Leads CSV"
    download_key = "filtered_leads" if is_filtered else "leads"

    card_open(table_title, "lb-lime", "#a6ce39", subtitle=table_subtitle)
    render_leads_table(
        leads,
        table_key="filtered_leads_table",
        download_key=download_key,
        download_label=download_label,
    )
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

            existing_notes = dedupe_notes(lead.get("notes") or [])
            existing_comment_default = (existing_notes[-1].get("text") if existing_notes else "") or ""

            c1, c2 = st.columns(2)

            with c1:
                leadDateEdit = st.date_input(
                    "Lead date (IST)",
                    value=existing_date_ist,
                    key=f"edit_lead_date_{lead.get('leadId')}",
                )
                companyName = st.text_input(
                    "Company",
                    value=lead.get("companyName") or "",
                    key=f"edit_company_{lead.get('leadId')}",
                )
                contactName = st.text_input(
                    "Contact person",
                    value=lead.get("contactName") or "",
                    key=f"edit_contact_name_{lead.get('leadId')}",
                )
                contactEmail = st.text_input(
                    "Email id",
                    value=lead.get("contactEmail") or "",
                    key=f"edit_contact_email_{lead.get('leadId')}",
                )
                contactPhone = st.text_input(
                    "Phone number",
                    value=lead.get("contactPhone") or "",
                    key=f"edit_contact_phone_{lead.get('leadId')}",
                )

            with c2:
                current_status_label = denormalize_lead_status(lead.get("leadStatus"))
                status_index = LEAD_STATUS_OPTIONS.index(current_status_label) if current_status_label in LEAD_STATUS_OPTIONS else 0
                leadStatusLabel = st.selectbox(
                    "Lead status",
                    LEAD_STATUS_OPTIONS,
                    index=status_index,
                    key=f"edit_status_{lead.get('leadId')}",
                )

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

                allocPick = st.selectbox(
                    "Allocated to (choose)",
                    alloc_options,
                    index=alloc_index,
                    key=f"edit_alloc_pick_{lead.get('leadId')}",
                )
                allocTyped = st.text_input(
                    "Or type allocated to (adds new)",
                    value="",
                    placeholder="Type a new name here...",
                    key=f"edit_alloc_typed_{lead.get('leadId')}",
                )
                allocatedToDisplayName = (allocTyped.strip() or (allocPick if allocPick not in {"None", "(TYPE NEW)"} else "")).strip() or None

            brokerage = st.text_input(
                "Brokerage received",
                value="" if lead.get("brokerageReceived") is None else str(lead.get("brokerageReceived")),
                key=f"edit_brokerage_{lead.get('leadId')}",
            )

            original_status_label = denormalize_lead_status(lead.get("leadStatus"))
            show_closed_fields = leadStatusLabel == "Closed"
            is_newly_marked_closed = original_status_label != "Closed" and show_closed_fields

            net_premium = ""
            if show_closed_fields:
                net_premium = st.text_input(
                    "Net Premium",
                    value="" if lead.get("netPremium") is None else str(lead.get("netPremium")),
                    key=f"edit_net_premium_{lead.get('leadId')}",
                )
            uploaded_policy_copy = None
            if show_closed_fields:
                if is_newly_marked_closed:
                    st.info("This lead will now require net premium details and a policy copy before saving as Closed.")
                uploaded_policy_copy = st.file_uploader(
                    "Policy Copy",
                    type=["pdf", "png", "jpg", "jpeg", "webp"],
                    help="Upload the issued policy copy for closed leads.",
                    key=f"policy_copy_upload_{lead.get('leadId')}",
                )
                if policy_copy_present(lead):
                    existing_policy = lead.get("policyCopy") or {}
                    st.caption(f"Existing file: {existing_policy.get('name') or 'Policy copy uploaded'}")
            else:
                st.caption("Policy Copy upload is available only when the lead status is Closed.")

            comment_edit = st.text_area(
                "Comments (optional)",
                value=existing_comment_default,
                height=90,
                placeholder="Update comment for this lead...",
                help="Saving will add this as a new note entry (keeps history).",
                key=f"edit_comment_{lead.get('leadId')}",
            )

            st.caption("Lead date defaults to current date unless you change it. Lead ID remains unchanged when updating or re-assigning an existing lead.")

            if can_edit_leads():
                save = st.button("Save changes", key=f"save_lead_{lead.get('leadId')}", use_container_width=True)
            else:
                st.info("You have view-only access. Contact an admin to make changes.")
                save = False

            if save:
                # ---- Money parsing ----
                brokerage_val: Any = brokerage.strip()
                if brokerage_val == "":
                    brokerage_val = None
                else:
                    try:
                        brokerage_val = float(brokerage_val)
                    except ValueError:
                        st.error("Brokerage must be a number (or empty).")
                        st.stop()

                net_premium_val: Any = net_premium.strip()
                if net_premium_val == "":
                    net_premium_val = None
                else:
                    try:
                        net_premium_val = float(net_premium_val)
                    except ValueError:
                        st.error("Net Premium must be a number (or empty).")
                        st.stop()

                policy_copy_doc = encode_uploaded_file(uploaded_policy_copy) if leadStatusLabel == "Closed" else None

                # ---- Lead date update (Lead ID stays unchanged for existing leads) ----
                updated_lead_dt_ist = datetime(
                    leadDateEdit.year,
                    leadDateEdit.month,
                    leadDateEdit.day,
                    0,
                    0,
                    0,
                    tzinfo=IST,
                )

                # ---- Updates ----
                updates: dict = {
                    "leadDate": updated_lead_dt_ist.astimezone(timezone.utc),
                    "companyName": companyName.strip() or None,
                    "contactName": contactName.strip() or None,
                    "contactEmail": contactEmail.strip() or None,
                    "contactPhone": contactPhone.strip() or None,
                    "leadStatus": normalize_lead_status(leadStatusLabel),
                    "allocatedTo": {"displayName": allocatedToDisplayName, "userId": None, "email": None},
                    "brokerageReceived": brokerage_val,
                    "netPremium": net_premium_val,
                    "policyCopy": policy_copy_doc if leadStatusLabel == "Closed" and policy_copy_doc else (lead.get("policyCopy") if leadStatusLabel == "Closed" else None),
                }
                current_db_doc = leads_col().find_one({"_id": lead_oid}, {"allocatedTo.displayName": 1}) or {}
                previous_alloc = (safe_get(current_db_doc, "allocatedTo.displayName") or "").strip() or None
                next_alloc = (allocatedToDisplayName or "").strip() or None
                allocation_push = None
                if previous_alloc and next_alloc and previous_alloc.lower() != next_alloc.lower():
                    allocation_push = {
                        "allocationHistory": {
                            "from": previous_alloc,
                            "to": next_alloc,
                            "editedAt": now_utc(),
                            "editedBy": current_username(),
                        }
                    }

                with db_loader("Saving lead..."):
                    try:
                        update_lead(lead_oid, updates, push_ops=allocation_push)
                    except DuplicateKeyError:
                        st.error("Lead ID collision occurred. Try saving again.")
                        st.stop()

                    if (comment_edit or "").strip() and (comment_edit or "").strip() != existing_comment_default.strip():
                        add_note(lead_oid, comment_edit.strip(), created_by=current_username())

                st.success("Saved. Click 'Refresh DB' in sidebar to reload cached DB connection.")

            selected_status = denormalize_lead_status(selected_lead.get("leadStatus"))
            if selected_status == "Closed" and policy_copy_present(selected_lead):
                if st.button("View Policy Copy", use_container_width=True, key=f"view_policy_copy_{selected_lead.get('leadId')}"):
                    show_policy_copy_dialog(selected_lead)

            if can_manage_deletions():
                st.markdown("---")
                st.caption("Admin only")
                if st.button("Archive this lead", key=f"archive_lead_{lead.get('leadId')}"):
                    with db_loader("Archiving lead..."):
                        archive_lead(lead_oid)
                    st.session_state.pop("selected_lead_id", None)
                    st.success("Lead archived. View it under 'Archived Leads'.")
                    st.rerun()

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
            notes = dedupe_notes([n for n in (selected_lead.get("notes") or []) if isinstance(n, dict)])
            notes_sorted = sorted(
                notes,
                key=lambda n: (
                    n.get("createdAt") if isinstance(n.get("createdAt"), datetime) else datetime.min.replace(tzinfo=timezone.utc)
                ),
                reverse=True,
            )
            if can_delete_comments() and notes_sorted:
                for idx, note in enumerate(notes_sorted):
                    meta = f"{str((note or {}).get('createdBy') or 'Unknown user').strip() or 'Unknown user'} • {format_note_datetime_ist((note or {}).get('createdAt'))}"
                    st.markdown(f"**{meta}**")
                    st.write(str((note or {}).get("text") or "").strip() or "(empty comment)")
                    if st.button("Delete comment", key=f"del_note_{selected_lead.get('leadId')}_{idx}"):
                        with db_loader("Deleting comment..."):
                            delete_note(selected_lead["_id"], note)
                        st.success("Comment deleted.")
                        st.rerun()
                    if idx < len(notes_sorted) - 1:
                        st.divider()
            else:
                st.markdown(comments_view_html(notes_sorted), unsafe_allow_html=True)
            card_close()

            card_open("Allocation History", "lb-cyan", "#00aeef", subtitle="Lead re-assignment audit trail")
            history_rows = [h for h in (selected_lead.get("allocationHistory") or []) if isinstance(h, dict)]
            history_rows = sorted(
                history_rows,
                key=lambda h: h.get("editedAt") if isinstance(h.get("editedAt"), datetime) else datetime.min.replace(tzinfo=timezone.utc),
            )
            if history_rows:
                view_rows: list[dict] = []
                for h in history_rows:
                    view_rows.append(
                        {
                            "First Allocation": (h.get("from") or "—") if h.get("from") else "—",
                            "Re-Allocated To": (h.get("to") or "—") if h.get("to") else "—",
                            "Edited By": (h.get("editedBy") or "Unknown user") if h.get("editedBy") else "Unknown user",
                            "Date & Time": format_note_datetime_ist(h.get("editedAt")),
                        }
                    )
                st.dataframe(pd.DataFrame(view_rows), use_container_width=True, hide_index=True)
            else:
                st.info("No allocation history available for this lead.")
            card_close()

elif page == "Create Lead":
    require_role(ROLE_MANAGER)
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
            net_premium = ""
            if leadStatus == "Closed":
                net_premium = st.text_input("Net Premium", value="")

            uploaded_policy_copy = None
            if leadStatus == "Closed":
                uploaded_policy_copy = st.file_uploader(
                    "Policy Copy",
                    type=["pdf", "png", "jpg", "jpeg", "webp"],
                    help="Upload the issued policy copy for closed leads.",
                    key="create_policy_copy_upload",
                )
            else:
                st.caption("Policy Copy upload is available only when the lead status is Closed.")

        comment = st.text_area(
            "Comments (optional)",
            value="",
            height=90,
            placeholder="Add an initial comment for this lead...",
        )

        submit_new_lead = st.form_submit_button("Create lead", use_container_width=True)

    if submit_new_lead:
        brokerage_val: Any = brokerage.strip()
        if brokerage_val == "":
            brokerage_val = None
        else:
            try:
                brokerage_val = float(brokerage_val)
            except ValueError:
                st.error("Brokerage must be a number (or empty).")
                st.stop()

        net_premium_val: Any = net_premium.strip()
        if net_premium_val == "":
            net_premium_val = None
        else:
            try:
                net_premium_val = float(net_premium_val)
            except ValueError:
                st.error("Net Premium must be a number (or empty).")
                st.stop()

        allocated_to_name = (allocTyped.strip() or (allocPick if allocPick not in {"None", "(TYPE NEW)"} else "")).strip() or None
        policy_copy_doc = encode_uploaded_file(uploaded_policy_copy) if leadStatus == "Closed" else None

        create_payload = {
            "leadDate": leadDate,
            "companyName": companyName.strip() or None,
            "contactName": contactName.strip() or None,
            "contactEmail": contactEmail.strip() or None,
            "contactPhone": contactPhone.strip() or None,
            "productType": None if productType == "(none)" else productType,
            "leadStatus": leadStatus,
            "allocatedToDisplayName": allocated_to_name,
            "brokerageReceived": brokerage_val,
            "netPremium": net_premium_val,
            "policyCopy": policy_copy_doc,
            "comment": comment.strip() or None,
        }
        with db_loader("Creating lead..."):
            new_id = create_lead(create_payload)
            created_doc = leads_col().find_one({"_id": new_id}, {"leadId": 1}) or {}
        st.success(f"Lead created: {created_doc.get('leadId') or 'Unknown'}")

    card_close()

elif page == "Archived Leads":
    require_role(ROLE_ADMIN)
    card_open("Archived Leads", "lb-lost", "#FF5252", subtitle="Soft-deleted leads — restore or permanently delete")

    with db_loader("Fetching archived leads..."):
        archived = fetch_archived_leads()

    if not archived:
        st.info("No archived leads found.")
    else:
        archive_rows = []
        for doc in archived:
            archive_rows.append({
                "Lead ID":      doc.get("leadId") or "—",
                "Name":         doc.get("contactName") or "—",
                "Company":      doc.get("companyName") or "—",
                "Status":       denormalize_lead_status(doc.get("leadStatus")) or "—",
                "Archived By":  doc.get("archivedBy") or "—",
                "Archived At":  format_note_datetime_ist(doc.get("archivedAt")),
            })

        st.dataframe(
            pd.DataFrame(archive_rows),
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("**Restore a Lead**")
        archive_id_map = {
            f"{doc.get('leadId') or '?'} — {doc.get('contactName') or '—'} (archived {format_note_datetime_ist(doc.get('archivedAt'))})": doc["_id"]
            for doc in archived
        }
        selected_archive_label = st.selectbox(
            "Select archived lead",
            options=list(archive_id_map.keys()),
            key="restore_lead_select",
        )
        if st.button("Restore Selected Lead", use_container_width=True):
            selected_archive_id = archive_id_map.get(selected_archive_label)
            if selected_archive_id:
                with db_loader("Restoring lead..."):
                    restore_lead(selected_archive_id)
                st.success("Lead restored to active leads.")
                st.rerun()

    card_close()
