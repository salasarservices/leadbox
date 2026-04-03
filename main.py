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
import uuid

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
  width: 48px;
  height: 48px;
  display: inline-block;
  position: relative;
  border: 4px solid #FFF;
  box-sizing: border-box;
  animation: fill 2s linear infinite alternate;
  color: rgba(255, 61, 0, 0.9);
  border-radius: 0 0 4px 4px;
}
.loader::after {
  content: '';
  box-sizing: border-box;
  position: absolute;
  left: 100%;
  top: 50%;
  transform: translateY(-50%);
  border: 4px solid #FFF;
  width: 20px;
  height: 25px;
  border-radius: 0 4px 4px 0;
}
@keyframes fill {
  0%   { box-shadow: 0 0 inset; }
  100% { box-shadow: 0 -48px inset; }
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

    # Keep last_activity_ts rolling (used for inactivity timeout above)
    st.session_state["last_activity_ts"] = now_ts

    # session_start_ts is set ONCE per login and never overwritten — used for the session timer display
    if "session_start_ts" not in st.session_state:
        st.session_state["session_start_ts"] = now_ts


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


def format_edit_history(note: dict) -> str:
    """Return edit metadata line based on whether editor differs from original author."""
    history = note.get("editHistory") or []
    if not history:
        return ""
    last = history[-1]
    editor = str(last.get("editedBy") or "unknown").strip().lower()
    author = str(note.get("createdBy") or "unknown").strip().lower()
    at = format_note_datetime_ist(last.get("editedAt"))
    count = len(history)
    suffix = f" ({count} edit{'s' if count > 1 else ''})" if count > 1 else ""
    if editor != author:
        return f"Last edited by {last.get('editedBy') or 'unknown'} • {at}{suffix}"
    else:
        return f"Last edited • {at}{suffix}"


def policy_copy_present(lead: dict) -> bool:
    policy_copy = lead.get("policyCopy") or {}
    if not isinstance(policy_copy, dict):
        return False
    # Check for inline data OR just the filename as an indicator.
    # policyCopy.data is excluded from the bulk fetch projection, so we fall
    # back to policyCopy.name which is always fetched.
    return bool(
        str(policy_copy.get("data") or "").strip()
        or str(policy_copy.get("name") or "").strip()
    )


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
    if not encoded and lead.get("_id"):
        # policyCopy.data was excluded from the bulk projection — fetch it now
        fresh = leads_col().find_one({"_id": lead["_id"]}, {"policyCopy": 1}) or {}
        policy_copy = fresh.get("policyCopy") or {}
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


def kpi_lead_detail_html(lead: dict) -> str:
    """Renders the KPI row showing selected lead's key details instead of aggregate stats."""
    lead_id   = lead.get("leadId") or "—"
    name      = lead.get("contactName") or "—"
    company   = lead.get("companyName") or "—"
    alloc     = allocation_chain_text(lead)
    status    = denormalize_lead_status(lead.get("leadStatus") or "")
    brokerage = format_inr_compact(parse_money(lead.get("brokerageReceived")) or 0)

    status_palette = LEAD_STATUS_BADGE_STYLES.get(
        normalize_lead_status(status),
        {"bg": "#536DFE"},
    )
    status_bg = status_palette.get("bg", "#536DFE")

    def _box(bg: str, label: str, value: str) -> str:
        val_len = len(str(value))
        fs = "1.0rem" if val_len > 16 else ("1.25rem" if val_len > 10 else "1.5rem")
        safe_value = str(value).replace("<", "&lt;").replace(">", "&gt;")
        return (
            f'<div class="kpi-wrap" style="flex:1;display:flex;flex-direction:column;align-items:center;">'
            f'<div class="kpi" style="background:{bg};width:100%;height:95px;border-radius:1px;'
            f'border:1px solid var(--border);box-shadow:var(--shadow);display:flex;align-items:center;justify-content:center;">'
            f'<div class="kpi-inner" style="text-align:center;padding:6px 8px;">'
            f'<div style="font-size:{fs};font-weight:900;color:#fff;overflow:hidden;'
            f'text-overflow:ellipsis;white-space:nowrap;max-width:150px;" title="{safe_value}">{safe_value}</div>'
            f'<div class="kpi-sub" style="margin-top:4px;font-size:0.72rem;color:rgba(255,255,255,0.85);'
            f'text-transform:uppercase;letter-spacing:0.06em;font-weight:900;">{label}</div>'
            f'</div></div></div>'
        )

    return (
        '<div class="kpi-row" style="display:flex;gap:12px;padding:10px 2px 6px 2px;align-items:flex-start;">'
        + _box("var(--pastel-navy)", "Lead ID",      lead_id)
        + _box("var(--pastel-lime)", "Name",         name)
        + _box("#FF5252",            "Company",      company)
        + _box("#8BBA29",            "Allocated To", alloc)
        + _box(status_bg,            "Status",       status)
        + _box("#7C4DFF",            "Brokerage",    brokerage)
        + "</div>"
    )


def kpi_counter_script(total: int, interested: int, not_interested: int, closed: int, total_brokerage: float):
    brok = format_inr_compact(total_brokerage)
    conversion = f"{(closed / total * 100):.1f}%" if total > 0 else "0%"
    # Values are embedded directly so the script string is unique per dataset.
    # This forces Streamlit to recreate the iframe on every filter/data change,
    # which re-triggers the animation with the correct current values.
    return f"""
<script>
(function() {{
  var _v = [{total}, {interested}, {not_interested}, {closed}, "{brok}", "{conversion}"];
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
    st.cache_data.clear()


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
    return is_admin()

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
        col.create_index([("leadDate", DESCENDING)], name="idx_leadDate")
    if "idx_leadStatus" not in existing:
        col.create_index([("leadStatus", ASCENDING)], name="idx_leadStatus")
    if "idx_allocatedTo" not in existing:
        col.create_index([("allocatedTo.displayName", ASCENDING)], name="idx_allocatedTo")
    # Compound indexes covering the two most common filter + sort combinations
    if "idx_status_date" not in existing:
        col.create_index(
            [("leadStatus", ASCENDING), ("leadDate", DESCENDING)],
            name="idx_status_date",
        )
    if "idx_alloc_date" not in existing:
        col.create_index(
            [("allocatedTo.displayName", ASCENDING), ("leadDate", DESCENDING)],
            name="idx_alloc_date",
        )

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
    q: Dict[str, Any] = {"isArchived": {"$ne": True}}
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


@st.cache_data(ttl=30, show_spinner=False)
def fetch_leads(filters: dict) -> list[dict]:
    col = leads_col()
    q = build_query(filters)
    # Exclude policyCopy.data (heavy base64 binary). It is fetched on-demand
    # inside show_policy_copy_dialog() when a user opens the policy copy.
    _PROJECTION = {"policyCopy.data": 0}
    docs = list(col.find(q, _PROJECTION).sort([("leadDate", DESCENDING)]))

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


def _invalidate_leads_cache() -> None:
    """Bust the fetch_leads cache after any write operation."""
    try:
        fetch_leads.clear()
    except Exception:
        pass


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


def generate_leads_pdf(df: pd.DataFrame, report_title: str, filters: Optional[dict] = None) -> bytes:
    """Generate a formatted PDF report from the leads download DataFrame."""
    import urllib.request as _urllib_request

    from reportlab.lib import colors as _rlcolors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4, landscape as _landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable,
        Image,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    _navy   = _rlcolors.HexColor("#2d448d")
    _lime   = _rlcolors.HexColor("#a6ce39")
    _row_alt = _rlcolors.HexColor("#eef3ff")
    _border = _rlcolors.HexColor("#d1d9f0")
    _grey_text = _rlcolors.HexColor("#64748b")

    PAGE_W, PAGE_H = _landscape(A4)
    MARGIN = 1.5 * cm

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=_landscape(A4),
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "lb_title",
        parent=styles["Normal"],
        fontSize=20,
        fontName="Helvetica-Bold",
        textColor=_navy,
        spaceAfter=2,
        leading=24,
    )
    sub_style = ParagraphStyle(
        "lb_sub",
        parent=styles["Normal"],
        fontSize=8.5,
        fontName="Helvetica",
        textColor=_grey_text,
        spaceAfter=4,
    )
    cell_style = ParagraphStyle(
        "lb_cell",
        parent=styles["Normal"],
        fontSize=7.5,
        fontName="Helvetica",
        textColor=_rlcolors.HexColor("#1e293b"),
        leading=10,
        wordWrap="CJK",
    )

    # ── Build human-readable filter description ──────────────────────────────
    def _describe_filters(f: dict) -> str:
        parts: list[str] = []
        status_val = (f.get("status") or "all").strip()
        if status_val.lower() != "all":
            parts.append(f"Status: {status_val.title()}")
        alloc_val = (f.get("allocatedTo") or "all").strip()
        if alloc_val.lower() != "all":
            parts.append(f"Allocated to: {alloc_val}")
        search_val = (f.get("search") or "").strip()
        if search_val:
            parts.append(f'Search: "{search_val}"')
        mode = (f.get("month_mode") or "all").strip()
        if mode == "month":
            m_num  = int(f.get("month_num")  or 1)
            m_year = int(f.get("month_year") or datetime.now(IST).year)
            parts.append(f"Period: {MONTHS[m_num - 1]} {m_year}")
        elif mode == "date range":
            rs = f.get("range_start")
            re = f.get("range_end")
            if rs and re:
                try:
                    parts.append(
                        f"Period: {rs.strftime('%d %b %Y')} \u2013 {re.strftime('%d %b %Y')}"
                    )
                except Exception:
                    pass
        return "  |  ".join(parts) if parts else "All leads (no filters applied)"

    filter_desc = _describe_filters(filters) if filters else "All leads (no filters applied)"

    filter_style = ParagraphStyle(
        "lb_filter",
        parent=styles["Normal"],
        fontSize=8.5,
        fontName="Helvetica-Oblique",
        textColor=_rlcolors.HexColor("#2d448d"),
        spaceAfter=3,
    )

    story: list = []

    # ── Logo (left-aligned, ~200 px wide) ───────────────────────────────────
    # 200 px at 96 dpi ≈ 5.29 cm; use proportional so height auto-scales
    try:
        with _urllib_request.urlopen(LOGO_URL, timeout=6) as _resp:
            _logo_bytes = _resp.read()
        logo_img = Image(BytesIO(_logo_bytes), width=5.3 * cm, kind="proportional")
        logo_img.hAlign = "LEFT"
        story.append(logo_img)
        story.append(Spacer(1, 0.25 * cm))
    except Exception:
        pass  # Logo fetch failed — continue without it

    # ── Title block ─────────────────────────────────────────────────────────
    gen_ts = datetime.now(IST).strftime("%d %B %Y  •  %I:%M %p IST")
    story.append(Paragraph(report_title, title_style))
    story.append(Paragraph(filter_desc, filter_style))
    story.append(
        Paragraph(
            f"Generated: {gen_ts}&nbsp;&nbsp;|&nbsp;&nbsp;Total Records: {len(df)}",
            sub_style,
        )
    )
    story.append(
        HRFlowable(
            width="100%",
            thickness=2,
            color=_navy,
            spaceAfter=8,
            spaceBefore=2,
        )
    )

    # ── Table ────────────────────────────────────────────────────────────────
    _display_cols = [
        "Number", "Lead ID", "Name", "Company",
        "Allocated To", "Status", "Brokerage Received",
        "Phone Number", "Email",
    ]
    _present = [c for c in _display_cols if c in df.columns]
    df_view = df[_present]

    # Wrap long cell text in Paragraphs so reportlab can reflow
    header_row = [
        Paragraph(
            f'<font name="Helvetica-Bold" color="white" size="8">{col.upper()}</font>',
            ParagraphStyle("hdr", alignment=TA_CENTER),
        )
        for col in df_view.columns
    ]
    data_rows = []
    for _, row in df_view.iterrows():
        data_rows.append(
            [Paragraph(str(v) if v is not None else "", cell_style) for v in row]
        )
    table_data = [header_row] + data_rows

    # Column widths — landscape A4 usable width ≈ 26.7 cm
    col_w_map = {
        "Number":            1.1 * cm,
        "Lead ID":           2.3 * cm,
        "Name":              3.8 * cm,
        "Company":           4.5 * cm,
        "Allocated To":      3.8 * cm,
        "Status":            2.2 * cm,
        "Brokerage Received":2.6 * cm,
        "Phone Number":      2.8 * cm,
        "Email":             4.0 * cm,
    }
    col_widths = [col_w_map.get(c, 3 * cm) for c in df_view.columns]

    tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(
        TableStyle([
            # Header background
            ("BACKGROUND",    (0, 0), (-1, 0),  _navy),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  _rlcolors.white),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, 0),  8),
            ("ALIGN",         (0, 0), (-1, 0),  "CENTER"),
            ("VALIGN",        (0, 0), (-1, 0),  "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, 0),  7),
            ("BOTTOMPADDING", (0, 0), (-1, 0),  7),
            # Accent line below header
            ("LINEBELOW",     (0, 0), (-1, 0),  2, _lime),
            # Data rows
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 1), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_rlcolors.white, _row_alt]),
            ("VALIGN",        (0, 1), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 1), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
            # Grid lines
            ("GRID",          (0, 0), (-1, -1), 0.4, _border),
            ("LINEBELOW",     (0, -1), (-1, -1), 1,  _navy),
        ])
    )
    story.append(tbl)

    # ── Footer on every page ────────────────────────────────────────────────
    def _add_footer(canvas, doc_obj):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(_grey_text)
        canvas.drawString(MARGIN, 0.9 * cm, "LeadBox — Salasar Services  |  Confidential")
        canvas.drawRightString(
            PAGE_W - MARGIN,
            0.9 * cm,
            f"Page {doc_obj.page}",
        )
        canvas.setStrokeColor(_border)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 1.25 * cm, PAGE_W - MARGIN, 1.25 * cm)
        canvas.restoreState()

    doc.build(story, onFirstPage=_add_footer, onLaterPages=_add_footer)
    buf.seek(0)
    return buf.read()


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
    else:
        # No row selected — clear so KPI row reverts to aggregate stats
        st.session_state.pop("selected_lead_id", None)


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
    _invalidate_leads_cache()


def add_note(_id: ObjectId, text: str, created_by: Optional[str] = None):
    col = leads_col()
    note = {
        "noteId": str(uuid.uuid4()),
        "text": text.strip(),
        "createdAt": now_utc(),
        "createdBy": created_by,
        "editHistory": [],
    }
    col.update_one({"_id": _id}, {"$push": {"notes": note}, "$set": {"updatedAt": now_utc()}})
    _invalidate_leads_cache()


def edit_note(_id: ObjectId, note: dict, new_text: str) -> None:
    """Edit an existing note in-place, preserving all original metadata.
    Appends an editHistory entry with previousText, editedBy, editedAt.
    If the note has no noteId (legacy), assigns one first.
    """
    col = leads_col()
    note_id = note.get("noteId")
    previous_text = str(note.get("text") or "").strip()
    edit_entry = {
        "previousText": previous_text,
        "editedBy": current_username(),
        "editedAt": now_utc(),
    }

    if note_id:
        # Update by noteId using positional filtered operator
        col.update_one(
            {"_id": _id, "notes.noteId": note_id},
            {
                "$set": {
                    "notes.$.text": new_text.strip(),
                    "updatedAt": now_utc(),
                },
                "$push": {"notes.$.editHistory": edit_entry},
            }
        )
    else:
        # Legacy note — no noteId. Match by exact content and assign one.
        new_note_id = str(uuid.uuid4())
        col.update_one(
            {
                "_id": _id,
                "notes.text": previous_text,
                "notes.createdBy": note.get("createdBy"),
            },
            {
                "$set": {
                    "notes.$.noteId": new_note_id,
                    "notes.$.text": new_text.strip(),
                    "updatedAt": now_utc(),
                },
                "$push": {"notes.$.editHistory": edit_entry},
            }
        )
    _invalidate_leads_cache()


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
    _invalidate_leads_cache()


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
    _invalidate_leads_cache()


def fetch_archived_leads() -> list[dict]:
    archive_col = mongo_client()[DB_NAME][COLL_ARCHIVE]
    return list(archive_col.find({}).sort([("archivedAt", DESCENDING)]))


def delete_note(_id: ObjectId, note: dict) -> None:
    col = leads_col()
    col.update_one({"_id": _id}, {"$pull": {"notes": note}, "$set": {"updatedAt": now_utc()}})
    _invalidate_leads_cache()


def delete_policy_copy(_id: ObjectId) -> None:
    col = leads_col()
    col.update_one({"_id": _id}, {"$unset": {"policyCopy": ""}, "$set": {"updatedAt": now_utc()}})
    _invalidate_leads_cache()


def find_duplicate_lead(phone: str | None, email: str | None) -> list[dict]:
    """Return existing (non-archived) leads that match on phone or email.
    Name alone is not a duplicate signal — many people share the same name."""
    col = leads_col()
    or_clauses = []
    if phone and phone.strip():
        or_clauses.append({"contactPhone": {"$regex": f"^{phone.strip()}$", "$options": "i"}})
    if email and email.strip():
        or_clauses.append({"contactEmail": {"$regex": f"^{email.strip()}$", "$options": "i"}})
    if not or_clauses:
        return []
    return list(col.find(
        {"$and": [{"isArchived": {"$ne": True}}, {"$or": or_clauses}]},
        {"leadId": 1, "contactName": 1, "contactPhone": 1, "contactEmail": 1, "companyName": 1, "leadStatus": 1},
    ))


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
        "notes": ([{"noteId": str(uuid.uuid4()), "text": initial_comment, "createdAt": now_utc(), "createdBy": created_by, "editHistory": []}] if initial_comment else []),
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
            _invalidate_leads_cache()
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
def user_status_card_html(username: str, role: str, db_ok: bool, login_ts: float) -> str:
    # Use the part after the first dot as the "name" (e.g. sal.amit → amit → Ami)
    # If no dot, use the username itself (e.g. sallead → Sal)
    _name_part = username.split(".", 1)[1] if "." in username else username
    initials = (_name_part[:3].title() if _name_part else "??")

    role_styles = {
        ROLE_ADMIN:   {"bar": "#11C15B", "pill_bg": "#EAF3DE", "pill_text": "#3B6D11", "avatar_bg": "#EAF3DE", "avatar_text": "#27500A"},
        ROLE_MANAGER: {"bar": "#448AFF", "pill_bg": "#E6F1FB", "pill_text": "#185FA5", "avatar_bg": "#E6F1FB", "avatar_text": "#0C447C"},
        ROLE_VIEWER:  {"bar": "#888780", "pill_bg": "#F1EFE8", "pill_text": "#5F5E5A", "avatar_bg": "#F1EFE8", "avatar_text": "#444441"},
    }
    s = role_styles.get(role, role_styles[ROLE_VIEWER])
    db_dot   = "#1D9E75" if db_ok else "#E24B4A"
    db_label = "Connected"  if db_ok else "Error"
    db_color = "#0F6E56"    if db_ok else "#A32D2D"

    env = str(st.secrets.get("app_env") or "PRODUCTION").upper()
    env_bg   = "#EAF3DE" if env == "PRODUCTION" else "#FAEEDA"
    env_text = "#3B6D11" if env == "PRODUCTION" else "#854F0B"

    # login_ts is a Unix epoch (seconds). JS will compute elapsed time client-side
    # and tick every second via setInterval — so no Streamlit rerun is needed.
    return f"""<!DOCTYPE html>
<html>
<head>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    background:transparent;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    overflow:hidden;
  }}
</style>
</head>
<body>
<div style="background:#fff;border:0.5px solid rgba(15,23,42,0.12);
  border-radius:12px;overflow:hidden;">
  <div style="height:3px;background:{s['bar']};"></div>
  <div style="padding:12px 14px;">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
      <div style="width:36px;height:36px;border-radius:50%;background:{s['avatar_bg']};
        display:flex;align-items:center;justify-content:center;
        font-size:11px;font-weight:700;color:{s['avatar_text']};flex-shrink:0;
        letter-spacing:0.02em;">{initials}</div>
      <div style="min-width:0;flex:1;">
        <div style="font-size:13px;font-weight:600;color:#0f172a;white-space:nowrap;
          overflow:hidden;text-overflow:ellipsis;">{username}</div>
        <div style="font-size:11px;color:#64748b;font-family:monospace;">@{username}</div>
      </div>
      <span style="background:{s['pill_bg']};color:{s['pill_text']};font-size:10px;
        font-weight:600;padding:3px 8px;border-radius:999px;white-space:nowrap;
        letter-spacing:0.04em;">{role.upper()}</span>
    </div>
    <div style="border-top:0.5px solid rgba(15,23,42,0.08);padding-top:10px;
      display:flex;flex-direction:column;gap:6px;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-size:11px;color:#64748b;">Session</span>
        <span id="session-timer" style="font-size:11px;color:#0f172a;font-variant-numeric:tabular-nums;">
          Active · 0s
        </span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-size:11px;color:#64748b;">DB</span>
        <span style="display:flex;align-items:center;gap:5px;font-size:11px;color:{db_color};">
          <span style="width:6px;height:6px;border-radius:50%;background:{db_dot};
            display:inline-block;"></span>
          {db_label}
        </span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-size:11px;color:#64748b;">Env</span>
        <span style="background:{env_bg};color:{env_text};font-size:10px;padding:2px 7px;
          border-radius:999px;font-weight:600;">{env}</span>
      </div>
    </div>
  </div>
</div>

<script>
(function () {{
  // Floor the server timestamp to avoid float subtraction giving decimal seconds
  var START_TS = Math.floor({login_ts});
  var el = document.getElementById('session-timer');

  function pad(n) {{ return n < 10 ? '0' + n : '' + n; }}

  function fmt(s) {{
    var h = Math.floor(s / 3600);
    var m = Math.floor((s % 3600) / 60);
    var sec = s % 60;
    if (h > 0) return 'Active \u00b7 ' + h + ':' + pad(m) + ':' + pad(sec);
    return 'Active \u00b7 ' + m + ':' + pad(sec);
  }}

  function tick() {{
    var elapsed = Math.max(0, Math.floor(Date.now() / 1000) - START_TS);
    if (el) el.textContent = fmt(elapsed);
  }}

  tick();
  setInterval(tick, 1000);
}})();
</script>
</body>
</html>"""

with st.sidebar:
    logged_in_user = st.session_state.get("logged_in_user") or "unknown"
    login_ts = float(st.session_state.get("session_start_ts") or datetime.now(timezone.utc).timestamp())
    # st_components.html runs a real iframe — the only way to execute JS in Streamlit.
    # height is sized to exactly fit the card (3px bar + ~149px body = 152px).
    st_components.html(
        user_status_card_html(logged_in_user, current_role(), db_ok, login_ts),
        height=152,
        scrolling=False,
    )

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
        if "generated_password_update" not in st.session_state:
            st.session_state["generated_password_update"] = generate_strong_password(16)

        with st.form("change_user_password_form"):
            selected_user_pwd = st.selectbox("Select User", options=usernames, key="pwd_user_select") if usernames else None
            new_pwd = st.text_input(
                "New Password",
                value=st.session_state["generated_password_update"],
                help="Use generated password or enter a custom strong password.",
            )
            pwd_cols = st.columns(2)
            with pwd_cols[0]:
                regen_pwd_btn = st.form_submit_button("Regenerate")
            with pwd_cols[1]:
                update_password_btn = st.form_submit_button("Update Password")

        if regen_pwd_btn:
            st.session_state["generated_password_update"] = generate_strong_password(16)
            st.rerun()

        if update_password_btn:
            if not selected_user_pwd:
                st.error("No users available.")
            else:
                ok_upd, msg_upd = set_dashboard_user_password(
                    username=selected_user_pwd,
                    password=new_pwd,
                    updated_by=st.session_state.get("logged_in_user"),
                )
                if ok_upd:
                    st.success(msg_upd)
                    st.session_state["generated_password_update"] = generate_strong_password(16)
                else:
                    st.error(msg_upd)

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
                if ok_r:
                    st.success(msg_r)
                else:
                    st.error(msg_r)

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
                if ok_d:
                    st.success(msg_d)
                else:
                    st.error(msg_d)

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

    # Show selected-lead details in KPI boxes when a row is chosen; otherwise show aggregate stats.
    # Sync selected_lead_id with the table widget's actual current selection.
    # The widget persists its own state in session_state["filtered_leads_table"],
    # which is the ground truth — prevents stale session state showing lead detail
    # when no row is visually selected (e.g. after filter changes or deselection).
    _table_widget_state = st.session_state.get("filtered_leads_table") or {}
    _table_sel_rows = (
        _table_widget_state.get("selection", {}).get("rows", [])
        if isinstance(_table_widget_state, dict) else []
    )
    if _table_sel_rows:
        _sel_idx = _table_sel_rows[0]
        if 0 <= _sel_idx < len(leads):
            st.session_state["selected_lead_id"] = leads[_sel_idx].get("leadId")
        else:
            st.session_state.pop("selected_lead_id", None)
    else:
        st.session_state.pop("selected_lead_id", None)

    _selected_lead_id = str(st.session_state.get("selected_lead_id") or "")
    _lead_map_by_id   = {str(d.get("leadId") or ""): d for d in leads}
    _selected_lead    = _lead_map_by_id.get(_selected_lead_id) if _selected_lead_id else None

    if _selected_lead:
        st.markdown(kpi_lead_detail_html(_selected_lead), unsafe_allow_html=True)
    else:
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

    card_open(table_title, "lb-leads-neutral", "#11c1b2", subtitle=table_subtitle)
    render_leads_table(
        leads,
        table_key="filtered_leads_table",
        download_key=download_key,
        download_label=download_label,
    )
    card_close()

    # ── PDF Report sidebar button ─────────────────────────────────────────────
    _, _df_download = build_leads_table_frames(leads)
    _pdf_report_title = ("Filtered Leads Report" if is_filtered else "Leads Report")
    with st.sidebar:
        card_open("Reports", "lb-navy", "#2d448d", subtitle="Export lead data as PDF")
        try:
            _pdf_bytes = generate_leads_pdf(_df_download, _pdf_report_title, filters=filters)
            _pdf_filename = f"{download_key}_report_{datetime.now(IST).strftime('%Y%m%d_%H%M%S')}.pdf"
            st.download_button(
                "Download PDF Report",
                data=_pdf_bytes,
                file_name=_pdf_filename,
                mime="application/pdf",
                use_container_width=True,
                key="pdf_report_btn",
            )
        except Exception as _pdf_err:
            st.error(f"PDF generation failed: {_pdf_err}")
        card_close()

    st.markdown('<div style="height:20px;min-height:20px;display:block;"></div>', unsafe_allow_html=True)
    left, right = st.columns([0.62, 0.38])

    with left:
        # ── SELECT LEAD bar ───────────────────────────────────────────────────
        st.markdown('<div class="lb-select-lead-label"></div>', unsafe_allow_html=True)

        def lead_label(d: dict) -> str:
            lid = d.get("leadId") or "?"
            name = (d.get("contactName") or "").strip()
            status = denormalize_lead_status(d.get("leadStatus") or "") or "—"
            return f"{lid} — {name} [{status}]"

        lead_options = [lead_label(d) for d in leads]
        lead_map = {lead_label(d): d for d in leads}
        lead_index_by_id = {str(d.get("leadId") or ""): idx for idx, d in enumerate(leads)}

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

            # Pre-compute allocation options (needed in both panels)
            current_status_label = denormalize_lead_status(lead.get("leadStatus"))
            status_index = LEAD_STATUS_OPTIONS.index(current_status_label) if current_status_label in LEAD_STATUS_OPTIONS else 0

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

            # ── Two-panel layout: Lead Summary | Edit Form ────────────────────
            summary_col, form_col = st.columns([0.30, 0.70])

            with summary_col:
                _lead_id_disp  = lead.get("leadId") or "—"
                _date_disp     = existing_date_ist.strftime("%Y/%m/%d") if existing_date_ist else "—"
                _status_raw    = (lead.get("leadStatus") or "fresh").lower()
                _status_disp   = denormalize_lead_status(lead.get("leadStatus") or "") or "Fresh"
                _contact_disp  = lead.get("contactName") or "—"
                _phone_disp    = lead.get("contactPhone") or "—"
                _email_disp    = lead.get("contactEmail") or "—"
                _alloc_disp    = (safe_get(lead, "allocatedTo.displayName") or "").strip() or "—"
                _broker_raw    = lead.get("brokerageReceived")
                _broker_disp   = f"₹{_broker_raw:,}" if isinstance(_broker_raw, (int, float)) else (f"₹{_broker_raw}" if _broker_raw is not None else "—")
                _status_colors = {"fresh": "#3b82f6", "allocated": "#f59e0b", "interested": "#10b981", "lost": "#ef4444", "closed": "#8bc34a"}
                _badge_bg      = _status_colors.get(_status_raw, "#3b82f6")

                st.markdown(f"""
                <div class="lb-lead-summary-panel">
                    <div class="lb-ls-header">LEAD SUMMARY</div>
                    <div class="lb-ls-lead-id">{_contact_disp}</div>
                    <div class="lb-ls-created">Created {_date_disp}</div>
                    <div class="lb-ls-sep"></div>
                    <div class="lb-ls-row">
                        <span class="lb-ls-key">Status</span>
                        <span class="lb-ls-status-badge" style="background:{_badge_bg}">{_status_disp.upper()}</span>
                    </div>
                    <div class="lb-ls-row">
                        <span class="lb-ls-key">Lead ID</span>
                        <span class="lb-ls-val">{_lead_id_disp}</span>
                    </div>
                    <div class="lb-ls-row">
                        <span class="lb-ls-key">Phone</span>
                        <span class="lb-ls-val">{_phone_disp}</span>
                    </div>
                    <div class="lb-ls-row">
                        <span class="lb-ls-key">Email</span>
                        <span class="lb-ls-val lb-ls-email">{_email_disp}</span>
                    </div>
                    <div class="lb-ls-row">
                        <span class="lb-ls-key">Allocated to</span>
                        <span class="lb-ls-val">{_alloc_disp}</span>
                    </div>
                    <div class="lb-ls-row">
                        <span class="lb-ls-key">Brokerage</span>
                        <span class="lb-ls-val">{_broker_disp}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Policy copy buttons inside the summary column
                _sel_status = denormalize_lead_status(lead.get("leadStatus"))
                if _sel_status == "Closed" and policy_copy_present(lead):
                    with st.container():
                        st.markdown('<div class="lb-policy-btn-group"></div>', unsafe_allow_html=True)
                        if st.button("View Policy Copy", use_container_width=True, key=f"view_policy_{lead.get('leadId')}"):
                            show_policy_copy_dialog(lead)
                        if is_admin():
                            if st.button("Delete Policy Copy", use_container_width=True, key=f"del_policy_{lead.get('leadId')}"):
                                with db_loader("Deleting policy copy..."):
                                    delete_policy_copy(lead_oid)
                                st.success("Policy copy deleted.")
                                st.rerun()

            with form_col:
                st.markdown('<div class="lb-edit-form-title">Edit lead details</div>', unsafe_allow_html=True)

                fc1, fc2 = st.columns(2)
                with fc1:
                    leadStatusLabel = st.selectbox(
                        "Lead status",
                        LEAD_STATUS_OPTIONS,
                        index=status_index,
                        key=f"edit_status_{lead.get('leadId')}",
                    )
                with fc2:
                    leadDateEdit = st.date_input(
                        "Lead date",
                        value=existing_date_ist,
                        key=f"edit_lead_date_{lead.get('leadId')}",
                    )

                fc3, fc4 = st.columns(2)
                with fc3:
                    companyName = st.text_input(
                        "Company",
                        value=lead.get("companyName") or "",
                        key=f"edit_company_{lead.get('leadId')}",
                    )
                with fc4:
                    allocPick = st.selectbox(
                        "Allocated to",
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

                fc5, fc6 = st.columns(2)
                with fc5:
                    contactName = st.text_input(
                        "Contact person",
                        value=lead.get("contactName") or "",
                        key=f"edit_contact_name_{lead.get('leadId')}",
                    )
                with fc6:
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
                    st.caption("Policy copy upload available only when status is Closed.")

                comment_edit = ""

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

                        if (comment_edit or "").strip():
                            add_note(lead_oid, comment_edit.strip(), created_by=current_username())

                    st.success("Saved. Click 'Refresh DB' in sidebar to reload cached DB connection.")

                if can_manage_deletions():
                    st.markdown("---")
                    st.caption("Admin only")
                    if st.button("Archive this lead", key=f"archive_lead_{lead.get('leadId')}"):
                        with db_loader("Archiving lead..."):
                            archive_lead(lead_oid)
                        st.session_state.pop("selected_lead_id", None)
                        st.success("Lead archived. View it under 'Archived Leads'.")
                        st.rerun()

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
                # Admin: all comments with edit + delete
                for idx, note in enumerate(notes_sorted):
                    author   = str((note or {}).get('createdBy') or 'Unknown user').strip() or 'Unknown user'
                    ts       = format_note_datetime_ist((note or {}).get('createdAt'))
                    text     = str((note or {}).get("text") or "").strip() or "(empty comment)"
                    edit_history_line = format_edit_history(note)
                    edit_key_a   = f"admin_editing_{selected_lead.get('leadId')}_{idx}"
                    is_editing_a = st.session_state.get(edit_key_a, False)

                    st.markdown(f"**{author} • {ts}**")
                    if edit_history_line:
                        st.caption(edit_history_line)

                    if is_editing_a:
                        edited_a = st.text_area(
                            "Edit",
                            value=text,
                            height=100,
                            key=f"admin_edit_text_{selected_lead.get('leadId')}_{idx}",
                            label_visibility="collapsed",
                        )
                        col_as, col_ac = st.columns(2)
                        with col_as:
                            if st.button("Save", key=f"admin_save_{selected_lead.get('leadId')}_{idx}", use_container_width=True):
                                if edited_a.strip() and edited_a.strip() != text:
                                    with db_loader("Saving comment..."):
                                        edit_note(selected_lead["_id"], note, edited_a.strip())
                                    st.session_state[edit_key_a] = False
                                    st.success("Comment updated.")
                                    st.rerun()
                                elif edited_a.strip() == text:
                                    st.session_state[edit_key_a] = False
                                    st.rerun()
                        with col_ac:
                            if st.button("Cancel", key=f"admin_cancel_{selected_lead.get('leadId')}_{idx}", use_container_width=True):
                                st.session_state[edit_key_a] = False
                                st.rerun()
                    else:
                        st.write(text)
                        col_ae, col_ad = st.columns(2)
                        with col_ae:
                            if st.button("Edit", key=f"admin_edit_btn_{selected_lead.get('leadId')}_{idx}", use_container_width=True):
                                st.session_state[edit_key_a] = True
                                st.rerun()
                        with col_ad:
                            if st.button("Delete", key=f"del_note_{selected_lead.get('leadId')}_{idx}", use_container_width=True):
                                with db_loader("Deleting comment..."):
                                    delete_note(selected_lead["_id"], note)
                                st.success("Comment deleted.")
                                st.rerun()
                    if idx < len(notes_sorted) - 1:
                        st.divider()

            elif can_edit_leads():
                # Manager: read-only for all except most recent which gets click-to-edit
                if not notes_sorted:
                    st.info("No comments available for this lead.")
                else:
                    for idx, note in enumerate(notes_sorted):
                        meta = f"{str((note or {}).get('createdBy') or 'Unknown user').strip() or 'Unknown user'} • {format_note_datetime_ist((note or {}).get('createdAt'))}"
                        edit_history_line = format_edit_history(note)
                        st.markdown(f"**{meta}**")
                        if edit_history_line:
                            st.caption(edit_history_line)
                        if idx == 0:
                            note_text = str((note or {}).get("text") or "").strip()
                            edit_key = f"editing_comment_{selected_lead.get('leadId')}"
                            is_editing = st.session_state.get(edit_key, False)
                            if is_editing:
                                edited_text = st.text_area(
                                    "Edit comment",
                                    value=note_text,
                                    height=100,
                                    key=f"inline_edit_text_{selected_lead.get('leadId')}",
                                    label_visibility="collapsed",
                                )
                                col_save, col_cancel = st.columns(2)
                                with col_save:
                                    if st.button("Save", key=f"save_inline_{selected_lead.get('leadId')}", use_container_width=True):
                                        if edited_text.strip() and edited_text.strip() != note_text:
                                            with db_loader("Saving comment..."):
                                                edit_note(selected_lead["_id"], note, edited_text.strip())
                                            st.session_state[edit_key] = False
                                            st.success("Comment updated.")
                                            st.rerun()
                                        elif edited_text.strip() == note_text:
                                            st.session_state[edit_key] = False
                                            st.rerun()
                                with col_cancel:
                                    if st.button("Cancel", key=f"cancel_inline_{selected_lead.get('leadId')}", use_container_width=True):
                                        st.session_state[edit_key] = False
                                        st.rerun()
                            else:
                                st.write(note_text or "(empty comment)")
                                if st.button("Edit comment", key=f"edit_btn_{selected_lead.get('leadId')}", use_container_width=True):
                                    st.session_state[edit_key] = True
                                    st.rerun()
                        else:
                            st.write(str((note or {}).get("text") or "").strip() or "(empty comment)")
                        if idx < len(notes_sorted) - 1:
                            st.divider()

                # Add new comment — always shown for managers
                st.divider()
                new_comment = st.text_area(
                    "Add new comment",
                    value="",
                    height=80,
                    placeholder="Type a new comment...",
                    key=f"new_comment_{selected_lead.get('leadId')}",
                )
                if st.button("Add comment", key=f"add_comment_{selected_lead.get('leadId')}", use_container_width=True):
                    if new_comment.strip():
                        with db_loader("Adding comment..."):
                            add_note(selected_lead["_id"], new_comment.strip(), created_by=current_username())
                        st.success("Comment added.")
                        st.rerun()

            else:
                # Viewer: fully read-only
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
            contactName = st.text_input("Contact person *")
            contactEmail = st.text_input("Email id")
            contactPhone = st.text_input("Phone number")

        with c2:
            productType = st.selectbox("Product type", ["(none)"] + product_opts)
            leadStatus = st.selectbox("Lead status", LEAD_STATUS_OPTIONS)
            st.markdown('<p class="lb-field-label-req">Allocated to * <span>(choose from list OR type a new name below)</span></p>', unsafe_allow_html=True)
            allocPick = st.selectbox("Allocated to", ["None", "(TYPE NEW)"] + alloc_opts, label_visibility="collapsed")
            allocTyped = st.text_input("Or type a new name", value="", placeholder="Type a new name here...", label_visibility="collapsed")
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
            "Comments *",
            value="",
            height=90,
            placeholder="Add an initial comment for this lead...",
        )

        st.markdown('<p class="lb-required-note">* Required fields</p>', unsafe_allow_html=True)
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

        # ── Required fields validation ────────────────────────────────────────
        _req_errors = []
        if not contactName.strip():
            _req_errors.append("**Contact Name** is required.")
        if not allocated_to_name:
            _req_errors.append("**Allocated To** is required — choose from the list or type a new name.")
        if not comment.strip():
            _req_errors.append("**Comment** is required.")
        if _req_errors:
            st.error("Please fix the following before creating a lead:\n\n" + "\n".join(f"- {e}" for e in _req_errors))
            st.stop()

        # ── Duplicate detection (phone / email only) ──────────────────────────
        duplicates = find_duplicate_lead(contactPhone.strip() or None, contactEmail.strip() or None)
        if duplicates:
            lines = ["**Duplicate lead detected.** A lead with the same phone or email already exists:\n"]
            for dup in duplicates:
                _d_status = denormalize_lead_status(dup.get("leadStatus") or "") or "—"
                lines.append(
                    f"- **{dup.get('leadId') or '?'}** — "
                    f"{dup.get('contactName') or '—'} | "
                    f"{dup.get('companyName') or '—'} | "
                    f"Phone: {dup.get('contactPhone') or '—'} | "
                    f"Email: {dup.get('contactEmail') or '—'} | "
                    f"Status: {_d_status}"
                )
            lines.append("\nPlease check the existing lead before creating a new one.")
            st.error("\n".join(lines))
            st.stop()

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
