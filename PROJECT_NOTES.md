# LeadBox — Project Notes

## Overview

LeadBox is an internal lead management application built with Streamlit, backed by a NoSQL document database. All runtime configuration (database URI, credentials, environment identifiers) is managed via environment secrets and must never be committed to version control.

- **Framework:** Streamlit
- **Database:** MongoDB
- **Timezone:** IST (Asia/Kolkata) — used for all date-related UI logic and monthly calculations

---

## Lead Identification

- Each lead is assigned a unique, human-readable ID upon creation.
- The ID encodes a monthly serial number derived from the **Lead Date** (IST).
- The serial counter resets at the start of each calendar month.
- If the Lead Date is changed to a different month or year, the system automatically regenerates the lead's ID and its monthly serial to remain consistent.

---

## Page Behaviors

### Create Lead

- On successful creation, the UI displays the newly assigned Lead ID only.
- Raw database documents or debug output are never shown to the user.

### Leads

#### Lead Selector
- Each lead is listed as: `LEAD ID — Contact Name [Status]`
- Company name is intentionally omitted from the selector label to reduce visual clutter.

#### Edit Form
- Includes an IST-aware Lead Date picker.
- Includes an optional Comments field.
  - Comments are appended as timestamped history entries; prior entries are never overwritten.

#### Refresh Connection
- A **Refresh DB** button in the sidebar clears the cached database connection.
- This does not trigger a full app rerun or force re-authentication.

#### Month-wise Analytics Graph
- Displays lead volume per calendar month using a continuous date series.
- The series starts from the earliest month present in the dataset and extends to the current month.
- Rendered with Plotly.

#### Filtered Leads Table
- A leads table is rendered only when an active filter is applied (by Status, Assigned User, or Month).
- Visible columns: Name, Company, Phone, Email, Assigned To, Status, Lead ID.
- Notes and internal metadata are excluded from this view.

---

## Dependencies

Defined in `requirements.txt`. Key packages:

| Package | Purpose |
|---|---|
| `streamlit` | UI framework |
| `pymongo` + `dnspython` | MongoDB connectivity |
| `pandas` | Data manipulation |
| `plotly` | Interactive charts |
| `pypdfium2` + `reportlab` | PDF processing and generation |

Version ranges are pinned in `requirements.txt`. Review for CVEs periodically.

---

## Security Notes

- All secrets (database URI, auth credentials) are injected at runtime via Streamlit's secrets management or environment variables — never hardcoded.
- `.streamlit/secrets.toml` and any `.env` files must be listed in `.gitignore`.
- This file must not contain database names, collection identifiers, field names, ID formats, or any information that reveals internal data structure.
