# LeadBox — Project Notes

Key product decisions and implementation details for the LeadBox Streamlit application.

---

## App Overview

- **Framework:** Streamlit (`>=1.33,<2`)
- **Database:** MongoDB
  - DB name: `sal-leads`
  - Collection: `leads`
- **Mongo URI secret key:** `mongo_uri_leads` (stored in Streamlit Cloud secrets)
- **Login credentials** stored in Streamlit secrets: `app_user`, `app_password`

---

## Timezone Handling

- All displayed/input dates are in **IST (Asia/Kolkata, UTC+5:30)**.
- Dates are stored in MongoDB as UTC `datetime` objects.
- Conversion helpers use `ZoneInfo("Asia/Kolkata")`.

---

## Lead ID Generation

- **Format:** `SalLeadNNMMMYY`
  - `NN` — zero-padded 2-digit serial number (e.g. `01`, `12`)
  - `MMM` — 3-letter uppercase month abbreviation (e.g. `JUL`)
  - `YY` — 2-digit year (e.g. `25`)
  - Example: `SalLead01JUL25`
- **Serial resets monthly** — the counter starts from `1` at the beginning of each new month and is based on the selected **Lead Date** month (not the creation date).
- The `legacyNumber` field stores the raw integer serial used to derive `leadId`.
- `leadId` has a unique index (`uniq_leadId`) in MongoDB.

---

## Lead Date Editing Behaviour

- When the **Lead Date** is changed on the edit form:
  - If the new date falls in a **different month or year** from the existing `leadId` suffix, the `leadId` **and** `legacyNumber` are regenerated for the new month.
  - If the new date stays within the same month/year, the existing `leadId` is preserved.
- Helper: `lead_id_from_existing_or_new(target_lead_date_ist, existing_lead_id)`.

---

## Create Lead Behaviour

- After successfully creating a lead, **no JSON dump or raw document** is shown.
- Only a **success toast** notification is displayed.
- The form is cleared/reset after creation.

---

## Leads Page Requirements

### Lead Selectbox Label Format

- Format: `LEADID — CONTACTNAME [STATUS]`
  - Uses the contact name, **not** the company name.
  - Example: `SalLead03JUL25 — Rahul Sharma [Interested]`

### Lead Date Calendar

- A date-picker (calendar widget) is present on the Leads page for selecting/editing the Lead Date.

### Comments / Notes (Editable, History-Based)

- The **Comments** field is editable on the Leads page.
- Saving a comment does **not** overwrite the previous comment; instead it is **appended as a new note entry** (timestamped history), preserving the full comment log.

### Refresh DB Button

- Calls `st.cache_resource.clear()` to clear only the cached `MongoClient` resource.
- Does **not** trigger an explicit `st.rerun()` and does **not** reset the login state.
- The app will reinitialise the DB connection naturally on the next Streamlit interaction.

### Month-wise Leads Graph

- Built with **Plotly** (`plotly.graph_objects.Scatter`, `mode="lines+markers"`).
- X-axis covers **all continuous months** from the **first month found in the DB** (e.g. `JUL 25`) up to and including the **current month**.
- X-axis tick labels use the format `MMM YY` (e.g. `JUL 25`, `AUG 25`).
- No months are skipped even if a month has zero leads.

### Filter-Triggered Table

- The leads table is shown **only when at least one of** these filters is active:
  - **Status**
  - **Allocated To**
  - **Month**
- A search-only query (no Status/AllocatedTo/Month filter) does **not** trigger the table.
- Table columns: `Lead ID`, `Name`, `Company`, `Phone`, `Email`, `Allocated To`, `Status`.

### Visual Highlight for Lead Picker

- The "Select a lead" selectbox is wrapped in a `<div class="lb-lead-picker">` HTML element.
- CSS class `.lb-lead-picker` applies a navy-tinted border, soft box-shadow, and bold navy label:

```css
.lb-lead-picker div[data-baseweb="select"] > div {
  border: 1px solid rgba(45, 68, 141, 0.35) !important;
  box-shadow: 0 10px 22px rgba(45, 68, 141, 0.10) !important;
  background: linear-gradient(180deg, rgba(238,242,255,0.65), #fff) !important;
}
.lb-lead-picker label {
  font-weight: 900 !important;
  color: #2d448d !important;
  letter-spacing: 0.02em !important;
}
```

---

## Dependencies (`requirements.txt`)

```
streamlit>=1.33,<2
pymongo>=4.6,<5
dnspython>=2.4,<3
pandas>=2.2,<3
plotly>=5.18,<6
```

`plotly` is required for the month-wise leads graph (`plotly.graph_objects`).
