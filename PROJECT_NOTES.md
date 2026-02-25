# LeadBox — Project Notes (Decisions & Behaviors)

## Overview
- App: **LeadBox** (Streamlit)
- Database: MongoDB
  - `DB_NAME = "sal-leads"`
  - Collection: `leads`
- Timezone: **IST** (`Asia/Kolkata`) used for lead-date UI and month logic.

## Lead ID rules
- Format: `SalLeadNNMMMYY` (example: `SalLead04FEB26`)
- Serial resets **monthly** based on selected **Lead Date (IST)**
- Stored field: `legacyNumber` = the monthly serial (1..n)

## Lead Date behavior
- Lead Date is editable on the **Leads** page.
- If Lead Date month/year changes, the system regenerates:
  - `leadId`
  - `legacyNumber`

## Create Lead page behavior
- After creating a lead:
  - Show only: `Lead created: <leadId>`
  - Do **not** show raw JSON / debug document output.

## Leads page behavior

### Lead picker label
- Show: `LEADID — CONTACTNAME [STATUS]`
- Do **not** show company name in the picker label.

### Edit form fields
- Includes Lead Date calendar (IST).
- Includes **Comments (optional)** field.
  - Comments are stored as **notes** (history preserved).
  - Editing/saving comments appends a new note entry.

### Refresh DB
- Sidebar button: **Refresh DB**
- Clears only the cached DB connection (Mongo client cache).
- Does **not** force an app rerun that could trigger login again.

### Month-wise graph
- Beautiful “month-wise leads received” graph (Plotly).
- Shows a continuous month series from the **first month present in DB** (e.g., `JUL 25`) up to the current month.
- X-axis labels: `JUL 25`, `AUG 25`, `SEP 25`, ...

### Filter-triggered leads table
- Show a clean, scrollable table **only when filtering by**:
  - Status, or
  - Allocated To, or
  - Filter by Month
- Table columns (no notes/comments):
  - Name, Company, Phone, Email, Allocated To, Status (+ Lead ID)

### UI highlight
- “Select a lead” dropdown is visually highlighted via a CSS wrapper class:
  - `.lb-lead-picker`

## Dependencies
If using Plotly graph:
- Add/keep in `requirements.txt`:
  - `plotly>=5.18,<6`
  - plus existing: `streamlit`, `pymongo`, `dnspython`, `pandas`
