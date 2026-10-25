import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

APP_TITLE = "FrameLock"
DB_PATH = Path(__file__).with_name("framelock.db")
GENESIS = "FRAMELOCK_AUDIT_GENESIS_V1"

st.set_page_config(
    page_title="FrameLock | Evidence Integrity",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            registered_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            event_time TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn

def latest_event_hash(conn):
    row = conn.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    return row["event_hash"] if row else GENESIS

def append_event(conn, evidence_id, event_type, details):
    event_time = now_utc()
    previous_hash = latest_event_hash(conn)
    payload = {
        "evidence_id": evidence_id,
        "event_type": event_type,
        "details": details,
        "event_time": event_time,
        "previous_hash": previous_hash,
    }
    event_hash = sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    conn.execute(
        """INSERT INTO audit_events
           (evidence_id, event_type, details, event_time, previous_hash, event_hash)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (evidence_id, event_type, details, event_time, previous_hash, event_hash),
    )
    conn.commit()

def verify_chain(conn):
    rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    expected_previous = GENESIS
    for row in rows:
        payload = {
            "evidence_id": row["evidence_id"],
            "event_type": row["event_type"],
            "details": row["details"],
            "event_time": row["event_time"],
            "previous_hash": row["previous_hash"],
        }
        expected_hash = sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        if row["previous_hash"] != expected_previous:
            return False, f"Event #{row['id']} points to an unexpected previous hash."
        if row["event_hash"] != expected_hash:
            return False, f"Event #{row['id']} hash does not match its contents."
        expected_previous = row["event_hash"]
    return True, f"All {len(rows)} audit event(s) passed the hash-chain check."

def format_bytes(n):
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n/1024:.1f} KB"
    return f"{n/(1024**2):.2f} MB"

conn = connect()

st.markdown("""
<style>
    .block-container {padding-top: 1.7rem; padding-bottom: 2.5rem; max-width: 1200px;}
    .hero {padding: 1.4rem 1.5rem; border: 1px solid rgba(128,128,128,.25); border-radius: 18px;
           background: linear-gradient(120deg, rgba(37,99,235,.13), rgba(14,165,233,.06));}
    .hero h1 {margin: 0 0 .35rem 0; font-size: 2.35rem;}
    .muted {color: #8b93a1; font-size: .95rem;}
    .tiny {font-size: .82rem; color: #8b93a1;}
    div[data-testid="stMetric"] {border: 1px solid rgba(128,128,128,.22); padding: 14px; border-radius: 14px;}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## 🔐 FrameLock")
    st.caption("Tamper-evident evidence handling demo")
    page = st.radio(
        "Navigation",
        ["Overview", "Register Evidence", "Verify Evidence", "Audit Timeline", "About & Limits"],
        label_visibility="collapsed",
    )
    st.divider()
    st.caption("Prototype • SHA-256 • SQLite")
    st.caption("For demonstration only — do not upload sensitive evidence.")

if page == "Overview":
    st.markdown("""
    <div class="hero">
      <h1>Evidence integrity, made visible.</h1>
      <p>Register a file, fingerprint it with SHA-256, and inspect a hash-linked audit trail.
      FrameLock helps demonstrate whether a file still matches its registered fingerprint.</p>
    </div>
    """, unsafe_allow_html=True)
    st.write("")
    total = conn.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()["n"]
    events = conn.execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]
    chain_ok, chain_msg = verify_chain(conn)
    c1, c2, c3 = st.columns(3)
    c1.metric("Registered files", total)
    c2.metric("Audit events", events)
    c3.metric("Audit chain", "Valid" if chain_ok else "Mismatch")
    st.write("")
    st.subheader("How the demo works")
    steps = st.columns(3)
    steps[0].markdown("### 01 · Register\nUpload a sample file and store its SHA-256 fingerprint.")
    steps[1].markdown("### 02 · Verify\nUpload the file again to compare its current fingerprint with the registered value.")
    steps[2].markdown("### 03 · Audit\nReview a hash-linked timeline of registration and verification actions.")
    if not chain_ok:
        st.error(chain_msg)
    else:
        st.success(chain_msg)
    st.info("Quick demo: register a small text file, verify the same file, then verify a modified copy to show a mismatch.")

elif page == "Register Evidence":
    st.title("Register evidence")
    st.write("Create a baseline fingerprint for a file. The file contents are hashed in memory; this prototype does not store the uploaded file itself.")
    uploaded = st.file_uploader("Choose a sample evidence file", key="register_file")
    label = st.text_input("Optional case / reference label", placeholder="e.g., Campus incident demo 01")
    if uploaded:
        content = uploaded.getvalue()
        digest = sha256_bytes(content)
        c1, c2 = st.columns(2)
        c1.metric("File size", format_bytes(len(content)))
        c2.metric("SHA-256 fingerprint", digest[:16] + "…")
        with st.expander("View full SHA-256 fingerprint"):
            st.code(digest, language=None)
        if st.button("Register fingerprint", type="primary", use_container_width=True):
            conn.execute(
                "INSERT INTO evidence (filename, sha256, size_bytes, registered_at) VALUES (?, ?, ?, ?)",
                (uploaded.name, digest, len(content), now_utc()),
            )
            evidence_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            details = json.dumps({
                "filename": uploaded.name,
                "size_bytes": len(content),
                "sha256": digest,
                "label": label.strip(),
            }, ensure_ascii=False)
            append_event(conn, evidence_id, "REGISTER", details)
            st.success(f"Registered successfully as Evidence ID {evidence_id}.")
            st.caption("Save the Evidence ID or find it on the Verify Evidence page.")
    st.caption("Tip: use a harmless sample .txt, .jpg, or .pdf file. Avoid real personal or confidential records.")

elif page == "Verify Evidence":
    st.title("Verify evidence")
    records = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    if not records:
        st.warning("No evidence has been registered yet. Open **Register Evidence** first.")
    else:
        options = {
            f"ID {r['id']} · {r['filename']} · {r['registered_at']}": r["id"]
            for r in records
        }
        selected_label = st.selectbox("Choose the registered evidence record", list(options.keys()))
        selected_id = options[selected_label]
        record = conn.execute("SELECT * FROM evidence WHERE id = ?", (selected_id,)).fetchone()
        st.markdown(f"**Registered filename:** `{record['filename']}`")
        st.markdown(f"**Registered at (UTC):** `{record['registered_at']}`")
        st.code(record["sha256"], language=None)
        uploaded = st.file_uploader("Upload the file you want to verify", key="verify_file")
        if uploaded:
            current_digest = sha256_bytes(uploaded.getvalue())
            same = current_digest == record["sha256"]
            if same:
                st.success("MATCH — the uploaded file matches the registered SHA-256 fingerprint.")
                event_type = "VERIFY_MATCH"
            else:
                st.error("MISMATCH — the uploaded file does not match the registered fingerprint.")
                event_type = "VERIFY_MISMATCH"
            with st.expander("Compare fingerprints"):
                left, right = st.columns(2)
                left.markdown("**Registered SHA-256**")
                left.code(record["sha256"], language=None)
                right.markdown("**Uploaded file SHA-256**")
                right.code(current_digest, language=None)
            if st.button("Record verification event", type="primary"):
                details = json.dumps({
                    "registered_filename": record["filename"],
                    "uploaded_filename": uploaded.name,
                    "result": "MATCH" if same else "MISMATCH",
                    "registered_sha256": record["sha256"],
                    "uploaded_sha256": current_digest,
                }, ensure_ascii=False)
                append_event(conn, selected_id, event_type, details)
                st.success("Verification event added to the audit timeline.")
    st.caption("A match means the bytes are identical to the registered file. It does not prove who created the file or whether the original recording is truthful.")

elif page == "Audit Timeline":
    st.title("Audit timeline")
    ok, message = verify_chain(conn)
    if ok:
        st.success(message)
    else:
        st.error(message)
    rows = conn.execute("""
        SELECT a.*, e.filename
        FROM audit_events a LEFT JOIN evidence e ON a.evidence_id = e.id
        ORDER BY a.id DESC
    """).fetchall()
    if not rows:
        st.info("No events yet. Register evidence to create the first audit event.")
    else:
        for row in rows:
            title = f"#{row['id']} · {row['event_type']} · {row['event_time']}"
            with st.expander(title):
                st.write(f"**Evidence ID:** {row['evidence_id'] if row['evidence_id'] is not None else '—'}")
                st.write(f"**Filename:** {row['filename'] or '—'}")
                try:
                    details = json.loads(row["details"])
                    st.json(details)
                except json.JSONDecodeError:
                    st.code(row["details"])
                st.caption("Previous event hash")
                st.code(row["previous_hash"], language=None)
                st.caption("This event hash")
                st.code(row["event_hash"], language=None)
    if st.button("Re-check audit chain"):
        ok, message = verify_chain(conn)
        if ok:
            st.success(message)
        else:
            st.error(message)

else:
    st.title("About FrameLock")
    st.write("FrameLock is a hackathon prototype for demonstrating file fingerprinting and a hash-linked audit history for evidence handling.")
    st.subheader("What it demonstrates")
    st.markdown("""
    - SHA-256 fingerprinting for uploaded files
    - Registering a baseline fingerprint
    - Detecting changes by comparing a later upload with the baseline
    - Recording registration and verification events
    - Checking whether audit events still form a consistent hash chain
    """)
    st.subheader("Important limitations")
    st.warning("""
    This is a prototype, not a production evidence-management system. It does not prove that a recording is authentic or truthful. A hash only shows whether bytes match a known fingerprint. The SQLite database is stored with the app and may be reset or lost when a hosted app restarts or redeploys; this demo is not a permanent evidence archive. A person who controls the app environment and database may be able to alter both the records and the chain. No external blockchain is deployed.
    """)
    st.subheader("Suggested judge demo")
    st.markdown("""
    1. Create a text file containing `Camera sample A`.
    2. Register it.
    3. Verify the same file — expect **MATCH**.
    4. Change the text to `Camera sample B` and verify it against the original record — expect **MISMATCH**.
    5. Open Audit Timeline and show the event hashes and chain check.
    """)

st.divider()
st.markdown('<p class="tiny">FrameLock • Hackathon prototype • Demonstration data only</p>', unsafe_allow_html=True)
