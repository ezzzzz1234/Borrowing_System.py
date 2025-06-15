import streamlit as st
import mysql.connector
import bcrypt
import qrcode
import io
import pandas as pd
from PIL import Image
from pyzbar.pyzbar import decode
from datetime import datetime, timedelta

# ────────────────────────────────────────────────────────────────────────────────
# 0) PAGE CONFIG – FIRST ST CALL
st.set_page_config(
    page_title="Lab Equipment Lending",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={'About': "Created by UMP IT Lab • © 2025"}
)

# ────────────────────────────────────────────────────────────────────────────────
# 1) GLOBAL STYLING
st.markdown("""
<style>
  .main { background: linear-gradient(135deg, #e0f7fa 0%, #f3e5f5 100%); padding:1rem; border-radius:12px; }
  [data-testid="stSidebar"] { background: linear-gradient(180deg, #f3e5f5 0%, #e0f7fa 100%); }
  h1,h2,h3 { color:#1f4e79; font-family:'Segoe UI',sans-serif; }
  .stButton>button { border-radius:8px; font-weight:600; padding:.5rem 1rem; }
  .stTextInput input, .stNumberInput input { border-radius:6px; padding:.4rem; }
  .stDataFrame thead { background-color:#c5cae9; }
  footer { visibility:hidden; }
  .footer { text-align:center; padding:1rem; color:#777; font-size:0.9rem; }
</style>
""", unsafe_allow_html=True)
st.markdown('<div class="main">', unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────────
# Helper to show or download a PDF
def show_pdf(title, path):
    st.header(f"📄 {title}")
    with open(path, "rb") as f:
        pdf_bytes = f.read()
    st.download_button(
        label=f"Download {title} (PDF)",
        data=pdf_bytes,
        file_name=f"{title.replace(' ', '_').lower()}.pdf",
        mime="application/pdf"
    )

# ────────────────────────────────────────────────────────────────────────────────
# 2) IDLE AUTO-LOGOUT SETUP
IDLE_TIMEOUT = timedelta(minutes=5)
if 'last_active' not in st.session_state:
    st.session_state.last_active = datetime.now()
if datetime.now() - st.session_state.last_active > IDLE_TIMEOUT:
    st.session_state.user = None
    st.session_state.role = None
st.session_state.last_active = datetime.now()

# ────────────────────────────────────────────────────────────────────────────────
# 3) DATABASE CONNECTION
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'hantu778',
    'database': 'equipment_borrowing',
    'port': 3306
}
@st.cache_resource
def get_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    conn.autocommit = False
    return conn

db     = get_db()
cursor = db.cursor(dictionary=True)

# ────────────────────────────────────────────────────────────────────────────────
# 4) SESSION STATE INIT
st.session_state.setdefault('admin_exists', False)
with st.spinner("Checking for Admin…"):
    cursor.execute("SELECT COUNT(*) cnt FROM users WHERE role='admin'")
    st.session_state.admin_exists = cursor.fetchone()['cnt'] > 0
st.session_state.setdefault('user', None)
st.session_state.setdefault('role', None)
st.session_state.setdefault('returned_requests', set())

# ────────────────────────────────────────────────────────────────────────────────
# 5) FIRST-RUN ADMIN SETUP
def first_run_admin():
    st.image("ump.jpg", use_container_width=True)
    st.header("⚙ First-Time Admin Setup")
    st.info("Create the initial Admin account.")
    n  = st.text_input("Full Name")
    e  = st.text_input("Email")
    r  = st.text_input("RFID ID")
    p1 = st.text_input("Password", type="password")
    p2 = st.text_input("Confirm Password", type="password")
    if st.button("Create Admin"):
        if not all([n,e,r,p1,p2]):
            st.error("All fields are required.")
        elif p1 != p2:
            st.error("Passwords do not match.")
        else:
            with st.spinner("Registering…"):
                cursor.execute("SELECT 1 FROM users WHERE email=%s OR rfid=%s", (e, r))
                if cursor.fetchone():
                    st.error("Email or RFID already in use.")
                else:
                    ph = bcrypt.hashpw(p1.encode(), bcrypt.gensalt()).decode()
                    cursor.execute(
                        "INSERT INTO users (name,email,password_hash,rfid,role) VALUES (%s,%s,%s,%s,'admin')",
                        (n, e, ph, r)
                    )
                    db.commit()
                    st.success("Admin created! Please log in.")
                    st.balloons()
                    st.session_state.admin_exists = True
    st.stop()

# ────────────────────────────────────────────────────────────────────────────────
# 6) LOGIN SCREEN
def login_screen():
    st.image("ump.jpg", use_container_width=True)
    st.header("🏷 Lab Equipment Lending")
    st.caption(datetime.now().strftime("🕒 %Y-%m-%d %H:%M:%S"))
    chosen = st.radio("I am logging in as:", ["Admin/Staff", "Student"])
    method = st.selectbox("Login via:", ["Email/Password", "RFID"])
    rec = None
    if method == "Email/Password":
        e = st.text_input("Email")
        p = st.text_input("Password", type="password")
        if st.button("Log In"):
            with st.spinner("Verifying…"):
                cursor.execute("SELECT * FROM users WHERE email=%s", (e,))
                u = cursor.fetchone()
            if not u or not bcrypt.checkpw(p.encode(), u['password_hash'].encode()):
                st.error("Invalid credentials.")
            elif (chosen == "Student" and u['role'] != "student") or (chosen == "Admin/Staff" and u['role'] not in ("admin","staff")):
                st.error("Role mismatch.")
            else:
                rec = u
    else:
        rfid = st.text_input("RFID ID")
        if st.button("Log In"):
            with st.spinner("Checking RFID…"):
                cursor.execute("SELECT * FROM users WHERE rfid=%s", (rfid,))
                u = cursor.fetchone()
            if not u:
                st.error("RFID not recognized.")
            elif (chosen == "Student" and u['role'] != "student") or (chosen == "Admin/Staff" and u['role'] not in ("admin","staff")):
                st.error("Role mismatch.")
            else:
                rec = u
    if rec:
        st.success(f"Welcome, {rec['name']}!")
        st.session_state.user = rec
        st.session_state.role = chosen
    st.stop()

# ────────────────────────────────────────────────────────────────────────────────
# 7) SIDEBAR + LOGOUT + METRICS + MENU
def init_sidebar():
    st.sidebar.image("ump.jpg", use_container_width=True)
    st.sidebar.markdown("---")
    if st.session_state.user:
        u = st.session_state.user
        st.sidebar.write(f"*User:* {u['name']}")
        st.sidebar.write(f"*Role:* {st.session_state.role}")
        if st.session_state.role == "Admin/Staff":
            with st.spinner("Loading metrics…"):
                cursor.execute("SELECT COUNT(*) cnt FROM equipment")
                eq = int(cursor.fetchone()['cnt'])
                cursor.execute("SELECT COUNT(*) cnt FROM users WHERE role='student'")
                ss = int(cursor.fetchone()['cnt'])
                st.sidebar.metric("Total Equipment", eq)
                st.sidebar.metric("Total Students", ss)
        if st.sidebar.button("Logout"):
            st.session_state.user = None
            st.session_state.role = None
            st.success("🔒 Logged out.")
            st.stop()

    # Add our two new menu items for both roles:
    if st.session_state.role == "Admin/Staff":
        menu = st.sidebar.selectbox(
            "Admin Menu",
            ["Manage Inventory", "Add Equipment", "Register User",
             "Installation Guide", "User Manual"]
        )
    else:
        menu = st.sidebar.selectbox(
            "Student Menu",
            ["Borrow Equipment", "Return Equipment", "My History",
             "Installation Guide", "User Manual"]
        )
    return menu

# ────────────────────────────────────────────────────────────────────────────────
# 8) ADMIN DASHBOARD
def admin_dashboard(choice):
    if choice == "Installation Guide":
        show_pdf("Installation Guide", "docs/installation_guide.pdf")
        return
    elif choice == "User Manual":
        show_pdf("User Manual", "docs/user_manual.pdf")
        return

    # Shared header
    st.image("ump.jpg", width=720)
    st.header(f"👋 Hello, {st.session_state.user['name']}")

    # KPI cards
    c1, c2, c3 = st.columns(3)
    with c1:
        cursor.execute("SELECT COUNT(*) cnt FROM equipment")
        c1.metric("Equipment Types", int(cursor.fetchone()['cnt']))
    with c2:
        cursor.execute("SELECT COALESCE(SUM(total_qty),0) total FROM equipment")
        c2.metric("Total Units", int(cursor.fetchone()['total']))
    with c3:
        cursor.execute("SELECT COUNT(*) cnt FROM borrow_requests WHERE status='confirmed'")
        c3.metric("Active Borrows", int(cursor.fetchone()['cnt']))

    if choice == "Manage Inventory":
        st.subheader("🔎 Inventory Browser")
        cursor.execute("SELECT * FROM equipment")
        df = pd.DataFrame(cursor.fetchall())
        q = st.text_input("Filter by name or QR")
        if q:
            df = df[df['name'].str.contains(q, case=False) | df['qr_code'].str.contains(q, case=False)]
        st.dataframe(df, height=350, use_container_width=True)

        with st.expander("🔄 Scan & Adjust"):
            img = st.camera_input("Scan QR Code")
            qr  = None
            if img:
                d = decode(Image.open(img))
                if d:
                    qr = d[0].data.decode()
                    st.write("QR:", qr)
                else:
                    st.error("No QR detected.")
            delta = st.number_input("Quantity Δ", step=1, value=0)
            if st.button("Update"):
                if not qr:
                    st.error("Scan first.")
                else:
                    cursor.execute("SELECT equipment_id,available_qty FROM equipment WHERE qr_code=%s", (qr,))
                    it = cursor.fetchone()
                    if not it:
                        st.error("Unknown QR.")
                    else:
                        new = it['available_qty'] + delta
                        if new < 0:
                            st.error("Cannot go below zero.")
                        else:
                            with st.spinner("Updating…"):
                                cursor.execute(
                                    "UPDATE equipment SET available_qty=%s WHERE equipment_id=%s",
                                    (new, it['equipment_id'])
                                )
                                cursor.execute(
                                    "INSERT INTO inventory_log (equipment_id,quantity_change,action,user_id) "
                                    "VALUES (%s,%s,%s,%s)",
                                    (it['equipment_id'], delta,
                                     'add' if delta > 0 else 'outgoing',
                                     st.session_state.user['user_id'])
                                )
                                db.commit()
                            st.success("Inventory updated.")
                            st.balloons()

    elif choice == "Add Equipment":
        st.subheader("➕ Add Equipment")
        with st.form("add_eq"):
            name = st.text_input("Name")
            desc = st.text_area("Description")
            qty  = st.number_input("Initial Quantity", min_value=1, step=1)
            if st.form_submit_button("Create"):
                if not name:
                    st.error("Name is required.")
                else:
                    cursor.execute("SELECT 1 FROM equipment WHERE name=%s", (name,))
                    if cursor.fetchone():
                        st.error("Name exists.")
                    else:
                        with st.spinner("Adding…"):
                            cursor.execute(
                                "INSERT INTO equipment (name,description,total_qty,available_qty) "
                                "VALUES (%s,%s,%s,%s)",
                                (name, desc, qty, qty)
                            )
                            eid = cursor.lastrowid
                            code = f"EQ{eid:05d}"
                            cursor.execute(
                                "UPDATE equipment SET qr_code=%s WHERE equipment_id=%s",
                                (code, eid)
                            )
                            db.commit()
                        buf = io.BytesIO()
                        qrcode.make(code).save(buf)
                        st.image(buf.getvalue(), caption=code)
                        st.success("Equipment added.")
                        st.balloons()

    else:  # Register User
        st.subheader("👤 Register New User")
        with st.form("reg_user"):
            n  = st.text_input("Name")
            e  = st.text_input("Email")
            r  = st.text_input("RFID ID")
            p1 = st.text_input("Password", type="password")
            p2 = st.text_input("Confirm Password", type="password")
            rl = st.selectbox("Role", ["staff","student"])
            if st.form_submit_button("Register"):
                if not all([n,e,r,p1,p2]):
                    st.error("All fields are required.")
                elif p1 != p2:
                    st.error("Passwords must match.")
                else:
                    cursor.execute("SELECT 1 FROM users WHERE email=%s OR rfid=%s", (e,r))
                    if cursor.fetchone():
                        st.error("Email or RFID in use.")
                    else:
                        with st.spinner("Registering…"):
                            ph = bcrypt.hashpw(p1.encode(), bcrypt.gensalt()).decode()
                            cursor.execute(
                                "INSERT INTO users (name,email,password_hash,rfid,role) "
                                "VALUES (%s,%s,%s,%s,%s)",
                                (n,e,ph,r,rl)
                            )
                            db.commit()
                        st.success(f"{rl.title()} registered.")
                        st.balloons()

# ────────────────────────────────────────────────────────────────────────────────
# 9) STUDENT DASHBOARD
def student_dashboard(choice):
    if choice == "Installation Guide":
        show_pdf("Installation Guide", "docs/installation_guide.pdf")
        return
    elif choice == "User Manual":
        show_pdf("User Manual", "docs/user_manual.pdf")
        return

    st.image("ump.jpg", width=720)
    st.header(f"🎓 Welcome, {st.session_state.user['name']}!")
    st.caption(datetime.now().strftime("🕒 %Y-%m-%d %H:%M:%S"))

    if choice == "Borrow Equipment":
        st.subheader("🔍 Available Equipment")
        cursor.execute("SELECT equipment_id,name,available_qty FROM equipment WHERE available_qty>0")
        eqs = cursor.fetchall()
        if not eqs:
            st.info("No items available.")
            return
        opts = {r['equipment_id']: f"{r['name']} ({r['available_qty']})" for r in eqs}
        sel  = st.multiselect("Up to 3 items", list(opts.values()), max_selections=3)
        borrow = []
        for lab in sel:
            eid = next(k for k,v in opts.items() if v==lab)
            maxq= min(2, next(r['available_qty'] for r in eqs if r['equipment_id']==eid))
            q   = st.number_input(f"Qty for {lab}", min_value=1, max_value=maxq, key=f"b{eid}")
            borrow.append((eid,q))
        if borrow and st.button("Confirm Borrow"):
            with st.spinner("Processing…"):
                cursor.execute(
                    "INSERT INTO borrow_requests (user_id,status) VALUES (%s,'confirmed')",
                    (st.session_state.user['user_id'],)
                )
                rid = cursor.lastrowid
                for eid,q in borrow:
                    cursor.execute(
                        "INSERT INTO borrow_items (request_id,equipment_id,quantity) VALUES (%s,%s,%s)",
                        (rid,eid,q)
                    )
                    cursor.execute(
                        "UPDATE equipment SET available_qty=available_qty-%s WHERE equipment_id=%s",
                        (q,eid)
                    )
                    cursor.execute(
                        "INSERT INTO inventory_log (equipment_id,quantity_change,action,user_id) "
                        "VALUES (%s,%s,'borrow',%s)",
                        (eid,-q,st.session_state.user['user_id'])
                    )
                cursor.execute(
                    "INSERT INTO borrow_history (request_id,action) VALUES (%s,'borrow')",
                    (rid,)
                )
                db.commit()
            code = f"BR{rid:05d}"
            buf  = io.BytesIO()
            qrcode.make(code).save(buf)
            st.image(buf.getvalue(), caption=code)
            st.success("Borrow confirmed!")
            st.balloons()

    elif choice == "Return Equipment":
        st.subheader("↩ Return Equipment")
        img = st.camera_input("Scan Borrow QR")
        if img:
            d = decode(Image.open(img))
            if not d:
                st.error("Invalid QR.")
            else:
                qr  = d[0].data.decode()
                rid = int(qr.replace("BR",""))
                if rid in st.session_state.returned_requests:
                    st.error("Already returned.")
                    return
                cursor.execute(
                    "SELECT * FROM borrow_requests WHERE request_id=%s AND status='confirmed'",
                    (rid,)
                )
                if not cursor.fetchone():
                    st.error("Invalid or already returned.")
                    return
                with st.spinner("Processing return…"):
                    cursor.execute(
                        "SELECT equipment_id,quantity FROM borrow_items WHERE request_id=%s",
                        (rid,)
                    )
                    its = cursor.fetchall()
                    for it in its:
                        cursor.execute(
                            "UPDATE equipment SET available_qty=available_qty+%s WHERE equipment_id=%s",
                            (it['quantity'], it['equipment_id'])
                        )
                        cursor.execute(
                            "INSERT INTO inventory_log (equipment_id,quantity_change,action,user_id) "
                            "VALUES (%s,%s,'return',%s)",
                            (it['equipment_id'], it['quantity'], st.session_state.user['user_id'])
                        )
                    cursor.execute(
                        "UPDATE borrow_requests SET status='cancelled' WHERE request_id=%s", (rid,)
                    )
                    cursor.execute(
                        "INSERT INTO borrow_history (request_id,action) VALUES (%s,'return')",
                        (rid,)
                    )
                    db.commit()
                st.session_state.returned_requests.add(rid)
                st.success("Return successful!")
                st.balloons()

    else:  # My History
        st.subheader("📜 My Borrowing History")
        with st.spinner("Loading…"):
            cursor.execute("""
                SELECT bh.performed_at, br.request_id, bh.action,
                       GROUP_CONCAT(CONCAT(bi.quantity,'×',e.name) SEPARATOR ', ') AS items,
                       br.status
                FROM borrow_history bh
                JOIN borrow_requests br USING(request_id)
                JOIN borrow_items bi USING(request_id)
                JOIN equipment e USING(equipment_id)
                WHERE br.user_id=%s
                GROUP BY bh.history_id
                ORDER BY bh.performed_at DESC
            """, (st.session_state.user['user_id'],))
            recs = cursor.fetchall()
        if not recs:
            st.info("No history yet.")
        else:
            for r in recs:
                st.write(f"[{r['performed_at']}]** Request #{r['request_id']} – {r['action'].title()}**")
                st.write(f"> {r['items']} • {r['status']}")
                st.markdown("---")

# ────────────────────────────────────────────────────────────────────────────────
# 10) MAIN FLOW
if not st.session_state.admin_exists:
    first_run_admin()
elif st.session_state.user is None:
    login_screen()
else:
    choice = init_sidebar()
    if st.session_state.role == "Admin/Staff":
        admin_dashboard(choice)
    else:
        student_dashboard(choice)

st.markdown('</div>', unsafe_allow_html=True)
st.markdown('<div class="footer">UMPSA Lab Equipment Lending App • © 2025</div>', unsafe_allow_html=True)
