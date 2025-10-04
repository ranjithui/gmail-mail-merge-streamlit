"""
Streamlit Gmail Mail Merge — Updated with Email Validation
"""

import streamlit as st
import pandas as pd
import base64
import io
import json
import time
import re
from urllib.parse import urlencode
from email.mime.text import MIMEText

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError

st.set_page_config(page_title="Gmail Mail Merge", layout="wide")
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

# --------------------------
# Helper: load client config
# --------------------------
def load_client_config():
    try:
        gmail = st.secrets["gmail"]
        client_id = gmail["client_id"]
        client_secret = gmail["client_secret"]
        redirect_uri = gmail.get("redirect_uri", "http://localhost:8501/")
        client_config = {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        }
        return client_config, redirect_uri
    except Exception:
        st.error("Missing gmail client details in Streamlit secrets. Add [gmail] client_id and client_secret.")
        st.stop()

# --------------------------
# OAuth functions
# --------------------------
def start_oauth_flow(client_config, redirect_uri):
    flow = Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=redirect_uri)
    auth_url, _ = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="consent")
    return flow, auth_url


def exchange_code_for_creds(flow, code):
    flow.fetch_token(code=code)
    return flow.credentials

# --------------------------
# Email helpers
# --------------------------
EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

def create_message(sender, to, subject, message_text):
    to_clean = str(to).strip()
    if not EMAIL_REGEX.match(to_clean):
        raise ValueError(f"Invalid email address: {to_clean}")

    msg = MIMEText(message_text, "plain")
    msg["to"] = to_clean
    msg["from"] = sender
    msg["subject"] = subject
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    return {"raw": raw}

# --------------------------
# UI
# --------------------------
st.title("📧 Gmail Mail Merge — Streamlit")
client_config, redirect_uri = load_client_config()

# OAuth authentication UI code (same as before, omitted for brevity)
# --------------------------
# Upload CSV and email template
# --------------------------
uploaded = st.file_uploader("Upload CSV file with email addresses", type=["csv", "xlsx"])

if uploaded is not None:
    try:
        if uploaded.name.lower().endswith(".csv"):
            df = pd.read_csv(uploaded)
        else:
            df = pd.read_excel(uploaded)
    except Exception as e:
        st.error(f"Failed to read file: {e}")
        st.stop()

    st.success(f"Loaded {len(df)} contacts")
    st.dataframe(df.head(20))

    email_col = st.selectbox("Select email column", options=list(df.columns), index=0)
    st.markdown("Use placeholders in the template that match your column names, e.g., {name}, {company}.")
    subject = st.text_input("Email subject", value="Hello {name}")
    body = st.text_area("Email body", height=200, value="Dear {name},\n\nThis is a test email.\n\nRegards,\nYour team")

    batch_size = st.number_input("Batch size", min_value=1, max_value=100, value=20)
    pause_sec = st.number_input("Pause seconds between batches", min_value=0, max_value=10, value=2)
    send_button = st.button("🚀 Send emails")

    if send_button:
        if "creds" not in st.session_state:
            st.error("Please authenticate first.")
            st.stop()

        creds = Credentials.from_authorized_user_info(json.loads(st.session_state["creds"]), SCOPES)
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            st.session_state["creds"] = creds.to_json()

        service = build("gmail", "v1", credentials=creds)

        total = len(df)
        sent = 0
        errors = []
        progress = st.progress(0)

        for i, row in df.iterrows():
            to_addr = row[email_col]
            context = row.to_dict()
            try:
                formatted_subject = subject.format(**context)
                formatted_body = body.format(**context)
                msg = create_message("me", to_addr, formatted_subject, formatted_body)
                service.users().messages().send(userId="me", body=msg).execute()
                sent += 1
                progress.progress(min(1.0, sent / total))
                st.write(f"✅ Sent to {to_addr}")
            except ValueError as ve:
                st.warning(f"Skipping {to_addr}: {ve}")
                errors.append((to_addr, str(ve)))
            except HttpError as he:
                st.error(f"Failed to send to {to_addr}: {he}")
                errors.append((to_addr, str(he)))

            if (i + 1) % batch_size == 0:
                time.sleep(pause_sec)

        st.success(f"Done. Sent: {sent}. Errors: {len(errors)}")
        if errors:
            st.write("Errors (first 10):")
            st.write(errors[:10])
