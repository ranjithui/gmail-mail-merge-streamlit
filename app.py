"""
Streamlit Gmail Mail Merge
-------------------------
Single-file Streamlit app that performs a mail-merge using the Gmail API.

How it meets your requirements:
- Uses OAuth but does NOT hardcode client secrets in the repo. It expects credentials in Streamlit Secrets.
- Allows different users to authenticate with their own Gmail account (each user performs OAuth in their browser).
- Ready to deploy to Streamlit Cloud (see instructions below).

Files / Secrets expected (put in Streamlit Cloud "Secrets")
----------------------------------------------------------
In Streamlit Cloud: set the following in Settings -> Secrets (secrets.toml)

[gmail]
client_id = "YOUR_CLIENT_ID.apps.googleusercontent.com"
client_secret = "YOUR_CLIENT_SECRET"
# Optional: redirect_uri - set to your deployed Streamlit app URL, e.g. "https://your-app.streamlit.app/"
redirect_uri = "http://localhost:8501/"

Required pip packages (put in requirements.txt in your repo):
streamlit
pandas
google-auth
google-auth-oauthlib
google-api-python-client

Google Cloud Console setup (summary):
1. Create a Google Cloud Project and enable the Gmail API.
2. Create OAuth 2.0 Client ID (type: Web application). Add an Authorized redirect URI matching
   the redirect_uri in your secrets (e.g. https://your-app.streamlit.app/).
3. Take the client_id and client_secret and paste them into Streamlit Secrets as above.

Notes:
- Each user authenticates with Google in their own browser; tokens are held in-session (you may choose to
  implement persistent storage per user if you have a backend).
- Google has quotas and anti-spam rules. Test with a small list first.

"""

import streamlit as st
import pandas as pd
import base64
import io
import json
import time
from urllib.parse import urlencode

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError

# --------------------------
# Config / Constants
# --------------------------
st.set_page_config(page_title="Gmail Mail Merge", layout="wide")
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

# --------------------------
# Helper: load client config from Streamlit secrets
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
    except Exception as e:
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
    creds = flow.credentials
    return creds

# --------------------------
# Email helpers
# --------------------------

def create_message(sender, to, subject, body_text):
    message = f"From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body_text}"
    raw = base64.urlsafe_b64encode(message.encode("utf-8")).decode("utf-8")
    return {"raw": raw}

# --------------------------
# UI
# --------------------------
st.title("📧 Gmail Mail Merge — Streamlit")
st.caption("Each user signs in with their own Gmail account. Client secrets must live in Streamlit Secrets, not the repo.")

client_config, redirect_uri = load_client_config()

col1, col2 = st.columns([2, 1])

with col1:
    st.header("1) Authenticate with Google")
    # Show link / flow
    if "creds" not in st.session_state:
        st.info("To send emails, you must authorize this app to send emails on your behalf.")

    # If the browser was redirected back with a code, capture it
    query_params = st.experimental_get_query_params()
    if "code" in query_params and "creds" not in st.session_state:
        # User was redirected back from Google's consent screen
        code = query_params.get("code")[0]
        try:
            flow = Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=redirect_uri)
            creds = exchange_code_for_creds(flow, code)
            st.session_state["creds"] = creds.to_json()
            st.success("Authentication succeeded — credentials stored in session.")
        except Exception as e:
            st.error(f"Failed to fetch token: {e}")

    if "creds" not in st.session_state:
        flow, auth_url = start_oauth_flow(client_config, redirect_uri)
        st.markdown("**Authorize this app**: click the link below, sign in with your Google account, and grant permission.\n\nAfter consent you'll be redirected back to this page.\nIf your browser does not auto-redirect, copy the `code` query parameter from the redirected URL and paste it in the box below.")
        st.write(f"Open the following URL (it opens in a new tab):")
        st.write(auth_url)
        st.markdown("---")
        pasted_code = st.text_input("If you were given a code paste it here (optional)")
        if pasted_code and "creds" not in st.session_state:
            try:
                creds = exchange_code_for_creds(flow, pasted_code)
                st.session_state["creds"] = creds.to_json()
                st.experimental_rerun()
            except Exception as e:
                st.error(f"Token exchange failed: {e}")
    else:
        st.success("✅ You are authenticated (token in session).")
        if st.button("🔓 Sign out (clear session token)"):
            st.session_state.pop("creds", None)
            st.experimental_rerun()

    # Offer token download so user can keep it for future sessions
    if "creds" in st.session_state:
        st.markdown("**Optional:** Download your token.json (keep private).")
        st.download_button("Download token.json", data=st.session_state["creds"], file_name="token.json")

with col2:
    st.header("Quick setup checklist")
    st.markdown("""
- Create Google Cloud project + enable Gmail API.
- Create OAuth Client ID (Web app). Add redirect URI matching your Streamlit app.
- Put client_id and client_secret into Streamlit Secrets under `[gmail]`.
- Deploy this repo to Streamlit Cloud.
""")
    st.markdown("---")
    st.markdown("**Secrets example** (in Streamlit Cloud -> Secrets):")
    st.code("""[gmail]
client_id = "..."
client_secret = "..."
redirect_uri = "https://your-app.streamlit.app/"
""", language="toml")

st.write("---")

# --------------------------
# Mail merge UI
# --------------------------
st.header("2) Upload contacts & write template")
uploaded = st.file_uploader("Upload CSV file with columns (email, name, etc.)", type=["csv", "xlsx"])

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
    st.markdown("Use placeholders in the template that match your column names, e.g. {name}, {company}.")
    subject = st.text_input("Email subject (you can use placeholders)", value="Hello {name}")
    body = st.text_area("Email body (plain text). Use placeholders like {name}.", height=200, value="Dear {name},\n\nThis is a test email.\n\nRegards,\nYour team")

    send_col1, send_col2 = st.columns([1, 3])
    with send_col1:
        batch_size = st.number_input("Batch size (pause after each batch)", min_value=1, max_value=100, value=20)
        pause_sec = st.number_input("Pause seconds between batches", min_value=0, max_value=10, value=2)
    with send_col2:
        send_button = st.button("🚀 Send emails")

    # --------------------------
    # Sending logic
    # --------------------------
    if send_button:
        if "creds" not in st.session_state:
            st.error("Please authenticate first.")
            st.stop()

        creds = Credentials.from_authorized_user_info(json.loads(st.session_state["creds"]), SCOPES)
        # refresh if needed
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                st.session_state["creds"] = creds.to_json()
            except Exception as e:
                st.error(f"Failed to refresh token: {e}")
                st.stop()

        try:
            service = build("gmail", "v1", credentials=creds)
        except Exception as e:
            st.error(f"Failed to build Gmail service: {e}")
            st.stop()

        total = len(df)
        progress = st.progress(0)
        sent = 0
        errors = []

        for i, row in df.iterrows():
            try:
                to_addr = row[email_col]
                context = row.to_dict()
                try:
                    formatted_subject = subject.format(**context)
                    formatted_body = body.format(**context)
                except Exception as e:
                    # placeholder formatting error
                    formatted_subject = subject
                    formatted_body = body
                    st.warning(f"Formatting error for row {i}: {e}")

                msg = create_message("me", to_addr, formatted_subject, formatted_body)
                send_result = service.users().messages().send(userId="me", body=msg).execute()
                sent += 1
                progress.progress(min(1.0, sent / total))
                st.write(f"✅ Sent to {to_addr}")
            except HttpError as he:
                errors.append((to_addr, str(he)))
                st.error(f"Failed to send to {to_addr}: {he}")
            except Exception as e:
                errors.append((to_addr if 'to_addr' in locals() else 'unknown', str(e)))
                st.error(f"Failed to send to {row.get(email_col,'unknown')}: {e}")

            # batching
            if (i + 1) % batch_size == 0:
                time.sleep(pause_sec)

        st.success(f"Done. Sent: {sent}. Errors: {len(errors)}")
        if errors:
            st.write("Errors (first 10):")
            st.write(errors[:10])

else:
    st.info("Upload a CSV/XLSX to get started.")

# --------------------------
# Footer / Notes
# --------------------------
st.write("---")
st.markdown("**Security & notes:**\n- Never commit client secrets or token files to a public repo. Use Streamlit Secrets for client credentials.\n- Tokens issued to each user live in their browser session. If you want server-side persistent tokens per user, you'll need a secure backend.\n- Respect Gmail sending limits and anti-spam policies.")

# End of file
