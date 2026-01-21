import os
import json
import requests
from flask import Flask, render_template, redirect, url_for, session, jsonify, request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

app = Flask(__name__)
app.secret_key = 'wealthwise-email-secret-key' # In production, use a random secret

# Configuration
# Note: Using the specific filename found in your directory
CLIENT_SECRETS_FILE = "client_secret_555314315936-rr3b7ufe3e3l5dgd62vvsrcqe662lkpo.apps.googleusercontent.com.json"
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # For local development only

def get_gmail_service():
    if 'credentials' not in session:
        return None
    
    creds = Credentials(**session['credentials'])
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        session['credentials'] = credentials_to_dict(creds)
        
    return build('gmail', 'v1', credentials=creds)

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

def categorize_email(headers, snippet):
    """
    Smart categorization logic based on headers and context
    """
    subject = ""
    sender = ""
    list_unsubscribe = False
    
    for h in headers:
        if h['name'] == 'Subject': subject = h['value'].lower()
        if h['name'] == 'From': sender = h['value'].lower()
        if h['name'] == 'List-Unsubscribe': list_unsubscribe = True

    # Logic:
    # 1. Social
    if any(x in sender for x in ['facebook', 'twitter', 'linkedin', 'instagram', 'youtube']):
        return "Social"
    
    # 2. Finance / Bills
    if any(x in subject for x in ['invoice', 'bill', 'receipt', 'payment', 'order', 'statement', 'transaction']):
        return "Finance & Bills"
    
    # 3. Promotions / Newsletters
    if list_unsubscribe or any(x in sender for x in ['newsletter', 'marketing', 'info@', 'no-reply@']):
        return "Promotions"
    
    # 4. Updates / Notifications
    if any(x in subject for x in ['update', 'security', 'alert', 'verify', 'confirm']):
        return "Updates"

    # 5. Travel
    if any(x in subject for x in ['flight', 'hotel', 'booking', 'reservation', 'ticket']):
        return "Travel"

    return "Primary"

@app.route('/')
def index():
    if 'credentials' in session:
        return render_template('dashboard.html', user=session.get('user_info'))
    return render_template('dashboard.html', user=None)

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('authorize', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=session['state'])
    flow.redirect_uri = url_for('authorize', _external=True)
    
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    
    # Get user info for UI
    user_info = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()
    session['user_info'] = user_info
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/emails')
def get_emails():
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        # Fetch last 50 messages for speed
        results = service.users().messages().list(userId='me', maxResults=50).execute()
        messages = results.get('messages', [])
        
        categorized = {
            "Primary": [],
            "Social": [],
            "Promotions": [],
            "Updates": [],
            "Finance & Bills": [],
            "Travel": []
        }

        for msg in messages:
            m = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            payload = m.get('payload', {})
            headers = payload.get('headers', [])
            snippet = m.get('snippet', '')
            
            # Extract meta
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
            
            cat = categorize_email(headers, snippet)
            
            categorized[cat].append({
                "id": msg['id'],
                "subject": subject,
                "from": sender,
                "snippet": snippet,
                "date": next((h['value'] for h in headers if h['name'] == 'Date'), ''),
                "url": f"https://mail.google.com/mail/u/0/#inbox/{msg['id']}"
            })

        return jsonify(categorized)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Ensure templates folder exists and files are correct
    app.run(port=5000, debug=True)
