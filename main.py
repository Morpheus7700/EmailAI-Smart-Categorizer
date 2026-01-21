import os
import json
import requests
from flask import Flask, render_template, redirect, url_for, session, jsonify, request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'wealthwise-email-dev-key')

# Force HTTPS for OAuth in production
if os.environ.get('VERCEL_URL'):
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'
else:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']

def get_google_config():
    """Returns and unwraps the Google Client Config"""
    env_config = os.environ.get('GOOGLE_CLIENT_CONFIG')
    config = None
    
    if env_config:
        config = json.loads(env_config)
    else:
        # Fallback to local file
        client_secrets_file = "client_secret_555314315936-rr3b7ufe3e3l5dgd62vvsrcqe662lkpo.apps.googleusercontent.com.json"
        if os.path.exists(client_secrets_file):
            with open(client_secrets_file, 'r') as f:
                config = json.load(f)
    
    if config and 'web' in config:
        return config['web'] # Unwrap the "web" key
    return config

def get_flow(state=None):
    config = get_google_config()
    if not config:
        raise Exception("Google Client Configuration missing!")
    
    flow = Flow.from_client_config(config, scopes=SCOPES, state=state)
    
    # FORCE EXACT REDIRECT URI from your Google Console Screenshot
    if os.environ.get('VERCEL_URL'):
        # We use the official domain to ensure it matches the Google whitelist perfectly
        flow.redirect_uri = "https://email-ai-smart-categorizer.vercel.app/authorized"
    else:
        flow.redirect_uri = url_for('authorize', _external=True)
    
    return flow

@app.route('/')
def index():
    if 'credentials' in session:
        return render_template('dashboard.html', user=session.get('user_info'))
    return render_template('dashboard.html', user=None)

@app.route('/login')
def login():
    flow = get_flow()
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/authorized')
def authorize():
    flow = get_flow(state=session.get('state'))
    
    authorization_response = request.url
    if 'http://' in authorization_response and os.environ.get('VERCEL_URL'):
        authorization_response = authorization_response.replace('http://', 'https://')
        
    flow.fetch_token(authorization_response=authorization_response)
    
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    
    user_info = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()
    session['user_info'] = user_info
    
    return redirect(url_for('index'))

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
    subject = ""
    sender = ""
    list_unsubscribe = False
    for h in headers:
        if h['name'] == 'Subject': subject = h['value'].lower()
        if h['name'] == 'From': sender = h['value'].lower()
        if h['name'] == 'List-Unsubscribe': list_unsubscribe = True

    if any(x in sender for x in ['facebook', 'twitter', 'linkedin', 'instagram', 'youtube']):
        return "Social"
    if any(x in subject for x in ['invoice', 'bill', 'receipt', 'payment', 'order', 'statement', 'transaction']):
        return "Finance & Bills"
    if list_unsubscribe or any(x in sender for x in ['newsletter', 'marketing', 'info@', 'no-reply@']):
        return "Promotions"
    if any(x in subject for x in ['update', 'security', 'alert', 'verify', 'confirm']):
        return "Updates"
    if any(x in subject for x in ['flight', 'hotel', 'booking', 'reservation', 'ticket']):
        return "Travel"
    return "Primary"

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
        results = service.users().messages().list(userId='me', maxResults=50).execute()
        messages = results.get('messages', [])
        
        categorized = {
            "Primary": [], "Social": [], "Promotions": [], 
            "Updates": [], "Finance & Bills": [], "Travel": []
        }

        for msg in messages:
            m = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            payload = m.get('payload', {})
            headers = payload.get('headers', [])
            snippet = m.get('snippet', '')
            
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

def get_gmail_service():
    if 'credentials' not in session:
        return None
    creds = Credentials(**session['credentials'])
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        session['credentials'] = credentials_to_dict(creds)
    return build('gmail', 'v1', credentials=creds)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
