import os
import json
import requests
import sys
from flask import Flask, render_template, redirect, url_for, session, jsonify, request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

app = Flask(__name__)
# IMPORTANT: Ensure FLASK_SECRET_KEY is set in Vercel Env Vars. 
# If not, sessions will reset on every redeploy/cold start.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'wealthwise-email-dev-key')

# Vercel Proxy Fixes
if os.environ.get('VERCEL_URL'):
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax', # Required for cross-site redirects (Google -> App)
        PREFERRED_URL_SCHEME='https'
    )
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'
else:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']

def get_google_config():
    env_config = os.environ.get('GOOGLE_CLIENT_CONFIG')
    config = None
    if env_config:
        try:
            config = json.loads(env_config)
        except Exception:
            return None
    else:
        client_secrets_file = "client_secret_555314315936-rr3b7ufe3e3l5dgd62vvsrcqe662lkpo.apps.googleusercontent.com.json"
        if os.path.exists(client_secrets_file):
            with open(client_secrets_file, 'r') as f:
                config = json.load(f)
    
    if config and 'web' in config:
        return config['web']
    return config

def get_flow(state=None):
    config = get_google_config()
    if not config:
        raise ValueError("Google Client Configuration is missing.")
    
    flow = Flow.from_client_config(config, scopes=SCOPES, state=state)
    
    # DYNAMIC REDIRECT URI
    # Instead of hardcoding, we use the host that the user is actually visiting.
    # This handles both the .vercel.app domain and any custom domains.
    if os.environ.get('VERCEL_URL'):
        # On Vercel, force HTTPS and use the current host
        flow.redirect_uri = f"https://{request.host}/authorized"
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
    try:
        flow = get_flow()
        authorization_url, state = flow.authorization_url(
            access_type='offline', 
            include_granted_scopes='true',
            prompt='select_account' # Forces account selection to prevent auto-login loops
        )
        session['state'] = state
        # Ensure session is saved before redirecting
        session.modified = True
        return redirect(authorization_url)
    except Exception as e:
        return f"Login Error: {str(e)}", 500

@app.route('/authorized')
def authorize():
    try:
        # 1. Retrieve the state we stored in /login
        state = session.get('state')
        if not state:
            return "Authorization Error: Session state missing. Please enable cookies and try again.", 400
            
        flow = get_flow(state=state)
        
        # 2. Reconstruct the full URL for verification
        # Google returns the response to the Vercel proxy via HTTP internally.
        # We must force it back to HTTPS for the library to validate it.
        authorization_response = request.url
        if os.environ.get('VERCEL_URL') and authorization_response.startswith('http://'):
            authorization_response = authorization_response.replace('http://', 'https://', 1)
            
        flow.fetch_token(authorization_response=authorization_response)
        
        # 3. Save credentials and user info
        credentials = flow.credentials
        session['credentials'] = credentials_to_dict(credentials)
        
        user_info = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()
        session['user_info'] = user_info
        
        # 4. Cleanup
        session.pop('state', None)
        session.modified = True
        
        return redirect(url_for('index'))
    except Exception as e:
        return f"Authorization Error: {str(e)}", 500

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/emails')
def get_emails():
    if 'credentials' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    creds = Credentials(**session['credentials'])
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            session['credentials'] = credentials_to_dict(creds)
        except:
            return jsonify({"error": "Auth Refresh Failed"}), 401
            
    service = build('gmail', 'v1', credentials=creds)

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
            
            cat = "Primary"
            sender_l = sender.lower()
            subj_l = subject.lower()
            
            if any(x in sender_l for x in ['facebook', 'twitter', 'linkedin', 'instagram', 'youtube']): cat = "Social"
            elif any(x in subj_l for x in ['invoice', 'bill', 'receipt', 'payment', 'order']): cat = "Finance & Bills"
            elif any(x in subj_l for x in ['flight', 'hotel', 'booking']): cat = "Travel"
            elif 'newsletter' in sender_l or 'marketing' in sender_l: cat = "Promotions"
            elif 'update' in subj_l or 'security' in subj_l: cat = "Updates"
            
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
    app.run(port=5000, debug=True)
