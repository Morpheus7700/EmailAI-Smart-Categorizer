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
# Use Environment Variable for secret key
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'wealthwise-email-dev-key')

# Vercel-specific session cookie settings to prevent state mismatch
if os.environ.get('VERCEL_URL'):
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'
else:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']

def get_google_config():
    """Returns the Google Client Config in the format expected by the library"""
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
    
    # The library expects {"web": {...}} or {"installed": {...}}
    # If the user provided the inner dict, wrap it.
    # If the user provided the full dict (which you did), keep it as is.
    if config and 'web' not in config and 'installed' not in config:
        return {"web": config}
    
    return config

def get_flow(state=None):
    config = get_google_config()
    if not config:
        raise ValueError("Google Client Configuration is missing or invalid.")
    
    flow = Flow.from_client_config(config, scopes=SCOPES, state=state)
    
    # Hardcoded redirect to match your screenshot exactly
    if os.environ.get('VERCEL_URL'):
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
    try:
        flow = get_flow()
        authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
        session['state'] = state
        return redirect(authorization_url)
    except Exception as e:
        return f"Login Error: {str(e)}", 500

@app.route('/authorized')
def authorize():
    try:
        # Get state from session
        state = session.get('state')
        if not state:
            return "Authorization Error: State missing in session. Please try logging in again.", 400
            
        flow = get_flow(state=state)
        
        authorization_response = request.url
        if 'http://' in authorization_response and os.environ.get('VERCEL_URL'):
            authorization_response = authorization_response.replace('http://', 'https://')
            
        flow.fetch_token(authorization_response=authorization_response)
        
        credentials = flow.credentials
        session['credentials'] = credentials_to_dict(credentials)
        
        # Build OAuth2 service to get user info
        oauth2_service = build('oauth2', 'v2', credentials=credentials)
        user_info = oauth2_service.userinfo().get().execute()
        session['user_info'] = user_info
        
        # Clean up state
        session.pop('state', None)
        
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
            
            # Simple Categorization
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