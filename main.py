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

# Production / Proxy Configuration (Cloud Run, Vercel, etc.)
# Check for K_SERVICE (Cloud Run) or VERCEL_URL (Vercel) to detect production environment
is_production = os.environ.get('K_SERVICE') or os.environ.get('VERCEL_URL')

if is_production:
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
        # Try generic name first, then specific if needed
        client_secrets_file = "client_secret.json"
        if os.path.exists(client_secrets_file):
            with open(client_secrets_file, 'r') as f:
                config = json.load(f)
    
    return config

def get_flow(state=None):
    config = get_google_config()
    if not config:
        raise ValueError("Google Client Configuration is missing.")
    
    flow = Flow.from_client_config(config, scopes=SCOPES, state=state)
    
    # DYNAMIC REDIRECT URI
    # Support explicit overwrite via env var (Best for Cloud Run/Production)
    if os.environ.get('REDIRECT_URI'):
        flow.redirect_uri = os.environ['REDIRECT_URI']
    elif is_production:
        # On Cloud Run/Vercel, force HTTPS and use the current host
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
        
        # FIX: Ensure HTTPS is used for validation if running behind a proxy (Vercel/Cloud Run)
        # Cloud Run sets K_SERVICE, Vercel sets VERCEL_URL
        if is_production and authorization_response.startswith('http://'):
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

import google.generativeai as genai

# Setup Gemini
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-1.5-flash')

def ai_categorize_batch(emails):
    """Uses Gemini to categorize a batch of emails based on context."""
    if not GEMINI_API_KEY:
        print("DEBUG: No GEMINI_API_KEY found. Using manual fallback.")
        return None
    
    prompt = """
    You are an expert email organizer. Categorize these 20 emails into EXACTLY one of these buckets:
    - 'Primary': Personal 1-to-1 emails, direct work communications, or important human-sent messages.
    - 'Social': Notifications from LinkedIn, Facebook, Twitter, Instagram, YouTube, or dating apps.
    - 'Promotions': Marketing emails, newsletters, sales, discounts, or coupons.
    - 'Updates': Automated alerts, security notices, password resets, shipping updates, or service announcements.
    - 'Finance & Bills': Bank statements, invoices, receipts, payment confirmations, or salary slips.
    - 'Travel': Flight tickets, hotel bookings, car rentals, or trip itineraries.

    Rules:
    1. Be aggressive. If it looks like a newsletter, it's 'Promotions'. If it's a notification from a service, it's 'Updates'.
    2. Respond ONLY with a valid JSON list of strings (e.g., ["Primary", "Social", ...]).
    3. The list MUST have exactly 20 items in the same order as the input.
    """
    
    email_data = [f"From: {e['from']} | Sub: {e['subject']} | Snippet: {e['snippet']}" for e in emails]
    try:
        response = model.generate_content(prompt + "\n\nEmails to categorize:\n" + json.dumps(email_data))
        text = response.text.strip()
        # Clean up Markdown
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
            
        categories = json.loads(text)
        print(f"DEBUG: AI Categorized {len(emails)} emails successfully.")
        return categories
    except Exception as e:
        print(f"DEBUG: AI Error: {str(e)}")
        return None

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
        # Increase limit to 100 for better robustness
        results = service.users().messages().list(userId='me', maxResults=100).execute()
        messages = results.get('messages', [])
        
        email_list = []
        for msg in messages:
            # We use format='metadata' to be faster while getting headers
            m = service.users().messages().get(userId='me', id=msg['id'], format='metadata').execute()
            headers = m.get('payload', {}).get('headers', [])
            
            email_list.append({
                "id": msg['id'],
                "subject": next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)'),
                "from": next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown'),
                "snippet": m.get('snippet', ''),
                "date": next((h['value'] for h in headers if h['name'] == 'Date'), ''),
                "url": f"https://mail.google.com/mail/u/0/#inbox/{msg['id']}"
            })

        categorized = {
            "Primary": [], "Social": [], "Promotions": [], 
            "Updates": [], "Finance & Bills": [], "Travel": []
        }

        # Batch process with AI
        for i in range(0, len(email_list), 20):
            batch = email_list[i:i+20]
            # Ensure the batch has exactly 20 items for the prompt rules, or handle the remainder
            categories = ai_categorize_batch(batch)
            
            for j, email in enumerate(batch):
                cat = "Primary" # Default
                if categories and j < len(categories):
                    cat = categories[j].strip()
                else:
                    # Robust manual fallback if AI is unavailable
                    s = (email['from'] + " " + email['subject']).lower()
                    if any(x in s for x in ['linkedin', 'facebook', 'twitter', 'instagram', 'youtube']): cat = "Social"
                    elif any(x in s for x in ['invoice', 'receipt', 'bill', 'payment', 'order']): cat = "Finance & Bills"
                    elif any(x in s for x in ['flight', 'hotel', 'booking', 'itinerary']): cat = "Travel"
                    elif any(x in s for x in ['newsletter', 'marketing', 'offer', 'sale']): cat = "Promotions"
                    elif any(x in s for x in ['security', 'alert', 'notice', 'password']): cat = "Updates"
                
                # Validation
                if cat not in categorized: cat = "Primary"
                categorized[cat].append(email)

        return jsonify(categorized)
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)
