import os
import json
import requests
from flask import Flask, render_template, redirect, url_for, session, jsonify, request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import google.generativeai as genai
from google.cloud import firestore
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-key-123')

# Admin Email - REPLACE THIS WITH YOUR EMAIL
ADMIN_EMAIL = "aniketroy2k@gmail.com"

# Initialize Firestore
# Note: In Cloud Run, it uses the service account automatically.
db = firestore.Client()

# Production / Proxy Configuration
is_production = os.environ.get('K_SERVICE') or os.environ.get('VERCEL_URL')
if is_production:
    # Optimized for Cloud Run and other production environments behind proxies
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PREFERRED_URL_SCHEME='https'
    )
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'
else:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Audit Log for AI (Last 5 batches)
ai_audit_logs = []

# Gemini Setup
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    
    # System Instruction for the model
    system_instruction = """You are an expert email triaging assistant. 
Categorize emails into Social, Promotions, Updates, Finance & Bills, Travel, or Primary.
CRITICAL: Only use 'Primary' for human-to-human personal emails. Be aggressive with other categories."""
    
    model = genai.GenerativeModel(
        model_name='gemini-1.5-flash',
        system_instruction=system_instruction,
        generation_config={
            "response_mime_type": "application/json",
            "response_schema": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "enum": ["Primary", "Social", "Promotions", "Updates", "Finance & Bills", "Travel"]
                        },
                        "reasoning": {"type": "string"}
                    },
                    "required": ["category", "reasoning"]
                }
            }
        }
    )

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']

def get_google_config():
    env_config = os.environ.get('GOOGLE_CLIENT_CONFIG')
    if env_config:
        return json.loads(env_config)
    client_secrets_file = "client_secret.json"
    if os.path.exists(client_secrets_file):
        with open(client_secrets_file, 'r') as f:
            return json.load(f)
    return None

def get_flow(state=None):
    config = get_google_config()
    if not config: raise ValueError("Google Client Configuration is missing.")
    flow = Flow.from_client_config(config, scopes=SCOPES, state=state)
    if os.environ.get('REDIRECT_URI'):
        flow.redirect_uri = os.environ['REDIRECT_URI']
    elif is_production:
        flow.redirect_uri = f"https://{request.host}/authorized"
    else:
        flow.redirect_uri = url_for('authorize', _external=True)
    return flow

# --- USER ROUTES ---

@app.route('/')
def index():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return render_template('login.html')
        
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            session.clear()
            return redirect(url_for('login_page'))
        
        user_data = user_doc.to_dict()
        return render_template('dashboard.html', user=user_data, is_admin=(user_data.get('email') == ADMIN_EMAIL))
    except Exception as e:
        app.logger.error(f"Index error: {str(e)}")
        return f"System Error: {str(e)}. Please check if Firestore is enabled and service account has permissions.", 500

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            
            user_ref = db.collection('users').document(email)
            if user_ref.get().exists:
                return "User already exists", 400
            
            user_ref.set({
                'email': email,
                'password': generate_password_hash(password),
                'gmail_connected': False
            })
            session['user_id'] = email
            return redirect(url_for('index', _external=True, _scheme='https' if is_production else 'http'))
        except Exception as e:
            app.logger.error(f"Signup error: {str(e)}")
            return f"Signup Error: {str(e)}. Check Firestore/Environment variables.", 500
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            
            user_doc = db.collection('users').document(email).get()
            if user_doc.exists and check_password_hash(user_doc.to_dict()['password'], password):
                session['user_id'] = email
                # Use a specific redirect to avoid relative path issues in some proxies
                return redirect(url_for('index', _external=True, _scheme='https' if is_production else 'http'))
            return "Invalid credentials", 401
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            return f"Login Error: {str(e)}. Check Firestore/Environment variables.", 500
    return render_template('login.html')

# --- GMAIL OAUTH ROUTES ---

@app.route('/connect-gmail')
def connect_gmail():
    if 'user_id' not in session: return redirect(url_for('login_page'))
    flow = get_flow()
    auth_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true', prompt='consent')
    session['state'] = state
    return redirect(auth_url)

@app.route('/authorized')
def authorize():
    try:
        state = session.get('state')
        flow = get_flow(state=state)
        auth_resp = request.url
        if is_production and auth_resp.startswith('http://'):
            auth_resp = auth_resp.replace('http://', 'https://', 1)
        
        flow.fetch_token(authorization_response=auth_resp)
        creds = flow.credentials
        
        # Save tokens to Firestore for the logged-in user
        user_id = session.get('user_id')
        user_info = build('oauth2', 'v2', credentials=creds).userinfo().get().execute()
        
        db.collection('users').document(user_id).update({
            'gmail_connected': True,
            'gmail_email': user_info.get('email'),
            'gmail_name': user_info.get('name'),
            'gmail_picture': user_info.get('picture'),
            'tokens': {
                'token': creds.token,
                'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes
            }
        })
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {str(e)}", 500

# --- ADMIN ROUTES ---

@app.route('/admin')
def admin_panel():
    user_id = session.get('user_id')
    if user_id != ADMIN_EMAIL:
        return "Unauthorized", 403
    
    users = [u.to_dict() for u in db.collection('users').stream()]
    return render_template('admin.html', users=users)

@app.route('/api/status')
def api_status():
    """Diagnostic route to check API and Model status."""
    status = {
        "gemini_api_key_set": bool(GEMINI_API_KEY),
        "model_initialized": 'model' in globals(),
        "is_production": bool(is_production),
        "admin_email": ADMIN_EMAIL
    }
    return jsonify(status)

@app.route('/api/logs')
def get_ai_logs():
    """Returns the last few AI audit logs."""
    return jsonify(ai_audit_logs)

@app.route('/api/emails')
def get_emails():
    user_id = session.get('user_id')
    if not user_id: return jsonify({"error": "Unauthorized"}), 401
    
    user_data = db.collection('users').document(user_id).get().to_dict()
    if not user_data.get('gmail_connected'): return jsonify({"error": "Gmail not connected"}), 400

    creds_dict = user_data['tokens']
    creds = Credentials(**creds_dict)
    
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        db.collection('users').document(user_id).update({'tokens.token': creds.token})
            
    service = build('gmail', 'v1', credentials=creds)
    try:
        results = service.users().messages().list(userId='me', maxResults=100).execute()
        messages = results.get('messages', [])
        email_list = []
        for msg in messages:
            m = service.users().messages().get(userId='me', id=msg['id'], format='metadata').execute()
            headers = m.get('payload', {}).get('headers', [])
            email_list.append({
                "id": msg['id'],
                "subject": next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)'),
                "from": next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown'),
                "list_id": next((h['value'] for h in headers if h['name'] == 'List-ID'), None),
                "snippet": m.get('snippet', ''),
                "date": next((h['value'] for h in headers if h['name'] == 'Date'), ''),
                "url": f"https://mail.google.com/mail/u/0/#inbox/{msg['id']}"
            })

        categorized_lists = {"Primary":[], "Social":[], "Promotions":[], "Updates":[], "Finance & Bills":[], "Travel":[]}
        
        # Normalization mapping
        CAT_MAP = {
            "primary": "Primary",
            "social": "Social",
            "promotions": "Promotions",
            "promo": "Promotions",
            "updates": "Updates",
            "update": "Updates",
            "finance & bills": "Finance & Bills",
            "finance": "Finance & Bills",
            "bills": "Finance & Bills",
            "travel": "Travel"
        }
        
        batch_size = 5 # Small batch for max accuracy
        for i in range(0, len(email_list), batch_size):
            batch = email_list[i:i+batch_size]
            app.logger.info(f"--- START BATCH {i//batch_size + 1} ---")
            results = ai_categorize_batch(batch)
            
            for j, email in enumerate(batch):
                # Fallback logic
                res = results[j] if results and j < len(results) else {"category": "Primary", "reasoning": "Fallback"}
                cat = res.get('category', 'Primary')
                
                # Double check normalization
                normalized_cat = CAT_MAP.get(cat.lower().strip(), "Primary")
                if normalized_cat not in categorized_lists:
                    normalized_cat = "Primary"
                
                email['reasoning'] = res.get('reasoning', '')
                categorized_lists[normalized_cat].append(email)
                app.logger.info(f"Email: {email['subject'][:30]}... -> Cat: {cat} -> Reason: {res.get('reasoning')}")
        
        final_counts = {k: len(v) for k, v in categorized_lists.items()}
        app.logger.info(f"FINAL CATEGORIZATION: {final_counts}")
        return jsonify(categorized_lists)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def ai_categorize_batch(emails):
    if not GEMINI_API_KEY: return None
    
    structured_data = []
    for e in emails:
        structured_data.append({
            "from": e.get('from'),
            "subject": e.get('subject'),
            "snippet": e.get('snippet', '')[:100]
        })

    try:
        # The model already has the response_schema and system_instruction 
        # from our previous edit to its initialization.
        response = model.generate_content(json.dumps(structured_data))
        results = json.loads(response.text.strip())
        
        # Save to global audit log for the /api/logs route
        global ai_audit_logs
        ai_audit_logs.insert(0, {
            "timestamp": "Latest Batch",
            "input": structured_data,
            "output": results
        })
        ai_audit_logs = ai_audit_logs[:5] 
        
        return results
    except Exception as e:
        app.logger.error(f"GEMINI ERROR: {str(e)}")
        return None

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    app.run(port=5000, debug=True)