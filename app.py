from flask import Flask, request, jsonify, session, redirect, render_template
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import base64
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# OAuth configuration
CLIENT_CONFIG = {
    "web": {
        "client_id": os.getenv('GOOGLE_CLIENT_ID'),
        "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [os.getenv('GOOGLE_REDIRECT_URI')],
        "javascript_origins": ["http://localhost:5001", "http://127.0.0.1:5001"]
    }
}

SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/userinfo.email'
]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth/google')
def google_auth():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri=os.getenv('GOOGLE_REDIRECT_URI')
    )
    
    # Generate URL for request to Google's OAuth 2.0 server
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    
    # Store the state in the session
    session['state'] = state
    
    return jsonify({'url': authorization_url})

@app.route('/oauth2callback')
def oauth2callback():
    # Verify state parameter
    if 'state' not in session:
        return redirect('/auth/google')  # Start over if state is missing
    
    try:
        flow = Flow.from_client_config(
            CLIENT_CONFIG,
            scopes=SCOPES,
            state=session['state'],
            redirect_uri=os.getenv('GOOGLE_REDIRECT_URI')
        )
        
        # Fetch the access token
        flow.fetch_token(authorization_response=request.url)
        
        # Store credentials in session
        credentials = flow.credentials
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        # Clean up the session state
        session.pop('state', None)
        
        return redirect('/')
        
    except Exception as e:
        print(f"Error in oauth2callback: {str(e)}")
        return redirect('/auth/google')  # Restart auth flow on error

@app.route('/auth/status')
def auth_status():
    if 'credentials' not in session:
        return jsonify({'authenticated': False})
    
    try:
        credentials = Credentials(**session['credentials'])
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        return jsonify({
            'authenticated': True,
            'email': user_info.get('email')
        })
    except Exception:
        return jsonify({'authenticated': False})

@app.route('/send-email', methods=['POST'])
def send_email():
    if 'credentials' not in session:
        return jsonify({'success': False, 'error': 'auth_required'})

    try:
        credentials = Credentials(**session['credentials'])
        service = build('gmail', 'v1', credentials=credentials)
        
        data = request.json
        message = MIMEText(data['body'])
        message['to'] = data['recipient']
        message['subject'] = data['subject']
        
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error sending email: {type(e).__name__}")
        return jsonify({'success': False, 'error': 'Failed to send email'})

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    port = int(os.getenv('PORT', 5001))
    app.run(debug=debug, port=port) 