# Email Service

## Setup

1. Clone the repository
2. Copy `.env.example` to `.env`
3. Fill in your credentials in `.env`:
   - Generate FLASK_SECRET_KEY using `python -c "import secrets; print(secrets.token_hex(32))"`
   - Add your Google OAuth credentials from Google Cloud Console
4. Install dependencies: `pip install -r requirements.txt`
5. Run the application: `python app.py`

## Environment Variables

- `FLASK_SECRET_KEY`: Secret key for Flask sessions
- `GOOGLE_CLIENT_ID`: Your Google OAuth client ID
- `GOOGLE_CLIENT_SECRET`: Your Google OAuth client secret
- `GOOGLE_REDIRECT_URI`: OAuth redirect URI (default: http://localhost:5001/oauth2callback)

## Security Notes

- Never commit `.env` file
- Keep your credentials secure
- Use HTTPS in production
- Regularly rotate secrets
