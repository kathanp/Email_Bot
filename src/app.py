from flask import Flask, render_template, request, jsonify
from email_service import EmailMicroservice

app = Flask(__name__)
email_service = EmailMicroservice()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/send-email', methods=['POST'])
def send_email():
    data = request.json
    try:
        success = email_service.send_email(
            recipient_email=data['recipient'],
            subject=data['subject'],
            body=data['body']
        )
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400 