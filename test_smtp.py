import smtplib

smtp_server = "smtp.gmail.com"
port = 587
sender_email = "sale.rrimp@gmail.com"
password = "mnuiachbwzesyzwv"

try:
    server = smtplib.SMTP(smtp_server, port)
    server.starttls()
    server.login(sender_email, password)
    print("Login successful!")
    server.quit()
except Exception as e:
    print(f"Error: {e}") 