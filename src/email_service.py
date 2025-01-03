# src/email_service.py

import logging
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from pathlib import Path

from .config import Config
from .file_handlers.excel_handler import ExcelHandler
from .file_handlers.pdf_handler import PDFHandler
from .templates.email_template import EmailTemplate

class EmailMicroservice:
    def __init__(self):
        """Initialize the email microservice."""
        try:
            # Validate configuration
            Config.validate_config()
            
            # Set up logging
            self._setup_logging()
            
        except Exception as e:
            print(f"Error initializing EmailMicroservice: {str(e)}")
            raise
    
    def _setup_logging(self):
        """Configure logging."""
        log_file = Path(Config.LOG_DIR) / f"email_service_{time.strftime('%Y%m%d_%H%M%S')}.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, Config.LOG_LEVEL),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def send_email(self, recipient_email, subject, body, max_retries=3):
        """Send email to a recipient with retry logic."""
        # Hardcode credentials temporarily for testing
        smtp_server = "smtp.gmail.com"
        port = 587
        sender_email = "sale.rrimp@gmail.com"
        password = "mnuiachbwzesyzwv"
        
        for attempt in range(max_retries):
            try:
                msg = MIMEMultipart()
                msg['From'] = sender_email  # Use sender_email instead of Config.SENDER_EMAIL
                msg['To'] = recipient_email
                msg['Subject'] = subject
                
                msg.attach(MIMEText(body, 'plain'))
                
                with smtplib.SMTP(smtp_server, port, timeout=30) as server:
                    server.starttls()
                    server.login(sender_email, password)  # Use direct credentials
                    server.send_message(msg)
                
                logging.info(f"Email sent successfully to {recipient_email}")
                return True
                
            except (smtplib.SMTPException, ConnectionError) as e:
                if attempt == max_retries - 1:
                    logging.error(f"Final attempt failed for {recipient_email}: {str(e)}")
                    return False
                logging.warning(f"Attempt {attempt + 1} failed, retrying: {str(e)}")
                time.sleep(2 ** attempt)
    
    def process_contacts(self, file_path):
        """Process contacts from file and send emails."""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"Contact file not found: {file_path}")
            
            logging.info(f"Processing file: {file_path}")
            
            # Read contacts based on file type
            if file_path.suffix.lower() == '.xlsx':
                contacts = ExcelHandler.read_contacts(file_path)
            elif file_path.suffix.lower() == '.pdf':
                contacts = PDFHandler.read_contacts(file_path)
            else:
                raise ValueError(f"Unsupported file format: {file_path.suffix}")
            
            if not contacts:
                raise ValueError("No valid contacts found in the file")
            
            successful_emails = 0
            failed_emails = 0
            
            print("\nStarting email campaign...")
            print("=" * 50)
            
            for i, contact in enumerate(contacts, 1):
                try:
                    subject, body = EmailTemplate.create_email_content(contact)
                    print(f"\nProcessing email {i}/{len(contacts)}:")
                    print(f"To: {contact['email']}")
                    print(f"Company: {contact['company_name']}")
                    
                    success = self.send_email(contact['email'], subject, body)
                    
                    if success:
                        successful_emails += 1
                        print("✓ Email sent successfully!")
                    else:
                        failed_emails += 1
                        print("✗ Failed to send email")
                    
                    print("-" * 50)
                    time.sleep(Config.DELAY_BETWEEN_EMAILS)
                    
                except Exception as e:
                    logging.error(f"Error processing contact {contact}: {str(e)}")
                    failed_emails += 1
                    print(f"✗ Error: {str(e)}")
                    print("-" * 50)
            
            print("\nEmail Campaign Summary:")
            print("=" * 50)
            print(f"Total emails processed: {len(contacts)}")
            print(f"Successfully sent: {successful_emails}")
            print(f"Failed: {failed_emails}")
            print("=" * 50)
            
            logging.info(f"Email campaign completed. Successful: {successful_emails}, Failed: {failed_emails}")
            return successful_emails, failed_emails
            
        except Exception as e:
            logging.error(f"Error processing contacts: {str(e)}")
            raise

if __name__ == "__main__":
    # Example usage
    service = EmailMicroservice()
    
    # Create input directory if it doesn't exist
    input_dir = Path(Config.INPUT_DIR)
    input_dir.mkdir(parents=True, exist_ok=True)
    
    file_path = input_dir / "Contacts.xlsx"
    
    # Add debug logging
    print(f"Looking for contacts file at: {file_path}")
    print(f"Directory exists: {input_dir.exists()}")
    print(f"Directory path: {input_dir.absolute()}")
    
    # Check if file exists before processing
    if not file_path.exists():
        print(f"Error: Contact file not found at {file_path}")
        exit(1)
        
    successful, failed = service.process_contacts(file_path)
    print(f"Emails sent successfully: {successful}")
    print(f"Failed emails: {failed}")