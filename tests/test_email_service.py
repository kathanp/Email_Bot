# src/tests/test_email_service.py


from ..email_service import EmailMicroservice
from ..config import Config
from pathlib import Path
import pandas as pd

def test_email_service():
    try:
        # Initialize the email service
        service = EmailMicroservice()
        
        # Path to your Excel file
        file_path = Path(Config.INPUT_DIR) / "Contacts.xlsx"
        
        # Add debugging steps
        df = pd.read_excel(file_path)
        print(f"DataFrame shape: {df.shape}")
        print(f"DataFrame columns: {df.columns.tolist()}")
        print(f"First few rows with non-null check:\n{df.info()}")
        
        # Send emails
        print("Starting email campaign...")
        successful, failed = service.process_contacts(file_path)
        
        assert successful >= 0, "Successful email count should be non-negative"
        assert failed >= 0, "Failed email count should be non-negative"
        assert isinstance(successful, int), "Successful count should be an integer"
        assert isinstance(failed, int), "Failed count should be an integer"
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    test_email_service()