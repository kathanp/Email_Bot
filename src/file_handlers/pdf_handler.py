# src/file_handlers/pdf_handler.py

import PyPDF2
import logging
import re

class PDFHandler:
    @staticmethod
    def read_contacts(file_path):
        try:
            contacts = []
            with open(file_path, 'rb') as file:
                reader = PyPDF2.PdfReader(file)
                
                for page in reader.pages:
                    text = page.extract_text()
                    # This is a simplified example - adjust the regex patterns
                    # based on your PDF structure
                    contact_blocks = text.split('\n\n')  # Assuming contacts are separated by double newlines
                    
                    for block in contact_blocks:
                        contact = PDFHandler._parse_contact_block(block)
                        if contact:
                            contacts.append(contact)
            
            return contacts
            
        except Exception as e:
            logging.error(f"Error reading PDF file: {str(e)}")
            raise
    
    @staticmethod
    def _parse_contact_block(block):
        # This is a simplified example - adjust based on your PDF structure
        email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        
        email_match = re.search(email_pattern, block)
        phone_match = re.search(phone_pattern, block)
        
        if email_match:
            lines = block.split('\n')
            return {
                'company_name': lines[0].strip() if lines else 'Unknown Company',
                'contact_name': lines[1].strip() if len(lines) > 1 else 'Unknown Contact',
                'email': email_match.group(),
                'phone': phone_match.group() if phone_match else ''
            }
        return None