# src/file_handlers/excel_handler.py
import pandas as pd
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class ExcelHandler:
    COLUMN_MAPPINGS = {
        'Number': ['Number'],
        'Company Name': ['Company Name'],
        'Executive Name': ['Executive Name'],
        'Email': ['Email']
    }

    @staticmethod
    def read_contacts(file_path: Path) -> List[Dict[str, Any]]:
        """Read and validate contacts from Excel file."""
        logger.info(f"Reading Excel file: {file_path}")
        
        try:
            # Read Excel file, skipping empty rows
            df = pd.read_excel(file_path, skiprows=lambda x: x in [0])  # Skip the first empty row
            
            # Clean column names immediately
            df.columns = [str(col).strip() for col in df.columns]
            
            logger.info(f"Initial columns: {list(df.columns)}")
            
            # Clean and prepare the data
            df = ExcelHandler._prepare_dataframe(df)
            
            # Convert to list of dictionaries and validate
            contacts = df.to_dict('records')
            valid_contacts = ExcelHandler._validate_contacts(contacts)
            
            if not valid_contacts:
                raise ValueError("No valid contacts found in the file")
            
            logger.info(f"Successfully read {len(valid_contacts)} valid contacts")
            return valid_contacts
            
        except Exception as e:
            logger.error(f"Error reading Excel file: {str(e)}")
            raise

    @staticmethod
    def _prepare_dataframe(df: pd.DataFrame) -> pd.DataFrame:
        try:
            # Log the first few rows to debug
            logger.debug(f"First few rows of raw data:\n{df.head()}")
            
            # Instead of dropping unnamed columns immediately, check if they contain data first
            # Use the first row as headers if current headers are all unnamed
            if all('Unnamed:' in str(col) for col in df.columns):
                logger.info("All columns are unnamed, using first row as headers")
                new_headers = df.iloc[0]
                df = df[1:]  # Remove the header row from data
                df.columns = [str(h).strip() if pd.notna(h) else f'Column_{i}' for i, h in enumerate(new_headers)]
            
            # Clean column names
            df.columns = [str(col).strip() if pd.notna(col) else '' for col in df.columns]
            
            # Now remove any remaining empty or unnamed columns
            unnamed_cols = [col for col in df.columns if not col or 'Unnamed:' in col]
            if unnamed_cols:
                df = df.drop(columns=unnamed_cols)

            # Clean data
            df = df.dropna(how='all')  # Remove empty rows
            
            # Convert all values to strings and clean them, handling NaN values
            for column in df.columns:
                df[column] = df[column].apply(lambda x: str(x).strip() if pd.notna(x) else '')

            df = df.reset_index(drop=True)

            logger.info(f"Available columns after cleaning: {df.columns.tolist()}")

            # Standardize column names
            df = ExcelHandler._standardize_columns(df)
            
            return df
            
        except Exception as e:
            logger.error(f"Error preparing dataframe: {str(e)}")
            raise

    @staticmethod
    def _standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
        """Standardize column names based on mappings."""
        current_columns = df.columns.tolist()
        logger.info(f"Current columns before standardization: {current_columns}")
        
        # If we have exactly 4 columns and they match our expected pattern, 
        # assume they are in the correct order
        if len(current_columns) == 4:
            expected_order = ['Number', 'Company Name', 'Executive Name', 'Email']
            column_mapping = dict(zip(current_columns, expected_order))
            df = df.rename(columns=column_mapping)
            logger.info(f"Columns after standardization: {df.columns.tolist()}")
            return df
        
        # Print first few rows to help with debugging
        logger.info(f"First row of data:\n{df.iloc[0] if not df.empty else 'Empty DataFrame'}")
        
        # Create a mapping of current columns to standard names
        column_mapping = {}
        missing_required = []
        
        for standard_name, variants in ExcelHandler.COLUMN_MAPPINGS.items():
            found = False
            for variant in variants:
                matching_cols = [
                    col for col in current_columns 
                    if col.lower().replace(' ', '') == variant.lower().replace(' ', '')
                ]
                if matching_cols:
                    column_mapping[matching_cols[0]] = standard_name
                    found = True
                    break
            
            if not found:
                # Only Email and Company Name are strictly required
                if standard_name in ['Email', 'Company Name']:
                    missing_required.append(standard_name)
                else:
                    # For non-required columns, add a default empty column
                    df[standard_name] = ''
                    logger.warning(f"Optional column '{standard_name}' not found, adding empty column")
        
        if missing_required:
            error_msg = f"Missing required columns: {', '.join(missing_required)}. Available columns: {current_columns}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Rename found columns
        df = df.rename(columns=column_mapping)
        logger.info(f"Columns after standardization: {df.columns.tolist()}")
        
        return df

    @staticmethod
    def _validate_contacts(contacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate contact data."""
        valid_contacts = []
        required_fields = ['Email', 'Company Name']
        
        for contact in contacts:
            try:
                # Clean strings and standardize keys
                cleaned_contact = {}
                for k, v in contact.items():
                    # Convert keys to standard format (e.g., 'Company Name' -> 'company_name')
                    key = k.lower().replace(' ', '_')
                    cleaned_contact[key] = str(v).strip()
                
                # Check required fields
                if not cleaned_contact.get('email') or not cleaned_contact.get('company_name'):
                    logger.warning(f"Missing required fields for contact: {cleaned_contact}")
                    continue
                
                # Validate email format
                if '@' not in cleaned_contact['email']:
                    logger.warning(f"Invalid email format for {cleaned_contact['company_name']}: {cleaned_contact['email']}")
                    continue
                
                valid_contacts.append(cleaned_contact)
                
            except Exception as e:
                logger.warning(f"Error validating contact {contact}: {str(e)}")
                continue
        
        return valid_contacts