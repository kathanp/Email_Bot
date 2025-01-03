# src/tests/test_file_handlers.py

from ..file_handlers.excel_handler import ExcelHandler
from ..file_handlers.pdf_handler import PDFHandler

def test_excel_handler():
    excel_handler = ExcelHandler()
    assert excel_handler is not None
