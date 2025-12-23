#!/usr/bin/env python3
"""
Extract information from PDF files for RT-950 Pro project.
Tries multiple PDF libraries to extract text content.
"""

import sys
from pathlib import Path

def extract_with_pypdf2(pdf_path):
    """Extract text using PyPDF2."""
    try:
        import PyPDF2
        text = ""
        with open(pdf_path, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)
            for page in pdf.pages:
                text += page.extract_text() + "\n"
        return text
    except Exception as e:
        return f"PyPDF2 error: {e}"

def extract_with_pdfplumber(pdf_path):
    """Extract text using pdfplumber."""
    try:
        import pdfplumber
        text = ""
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        return text
    except Exception as e:
        return f"pdfplumber error: {e}"

def extract_with_pypdf(pdf_path):
    """Extract text using pypdf (PyPDF2 successor)."""
    try:
        import pypdf
        text = ""
        with open(pdf_path, 'rb') as f:
            pdf = pypdf.PdfReader(f)
            for page in pdf.pages:
                text += page.extract_text() + "\n"
        return text
    except Exception as e:
        return f"pypdf error: {e}"

def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_pdf_info.py <pdf_file>")
        sys.exit(1)
    
    pdf_path = Path(sys.argv[1])
    if not pdf_path.exists():
        print(f"Error: File not found: {pdf_path}")
        sys.exit(1)
    
    print(f"Extracting text from: {pdf_path}")
    print("=" * 80)
    
    # Try different libraries
    text = None
    
    # Try pypdf first (most modern)
    result = extract_with_pypdf(pdf_path)
    if result and not result.startswith("pypdf error"):
        text = result
        print(f"Successfully extracted using pypdf")
    else:
        # Try pdfplumber
        result = extract_with_pdfplumber(pdf_path)
        if result and not result.startswith("pdfplumber error"):
            text = result
            print(f"Successfully extracted using pdfplumber")
        else:
            # Try PyPDF2
            result = extract_with_pypdf2(pdf_path)
            if result and not result.startswith("PyPDF2 error"):
                text = result
                print(f"Successfully extracted using PyPDF2")
    
    if text:
        # Print first 5000 characters as preview
        print("\n--- Extracted Text (first 5000 chars) ---")
        print(text[:5000])
        if len(text) > 5000:
            print(f"\n... (truncated, total {len(text)} characters)")
        
        # Save to text file
        output_file = pdf_path.with_suffix('.txt')
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"\nFull text saved to: {output_file}")
    else:
        print("\nError: Could not extract text with any available library")
        print("Try installing: pip install pypdf pdfplumber PyPDF2")

if __name__ == '__main__':
    main()

