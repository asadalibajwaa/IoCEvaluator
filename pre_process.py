import os
import PyPDF2
from bs4 import BeautifulSoup
from docx import Document


def text_from_html(html_path):
    with open(html_path, 'r', encoding='utf-8') as file:
        soup = BeautifulSoup(file, 'html.parser')
        return soup.get_text(separator="\n")

def text_from_docx(docx_path):
    doc = Document(docx_path)
    text = ""
    for para in doc.paragraphs:
        text += para.text + "\n"
    return text

def text_from_pdf(pdf_path):
    text = ""
    with open(pdf_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        for page in reader.pages:
            text += page.extract_text() + "\n"
    return text

def text_from_txt(txt_path):
    with open(txt_path, 'r', encoding='utf-8') as file:
        return file.read()

def extract_text_from_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext == '.html' or ext == '.htm':
        return text_from_html(file_path)
    elif ext == '.docx':
        return text_from_docx(file_path)
    elif ext == '.pdf':
        return text_from_pdf(file_path)
    elif ext == '.txt':
        return text_from_txt(file_path)
    else:
        raise ValueError(f"Unsupported file format: {ext}")

def main():
    file_paths = [
        'report 1.html',  # you can replace with your file paths or you can give it a path of your folder
        'report 2.docx',
        'report 3.pdf',
        'report 4.txt'
    ]

    for file_path in file_paths:
        try:
            text = extract_text_from_file(file_path)
            print(f"Text extracted from {file_path}:\n{text}\n")
        except Exception as e:
            print(f"Error processing {file_path}: {e}")

if __name__ == "__main__":
    main()
