from fpdf import FPDF
import os
import zipfile

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'CrypticNotes', 0, 1, 'C')

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf(title, content, output_path):
    pdf = PDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, title, 0, 1, 'C')
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(0, 10, content)
    pdf.output(output_path)

def create_zip_file(pdf_filenames, zip_filename):
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        for pdf_filename in pdf_filenames:
            zipf.write(pdf_filename, os.path.basename(pdf_filename))

def cleanup_files(filenames):
    for filename in filenames:
        os.remove(filename)
    if os.path.exists('temp'):
        os.rmdir('temp')
