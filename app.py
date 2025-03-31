from flask import Flask, request, render_template, send_from_directory
import os
import re
import requests
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import json
from textwrap import wrap

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load environment variables from .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_Key")
if not VT_API_KEY:
    raise ValueError("VirusTotal API key not found. Please set VT_API_KEY in .env file.")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/upload", methods=["GET", "POST"])
def upload_email():
    if request.method == "POST":
        files = request.files.getlist("email_file")
        results = []
        
        for file in files:
            if file:
                filepath = os.path.join(UPLOAD_FOLDER, file.filename)
                file.save(filepath)
                print(f"File uploaded: {file.filename}")
            
                # Extract email data
                headers, urls, attachments_info, email_safety_verdict = extract_email_data(filepath)

                # Scan URLs
                url_reports = {url: scan_url_virustotal(url) for url in urls}

                # Save reports
                json_report_path = save_report_json(headers, url_reports, attachments_info,
                                                    email_safety_verdict, 
                                                    filename=f"{file.filename}_report.json")
                pdf_report_path = save_report_pdf(headers, url_reports, attachments_info,
                                                  email_safety_verdict, 
                                                  filename=f"{file.filename}_report.pdf")

                # Append results for rendering
                results.append({
                    "filename": file.filename,
                    "headers": headers,
                    "urls": url_reports,
                    "attachments": attachments_info,
                    "json_report": json_report_path,
                    "pdf_report": pdf_report_path,
                    "email_safety_verdict": email_safety_verdict
                })

        return render_template("results.html", results=results)

    return render_template("index.html")

@app.route('/download_json')
def download_json():
    filename = request.args.get('filename')
    if filename and os.path.exists(os.path.join(UPLOAD_FOLDER, filename)):
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    return "File not found", 404

@app.route('/download_pdf')
def download_pdf():
    filename = request.args.get('filename')
    if filename and os.path.exists(os.path.join(UPLOAD_FOLDER, filename)):
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    return "File not found", 404

def extract_email_data(filepath):
    """Extracts email headers, URLs, and attachments."""
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # Extract headers
    headers = {
        "From": msg["From"],
        "To": msg["To"],
        "Subject": msg["Subject"],
        "Return-Path": msg["Return-Path"],
        "Received-SPF": msg["Received-SPF"],
        "DKIM-Signature": msg["DKIM-Signature"],
        "Authentication-Results": msg["Authentication-Results"],
        "Date": msg["Date"]
    }

    # Extract URLs from email body
    urls = []
    attachments_info = {}

    if msg.is_multipart():
        for part in msg.iter_parts():
            content_type = part.get_content_type()
            if "text/html" in content_type or "text/plain" in content_type:
                body = part.get_content()
                urls.extend(extract_urls(str(body)))
            elif part.get_content_maintype() == "application":
                # Handle attachments
                filename = part.get_filename()
                attachment_data = part.get_payload(decode=True)
                if filename:
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    with open(file_path, "wb") as f:
                        f.write(attachment_data)
                    attachments_info[filename] = scan_attachment_virustotal(file_path)
    else:
        body = msg.get_content()
        urls.extend(extract_urls(str(body)))

    # Determine if the email is safe or suspicious
    email_safety_verdict = validate_email(headers)

    return headers, list(set(urls)), attachments_info, email_safety_verdict

def validate_email(headers):
    """Determines if an email is legitimate based on SPF, DKIM, and DMARC headers."""
    spf_pass = "pass" in (headers.get("Received-SPF", "") or "").lower()

    auth_results = headers.get("Authentication-Results")
    if auth_results is None:
        auth_results = ""  # Ensure it's a string

    dkim_pass = "dkim=pass" in auth_results.lower()
    dmarc_pass = "dmarc=pass" in auth_results.lower()

    if spf_pass and dkim_pass and dmarc_pass:
        return "✅ This email appears to be from a legitimate source. (Passed SPF, DKIM, and DMARC)"
    elif spf_pass or dkim_pass or dmarc_pass:
        return "⚠️ This email may not be from a legitimate source. (Failed SPF, DKIM, or DMARC)"
    else:
        return (
            "❓ Unable to determine email authenticity.\n\n"
            "This email lacks proper authentication checks (SPF, DKIM, DMARC). It may be a phishing attempt.\n\n"
            "Here are some steps you can take to verify the email:\n"
            "🔹 Verify the sender manually – Contact the sender through a known and trusted method.\n"
            "🔹 Look for suspicious elements – Check for urgent language, unexpected attachments, or requests for sensitive info.\n"
            "🔹 Avoid clicking links – Hover over links to preview their destination or use VirusTotal.\n"
            "🔹 Check SPF, DKIM, and DMARC records – Use tools like MXToolBox to analyze the sender’s domain authentication.\n"
            "🔹 Report the email – If you suspect phishing, report it to your IT team or email provider."
        )

def scan_attachment_virustotal(file_path):
    """Scan an attachment with VirusTotal."""
    headers = {"x-apikey": VT_API_KEY}
    with open(file_path, "rb") as file:
        files = {"file": (file_path, file)}
        response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)

    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        # Retrieve scan result for attachment
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_response = requests.get(report_url, headers=headers)
        
        if report_response.status_code == 200:
            vt_report = report_response.json()
            return f"https://www.virustotal.com/gui/file/{vt_report['meta']['file_info']['sha256']}"
    return "Scan failed"

def extract_urls(text):
    """Extracts URLs from a given text."""
    soup = BeautifulSoup(text, "html.parser")
    urls = [a["href"] for a in soup.find_all("a", href=True)]
    urls += re.findall(r'http[s]?://[^\s<>"]+|www\.[^\s<>"]+', text)
    return list(set(urls))  # Remove duplicates

def scan_url_virustotal(url):
    """Submits a URL to VirusTotal and retrieves the report link."""
    headers = {"x-apikey": VT_API_KEY}
    
    # Step 1: Submit URL for scanning
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})

    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        
        # Step 2: Retrieve the scan report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_response = requests.get(report_url, headers=headers)
        
        if report_response.status_code == 200:
            vt_report = report_response.json()
            
            # Extract the final report link
            final_report_link = f"https://www.virustotal.com/gui/url/{vt_report['meta']['url_info']['id']}"
            return final_report_link

    return "Scan failed"

def sanitize_filename(filename, max_length=50):
    """Sanitizes and truncates filenames to prevent errors."""
    filename = re.sub(r'[\/:*?"&lt;&gt;|]', '_', filename)  # Replace invalid characters
    return filename[:max_length]  # Truncate if too long

def save_report_json(headers, urls, attachments_info, email_safety_verdict, filename="report.json"):
    """Saves analysis results as a JSON file."""
    filename = sanitize_filename(filename)
    if not filename.endswith(".json"):
        filename += ".json"

    report_data = {
        "headers": headers,
        "urls": urls,
        "attachments": attachments_info,
        "email_safety_verdict": email_safety_verdict  # Include the safety verdict in the JSON report
    }

    json_path = os.path.join(UPLOAD_FOLDER, filename)

    try:
        with open(json_path, "w") as json_file:
            json.dump(report_data, json_file, indent=4)
    except OSError as e:
        print(f"Error saving JSON report: {e}")
        json_path = os.path.join(UPLOAD_FOLDER, "default_report.json")
        with open(json_path, "w") as json_file:
            json.dump(report_data, json_file, indent=4)

    return json_path

def save_report_pdf(headers, urls, attachments_info, email_safety_verdict, filename="report.pdf"):
    """Saves analysis results as a PDF file with improved formatting."""
    pdf_path = os.path.join(UPLOAD_FOLDER, filename)
    c = canvas.Canvas(pdf_path, pagesize=letter)
    page_height = letter[1] # Height of the page
    margin = 50  # Margin from the bottom of the page
    
    def wrap_text(text, width=80):
        """Wrap text to fit within a given width."""
        return wrap(text, width)
    
    def check_page_space(y_position, line_height=15):
        """Check if there is enough space on the current page, and create a new page if needed."""
        if y_position < margin:
            c.showPage()  # Finish the current page and start a new one
            c.setFont("Helvetica", 10)  # Reset font for the new page
            return page_height - margin  # Reset y_position for the new page
        return y_position

    y_position = page_height - margin  # Initial Y position

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, y_position, "Phishing Email Analysis Report")
    y_position -= 30

    # Section: Email Headers
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y_position, "Email Headers:")
    c.setFont("Helvetica", 10)
    y_position -= 20
    for key, value in headers.items():
        wrapped_lines = wrap_text(f"{key}: {value}", 80)
        for line in wrapped_lines:
            y_position = check_page_space(y_position)  # Check if there's enough space on the page
            c.drawString(120, y_position, line)
            y_position -= 15
        y_position -= 5  # Extra space after each header

    # Section: Scanned URLs
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y_position, "Scanned URLs:")
    c.setFont("Helvetica", 10)
    y_position -= 20
    for url, result in urls.items():
        wrapped_lines = wrap_text(f"{url}: {result}", 80)
        for line in wrapped_lines:
            y_position = check_page_space(y_position)  # Check if there's enough space on the page
            c.drawString(120, y_position, line)
            y_position -= 15
        y_position -= 5  # Extra space after each URL

    # Section: Attachment Scan Results
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y_position, "Attachment Scan Results:")
    c.setFont("Helvetica", 10)
    y_position -= 20
    for filename, result in attachments_info.items():
        wrapped_lines = wrap_text(f"{filename}: {result}", 80)
        for line in wrapped_lines:
            y_position = check_page_space(y_position)  # Check for page space
            c.drawString(120, y_position, line)
            y_position -= 15
        y_position -= 5  # Extra space after each attachment

    # Section: Email Safety Verdict
    c.setFont("Helvetica-Bold", 12)
    y_position = check_page_space(y_position)  # Check for page space
    c.drawString(100, y_position, "Email Safety Verdict:")
    c.setFont("Helvetica", 10)
    y_position -= 20

    # Create a TextObject for multi-line text
    text_object = c.beginText(120, y_position)  # Start at the current position
    text_object.setFont("Helvetica", 10)

    # Split the text by newlines and wrap each line
    for paragraph in email_safety_verdict.split("\n"):
        wrapped_lines = wrap_text(paragraph, 80)  # Wrap each paragraph to fit the width
        for line in wrapped_lines:
            text_object.textLine(line)  # Add each wrapped line to the TextObject
        text_object.textLine("")  # Add a blank line between paragraphs

    # Draw the TextObject on the canvas
    c.drawText(text_object)

    # Update y_position after drawing the text
    y_position = text_object.getY() - 15  # Adjust for spacing after the text

    # Section: Safety Tips (if applicable)
    if "Unable to determine" in email_safety_verdict:
        y_position -= 20
        c.setFont("Helvetica-Bold", 12)
        y_position = check_page_space(y_position)  # Check for page space
        c.drawString(100, y_position, "Recommended Actions:")
        y_position -= 20
        c.setFont("Helvetica", 10)
        tips = [
            "🔹 Verify the sender manually – Contact the sender through a known and trusted method.",
            "🔹 Look for suspicious elements – Check for urgent language, unexpected attachments, or requests for sensitive info.",
            "🔹 Avoid clicking links – Hover over links to preview their destination or use VirusTotal.",
            "🔹 Check SPF, DKIM, and DMARC records – Use tools like MXToolBox to analyze the sender’s domain authentication.",
            "🔹 Report the email – If you suspect phishing, report it to your IT team or email provider."
        ]
        for tip in tips:
            wrapped_tip = wrap_text(tip, 80)
            for line in wrapped_tip:
                y_position = check_page_space(y_position)  # Check for page space
                c.drawString(120, y_position, line)
                y_position -= 15
            y_position -= 5  # Extra space after each tip

    c.save()
    return pdf_path

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)