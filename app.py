from flask import Flask, request, render_template
import os
import re
import requests
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from dotenv import load_dotenv

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load environment variables from .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    raise ValueError("VirusTotal API key not found. Please set VT_API_KEY in .env file.")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/upload", methods=["GET", "POST"])
def upload_email():
    if request.method == "POST":
        file = request.files["email_file"]
        if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            print(f"File uploaded: {file.filename}")
        
            # Extract headers
            headers, urls, attachments_info = extract_email_data(filepath)

            # Scan URLs with VirusTotal
            url_reports = {url: scan_url_virustotal(url) for url in urls}

            return render_template("results.html", headers=headers, urls=url_reports, attachments=attachments_info)

    return render_template("index.html")

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
        "Date": msg["Date"]
    }

    # Extract URLs from HTML & plain text parts and scan attachments
    attachments_info = {} # Store attachment scan results
    urls = []
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
                    # Scan attachments
                    attachment_scan_result = scan_attachment_virustotal(file_path)
                    attachments_info = {filename: attachment_scan_result}
    else:
        body = msg.get_content()
        urls.extend(extract_urls(str(body)))

    return headers, list(set(urls)), attachments_info

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

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")