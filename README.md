# Phishing Email Analyser

## Overview
Phishing Email Analyser is a web-based tool that allows users to upload email files for phishing analysis. The tool extracts email metadata, scans URLs using VirusTotal, and provides an easy-to-read report of potential threats.

## Current Features
- **Email File Upload**: Users can upload `.eml` or `.msg` files for analysis.
- **Metadata Extraction**: The tool extracts key details such as sender, subject, and email headers.
- **VirusTotal URL Scanning**: Detects malicious links by scanning them with VirusTotal.
- **Attachment Analysis**: Identifies potentially harmful email attachments.
- **User-Friendly Interface**: A simple and intuitive UI for easy navigation.
- **Dockerized Deployment**: The application is containerized using Docker for easy deployment.
- **Hosted on Render**: The tool is live and accessible online for external users.
- **Saving Analysis Reports (PDF/JSON)**: Allow users to download or store reports for future reference.
- **Email Validation (Fake vs. Real)**: Implement checks to determine if an email is from a legitimate source.
- **Multi-Email Upload & Batch Processing**: Enable users to upload multiple emails at once for bulk analysis.

## Planned Features
To enhance functionality and user experience, we plan to implement the following:
- **Improve UI with Bootstrap or Tailwind CSS**:
  - Enhance design consistency and responsiveness.
  - Add **modals or tooltips** to explain the results and improve user experience.

## Installation & Deployment
### Local Setup
1. Clone the repository:
   ```
   git clone https://github.com/PDFour4/phishing-analyser.git
   cd phishing-analyser
   ```
2. Set up a virtual environment (recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Create a `.env` file and add your VirusTotal API key:
   ```
   VT_Key=your_api_key_here
   ```
5. Run the application:
   ```
   python app.py
   ```

### Docker Deployment
1. Build and run the Docker container:
   ```
   docker build -t phishing-analyser .
   docker run -p 5000:5000 --env-file .env phishing-analyser
   ```

## Contributing
If you would like to contribute, feel free to submit a pull request or open an issue for discussion.

--- 

Let me know if you want any changes! 🚀
