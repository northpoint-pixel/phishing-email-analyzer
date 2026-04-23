import json
import os
import re
from datetime import datetime
from urllib.parse import urlparse
from analyzer.rules import (
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_ATTACHMENT_TYPES,
    TRUSTED_DOMAINS
)

URL_REGEX = r"https?://[^\s]+"
EMAIL_REGEX = r"From:\s*(.*<([^>]+)>)"
ATTACHMENT_REGEX = r"Attachment:\s*(.+)"

def extract_sender(text):
    match = re.search(EMAIL_REGEX, text, re.IGNORECASE)
    if match:
        return match.group(2).strip()
    return None

def extract_urls(text):
    return re.findall(URL_REGEX, text)

def extract_attachment(text):
    match = re.search(ATTACHMENT_REGEX, text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None

def get_domain_from_email(email):
    if email and "@" in email:
        return email.split("@")[-1].lower()
    return None

def get_domain_from_url(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return None

def score_risk(findings):
    score = len(findings)

    if score >= 5:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "SAFE"

def analyze_email(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Email file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as file:
        text = file.read()

    findings = []

    lower_text = text.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lower_text:
            findings.append(f"Suspicious keyword detected: '{keyword}'")

    sender_email = extract_sender(text)
    sender_domain = get_domain_from_email(sender_email)

    if sender_email:
        findings.append(f"Sender email found: {sender_email}")
    else:
        findings.append("No sender email could be extracted")

    urls = extract_urls(text)
    for url in urls:
        domain = get_domain_from_url(url)
        findings.append(f"Link detected: {url}")

        if domain and sender_domain and domain != sender_domain:
            findings.append(
                f"URL domain does not match sender domain: {domain} vs {sender_domain}"
            )

        if domain and domain not in TRUSTED_DOMAINS:
            findings.append(f"Untrusted or unknown domain detected: {domain}")

        if "@" in url:
            findings.append("Suspicious URL contains @ symbol")

        if "login" in url.lower() or "verify" in url.lower():
            findings.append("URL contains phishing-related wording")

    attachment = extract_attachment(text)
    if attachment:
        findings.append(f"Attachment detected: {attachment}")
        for ext in SUSPICIOUS_ATTACHMENT_TYPES:
            if attachment.lower().endswith(ext):
                findings.append(f"Suspicious attachment type detected: {ext}")

    if sender_domain:
        for trusted in TRUSTED_DOMAINS:
            if trusted.replace("o", "0") in sender_domain or trusted.replace("i", "1") in sender_domain:
                findings.append("Potential lookalike domain detected")

    risk_level = score_risk(findings)

    report = {
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "urls_found": urls,
        "attachment": attachment,
        "risk_level": risk_level,
        "findings": findings
    }

    return report

def save_report(report):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = f"results/phishing_report_{timestamp}.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\nReport saved to: {output_file}")

def print_report(report):
    print("\nPhishing Email Analysis Report")
    print("=" * 40)
    print(f"Sender Email: {report['sender_email']}")
    print(f"Sender Domain: {report['sender_domain']}")
    print(f"Risk Level: {report['risk_level']}")
    print("\nFindings:")
    for item in report["findings"]:
        print(f"- {item}")

def main():
    print("Phishing Email Analyzer")
    print("=" * 40)

    file_path = input("Enter email file path (example samples/sample_phishing_email.txt): ").strip()

    report = analyze_email(file_path)
    print_report(report)
    save_report(report)

if __name__ == "__main__":
    main()