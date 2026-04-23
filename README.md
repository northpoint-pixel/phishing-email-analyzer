# Phishing Email Analyzer

A Python-based phishing email analyzer that scans email content for suspicious indicators and generates a risk report.

## Features

- Extracts sender email and domain
- Detects suspicious keywords
- Extracts links from email content
- Flags untrusted or mismatched domains
- Detects suspicious attachment types
- Assigns a phishing risk level
- Saves results as JSON

## Tech Stack

- Python 3
- Regular expressions
- URL parsing
- JSON

## Purpose

This project was built to demonstrate practical phishing detection, email analysis, and security reporting skills relevant to IT support, help desk, and entry-level cybersecurity roles.

## Project Structure

```bash
phishing-email-analyzer/
├─ README.md
├─ .gitignore
├─ requirements.txt
├─ analyzer/
│  ├─ analyze_email.py
│  └─ rules.py
├─ samples/
│  └─ sample_phishing_email.txt
├─ results/
├─ docs/