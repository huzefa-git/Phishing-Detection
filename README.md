# Phishing Detection System

A Python-based phishing detection application that analyzes URLs and email-related data to identify potentially malicious or phishing attempts.  
The system combines **feature-based machine learning**, **security heuristics**, and a **Flask web interface** to simulate a real-world phishing analysis tool.

---

## Features

- **URL Phishing Detection**
  - Extracts structural features from URLs
  - Uses a trained Random Forest model to classify URLs as phishing or safe

- **Bulk URL Analysis**
  - Upload files (`.txt`, `.csv`, `.html`) containing multiple URLs
  - Batch prediction support

- **Email Header Analysis**
  - Parses email headers
  - Detects mismatches between `From` and `Received` domains
  - Highlights potential spoofing indicators

- **Domain Reputation Check**
  - WHOIS-based domain age analysis
  - Flags newly created or suspicious domains

- **SSL Certificate Validation**
  - Checks SSL certificate validity and expiry

- **User Authentication**
  - Signup/Login system using Flask & SQLite
  - Session-based access control

---

## Approach & Architecture

1. **Feature Extraction**
   - URL length
   - Number of dots, hyphens, slashes
   - Presence of IP address
   - HTTPS usage
   - Query parameters count

2. **Model Training**
   - Dataset: `malicious_phish.csv`
   - Labels: `phishing` vs `benign`
   - Algorithm: `RandomForestClassifier`
   - Evaluation using train-test split

3. **Prediction Pipeline**
   - URL → Feature Extraction → ML Model → Classification
   - Integrated into Flask routes for real-time analysis

---

## Tech Stack

- **Language:** Python  
- **Framework:** Flask  
- **Machine Learning:** Scikit-learn  
- **Database:** SQLite (SQLAlchemy ORM)  
- **Security Concepts:** Phishing indicators, URL analysis, email header inspection  
- **Tools:** Git, GitHub

---
