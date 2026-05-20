# 🛡️ WEB-MXDR: Managed Extended Detection and Response for Web Applications

## 📌 Project Overview
**WEB-MXDR (Managed Extended Detection and Response)** is a cybersecurity project designed to detect and analyze web-based attacks using **Machine Learning–based anomaly detection** combined with **threat intelligence**.

Modern web applications are highly exposed to cyber threats such as SQL Injection, Cross-Site Scripting (XSS), and brute-force attacks. Traditional security mechanisms struggle to detect zero-day and behavior-based attacks.  

This project introduces an intelligent system that learns normal traffic patterns and identifies suspicious activities in real time.

---

## 🎯 Objectives
- Detect malicious web traffic using ML-based anomaly detection
- Overcome limitations of signature-based IDS systems
- Provide contextual threat intelligence
- Enable real-time monitoring and alerts
- Improve proactive cybersecurity defense

---

## 🚨 Problem Statement

### Challenges in Existing Systems
- ❌ Cannot detect unknown or zero-day attacks
- ❌ Requires frequent signature updates
- ❌ Easily bypassed using obfuscation techniques
- ❌ Raw logs lack contextual intelligence
- ❌ Reactive rather than proactive security

---

## 🧠 Proposed Solution
WEB-MXDR integrates:

- Machine Learning anomaly detection
- Behavioral traffic monitoring
- Threat intelligence enrichment
- Real-time anomaly scoring

The system identifies attacks by detecting deviations from normal behavior instead of relying on known attack signatures.

---

## ⚙️ Technical Implementation

### 🔹 ML-Based Anomaly Detection

#### Training Phase
- Collect baseline normal traffic
- Extract features such as:
  - URL length
  - Parameter count
  - Character distribution
- Train an **Isolation Forest** model

#### Inference Phase
- Convert incoming requests into feature vectors
- Calculate anomaly score
- Trigger alerts when threshold is exceeded

### ✅ Why Unsupervised Learning?
- No labeled attack dataset required
- Detects zero-day attacks
- Learns evolving attack patterns
- Adaptive detection mechanism

---

## 🧰 Tools & Technologies
- Python
- Machine Learning (Isolation Forest)
- Web Log Analysis
- Threat Intelligence Concepts
- Data Processing & Feature Engineering

---

## 💡 Innovation
- Behavior-based detection instead of signature matching
- Real-time anomaly detection
- Context-aware threat analysis
- Scalable security approach

---

## 🔍 Attacks Detected
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Brute Force Attacks
- Unknown / Zero-Day Exploits

---

## 📸 Project Screenshots



---

## 📈 Future Scope
- Multi-IP correlation & attack campaign detection
- Continuous learning feedback loop
- Analyst feedback integration
- Automated response mechanisms

---

## 👩‍💻 Contributors
- **Firdous Umme Hani**
- **Meghana Kasa**

### Guide
Dr. Swetha M S  
Associate Professor, Department of CSE

---

## 🏫 Institution
BMS Institute of Technology & Management (BMSIT&M)

---

## 📜 License
This project is developed for academic and educational purposes.

---

## ⭐ Acknowledgement
Developed as part of an academic cybersecurity project focusing on intelligent web threat detection using Machine Learning.
