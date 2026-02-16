# 🔐 CloudSecure AI Security Analyzer

An AI-powered AWS CloudTrail log analyzer that automatically 
detects suspicious security events and generates professional 
HTML security reports.

---

## 🎯 What It Does
```
CloudTrail Logs (JSON)
        ↓
Python reads and parses events
        ↓
Groq AI (Llama3) analyzes each event
        ↓
Severity assigned (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        ↓
Professional HTML report generated
        ↓
Open in browser - instant security insights!
```

---

## 🚨 Sample Report Output

The analyzer detected these events in the sample logs:

| Severity | Count | Examples |
|----------|-------|---------|
| 🔴 CRITICAL | 3 | CreateAccessKey, PutBucketPolicy, StopInstances |
| 🟠 HIGH | 2 | DeleteBucket, AuthorizeSecurityGroupIngress |
| 🟡 MEDIUM | 2 | Failed ConsoleLogin, GetSecretValue |
| 🔵 LOW | 1 | Successful ConsoleLogin with MFA |
| 🟢 INFO | 0 | - |

---

## 🏗️ Architecture
```
┌─────────────────────────────────────────┐
│         CloudTrail Log File             │
│         (JSON format)                   │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│         analyzer.py                     │
│  1. Load and parse JSON logs            │
│  2. Send each event to Groq AI          │
│  3. Parse AI response                   │
│  4. Generate HTML report                │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│         Groq AI (Llama3-70b)            │
│  - Analyzes security context            │
│  - Assigns severity level               │
│  - Explains risk                        │
│  - Recommends action                    │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│      security_report.html               │
│  - Professional dark theme              │
│  - Color-coded severity cards           │
│  - Finding, Risk, Action per event      │
│  - Opens in any browser                 │
└─────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Technology | Purpose |
|-----------|---------|
| Python 3.x | Core application language |
| Groq AI (Llama3-70b) | AI security analysis engine |
| AWS CloudTrail | Security log source |
| python-dotenv | Secure API key management |
| HTML/CSS | Professional report generation |

---

## 📁 Project Structure
```
CloudSecure-AI-Security-Analyzer/
├── analyzer.py                    # Main application
├── .env                           # API keys (never commit!)
├── .gitignore                     # Protects sensitive files
├── README.md                      # This file
├── sample_logs/
│   └── cloudtrail_events.json     # Sample CloudTrail logs
├── reports/
│   └── security_report.html       # Generated report
└── docs/
    └── EXPLANATION.md             # Code explanation
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.x installed
- Groq API key (free at https://console.groq.com)

### Installation
```bash
# Clone repository
git clone https://github.com/Abhikarthik3104/cloudsecure-ai-security-analyzer.git
cd cloudsecure-ai-security-analyzer

# Install dependencies
pip install groq python-dotenv

# Create .env file
echo "GROQ_API_KEY=your-key-here" > .env

# Run analyzer
python analyzer.py

# Open report
start reports\security_report.html
```

---

## 🔍 Security Events Detected

### Events in Sample Logs:

| Event | User | Risk Level | Reason |
|-------|------|------------|--------|
| ConsoleLogin ✅ | admin-user | LOW | MFA used, known IP |
| ConsoleLogin ❌ | developer-user | MEDIUM | Failed login attempt |
| DeleteBucket | developer-user | HIGH | Production bucket deleted |
| CreateAccessKey | unknown-user | CRITICAL | Suspicious key creation |
| AuthorizeSecurityGroupIngress | developer-user | HIGH | SSH opened to 0.0.0.0/0 |
| GetSecretValue | developer-user | MEDIUM | Accessed prod DB password |
| StopInstances | unknown-user | CRITICAL | Production server stopped |
| PutBucketPolicy | unknown-user | CRITICAL | Public access enabled |

---

## 🎯 Key Security Concepts Demonstrated

### 1. CloudTrail Log Analysis
CloudTrail records every API call in AWS. This tool
reads those logs and identifies which events are 
suspicious vs normal.

### 2. AI-Powered Analysis
Instead of hardcoded rules, Groq AI understands
the CONTEXT of each event:
- WHO did it (admin vs unknown user)
- WHAT they did (delete vs read)
- WHERE from (known IP vs suspicious IP)
- HOW (with MFA or without)

### 3. Severity Classification
```
CRITICAL = Immediate action required
HIGH     = Investigate within 1 hour  
MEDIUM   = Review within 24 hours
LOW      = Monitor, no immediate action
INFO     = Normal expected activity
```

### 4. Defense in Depth Thinking
The tool checks multiple factors:
- User identity (known vs unknown)
- IP address (internal vs external)
- Action type (read vs write vs delete)
- MFA status (enabled vs disabled)

---

## 💡 Real World Use Cases

This tool simulates what enterprise security tools do:

| Enterprise Tool | What It Does | Our Tool Does |
|----------------|--------------|---------------|
| AWS GuardDuty | Analyzes CloudTrail | ✅ Same concept |
| Splunk SIEM | Parses security logs | ✅ Same concept |
| Datadog Security | AI threat detection | ✅ Same concept |
| CrowdStrike | Automated analysis | ✅ Same concept |

---

## 🎤 Interview Talking Points

**"Tell me about your AI security project"**

"I built an AI-powered CloudTrail log analyzer using 
Python and Groq AI. It reads AWS security events, sends 
them to an LLM for analysis, and generates professional 
HTML reports with severity classifications and remediation 
actions. This simulates what enterprise SIEM tools like 
Splunk do, but built from scratch to understand the 
underlying concepts."

---

## 📈 Future Improvements

- [ ] Real AWS CloudTrail integration (boto3)
- [ ] Email alerts for CRITICAL findings via SNS
- [ ] Multiple log file processing
- [ ] Dashboard with charts and trends
- [ ] Slack notifications integration
- [ ] Automated remediation suggestions

---

## 👨‍💻 Author

**Abhi** | Cloud Security Engineer  
GitHub: [Abhikarthik3104](https://github.com/Abhikarthik3104)

---

*Built as part of 90-day Cloud Security Portfolio Challenge*
*Project 3 of 5*