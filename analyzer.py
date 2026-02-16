#!/usr/bin/env python3
"""
CloudSecure AI Security Analyzer
Analyzes AWS CloudTrail logs using Groq AI (Llama3)
and generates professional security reports
"""

import json
import os
import datetime
from groq import Groq
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv()

# Initialize Groq AI client
client = Groq(api_key=os.getenv('GROQ_API_KEY'))
def load_cloudtrail_logs(filepath):
    """Load CloudTrail log file"""
    print(f"📂 Loading logs from: {filepath}")
    with open(filepath, 'r') as f:
        data = json.load(f)
    events = data.get('Records', [])
    print(f"✅ Loaded {len(events)} security events")
    return events

def analyze_event_with_ai(event):
    """Use Groq AI to analyze a single security event"""

    event_json = json.dumps(event, indent=2)

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        max_tokens=500,
        messages=[
            {
                "role": "system",
                "content": "You are a cloud security analyst. Analyze AWS CloudTrail events and identify security risks. Always respond in exactly the format requested."
            },
            {
                "role": "user",
                "content": f"""Analyze this AWS CloudTrail event and provide:

1. SEVERITY: (CRITICAL/HIGH/MEDIUM/LOW/INFO)
2. FINDING: One sentence describing what happened
3. RISK: Why this is or isn't a security concern
4. ACTION: Recommended response

Format your response EXACTLY like this with no extra text:
SEVERITY: [level]
FINDING: [one sentence]
RISK: [one sentence]
ACTION: [one sentence]

CloudTrail Event:
{event_json}"""
            }
        ]
    )

    return response.choices[0].message.content

def parse_ai_response(response_text):
    """Parse AI response into structured data"""
    lines = response_text.strip().split('\n')
    result = {
        'severity': 'INFO',
        'finding': 'Event analyzed',
        'risk': 'Review recommended',
        'action': 'Monitor activity'
    }

    for line in lines:
        line = line.strip()
        if line.startswith('SEVERITY:'):
            severity = line.replace('SEVERITY:', '').strip().upper()
            # Clean up severity - extract just the word
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev in severity:
                    result['severity'] = sev
                    break
        elif line.startswith('FINDING:'):
            result['finding'] = line.replace('FINDING:', '').strip()
        elif line.startswith('RISK:'):
            result['risk'] = line.replace('RISK:', '').strip()
        elif line.startswith('ACTION:'):
            result['action'] = line.replace('ACTION:', '').strip()

    return result

def get_severity_color(severity):
    """Get color for severity level"""
    colors = {
        'CRITICAL': '#dc3545',
        'HIGH':     '#fd7e14',
        'MEDIUM':   '#ffc107',
        'LOW':      '#17a2b8',
        'INFO':     '#28a745'
    }
    return colors.get(severity.upper(), '#6c757d')

def generate_html_report(events, analyses):
    """Generate professional HTML security report"""

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Count severities
    severity_counts = {
        'CRITICAL': 0, 'HIGH': 0,
        'MEDIUM': 0, 'LOW': 0, 'INFO': 0
    }
    for analysis in analyses:
        sev = analysis['severity'].upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Build events HTML
    events_html = ""
    for i, (event, analysis) in enumerate(zip(events, analyses)):
        severity = analysis['severity'].upper()
        color = get_severity_color(severity)

        events_html += f"""
        <div class="event-card">
            <div class="event-header" style="border-left: 5px solid {color}">
                <div class="event-info">
                    <span class="event-name">{event.get('eventName', 'Unknown')}</span>
                    <span class="event-user">👤 {event.get('userIdentity', {}).get('userName', 'Unknown')}</span>
                    <span class="event-time">🕐 {event.get('eventTime', 'Unknown')}</span>
                    <span class="event-ip">🌐 {event.get('sourceIPAddress', 'Unknown')}</span>
                </div>
                <span class="severity-badge" style="background-color: {color}">
                    {severity}
                </span>
            </div>
            <div class="event-analysis">
                <div class="analysis-item">
                    <strong>🔍 Finding:</strong> {analysis['finding']}
                </div>
                <div class="analysis-item">
                    <strong>⚠️ Risk:</strong> {analysis['risk']}
                </div>
                <div class="analysis-item">
                    <strong>✅ Action:</strong> {analysis['action']}
                </div>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudSecure Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #0f1117;
            color: #e0e0e0;
            min-height: 100vh;
        }}

        .header {{
            background: linear-gradient(135deg, #1a1f2e 0%, #16213e 50%, #0f3460 100%);
            padding: 40px;
            border-bottom: 2px solid #e94560;
        }}

        .header h1 {{
            font-size: 2.5rem;
            color: #ffffff;
            margin-bottom: 8px;
        }}

        .header h1 span {{ color: #e94560; }}

        .header p {{
            color: #a0a0b0;
            font-size: 1rem;
            margin-top: 6px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 30px 20px;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 16px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: #1a1f2e;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border: 1px solid #2a2f3e;
            transition: transform 0.2s;
        }}

        .summary-card:hover {{ transform: translateY(-3px); }}

        .summary-card .count {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 8px;
        }}

        .summary-card .label {{
            font-size: 0.85rem;
            color: #a0a0b0;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .section-title {{
            font-size: 1.3rem;
            color: #ffffff;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #2a2f3e;
        }}

        .event-card {{
            background: #1a1f2e;
            border-radius: 12px;
            margin-bottom: 16px;
            overflow: hidden;
            border: 1px solid #2a2f3e;
            transition: transform 0.2s;
        }}

        .event-card:hover {{ transform: translateX(4px); }}

        .event-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            background: #1e2435;
            flex-wrap: wrap;
            gap: 10px;
        }}

        .event-info {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            align-items: center;
        }}

        .event-name {{
            font-weight: bold;
            font-size: 1rem;
            color: #ffffff;
        }}

        .event-user, .event-time, .event-ip {{
            font-size: 0.85rem;
            color: #a0a0b0;
        }}

        .severity-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            color: white;
            letter-spacing: 1px;
        }}

        .event-analysis {{ padding: 16px 20px; }}

        .analysis-item {{
            padding: 8px 0;
            border-bottom: 1px solid #2a2f3e;
            font-size: 0.92rem;
            line-height: 1.6;
        }}

        .analysis-item:last-child {{ border-bottom: none; }}

        .footer {{
            text-align: center;
            padding: 30px;
            color: #606070;
            font-size: 0.85rem;
            border-top: 1px solid #2a2f3e;
            margin-top: 40px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 CloudSecure <span>Security Report</span></h1>
        <p>AI-Powered CloudTrail Log Analysis | Generated: {timestamp}</p>
        <p>⚡ Powered by Groq AI (Llama3) | Total Events Analyzed: {len(events)}</p>
    </div>

    <div class="container">
        <div class="summary-grid">
            <div class="summary-card">
                <div class="count" style="color: #dc3545">{severity_counts['CRITICAL']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #fd7e14">{severity_counts['HIGH']}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #ffc107">{severity_counts['MEDIUM']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #17a2b8">{severity_counts['LOW']}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #28a745">{severity_counts['INFO']}</div>
                <div class="label">Info</div>
            </div>
        </div>

        <h2 class="section-title">📋 Security Events Analysis</h2>

        {events_html}
    </div>

    <div class="footer">
        <p>CloudSecure AI Security Analyzer | Built by Abhi |
        Powered by Groq AI</p>
        <p>🔒 This report is confidential</p>
    </div>
</body>
</html>"""

    return html

def main():
    print("=" * 50)
    print("🔐 CloudSecure AI Security Analyzer")
    print("=" * 50)

    # Check API key
    if not os.getenv('GROQ_API_KEY'):
        print("❌ ERROR: GROQ_API_KEY not found in .env file!")
        print("Add this to your .env file:")
        print("GROQ_API_KEY=gsk_your-key-here")
        return

    # Load logs
    log_file = "sample_logs/cloudtrail_events.json"

    if not os.path.exists(log_file):
        print(f"❌ ERROR: Log file not found: {log_file}")
        return

    events = load_cloudtrail_logs(log_file)

    # Analyze each event
    print("\n🤖 Analyzing events with Groq AI (Llama3)...")
    print("-" * 50)

    analyses = []
    for i, event in enumerate(events):
        event_name = event.get('eventName', 'Unknown')
        print(f"Analyzing event {i+1}/{len(events)}: {event_name}...")

        ai_response = analyze_event_with_ai(event)
        analysis = parse_ai_response(ai_response)
        analyses.append(analysis)

        print(f"  → Severity: {analysis['severity']}")

    # Generate report
    print("\n📊 Generating HTML report...")
    html_report = generate_html_report(events, analyses)

    # Save report
    report_path = "reports/security_report.html"
    os.makedirs("reports", exist_ok=True)

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_report)

    print(f"✅ Report saved: {report_path}")

    # Print summary
    print("\n" + "=" * 50)
    print("📊 ANALYSIS SUMMARY")
    print("=" * 50)

    severity_counts = {}
    for analysis in analyses:
        sev = analysis['severity'].upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for severity, count in sorted(severity_counts.items()):
        emoji = {'CRITICAL': '🔴', 'HIGH': '🟠',
                 'MEDIUM': '🟡', 'LOW': '🔵', 'INFO': '🟢'}
        print(f"  {emoji.get(severity, '⚪')} {severity}: {count} events")

    print(f"\n✅ Total: {len(events)} events analyzed")
    print(f"📄 Report: {report_path}")
    print("\n🌐 Open reports/security_report.html in your browser!")
    print("=" * 50)

if __name__ == "__main__":
    main()