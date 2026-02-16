#!/usr/bin/env python3
"""
Fetch REAL CloudTrail logs from YOUR AWS account
and save them for analysis
"""

import boto3
import json
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

def fetch_real_cloudtrail_logs(hours=24, max_events=20):
    """
    Fetch real CloudTrail events from your AWS account
    
    hours = How far back to look (default 24 hours)
    max_events = Maximum events to fetch (default 20)
    """
    
    print("=" * 50)
    print("🔍 Fetching REAL CloudTrail logs from AWS...")
    print("=" * 50)
    
    # Connect to AWS CloudTrail
    cloudtrail = boto3.client(
        'cloudtrail',
        region_name='us-east-1'
    )
    
    # Time range - last 24 hours
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    print(f"📅 Time range: Last {hours} hours")
    print(f"   From: {start_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"   To:   {end_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print()
    
    # Fetch events from CloudTrail
    print("📡 Connecting to AWS CloudTrail...")
    
    response = cloudtrail.lookup_events(
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=max_events
    )
    
    raw_events = response.get('Events', [])
    print(f"✅ Found {len(raw_events)} real events!")
    print()
    
    if len(raw_events) == 0:
        print("⚠️  No events found in last 24 hours")
        print("   Try increasing hours parameter")
        print("   Or make sure AWS CLI is configured")
        return None
    
    # Convert to CloudTrail format
    records = []
    print("📋 Events found:")
    print("-" * 40)
    
    for event in raw_events:
        # Parse the CloudTrail event JSON
        cloud_trail_event = json.loads(
            event.get('CloudTrailEvent', '{}')
        )
        
        event_name = event.get('EventName', 'Unknown')
        username = event.get('Username', 'Unknown')
        event_time = event.get('EventTime', '')
        
        # Convert datetime to string if needed
        if hasattr(event_time, 'strftime'):
            event_time = event_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        print(f"  → {event_name} by {username} at {event_time}")
        
        records.append(cloud_trail_event)
    
    print("-" * 40)
    
    # Save to file
    output = {"Records": records}
    output_path = "sample_logs/real_cloudtrail_events.json"
    
    os.makedirs("sample_logs", exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    
    print(f"\n✅ Real logs saved to: {output_path}")
    print(f"📊 Total events: {len(records)}")
    
    return output_path

def main():
    # Check AWS credentials
    print("🔑 Checking AWS credentials...")
    
    try:
        sts = boto3.client('sts', region_name='us-east-1')
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        arn = identity['Arn']
        print(f"✅ Connected as: {arn}")
        print(f"✅ Account ID: {account_id}")
        print()
    except Exception as e:
        print(f"❌ AWS credentials error: {e}")
        print()
        print("Fix: Run this command:")
        print("  aws configure")
        print("  Enter your Access Key, Secret Key, Region")
        return
    
    # Fetch logs - last 72 hours to get more events
    log_file = fetch_real_cloudtrail_logs(
        hours=72,
        max_events=15
    )
    
    if log_file:
        print()
        print("=" * 50)
        print("🚀 Now run the analyzer!")
        print("=" * 50)
        print()
        print("Run this command:")
        print("  python analyzer.py --file sample_logs/real_cloudtrail_events.json")
        print()
        print("Or update analyzer.py to use real logs:")
        print('  log_file = "sample_logs/real_cloudtrail_events.json"')

if __name__ == "__main__":
    main()