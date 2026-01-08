import json
import os
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from pathlib import Path
import hvac
import requests
import xml.etree.ElementTree as ET
import boto3
from collections import defaultdict

# --- Environment Configuration ---
ENV_CONFIG = {
    'prod': {
        'vault_url': 'https://vault.topgolf.io',
        'vault_secret_path': 'sys-hris-api',
        'vault_mount_point': 'mulesoft-integrations',
        'workday_host': 'services1.wd501.myworkday.com',
        'cache_host': 'tg-cache-sys-api.rtf.topgolf.io',  # TODO: confirm prod cache URL
        'report_output_path': r'\\TIO365TEST\Integrations\Reconciliation\Reports',
    },
    'preprod': {
        'vault_url': 'https://vault.preprod.topgolf.io',
        'vault_secret_path': 'sys-hris-api',
        'vault_mount_point': 'mulesoft-integrations',
        'workday_host': 'impl-services1.wd501.myworkday.com',
        'cache_host': 'tg-cache-sys-api.preprod.rtf.topgolf.io',
        'report_output_path': r'\\TIO365TEST\Integrations\Reconciliation\Reports',
    },
    'sandbox': {
        'vault_url': 'https://vault.preprod.topgolf.io',
        'vault_secret_path': 'sys-hris-api',
        'vault_mount_point': 'mulesoft-integrations',
        'workday_host': 'impl-services1.wd501.myworkday.com',
        'cache_host': 'tg-cache-sys-api.preprod.rtf.topgolf.io',
        'report_output_path': './reports',  # Local for sandbox testing
    },
    'local': {
        'vault_url': 'https://vault.preprod.topgolf.io',
        'vault_secret_path': 'sys-hris-api',
        'vault_mount_point': 'mulesoft-integrations',
        'workday_host': 'services1.wd501.myworkday.com',
        'cache_host': 'tg-cache-sys-api.preprod.rtf.topgolf.io',
        'report_output_path': './reports',  # Local for development
    }
}

# Backwards compatibility alias
VAULT_CONFIG = {env: {
    'url': cfg['vault_url'],
    'secret_path': cfg['vault_secret_path'],
    'mount_point': cfg['vault_mount_point']
} for env, cfg in ENV_CONFIG.items()}

# --- Vault Secret Retrieval ---
def get_vault_client(environment: str = 'prod') -> hvac.Client:
    """
    Get authenticated Vault client.
    
    Tries authentication methods in order:
    1. Token auth (VAULT_TOKEN env var) - for local testing
    2. AWS IAM auth - for Lambda execution
    """
    config = VAULT_CONFIG.get(environment, VAULT_CONFIG['prod'])
    vault_url = os.environ.get('VAULT_ADDR', config['url'])
    
    client = hvac.Client(url=vault_url)
    
    # Method 1: Token auth (for local testing)
    vault_token = os.environ.get('VAULT_TOKEN')
    if vault_token:
        client.token = vault_token
        if client.is_authenticated():
            print(f"[VAULT] Authenticated using token")
            return client
        else:
            print(f"[VAULT] Token auth failed - token may be expired")
    
    # Method 2: AWS IAM auth (for Lambda)
    try:
        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials:
            frozen_credentials = credentials.get_frozen_credentials()
            vault_role = os.environ.get('VAULT_ROLE', 'lambda-timecard-reconciliation')
            
            client.auth.aws.iam_login(
                access_key=frozen_credentials.access_key,
                secret_key=frozen_credentials.secret_key,
                session_token=frozen_credentials.token,
                role=vault_role
            )
            print(f"[VAULT] Authenticated using AWS IAM role: {vault_role}")
            return client
    except Exception as e:
        print(f"[VAULT] AWS IAM auth failed: {e}")
    
    raise RuntimeError("Could not authenticate to Vault (tried token and IAM methods)")

def get_secrets_from_vault(environment: str = 'prod') -> Dict[str, str]:
    """
    Fetch secrets from Vault KV v2.

    Authentication priority:
    1. VAULT_TOKEN env var (local testing)
    2. AWS IAM auth (Lambda execution)
    3. Fall back to environment variables
    
    Args:
        environment: 'prod' or 'preprod'
    """
    config = VAULT_CONFIG.get(environment, VAULT_CONFIG['prod'])
    
    # 1) Try Vault authentication
    try:
        client = get_vault_client(environment)
        
        resp = client.secrets.kv.v2.read_secret_version(
            path=config['secret_path'],
            mount_point=config['mount_point']
        )
        
        # Extract secrets from response
        vault_data = resp.get('data', {}).get('data', {})
        
        # Map Vault keys to our expected keys
        secrets = {
            'workday_password': vault_data.get('workday_password_prop'),
            'workday_user': vault_data.get('workday_user_prop', 'ISU_INT032_POS_Timecards_Inbound'),
            'toast_client_id': vault_data.get('toast_client_id'),
            'toast_client_secret': vault_data.get('toast_client_secret'),
        }
        
        print(f"[VAULT] Successfully retrieved secrets from {environment} Vault ({config['url']})")
        return {k: v for k, v in secrets.items() if v}
        
    except Exception as e:
        print(f"[VAULT] Failed to get secrets from Vault: {e}")
        print(f"[VAULT] Falling back to environment variables...")

    # 2) Fallback: environment variables (for local testing)
    env_secrets = {
        'pos_sys_api_client_id': os.environ.get('POS_SYS_API_CLIENT_ID'),
        'pos_sys_api_client_secret': os.environ.get('POS_SYS_API_CLIENT_SECRET'),
        'toast_client_id': os.environ.get('TOAST_CLIENT_ID'),
        'toast_client_secret': os.environ.get('TOAST_CLIENT_SECRET'),
        'toast_bearer_token': os.environ.get('TOAST_BEARER_TOKEN'),
        'workday_user': os.environ.get('WORKDAY_USER'),
        'workday_password': os.environ.get('WORKDAY_PASSWORD'),
        'workday_tenant': os.environ.get('WORKDAY_TENANT'),
        'workday_host': os.environ.get('WORKDAY_HOST'),
        'workday_host_sandbox': os.environ.get('WORKDAY_HOST_SANDBOX'),
    }
    secrets = {k: v for k, v in env_secrets.items() if v}
    if secrets:
        print("[LOCAL TEST] Using environment variables for secrets")
        return secrets

    raise RuntimeError(
        "Secrets not available. Ensure Lambda has IAM role with Vault access, "
        "or set environment variables for local testing."
    )

# --- Slack Notification ---
def send_slack_message(text: str, webhook_url: str = None):
    """Send formatted message to Slack channel."""
    if not webhook_url:
        print(f"\n--- SLACK (LOCAL TEST) ---")
        print(text)
        print(f"--- END SLACK ---\n")
        return
    
    # Use simple text format to avoid blocks issues
    message = {
        "text": text
    }
    
    try:
        response = requests.post(
            webhook_url,
            json=message,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ Slack notification sent to #timecard-reconciliation-project")
        else:
            print(f"❌ Failed to send Slack notification: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Error sending Slack notification: {e}")

# --- Email Notification (AWS SES) ---
def send_email(subject: str, body: str, to_addresses: list, from_address: str):
    print(f"\n--- EMAIL (LOCAL TEST) ---")
    print(f"From: {from_address}")
    print(f"To: {', '.join(to_addresses)}")
    print(f"Subject: {subject}")
    print(f"Body:\n{body}")
    print(f"--- END EMAIL ---\n")

# --- HTML Report Generation ---
def generate_html_report(
    business_date: str,
    run_type: str,
    toast_stats: Dict[str, Dict[str, Any]],
    wd_stats: Dict[str, Dict[str, Any]],
    toast_missing_in_workday: List[Dict[str, Any]],
    workday_missing_in_toast: List[Dict[str, Any]],
    odd_punch_venues: Dict[str, List[str]],
    missing_punches_by_venue: Dict[str, Dict[str, Any]],
    venue_names: Dict[str, str] = None
) -> str:
    """
    Generate a professional HTML report for the timecard reconciliation.
    
    Args:
        business_date: The date being reconciled
        run_type: Type of reconciliation run (daily_scheduled, adhoc, etc.)
        toast_stats: Aggregated Toast timecard statistics by venue
        wd_stats: Aggregated Workday timecard statistics by venue
        toast_missing_in_workday: Toast punches not found in Workday
        workday_missing_in_toast: Workday punches not found in Toast
        odd_punch_venues: Venues with employees having odd punch counts
        missing_punches_by_venue: Missing punches grouped by venue
        
    Returns:
        HTML string of the complete report
    """
    # Calculate totals - use punch counts for accurate comparison
    # Toast 'punches' = actual punch events, Workday 'count' = raw events (also punches)
    total_toast_punches = sum(stats.get('punches', 0) for stats in toast_stats.values())
    total_toast_hours = sum(stats['hours'] for stats in toast_stats.values())
    total_wd_punches = sum(stats.get('count', 0) for stats in wd_stats.values())
    total_wd_hours = sum(stats.get('hours', 0.0) for stats in wd_stats.values())
    total_odd_punch_employees = sum(len(employees) for employees in odd_punch_venues.values())
    
    # Determine report context (same-day vs historical)
    today = datetime.now().strftime('%Y-%m-%d')
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    
    if business_date == today:
        report_context = 'live'
        context_label = '📊 Live Report'
        context_description = 'Employees may still be working - open timecards are expected'
        context_color = '#3b82f6'  # Blue
        odd_punch_title = '🟢 Employees Currently Working'
        odd_punch_severity = 'info'  # Expected, not an error
    elif business_date == yesterday:
        report_context = 'recent'
        context_label = '📋 Recent Report'
        context_description = 'Previous business day - open timecards may need review'
        context_color = '#f59e0b'  # Amber
        odd_punch_title = '🟡 Open Timecards (Pending Resolution)'
        odd_punch_severity = 'warning'
    else:
        report_context = 'historical'
        context_label = '📁 Historical Report'
        context_description = 'Closed business day - open timecards require investigation'
        context_color = '#ef4444'  # Red
        odd_punch_title = '🔴 Incomplete Timecards (Data Issue)'
        odd_punch_severity = 'error'
    
    # Determine status colors based on punch counts
    # Workday - Toast: negative means missing in Workday (what we care about)
    punch_diff = total_wd_punches - total_toast_punches
    hours_diff = total_wd_hours - total_toast_hours
    
    punch_status_color = "#22c55e" if punch_diff == 0 else "#ef4444" if punch_diff < -10 else "#f59e0b"
    hours_status_color = "#22c55e" if abs(hours_diff) < 1 else "#ef4444" if abs(hours_diff) > 10 else "#f59e0b"
    overall_status = "✅ PASS" if punch_diff == 0 and abs(hours_diff) < 1 else "⚠️ REVIEW" if punch_diff >= -10 else "❌ FAIL"
    overall_color = "#22c55e" if "PASS" in overall_status else "#f59e0b" if "REVIEW" in overall_status else "#ef4444"
    
    report_generated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Timecard Reconciliation Report - {business_date}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3a5f 0%, #0f1f38 100%);
            min-height: 100vh;
            color: #e2e8f0;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 24px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
        }}
        
        .header h1 {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 8px;
            color: #fff;
        }}
        
        .header-meta {{
            display: flex;
            gap: 24px;
            flex-wrap: wrap;
            color: #93c5fd;
            font-size: 0.95rem;
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 1.1rem;
            background-color: {overall_color};
            color: white;
            margin-top: 16px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        
        .summary-card {{
            background: rgba(30, 41, 59, 0.8);
            border-radius: 12px;
            padding: 24px;
            border: 1px solid rgba(148, 163, 184, 0.2);
            backdrop-filter: blur(10px);
        }}
        
        .summary-card h3 {{
            color: #94a3b8;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }}
        
        .summary-card .value {{
            font-size: 2rem;
            font-weight: 700;
            color: #fff;
        }}
        
        .summary-card .sub-value {{
            font-size: 0.9rem;
            color: #64748b;
            margin-top: 4px;
        }}
        
        .diff-positive {{ color: #22c55e; }}
        .diff-negative {{ color: #ef4444; }}
        .diff-warning {{ color: #f59e0b; }}
        
        .section {{
            background: rgba(30, 41, 59, 0.8);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            border: 1px solid rgba(148, 163, 184, 0.2);
        }}
        
        .section h2 {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(148, 163, 184, 0.2);
            color: #f1f5f9;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        
        th {{
            background: rgba(15, 23, 42, 0.6);
            padding: 12px 16px;
            text-align: left;
            font-weight: 600;
            color: #94a3b8;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}
        
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid rgba(148, 163, 184, 0.1);
            color: #e2e8f0;
        }}
        
        tr:hover td {{
            background: rgba(30, 41, 59, 0.5);
        }}
        
        .venue-match {{ color: #22c55e; }}
        .venue-mismatch {{ color: #ef4444; }}
        .venue-warning {{ color: #f59e0b; }}
        
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        
        .badge-success {{ background: rgba(34, 197, 94, 0.2); color: #22c55e; }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; }}
        .badge-error {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; }}
        
        .context-banner {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 20px;
            border-radius: 8px;
            margin-top: 16px;
            font-size: 0.95rem;
        }}
        
        .context-banner.live {{
            background: rgba(59, 130, 246, 0.15);
            border: 1px solid rgba(59, 130, 246, 0.3);
            color: #93c5fd;
        }}
        
        .context-banner.recent {{
            background: rgba(245, 158, 11, 0.15);
            border: 1px solid rgba(245, 158, 11, 0.3);
            color: #fcd34d;
        }}
        
        .context-banner.historical {{
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
        }}
        
        .context-label {{
            font-weight: 600;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85rem;
        }}
        
        .context-banner.live .context-label {{ background: rgba(59, 130, 246, 0.3); }}
        .context-banner.recent .context-label {{ background: rgba(245, 158, 11, 0.3); }}
        .context-banner.historical .context-label {{ background: rgba(239, 68, 68, 0.3); }}
        
        .odd-punch-section.info {{
            border-left: 4px solid #3b82f6;
        }}
        
        .odd-punch-section.warning {{
            border-left: 4px solid #f59e0b;
        }}
        
        .odd-punch-section.error {{
            border-left: 4px solid #ef4444;
        }}
        
        .missing-punch-item {{
            background: rgba(15, 23, 42, 0.4);
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 8px;
            border-left: 3px solid #ef4444;
        }}
        
        .missing-punch-item.workday {{
            border-left-color: #f59e0b;
        }}
        
        .missing-punch-details {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 8px;
            margin-top: 8px;
            font-size: 0.85rem;
            color: #94a3b8;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #64748b;
            font-size: 0.85rem;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #64748b;
        }}
        
        .collapse-toggle {{
            cursor: pointer;
            user-select: none;
        }}
        
        .collapse-toggle:hover {{
            color: #60a5fa;
        }}
        
        /* Expandable venue sections */
        .venue-expand-btn {{
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.4);
            color: #f87171;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}
        
        .venue-expand-btn:hover {{
            background: rgba(239, 68, 68, 0.3);
            transform: translateY(-1px);
        }}
        
        .venue-expand-btn.workday {{
            background: rgba(245, 158, 11, 0.2);
            border-color: rgba(245, 158, 11, 0.4);
            color: #fbbf24;
        }}
        
        .venue-expand-btn.workday:hover {{
            background: rgba(245, 158, 11, 0.3);
        }}
        
        .venue-expand-btn.match {{
            background: rgba(34, 197, 94, 0.2);
            border-color: rgba(34, 197, 94, 0.4);
            color: #4ade80;
        }}
        
        .venue-missing-section {{
            display: none;
            background: rgba(15, 23, 42, 0.6);
            border-radius: 12px;
            padding: 20px;
            margin: 16px 0;
            border: 1px solid rgba(148, 163, 184, 0.15);
            max-height: 500px;
            overflow-y: auto;
        }}
        
        .venue-missing-section.expanded {{
            display: block;
            animation: slideDown 0.3s ease-out;
        }}
        
        @keyframes slideDown {{
            from {{
                opacity: 0;
                transform: translateY(-10px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}
        
        .venue-missing-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 12px;
            margin-bottom: 16px;
            border-bottom: 1px solid rgba(148, 163, 184, 0.2);
        }}
        
        .venue-missing-header h4 {{
            margin: 0;
            color: #f1f5f9;
            font-size: 1rem;
        }}
        
        .venue-missing-close {{
            background: rgba(148, 163, 184, 0.2);
            border: none;
            color: #94a3b8;
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.2s;
        }}
        
        .venue-missing-close:hover {{
            background: rgba(239, 68, 68, 0.3);
            color: #f87171;
        }}
        
        .venue-missing-grid {{
            display: grid;
            gap: 8px;
        }}
        
        .venue-summary-row {{
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            align-items: center;
        }}
        
        .view-missing-link {{
            color: #60a5fa;
            cursor: pointer;
            text-decoration: underline;
            font-size: 0.85rem;
        }}
        
        .view-missing-link:hover {{
            color: #93c5fd;
        }}
        
        .missing-by-venue-section {{
            margin-bottom: 24px;
        }}
        
        .venue-accordion {{
            background: rgba(15, 23, 42, 0.4);
            border-radius: 8px;
            margin-bottom: 8px;
            overflow: hidden;
            border: 1px solid rgba(148, 163, 184, 0.1);
        }}
        
        .venue-accordion-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px;
            cursor: pointer;
            background: rgba(30, 41, 59, 0.5);
            transition: background 0.2s;
        }}
        
        .venue-accordion-header:hover {{
            background: rgba(30, 41, 59, 0.8);
        }}
        
        .venue-accordion-title {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        .venue-accordion-title strong {{
            color: #f1f5f9;
        }}
        
        .venue-accordion-count {{
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        
        .venue-accordion-count.workday {{
            background: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
        }}
        
        .venue-accordion-arrow {{
            color: #64748b;
            transition: transform 0.3s;
        }}
        
        .venue-accordion.expanded .venue-accordion-arrow {{
            transform: rotate(180deg);
        }}
        
        .venue-accordion-content {{
            display: none;
            padding: 16px;
            background: rgba(15, 23, 42, 0.3);
        }}
        
        .venue-accordion.expanded .venue-accordion-content {{
            display: block;
        }}
        
        .stats-summary {{
            display: flex;
            gap: 24px;
            flex-wrap: wrap;
            margin-bottom: 20px;
            padding: 12px 16px;
            background: rgba(30, 41, 59, 0.5);
            border-radius: 8px;
        }}
        
        .stats-summary-item {{
            color: #94a3b8;
            font-size: 0.85rem;
        }}
        
        .stats-summary-item strong {{
            color: #f1f5f9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕐 Timecard Reconciliation Report</h1>
            <div class="header-meta">
                <span>📅 Business Date: <strong>{business_date}</strong></span>
                <span>🏃 Run Type: <strong>{run_type}</strong></span>
                <span>🕐 Generated: <strong>{report_generated}</strong></span>
            </div>
            <div class="status-badge">{overall_status}</div>
            <div class="context-banner {report_context}">
                <span class="context-label">{context_label}</span>
                <span>{context_description}</span>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Toast Punches</h3>
                <div class="value">{total_toast_punches:,}</div>
                <div class="sub-value">{total_toast_hours:,.2f} hours</div>
            </div>
            <div class="summary-card">
                <h3>Workday Punches</h3>
                <div class="value">{total_wd_punches:,}</div>
                <div class="sub-value">{total_wd_hours:,.2f} hours</div>
            </div>
            <div class="summary-card">
                <h3>Punch Difference</h3>
                <div class="value" style="color: {punch_status_color}">{punch_diff:+d}</div>
                <div class="sub-value">Workday - Toast (negative = missing)</div>
            </div>
            <div class="summary-card">
                <h3>Hours Difference</h3>
                <div class="value" style="color: {hours_status_color}">{hours_diff:+,.2f}</div>
                <div class="sub-value">Workday - Toast</div>
            </div>
            <div class="summary-card">
                <h3>Missing in Workday</h3>
                <div class="value" style="color: {'#ef4444' if len(toast_missing_in_workday) > 0 else '#22c55e'}">{len(toast_missing_in_workday)}</div>
                <div class="sub-value">Toast punches to reprocess</div>
            </div>
            <div class="summary-card">
                <h3>{'Still Working' if report_context == 'live' else 'Open Timecards' if report_context == 'recent' else 'Incomplete Timecards'}</h3>
                <div class="value" style="color: {context_color}">{total_odd_punch_employees}</div>
                <div class="sub-value">{'Employees currently clocked in' if report_context == 'live' else 'Employees with open punches' if report_context == 'recent' else 'Requires investigation'}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Venue Comparison</h2>
"""
    
    # Generate venue comparison table
    all_venues = sorted(set(toast_stats.keys()) | set(wd_stats.keys()))
    
    # Default venue_names if not provided
    if venue_names is None:
        venue_names = {}
    
    # Pre-calculate missing counts per venue for the table
    # The table uses site_id as the key (see toast_stats re-keying logic in main handler)
    # So we must use venue_site_id here to match
    toast_missing_by_venue = {}
    
    for punch in toast_missing_in_workday:
        # Use venue_site_id as key to match the table's venue keys
        # The table re-keys from hris_location → site_id, so we use site_id here
        venue_key = punch.get('venue_site_id', 'Unknown')
        if venue_key not in toast_missing_by_venue:
            toast_missing_by_venue[venue_key] = []
        toast_missing_by_venue[venue_key].append(punch)
    
    # Debug: print the venue keys being used
    print(f"[HTML] Toast stats venues: {sorted(list(toast_stats.keys()))[:5]}...")
    print(f"[HTML] Toast missing by venue keys: {sorted(list(toast_missing_by_venue.keys()))[:5]}...")
    
    if all_venues:
        html += """
            <table>
                <thead>
                    <tr>
                        <th>Site ID</th>
                        <th>Name</th>
                        <th>Toast Punches</th>
                        <th>Toast Hours</th>
                        <th>Workday Punches</th>
                        <th>Workday Hours</th>
                        <th>Punch Diff</th>
                        <th>Hours Diff</th>
                        <th>Odd Punches</th>
                        <th>Status</th>
                        <th>Missing in Workday</th>
                    </tr>
                </thead>
                <tbody>
"""
        for venue in all_venues:
            # Get the display name for this venue
            display_name = venue_names.get(venue, venue)
            toast_punches = toast_stats.get(venue, {}).get('punches', 0)
            toast_hours = toast_stats.get(venue, {}).get('hours', 0.0)
            # Workday 'count' is raw events (each is a punch), so use it as punch count
            wd_punches = wd_stats.get(venue, {}).get('count', 0)
            wd_hours = wd_stats.get(venue, {}).get('hours', 0.0)
            # Compare raw punches for accurate diff (Workday - Toast: negative = missing in Workday)
            venue_punch_diff = wd_punches - toast_punches
            venue_hours_diff = wd_hours - toast_hours
            venue_odd_count = len(odd_punch_venues.get(venue, []))
            
            # Get missing punch count for this venue (Toast punches missing in Workday)
            venue_toast_missing = len(toast_missing_by_venue.get(venue, []))
            
            # Determine venue status based on punch diff and missing count
            if venue_punch_diff == 0 and venue_toast_missing == 0:
                status_badge = '<span class="badge badge-success">Match</span>'
            elif venue_punch_diff >= -5 and venue_toast_missing <= 5:
                status_badge = '<span class="badge badge-warning">Review</span>'
            else:
                status_badge = '<span class="badge badge-error">Mismatch</span>'
            
            # Green if zero, red if negative (missing in Workday), amber otherwise
            punch_diff_class = "diff-positive" if venue_punch_diff == 0 else "diff-negative" if venue_punch_diff < 0 else "diff-warning"
            hours_diff_class = "diff-positive" if abs(venue_hours_diff) < 1 else "diff-negative" if venue_hours_diff < -1 else "diff-warning"
            
            # Create safe venue ID for HTML (replace special characters)
            safe_venue_id = venue.replace(' ', '_').replace('.', '_').replace("'", '')
            
            # Create missing details buttons (only Toast missing - Workday is source of truth focus)
            missing_buttons = []
            if venue_toast_missing > 0:
                missing_buttons.append(f'<button class="venue-expand-btn" onclick="scrollToVenue(\'{safe_venue_id}\', \'toast\')">🔴 {venue_toast_missing} Missing</button>')
            else:
                missing_buttons.append('<span class="badge badge-success">✓ All Synced</span>')
            
            missing_details_html = ' '.join(missing_buttons)
            
            html += f"""
                    <tr>
                        <td><strong>{venue}</strong></td>
                        <td>{display_name}</td>
                        <td>{toast_punches:,}</td>
                        <td>{toast_hours:,.2f}</td>
                        <td>{wd_punches:,}</td>
                        <td>{wd_hours:,.2f}</td>
                        <td class="{punch_diff_class}">{venue_punch_diff:+d}</td>
                        <td class="{hours_diff_class}">{venue_hours_diff:+,.2f}</td>
                        <td style="color: {'#f59e0b' if venue_odd_count > 0 else '#22c55e'}">{venue_odd_count}</td>
                        <td>{status_badge}</td>
                        <td>{missing_details_html}</td>
                    </tr>
"""
        html += """
                </tbody>
            </table>
"""
    else:
        html += '<div class="empty-state">No venue data available</div>'
    
    html += """
        </div>
"""
    
    # Missing punches section - Toast missing in Workday (Grouped by Venue)
    html += """
        <div class="section">
            <h2>🔴 Toast Punches Missing in Workday (Reprocess Required)</h2>
"""
    
    if toast_missing_in_workday:
        # Calculate summary statistics
        venues_with_toast_missing = sorted(toast_missing_by_venue.keys())
        html += f'''
            <div class="stats-summary">
                <span class="stats-summary-item">📊 Total Missing: <strong>{len(toast_missing_in_workday)}</strong></span>
                <span class="stats-summary-item">🏢 Venues Affected: <strong>{len(venues_with_toast_missing)}</strong></span>
                <span class="stats-summary-item" style="margin-left: auto;">
                    <button class="venue-expand-btn" onclick="expandAllVenues('toast-missing')">Expand All</button>
                    <button class="venue-expand-btn" style="margin-left: 8px;" onclick="collapseAllVenues('toast-missing')">Collapse All</button>
                </span>
            </div>
            <p style="margin-bottom: 16px; color: #94a3b8;">Click on a venue to view its missing punches. These need to be reprocessed to Workday.</p>
'''
        
        # Group by venue in accordion format
        for venue in venues_with_toast_missing:
            punches = toast_missing_by_venue[venue]
            safe_venue_id = venue.replace(' ', '_').replace('.', '_').replace("'", '')
            venue_display = venue_names.get(venue, venue)
            
            html += f'''
            <div class="venue-accordion toast-missing" id="accordion-toast-{safe_venue_id}">
                <div class="venue-accordion-header" onclick="toggleVenueAccordion('toast-{safe_venue_id}')">
                    <div class="venue-accordion-title">
                        <strong>📍 {venue}</strong>
                        <span style="color: #64748b;">({venue_display})</span>
                        <span class="venue-accordion-count">{len(punches)} missing</span>
                    </div>
                    <span class="venue-accordion-arrow">▼</span>
                </div>
                <div class="venue-accordion-content">
                    <div class="venue-missing-grid">
'''
            # Show all punches for this venue (no limit per venue)
            for punch in punches:
                html += f'''
                        <div class="missing-punch-item">
                            <strong>{punch.get('employee_name', 'Unknown')} ({punch.get('employee_id', 'Unknown')})</strong>
                            <div class="missing-punch-details">
                                <span>🕐 Time: {punch.get('punch_time', 'Unknown')}</span>
                                <span>📝 Event: {punch.get('event_type', 'Unknown')}</span>
                                <span>➡️ Expected: {punch.get('expected_workday_event', 'Unknown')}</span>
                            </div>
                        </div>
'''
            html += '''
                    </div>
                </div>
            </div>
'''
    else:
        html += '<div class="empty-state">✅ All Toast punches found in Workday</div>'
    
    html += """
        </div>
"""
    
    # Odd punch counts section - context-aware
    # Note: "Workday Missing in Toast" section removed - focus is on Toast→Workday sync issues only
    html += f"""
        <div class="section odd-punch-section {odd_punch_severity}">
            <h2>{odd_punch_title}</h2>
"""
    
    if odd_punch_venues:
        # Context-aware description
        if report_context == 'live':
            description = f"Found {total_odd_punch_employees} employees currently clocked in across {len(odd_punch_venues)} venues. This is expected for a live report."
            action_note = "💡 <strong>Tip:</strong> These employees are likely still working. Check back after end of business for final reconciliation."
            venue_icon_color = "#3b82f6"  # Blue for info
        elif report_context == 'recent':
            description = f"Found {total_odd_punch_employees} employees with open timecards across {len(odd_punch_venues)} venues. These may auto-close or need manager review."
            action_note = "💡 <strong>Action:</strong> Review these with venue managers. Some may have been auto-clocked-out by the system."
            venue_icon_color = "#f59e0b"  # Amber for warning
        else:
            description = f"Found {total_odd_punch_employees} employees with incomplete timecards across {len(odd_punch_venues)} venues. These require investigation."
            action_note = "⚠️ <strong>Action Required:</strong> These represent potential payroll discrepancies. Investigate each case and create corrective entries."
            venue_icon_color = "#ef4444"  # Red for error
        
        html += f'<p style="margin-bottom: 8px; color: #94a3b8;">{description}</p>'
        html += f'<p style="margin-bottom: 16px; color: #94a3b8; font-style: italic;">{action_note}</p>'
        
        for venue in sorted(odd_punch_venues.keys()):
            employees = odd_punch_venues[venue]
            html += f"""
            <div style="margin-bottom: 16px;">
                <h4 style="color: {venue_icon_color}; margin-bottom: 8px;">📍 {venue} ({len(employees)} employees)</h4>
                <ul style="list-style: none; padding-left: 16px;">
"""
            for emp_info in employees[:10]:
                html += f'<li style="color: #94a3b8; margin-bottom: 4px;">• {emp_info}</li>'
            
            if len(employees) > 10:
                html += f'<li style="color: #64748b;">... and {len(employees) - 10} more</li>'
            
            html += """
                </ul>
            </div>
"""
    else:
        if report_context == 'live':
            html += '<div class="empty-state">✅ No employees currently working (unusual for a live report)</div>'
        else:
            html += '<div class="empty-state">✅ All employees have complete timecard sequences</div>'
    
    html += """
        </div>
        
        <div class="footer">
            <p>Topgolf Timecard Reconciliation System | Generated automatically</p>
            <p>For questions, contact the Integrations Team</p>
        </div>
    </div>
    
    <script>
        // Toggle venue accordion sections
        function toggleVenueAccordion(venueId) {
            const accordion = document.getElementById('accordion-' + venueId);
            if (accordion) {
                accordion.classList.toggle('expanded');
            }
        }
        
        // Close a specific venue section
        function closeVenueSection(venueId) {
            const accordion = document.getElementById('accordion-' + venueId);
            if (accordion) {
                accordion.classList.remove('expanded');
            }
        }
        
        // Expand all sections
        function expandAllVenues(sectionType) {
            const accordions = document.querySelectorAll('.venue-accordion.' + sectionType);
            accordions.forEach(accordion => accordion.classList.add('expanded'));
        }
        
        // Collapse all sections
        function collapseAllVenues(sectionType) {
            const accordions = document.querySelectorAll('.venue-accordion.' + sectionType);
            accordions.forEach(accordion => accordion.classList.remove('expanded'));
        }
        
        // Scroll to a venue section and expand it
        function scrollToVenue(venueId, sectionType) {
            const sectionPrefix = sectionType === 'toast' ? 'toast-' : 'wd-';
            const accordion = document.getElementById('accordion-' + sectionPrefix + venueId);
            if (accordion) {
                accordion.classList.add('expanded');
                accordion.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }
    </script>
</body>
</html>
"""
    
    return html


def save_html_report(html_content: str, business_date: str, report_path: str = None, environment: str = 'local') -> str:
    """
    Save the HTML report to the specified location.
    
    Args:
        html_content: The HTML report content
        business_date: The business date for filename generation
        report_path: Optional custom path. If not provided, uses environment config
        environment: Environment name ('prod', 'preprod', 'sandbox', 'local')
    
    Returns:
        The full path where the report was saved
    
    Supports:
        - Local paths (e.g., ./reports, /tmp/reports)
        - UNC network paths (e.g., \\\\TIO365TEST\\Integrations\\Reconciliation\\Reports)
    """
    # Determine output path (priority: explicit path > env var > config > default)
    if report_path:
        base_path = report_path
    elif os.environ.get('REPORT_OUTPUT_PATH'):
        base_path = os.environ.get('REPORT_OUTPUT_PATH')
    else:
        # Use environment config
        env_config = ENV_CONFIG.get(environment, ENV_CONFIG['local'])
        base_path = env_config.get('report_output_path', './reports')
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"timecard_reconciliation_{business_date}_{timestamp}.html"
    
    # Handle both local and UNC paths
    if base_path.startswith('\\\\'):
        # UNC path - use raw string handling
        full_path = os.path.join(base_path, filename)
    else:
        # Local path - use pathlib for better cross-platform support
        output_dir = Path(base_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        full_path = str(output_dir / filename)
    
    try:
        # Write the file
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ HTML report saved to: {full_path}")
        return full_path
        
    except PermissionError as e:
        print(f"❌ Permission denied writing to {full_path}: {e}")
        # Fallback to local temp directory
        fallback_path = Path('./reports')
        fallback_path.mkdir(parents=True, exist_ok=True)
        fallback_full = str(fallback_path / filename)
        
        with open(fallback_full, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"⚠️ Fallback: HTML report saved to: {fallback_full}")
        return fallback_full
        
    except OSError as e:
        print(f"❌ OS error writing to {full_path}: {e}")
        # Fallback to local temp directory
        fallback_path = Path('./reports')
        fallback_path.mkdir(parents=True, exist_ok=True)
        fallback_full = str(fallback_path / filename)
        
        with open(fallback_full, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"⚠️ Fallback: HTML report saved to: {fallback_full}")
        return fallback_full

# --- API Call Stubs (to be implemented) ---
def get_pos_site_details_from_cache(site_id: str, secrets: Dict[str, str]) -> Dict[str, Any]:
    """
    Fetch per-site details from cache (key: site_{siteId}) so we can derive HRIS location names.

    This lets reconciliation reports use the same canonical venue identifier Workday imports use
    (e.g., hris_sys_info.hris_sys_location = "Ft_Worth") instead of raw numeric siteId.
    """
    try:
        # Cache SYS API configuration (from MuleSoft config)
        host = "tg-cache-sys-api.preprod.rtf.topgolf.io"
        port = "443"
        base_path = "/api/v1"
        
        url = f"https://{host}:{port}{base_path}/cache"
        headers = {
            'type': 'pos',
            'Content-Type': 'application/json'
        }
        # Key format is site_{siteId} (not pos_site_{siteId})
        params = {"key": f"site_{site_id}"}

        response = requests.get(url, params=params, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()
            
            # Cache stores JSON as string - need to parse if it's a string
            if isinstance(data, str):
                try:
                    import json
                    data = json.loads(data)
                except json.JSONDecodeError:
                    print(f"[REAL] Cache returned unparseable string for site_{site_id}")
                    return {}
            
            if isinstance(data, dict):
                # Check if we got hris_sys_info
                hris_info = data.get('hris_sys_info', {})
                hris_loc = hris_info.get('hris_sys_location') if hris_info else None
                if hris_loc:
                    print(f"[REAL] Cache hit: site_{site_id} → hris_sys_location={hris_loc}")
                else:
                    # Log what keys we did get, to help debug
                    keys = list(data.keys())[:10] if data else []
                    print(f"[REAL] Cache miss: site_{site_id} has no hris_sys_location (keys: {keys})")
                    # Dump first response to see structure
                    if site_id in ['29', '1038', '10']:
                        import json as json_module
                        print(f"[DEBUG] Full cache response for site_{site_id}:")
                        print(json_module.dumps(data, indent=2, default=str)[:1000])
                return data
            else:
                print(f"[REAL] Cache returned non-dict for site_{site_id}: {type(data)}")
            return {}

        print(f"[REAL] Cache API error for site_{site_id}: {response.status_code} - {response.text[:200]}")
        return {}
    except Exception as e:
        print(f"[REAL] Cache API exception for site_{site_id}: {e}")
        return {}


def get_venue_guids_from_cache(secrets: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Get list of active venue GUIDs from Redis cache (similar to prc-associate flow)
    Returns list of venue objects with siteId, toastGuid, and timezone offsets
    """
    try:
        # Cache SYS API configuration (from MuleSoft config)
        host = "tg-cache-sys-api.preprod.rtf.topgolf.io"
        port = "443"
        base_path = "/api/v1"
        
        # Build the URL for cache endpoint
        url = f"https://{host}:{port}{base_path}/cache"
        
        # Headers - just need type: pos
        headers = {
            'type': 'pos',
            'Content-Type': 'application/json'
        }
        
        # Query parameters - get venues key (from MuleSoft config: cache.sys.api.venues.key=venues)
        params = {
            "key": "venues"  # This is the Redis key containing all live venues
        }
        
        print(f"[REAL] Calling cache API for active venues: {url}")
        print(f"[REAL] Cache API params: {params}")
        print(f"[REAL] Cache API headers: type=pos")
        
        # Make the API call
        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        
        print(f"[REAL] Cache API response status: {response.status_code}")
        if response.status_code != 200:
            print(f"[REAL] Cache API response body: {response.text[:500]}")
        
        if response.status_code == 200:
            data = response.json()
            
            # Cache stores JSON as string - need to parse if it's a string
            if isinstance(data, str):
                try:
                    import json
                    data = json.loads(data)
                    print(f"[REAL] Parsed venues JSON string successfully")
                except json.JSONDecodeError as e:
                    print(f"[REAL] Cache returned unparseable string for venues: {e}")
                    return get_fallback_venue_list()
            
            # Process venues from the actual Redis structure
            active_venues = []
            for venue in data:
                if venue.get('toastGuid'):
                    v = {
                        'siteId': venue.get('siteId'),
                        'toastGuid': venue.get('toastGuid'),
                        'name': f"Venue_{venue.get('siteId')}",  # Generate name from siteId
                        'offSet': venue.get('offSet', '-00:00'),  # Venue timezone offset
                        'toastOffSet': venue.get('toastOffSet', '-05:00'),  # Toast timezone offset
                        'active': True  # Assume all venues in pos_venues are active
                    }
                    # Best-effort enrichment: derive HRIS location name (e.g., "Ft_Worth") from per-site cache
                    site_id = v.get('siteId')
                    if site_id:
                        site_details = get_pos_site_details_from_cache(str(site_id), secrets)
                        hris_loc = (site_details.get('hris_sys_info') or {}).get('hris_sys_location')
                        if hris_loc:
                            v['hris_location_id'] = hris_loc
                        # Prefer human-friendly venue_name if present
                        venue_name = site_details.get('venue_name') or site_details.get('city_name')
                        if venue_name:
                            v['name'] = venue_name
                    active_venues.append(v)
            
            print(f"[REAL] Cache API success: {len(active_venues)} active venue GUIDs found")
            return active_venues
        else:
            print(f"[REAL] Cache API error: {response.status_code} - {response.text}")
            print(f"[REAL] Cache endpoint not available yet - using fallback venue list")
            return get_fallback_venue_list()
            
    except Exception as e:
        print(f"[REAL] Cache API exception: {e}")
        print(f"[REAL] Using fallback venue list")
        return get_fallback_venue_list()

def get_fallback_venue_list() -> List[Dict[str, Any]]:
    """
    Fallback venue list for when cache API is not available.
    This includes all actual Toast venues with real GUIDs.
    """
    print(f"[REAL] Using fallback venue list with all actual Toast venues")
    
    # All actual Toast venues with real GUIDs
    # hris_location_id maps to Workday Location_ID
    fallback_venues = [
        {
            'siteId': '29',
            'toastGuid': '8fd72cd1-0d1e-4fcb-aab1-eedbd89cb3ef',
            'name': 'Fort Worth',
            'hris_location_id': 'Ft_Worth',  # Maps to Workday Location_ID
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '10',
            'toastGuid': 'd3351fb8-29d3-438b-a1d3-d749d615096e',
            'name': 'The Colony',
            'hris_location_id': 'The_Colony',  # Maps to Workday Location_ID
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '1064',
            'toastGuid': 'bec8da8b-51e0-4b88-9ed8-6f99d19cd972',
            'name': 'Topgolf Venue 1064',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '1102',
            'toastGuid': '4006b0f2-8aa6-40b6-8ff2-cae0cd02dece',
            'name': 'Topgolf Venue 1102',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '1306',
            'toastGuid': '64f4c133-e87c-4910-919c-877d841e27ee',
            'name': 'Topgolf Venue 1306',
            'offSet': '-00:00',
            'toastOffSet': '-06:00',
            'active': True
        },
        {
            'siteId': '15',
            'toastGuid': 'a5aa2db4-6762-4b1b-9eba-cfa4c8b8a23e',
            'name': 'Topgolf Venue 15',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '9',
            'toastGuid': '5a7f97cd-ee2d-498b-a483-a384a2a0fd94',
            'name': 'Topgolf Venue 9',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '11',
            'toastGuid': '89f3c791-feb0-4760-84fb-f1639be397ea',
            'name': 'Topgolf Venue 11',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '38',
            'toastGuid': '77ed9542-7b39-4dca-9911-87437fdd0234',
            'name': 'Topgolf Venue 38',
            'offSet': '-00:00',
            'toastOffSet': '-07:00',
            'active': True
        },
        {
            'siteId': '1068',
            'toastGuid': 'a6083fcc-9ae3-4faa-b3cc-f29e0e3666d6',
            'name': 'Topgolf Venue 1068',
            'offSet': '-00:00',
            'toastOffSet': '-07:00',
            'active': True
        },
        {
            'siteId': '1092',
            'toastGuid': '31ff46b9-44bc-40f4-804f-eec7660b5108',
            'name': 'Topgolf Venue 1092',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '1098',
            'toastGuid': '56468054-5c05-4b8c-9a61-95790d861c17',
            'name': 'Topgolf Venue 1098',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '1038',
            'toastGuid': '56468054-5c05-4b8c-9a61-95790d861c17',
            'name': 'Topgolf Venue 1038',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '1084',
            'toastGuid': '5128ca2d-cd69-4b35-b026-7991a6021dc5',
            'name': 'Topgolf Venue 1084',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '18',
            'toastGuid': '13453438-025d-4d7c-8d1d-327c593f1242',
            'name': 'Topgolf Venue 18',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '1305',
            'toastGuid': '537ca41c-6618-47b3-a24f-265d5f3cfdbd',
            'name': 'Topgolf Venue 1305',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '20',
            'toastGuid': '02966def-8998-4060-a35a-e2684edc3795',
            'name': 'Topgolf Venue 20',
            'offSet': '-00:00',
            'toastOffSet': '-06:00',
            'active': True
        },
        {
            'siteId': '69',
            'toastGuid': 'f9734e7d-f641-453c-bfdb-0bf4507b7fb3',
            'name': 'Topgolf Venue 69',
            'offSet': '-00:00',
            'toastOffSet': '-06:00',
            'active': True
        },
        {
            'siteId': '28',
            'toastGuid': 'e77a7922-b596-461d-a004-02ba644b8948',
            'name': 'Topgolf Venue 28',
            'offSet': '-00:00',
            'toastOffSet': '-07:00',
            'active': True
        },
        {
            'siteId': '1085',
            'toastGuid': 'acf8b2cc-b0a6-4025-91d4-b0589cee742e',
            'name': 'Topgolf Venue 1085',
            'offSet': '-00:00',
            'toastOffSet': '-07:00',
            'active': True
        },
        {
            'siteId': '1083',
            'toastGuid': 'd5db17d2-66c6-4379-97d2-76d7bc44d2c9',
            'name': 'Topgolf Venue 1083',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '1081',
            'toastGuid': 'e69d6ba5-69c9-4ba9-b029-884b497169db',
            'name': 'Topgolf Venue 1081',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '71',
            'toastGuid': '76e65dce-154b-4af0-b334-a558a4633643',
            'name': 'Topgolf Venue 71',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '5',
            'toastGuid': '8c78989e-c67f-4f75-bb34-1157f711f5bd',
            'name': 'Topgolf Venue 5',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '7',
            'toastGuid': '41d5e749-8ef0-49c7-8495-eef504abebea',
            'name': 'Topgolf Venue 7',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '1057',
            'toastGuid': '8bdd11d0-c321-46bf-852a-da2936218e7f',
            'name': 'Topgolf Venue 1057',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '1061',
            'toastGuid': 'f55dcd92-f7ec-469c-9afb-a6955b095a3d',
            'name': 'Topgolf Venue 1061',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '1077',
            'toastGuid': '2ed61080-255d-4898-9d6d-981b4f91683e',
            'name': 'Topgolf Venue 1077',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '13',
            'toastGuid': '720212ea-bd99-4a03-a7d8-1f690a224a47',
            'name': 'Topgolf Venue 13',
            'offSet': '-00:00',
            'toastOffSet': '-07:00',
            'active': True
        },
        {
            'siteId': '47',
            'toastGuid': '61972af5-77cf-4b8b-9079-48322595db87',
            'name': 'Topgolf Venue 47',
            'offSet': '-00:00',
            'toastOffSet': '-07:00',
            'active': True
        },
        {
            'siteId': '14',
            'toastGuid': '22bc8028-c626-4518-9921-5f3d066a81f4',
            'name': 'Topgolf Venue 14',
            'offSet': '-00:00',
            'toastOffSet': '-07:00',
            'active': True
        },
        {
            'siteId': '1315',
            'toastGuid': 'a6c0e179-e4d8-4965-9e67-5f848ca10b06',
            'name': 'Topgolf Venue 1315',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '1072',
            'toastGuid': '0bba08a2-2cff-40bd-8d3e-a3cec8d271ba',
            'name': 'Topgolf Venue 1072',
            'offSet': '-00:00',
            'toastOffSet': '-07:00',
            'active': True
        },
        {
            'siteId': '55',
            'toastGuid': '17dd6001-cab9-4f80-af6e-ec11bae57066',
            'name': 'Topgolf Venue 55',
            'offSet': '-00:00',
            'toastOffSet': '-07:00',
            'active': True
        },
        {
            'siteId': '30',
            'toastGuid': '9b932e28-4cc4-41ad-aad1-d12a910c845e',
            'name': 'Topgolf Venue 30',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '17',
            'toastGuid': '5b253037-7736-42fb-acad-b8448e0844d9',
            'name': 'Topgolf Venue 17',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '1116',
            'toastGuid': '21c0320a-bfd5-4afa-b33a-679053a363e9',
            'name': 'Topgolf Venue 1116',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '1304',
            'toastGuid': '2549353e-0059-4f8a-b227-6c6142d8464b',
            'name': 'Topgolf Venue 1304',
            'offSet': '-00:00',
            'toastOffSet': '-06:00',
            'active': True
        },
        {
            'siteId': '33',
            'toastGuid': '312bfe0c-7392-4d7f-b736-8b2057215867',
            'name': 'Topgolf Venue 33',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '1070',
            'toastGuid': '87b0fda2-a20c-4335-83ef-47397a6f0ad1',
            'name': 'Topgolf Venue 1070',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '46',
            'toastGuid': '5ed9c7f2-9f10-4c48-ae4e-203143dde80f',
            'name': 'Topgolf Venue 46',
            'offSet': '-00:00',
            'toastOffSet': '-05:00',
            'active': True
        },
        {
            'siteId': '41',
            'toastGuid': 'b3384c6a-e2e1-4de5-ae35-df7bbcec8df0',
            'name': 'Topgolf Venue 41',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        },
        {
            'siteId': '44',
            'toastGuid': 'ce89c632-2fbc-4a0d-be4e-9b6cbedc2e0c',
            'name': 'Topgolf Venue 44',
            'offSet': '-00:00',
            'toastOffSet': '-04:00',
            'active': True
        }
    ]
    
    print(f"[REAL] Fallback venue list: {len(fallback_venues)} venues with real GUIDs")
    return fallback_venues

def get_workday_location_mapping(secrets: Dict[str, str]) -> Dict[str, str]:
    """
    Get mapping of Toast venue GUIDs to Workday location WIDs from cache.
    This is needed to properly match venues between Toast and Workday systems.
    """
    try:
        # Cache API configuration
        host = "tg-pos-sys-api.preprod.rtf.topgolf.io"  # Adjust if different
        port = "443"
        base_path = "/api/v2"
        client_id = secrets.get('pos_sys_api_client_id')
        client_secret = secrets.get('pos_sys_api_client_secret')
        
        # Build the URL for location mapping cache endpoint
        url = f"https://{host}:{port}{base_path}/cache/workday-locations"
        
        # Headers
        headers = {
            'Authorization': f'Bearer {client_id}:{client_secret}',
            'Content-Type': 'application/json'
        }
        
        print(f"[REAL] Calling cache API for Workday location mapping: {url}")
        
        # Make the API call
        response = requests.get(
            url,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            location_data = response.json()
            print(f"[REAL] Workday location mapping cache success: {len(location_data)} locations found")
            
            # Create mapping of Toast GUID to Workday location WID
            location_mapping = {}
            for location in location_data:
                toast_guid = location.get('toastGuid')
                workday_location_wid = location.get('workdayLocationWID')
                if toast_guid and workday_location_wid:
                    location_mapping[toast_guid] = workday_location_wid
                    print(f"[REAL] Mapped {toast_guid} -> {workday_location_wid}")
            
            return location_mapping
        else:
            print(f"[REAL] Workday location mapping cache error: {response.status_code} - {response.text}")
            # Return mock data for testing
            return {
                "8fd72cd1-0d1e-4fcb-aab1-eedbd89cb3ef": "mock_workday_location_29",
                "d3351fb8-29d3-438b-a1d3-d749d615096e": "mock_workday_location_10"
            }
            
    except Exception as e:
        print(f"[REAL] Workday location mapping cache exception: {e}")
        # Return mock data for testing
        return {
            "8fd72cd1-0d1e-4fcb-aab1-eedbd89cb3ef": "mock_workday_location_29",
            "d3351fb8-29d3-438b-a1d3-d749d615096e": "mock_workday_location_10"
        }

# DEBUG: Limit Toast API calls to specific venues to avoid 429 rate limiting
# Set to None to process all venues, or list of site IDs to filter
# Colony = 10, Fort Worth = 29
# DEBUG_TOAST_VENUES = ['10', '29']  # Only Colony and Fort Worth for testing
DEBUG_TOAST_VENUES = None  # Process all venues

def get_all_venue_timecards(from_date: str, to_date: str, secrets: dict) -> List[Dict[str, Any]]:
    """
    Get timecards from all active venues for the specified date range.
    
    Args:
        from_date: Start date (YYYY-MM-DD)
        to_date: End date (YYYY-MM-DD)
        secrets: API credentials
    """
    print(f"[REAL] Getting Toast timecards for date range: {from_date} to {to_date}")
    
    # Get active venues from cache
    venues = get_venue_guids_from_cache(secrets)
    if not venues:
        print("[REAL] No active venues found")
        return []
    
    # Enrich venues with hris_location_id from per-site cache if not already set
    # This is critical for matching Toast venues to Workday locations
    print(f"[REAL] Enriching {len(venues)} venues with hris_location_id from per-site cache...")
    enriched_count = 0
    for venue in venues:
        if not venue.get('hris_location_id'):
            site_id = venue.get('siteId')
            if site_id:
                site_details = get_pos_site_details_from_cache(str(site_id), secrets)
                hris_loc = (site_details.get('hris_sys_info') or {}).get('hris_sys_location')
                if hris_loc:
                    venue['hris_location_id'] = hris_loc
                    enriched_count += 1
                    print(f"[REAL]   Site {site_id} → {hris_loc}")
                # Also get venue name if available
                venue_name = site_details.get('venue_name') or site_details.get('city_name')
                if venue_name and venue.get('name', '').startswith('Topgolf Venue'):
                    venue['name'] = venue_name
    
    if enriched_count > 0:
        print(f"[REAL] Enriched {enriched_count} venues with hris_location_id from per-site cache")
    
    # Log HRIS location mapping status
    venues_with_hris = sum(1 for v in venues if v.get('hris_location_id'))
    unmapped_sites = [(v.get('siteId'), v.get('name')) for v in venues if not v.get('hris_location_id')]
    print(f"[REAL] HRIS Location Mapping: {venues_with_hris}/{len(venues)} venues have hris_location_id")
    if unmapped_sites:
        print(f"[REAL] ⚠️ WARNING: {len(unmapped_sites)} venues still missing hris_location_id:")
        for site_id, name in unmapped_sites:
            print(f"[REAL]   - Site {site_id}: {name}")
    
    # Filter venues if DEBUG_TOAST_VENUES is set
    if DEBUG_TOAST_VENUES:
        original_count = len(venues)
        venues = [v for v in venues if v.get('siteId') in DEBUG_TOAST_VENUES]
        print(f"[REAL] DEBUG MODE: Filtering to {len(venues)} venues (from {original_count}): {DEBUG_TOAST_VENUES}")
    
    all_timecards = []
    venue_summary = []
    
    # Process each venue
    for venue in venues:
        venue_site_id = venue.get('siteId', '')
        venue_name = venue.get('name', f'Venue_{venue_site_id}')
        venue_guid = venue.get('toastGuid', '')
        venue_offset = venue.get('offSet', '')
        toast_offset = venue.get('toastOffSet', '')
        
        hris_location = venue.get('hris_location_id', 'NOT_FOUND')
        print(f"[REAL] Processing venue: {venue_name} (Site: {venue_site_id}, HRIS: {hris_location})")
        print(f"[REAL] Timezone offsets - Venue: {venue_offset}, Toast: {toast_offset}")
        
        # Get timecards for this venue
        venue_timecards = call_sys_pos_api_for_venue(venue_guid, from_date, to_date, secrets, venue)
        
        # Add venue metadata to each timecard
        hris_loc = venue.get('hris_location_id')
        for timecard in venue_timecards:
            timecard['venue_site_id'] = venue_site_id
            timecard['venue_name'] = venue_name
            timecard['venue_guid'] = venue_guid
            timecard['venue_offset'] = venue_offset
            timecard['toast_offset'] = toast_offset
            
            # Calculate total hours from regularHours + overtimeHours
            regular_hours = timecard.get('regularHours', 0.0) or 0.0
            overtime_hours = timecard.get('overtimeHours', 0.0) or 0.0
            timecard['hours'] = regular_hours + overtime_hours
            
            # Set hris_location_id (e.g., "The_Colony") - used to match with Workday Location_ID
            if hris_loc:
                timecard['hris_location_id'] = hris_loc
                # Use hris_location_id as the primary venue key for aggregation/matching
                timecard['venue'] = hris_loc
            else:
                # Fallback to site_id if no HRIS location available
                timecard['venue'] = venue_site_id
            
            # Extract employee_id from employeeReference.externalId (e.g., "CUSTOM-TOPGOLF:1042447" -> "1042447")
            emp_ref = timecard.get('employeeReference', {})
            emp_external_id = emp_ref.get('externalId', '')
            if emp_external_id and ':' in emp_external_id:
                timecard['employee_id'] = emp_external_id.split(':')[-1]
            elif emp_external_id:
                timecard['employee_id'] = emp_external_id
        
        all_timecards.extend(venue_timecards)
        
        # Calculate punch metrics for this venue
        total_punches = len(venue_timecards)
        total_hours = sum(tc.get('regularHours', 0.0) + tc.get('overtimeHours', 0.0) for tc in venue_timecards)
        unique_employees = len(set(tc.get('employeeReference', {}).get('externalId', '') for tc in venue_timecards if tc.get('employeeReference')))
        
        venue_summary.append({
            'venue_name': venue_name,
            'site_id': venue_site_id,
            'total_punches': total_punches,
            'total_hours': total_hours,
            'unique_employees': unique_employees,
            'status': 'SUCCESS' if total_punches > 0 else 'NO_DATA'
        })
        
        print(f"[REAL] Found {total_punches} timecards for venue {venue_name}")
        print(f"[REAL]   - Total hours: {total_hours:.2f}")
        print(f"[REAL]   - Unique employees: {unique_employees}")
    
    # Print venue summary
    print(f"\n[REAL] VENUE SUMMARY:")
    print(f"[REAL] {'='*60}")
    total_all_punches = sum(vs['total_punches'] for vs in venue_summary)
    total_all_hours = sum(vs['total_hours'] for vs in venue_summary)
    total_all_employees = sum(vs['unique_employees'] for vs in venue_summary)
    
    for vs in venue_summary:
        status_icon = "✅" if vs['status'] == 'SUCCESS' else "⚠️"
        print(f"[REAL] {status_icon} {vs['venue_name']} (Site {vs['site_id']}): {vs['total_punches']} punches, {vs['total_hours']:.2f} hours, {vs['unique_employees']} employees")
    
    print(f"[REAL] {'='*60}")
    print(f"[REAL] TOTALS: {total_all_punches} punches, {total_all_hours:.2f} hours, {total_all_employees} employees across {len(venue_summary)} venues")
    print(f"[REAL] {'='*60}")
    
    return all_timecards

# Cache for Toast bearer token to avoid rate limiting (429 errors)
_toast_token_cache = {
    'token': None,
    'expires_at': None
}

def get_toast_bearer_token(secrets: dict, force_refresh: bool = False) -> str:
    """
    Authenticate with Toast API and get a Bearer token.
    Caches the token to avoid rate limiting on repeated calls.
    
    Args:
        secrets: API credentials containing client_id and client_secret
        force_refresh: Force a new token even if cached one exists
        
    Returns:
        Bearer token for Toast API calls
    """
    global _toast_token_cache
    
    # Return cached token if still valid (tokens typically last 1 hour, we use 50 min buffer)
    if not force_refresh and _toast_token_cache['token'] and _toast_token_cache['expires_at']:
        if datetime.now() < _toast_token_cache['expires_at']:
            print(f"[REAL] Using cached Toast token (expires in {(_toast_token_cache['expires_at'] - datetime.now()).seconds // 60} minutes)")
            return _toast_token_cache['token']
    
    try:
        auth_url = "https://ws-api.toasttab.com/authentication/v1/authentication/login"
        
        auth_payload = {
            "clientId": secrets.get('toast_client_id', ''),
            "clientSecret": secrets.get('toast_client_secret', ''),
            "userAccessType": "TOAST_MACHINE_CLIENT"
        }
        
        auth_headers = {
            'Content-Type': 'application/json'
        }
        
        print(f"[REAL] Authenticating with Toast API...")
        auth_response = requests.post(
            auth_url,
            json=auth_payload,
            headers=auth_headers,
            timeout=30
        )
        
        if auth_response.status_code == 200:
            auth_data = auth_response.json()
            # Token is nested inside 'token' object
            token_data = auth_data.get('token', {})
            access_token = token_data.get('accessToken', '')
            
            # Cache the token with 50 minute expiry (tokens usually last 1 hour)
            _toast_token_cache['token'] = access_token
            _toast_token_cache['expires_at'] = datetime.now() + timedelta(minutes=50)
            
            print(f"[REAL] Toast authentication successful, token cached (length: {len(access_token)})")
            return access_token
        else:
            print(f"[REAL] Toast authentication failed: {auth_response.status_code} - {auth_response.text}")
            return secrets.get('toast_bearer_token', '')  # Fallback to stored token
            
    except Exception as e:
        print(f"[REAL] Toast authentication error: {e}")
        return secrets.get('toast_bearer_token', '')  # Fallback to stored token

def call_sys_pos_api_for_venue(venue_guid: str, from_date: str, to_date: str, secrets: dict, venue_info: dict) -> List[Dict[str, Any]]:
    """
    Call Toast API to get timecards for a specific venue and date range.
    
    Args:
        venue_guid: Toast venue GUID
        from_date: Start date (YYYY-MM-DD)
        to_date: End date (YYYY-MM-DD)
        secrets: API credentials
        venue_info: Venue information dictionary
    """
    try:
        # Get fresh Bearer token
        bearer_token = get_toast_bearer_token(secrets)
        
        # Toast API configuration - using the working format from your successful curl
        host = "ws-api.toasttab.com"
        endpoint = f"/labor/v1/timeEntries"
        
        # Build the URL
        url = f"https://{host}{endpoint}"
        
        # Query parameters - convert to Toast's required format with milliseconds and timezone offset
        # Toast requires format: "2024-09-15T05:00:00.000-0000"
        def convert_toast_date_format(date_str, is_end_date=False):
            # If already in ISO format with Z suffix, convert Z to .000-0000
            if date_str.endswith('Z'):
                return date_str.replace('Z', '.000-0000')
            # If already in full ISO format with T, add milliseconds if missing
            if 'T' in date_str:
                # Has time component already
                if '.' not in date_str:
                    # Add milliseconds before timezone offset
                    if '+' in date_str:
                        parts = date_str.split('+')
                        return f"{parts[0]}.000+{parts[1]}"
                    elif date_str.count('-') > 2:  # Has negative timezone offset
                        # Find the timezone offset (last - that's not part of date)
                        idx = date_str.rfind('-')
                        return f"{date_str[:idx]}.000{date_str[idx:]}"
                return date_str
            # Check for Workday-style format: YYYY-MM-DD-HH:MM (e.g., 2026-01-05-05:00)
            # This has 3 dashes and a colon in the time portion
            import re
            workday_pattern = re.match(r'^(\d{4}-\d{2}-\d{2})-(\d{2}):(\d{2})$', date_str)
            if workday_pattern:
                date_part = workday_pattern.group(1)  # 2026-01-05
                hour = workday_pattern.group(2)       # 05
                minute = workday_pattern.group(3)    # 00
                if is_end_date:
                    # For end date, use the specified time but at :59 seconds
                    return f"{date_part}T{hour}:{minute}:59.999-0000"
                else:
                    # For start date, use the specified time at :00 seconds
                    return f"{date_part}T{hour}:{minute}:00.000-0000"
            # Plain date format (YYYY-MM-DD) - convert to full ISO datetime
            if is_end_date:
                # End of day
                return f"{date_str}T23:59:59.999-0000"
            else:
                # Start of day
                return f"{date_str}T00:00:00.000-0000"
        
        params = {
            'startDate': convert_toast_date_format(from_date, is_end_date=False),
            'endDate': convert_toast_date_format(to_date, is_end_date=True)
        }
        
        # Headers - using the correct format from your working curl example
        headers = {
            'Toast-Restaurant-External-ID': venue_guid,
            'Authorization': f"Bearer {bearer_token}",
            'Content-Type': 'application/json'
        }
        
        print(f"[REAL] Calling SYS-POS API for venue {venue_guid}: {url}")
        print(f"[REAL] Date range: {from_date} to {to_date}")
        print(f"[REAL] Headers: {headers}")
        print(f"[REAL] Params: {params}")
        
        # Make the API call
        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            # API returns a list directly, not an object with timeCards property
            timecards = data if isinstance(data, list) else []
            print(f"[REAL] SYS-POS API success for venue {venue_guid}: {len(timecards)} timecards found")
            return timecards
        else:
            print(f"[REAL] SYS-POS API error for venue {venue_guid}: {response.status_code}")
            print(f"[REAL] Error response: {response.text}")
            print(f"[REAL] Full URL: {response.url}")
            return []
            
    except Exception as e:
        print(f"[REAL] SYS-POS API exception for venue {venue_guid}: {e}")
        return []

def call_sys_pos_api(date_str: str, date_type: str, secrets: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Call the SYS-POS API to get Toast timecards for the given date.
    Simple approach - one call, map employees to venues.
    """
    try:
        # SYS-POS API configuration
        host = "tg-pos-sys-api.preprod.rtf.topgolf.io"
        port = "443"
        base_path = "/api/v2"
        client_id = secrets.get('pos_sys_api_client_id')
        client_secret = secrets.get('pos_sys_api_client_secret')
        restaurant_guid = "1a19d1cc-bf22-4564-8ec2-1add1992c3d8"  # Use any venue GUID
        
        # Build the URL
        url = f"https://{host}:{port}{base_path}/pos/timeCards"
        
        # Headers
        headers = {
            'systemId': 'toast',
            'restaurantGUID': restaurant_guid,
            'client_id': client_id,
            'client_secret': client_secret,
            'Content-Type': 'application/json'
        }
        
        # Query parameters - look back a week to find data in pre-prod
        from_date_obj = datetime.strptime(date_str, '%Y-%m-%d') - timedelta(days=7)
        from_date_str = from_date_obj.strftime('%Y-%m-%d')
        
        params = {
            "fromDate": f"{from_date_str}T00:00:00Z",
            "toDate": f"{date_str}T23:59:59Z",
            "includeArchived": "true",
            "toastOffSet": "0"
        }
        
        print(f"[REAL] Calling SYS-POS API: {url}")
        print(f"[REAL] Date type: {date_type}, Date: {date_str}")
        
        # Make the API call
        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"[REAL] SYS-POS API success: {len(data)} timecards found")
            
            # Debug: Show first raw timecard structure to verify field names
            if data and len(data) > 0:
                sample_tc = data[0]
                print(f"[REAL] Sample Toast timecard keys: {list(sample_tc.keys())}")
                print(f"[REAL] Sample regularHours: {sample_tc.get('regularHours')}, overtimeHours: {sample_tc.get('overtimeHours')}")
                # Check for alternative hour field names
                hour_fields = [k for k in sample_tc.keys() if 'hour' in k.lower() or 'time' in k.lower()]
                print(f"[REAL] Hour/time related fields: {hour_fields}")
            
            # Transform the data to canonical format
            transformed_data = []
            for tc in data:
                # Simple venue mapping based on employee
                venue = get_venue_from_employee(tc)
                
                # Add venue to the timecard object
                tc['venue'] = venue
                
                # Convert to canonical format
                canonical_tc = normalize_toast_timecard(tc)
                transformed_data.append(canonical_tc)
            
            return transformed_data
        else:
            print(f"[REAL] SYS-POS API error: {response.status_code} - {response.text}")
            # Fall back to mock data for testing
            return [
                {"guid": "abc-123", "venue": "VenueA", "hours": 8.0},
                {"guid": "def-456", "venue": "VenueA", "hours": 7.5},
                {"guid": "ghi-789", "venue": "VenueB", "hours": 6.0},
            ]
            
    except Exception as e:
        print(f"[REAL] SYS-POS API exception: {e}")
        # Fall back to mock data for testing
        return [
            {"guid": "abc-123", "venue": "VenueA", "hours": 8.0},
            {"guid": "def-456", "venue": "VenueA", "hours": 7.5},
            {"guid": "ghi-789", "venue": "VenueB", "hours": 6.0},
        ]

def get_venue_from_employee(tc: dict) -> str:
    """
    Simple venue mapping based on employee external ID.
    No complex business logic - just a lookup table.
    """
    # Simple employee to venue mapping
    EMPLOYEE_TO_VENUE = {
        "1026111": "venue_guid_1",
        "1027849": "venue_guid_2",
        "9999997": "venue_guid_3",
        # Add more as needed
    }
    
    # Get employee ID from timecard
    employee_ref = tc.get('employeeReference', {})
    employee_id = employee_ref.get('externalId', '')
    
    # Extract employee number from external ID (e.g., "CUSTOM-TOPGOLF:1026111" -> "1026111")
    if employee_id and ':' in employee_id:
        employee_number = employee_id.split(':')[-1]
        if employee_number in EMPLOYEE_TO_VENUE:
            return f"Venue_{EMPLOYEE_TO_VENUE[employee_number]}"
    
    # Fallback to job profile if no employee mapping
    if tc.get('jobReference') and tc['jobReference'].get('externalId'):
        job_profile = tc['jobReference']['externalId']
        return f"JobProfile_{job_profile}"
    
    # Last resort
    business_date = tc.get('businessDate', 'Unknown_Date')
    return f"Unknown_{business_date}"

def call_proshop_api(guids: List[str], secrets: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Call Proshop (Workday) API to get time clock events for the given GUIDs.
    TODO: Implement actual API call using requests and secrets
    """
    print(f"[MOCK] Call Proshop API for GUIDs: {guids}")
    # Return mock data for local testing
    return [
        {"guid": "abc-123", "venue": "VenueA", "hours": 8.0},
        {"guid": "ghi-789", "venue": "VenueB", "hours": 5.5},
    ]

def call_workday_timecards_api(from_date: str = None, to_date: str = None, 
                              location_id: str = None, clock_event_id: str = None, 
                              secrets: dict = None, environment: str = 'prod') -> List[Dict[str, Any]]:
    """
    Call Workday RaaS API to get time clock events with flexible query parameters.
    
    Query parameter combinations:
    1. Single time clock: clockEventID only
    2. Date range only: fromDate and toDate only  
    3. Single location + date range: fromDate, toDate, and location
    4. All events in date range: fromDate and toDate (default)
    
    Args:
        from_date: Start date (YYYY-MM-DD)
        to_date: End date (YYYY-MM-DD) 
        location_id: Workday location ID (e.g., "L255")
        clock_event_id: Specific time clock event ID
        secrets: API credentials
        environment: 'prod', 'preprod', or 'sandbox'
    """
    try:
        # Workday RaaS API configuration - host based on environment
        env_config = ENV_CONFIG.get(environment, ENV_CONFIG['prod'])
        host = env_config['workday_host']
        print(f"[REAL] Using Workday host for {environment}: {host}")
        tenant = secrets.get('workday_tenant', 'topgolf')
        report_name = "ISU_INT032_POS_Timecards_Inbound"
        report_type = "Time_Clock_Event_Audit"
        
        # Build the URL
        url = f"https://{host}/ccx/service/customreport2/{tenant}/{report_name}/{report_type}"
        
        # Build query parameters based on provided arguments
        params = {}
        # If caller provided ISO datetimes (for partial-day windows), we will:
        # 1) query Workday using date-only prompts (YYYY-MM-DD) which is the known working format
        # 2) filter returned events locally to the exact datetime window
        # Only apply time-window filter if input dates had time components
        from_dt = None
        to_dt = None
        apply_time_filter = False  # Only filter if ISO datetimes were provided
        
        if clock_event_id:
            # Option 1: Single time clock event
            params['clockEventID'] = clock_event_id
            print(f"[REAL] Calling Workday API for single clock event: {clock_event_id}")
            
        elif from_date and to_date:
            import re
            # Check for Workday-style format: YYYY-MM-DD-HH:MM (e.g., 2026-01-05-05:00)
            workday_format_pattern = r'^\d{4}-\d{2}-\d{2}-\d{2}:\d{2}$'
            is_workday_format = re.match(workday_format_pattern, from_date) and re.match(workday_format_pattern, to_date)
            
            # Check if input dates have ISO time components (with 'T')
            has_iso_time_component = 'T' in from_date or 'T' in to_date
            apply_time_filter = has_iso_time_component
            
            # Workday date format is YYYY-MM-DD-HH:MM
            if is_workday_format:
                # Already in Workday format - pass through directly
                params['fromDate'] = from_date
                params['toDate'] = to_date
                print(f"[REAL] Workday format input detected - using directly: {params['fromDate']} to {params['toDate']}")
            elif has_iso_time_component:
                from datetime import datetime as dt_module
                
                # Parse ISO datetimes for local filtering
                def _parse_iso_or_date(s: str):
                    if 'T' in s:
                        return dt_module.fromisoformat(s.replace('Z', '+00:00'))
                    return dt_module.fromisoformat(f"{s}T00:00:00+00:00")

                from_dt = _parse_iso_or_date(from_date)
                to_dt = _parse_iso_or_date(to_date)
                
                # Format for Workday: YYYY-MM-DD-HH:MM
                params['fromDate'] = from_dt.strftime('%Y-%m-%d-%H:%M')
                params['toDate'] = to_dt.strftime('%Y-%m-%d-%H:%M')
                print(f"[REAL] ISO datetime input detected - will apply local time-window filter")
            else:
                # Plain dates (YYYY-MM-DD) - convert to Workday format YYYY-MM-DD-HH:MM
                # Use 05:00 as the boundary time (5 AM to 5 AM next day)
                # This matches the working Postman format and avoids -00:00 parsing issues
                from datetime import datetime as dt_module
                
                from_date_obj = dt_module.strptime(from_date, '%Y-%m-%d')
                to_date_obj = dt_module.strptime(to_date, '%Y-%m-%d')
                # Add one day to end date to capture full day
                to_date_next = to_date_obj + timedelta(days=1)
                
                params['fromDate'] = f"{from_date}-05:00"
                params['toDate'] = to_date_next.strftime('%Y-%m-%d') + "-05:00"
                print(f"[REAL] Plain date input - using Workday format: {params['fromDate']} to {params['toDate']}")
            
            if location_id:
                # Option 3: Single location + date range
                params['location'] = location_id
                print(f"[REAL] Calling Workday API for location {location_id} from {from_date} to {to_date}")
            else:
                # Option 2/4: Date range only (all locations)
                print(f"[REAL] Calling Workday API for all locations from {from_date} to {to_date}")
                
        else:
            print("[REAL] Error: Invalid parameter combination. Need either clockEventID or both fromDate and toDate")
            return []
        
        # Headers - using Basic Auth with the provided credentials
        username = secrets.get('workday_user', 'ISU_INT032_POS_Timecards_Inbound')
        password = secrets.get('workday_password', '')
        if not password:
            print("[REAL] Workday Timecards API error: workday_password missing from secrets")
            return []

        headers = {
            # Workday RaaS typically returns XML by default; be explicit
            'Accept': 'application/xml',
            'User-Agent': 'timecard-reconciliation/1.0'
        }
        
        print(f"[REAL] Calling Workday Timecards API: {url}")
        print(f"[REAL] Query parameters: {params}")
        
        # Make the API call - standard HTTP Basic Auth
        response = requests.get(
            url,
            params=params,
            headers=headers,
            auth=(username, password),
            timeout=30
        )
        
        if response.status_code == 200:
            content_type = response.headers.get('Content-Type', '')
            print(f"[REAL] Workday API 200 OK (Content-Type: {content_type})")
            # Parse XML response
            print(f"[REAL] Workday API returned {len(response.content)} bytes")
            try:
                root = ET.fromstring(response.content)
            except Exception as e:
                snippet = response.text[:500] if response.text else ''
                print(f"[REAL] Workday XML parse error: {e}")
                print(f"[REAL] Workday response snippet (first 500 chars): {snippet}")
                return []
            
            # Extract time clock events from XML
            timecards = []
            # Namespace-agnostic search (Workday report namespace varies by report name/type)
            entries = root.findall('.//{*}Report_Entry')
            print(f"[REAL] Found {len(entries)} Report_Entry elements in XML")

            if not entries:
                snippet = response.text[:500] if response.text else ''
                print("[REAL] Workday returned 200 but no Report_Entry elements were found.")
                print(f"[REAL] Workday response snippet (first 500 chars): {snippet}")
            
            # Debug: Print first entry structure to see ALL available fields (including nested)
            if entries:
                first_entry = entries[0]
                print(f"[REAL] Sample Workday entry structure (ALL fields):")
                def print_element(el, indent=2):
                    tag = el.tag.split('}', 1)[-1]  # strip namespace if present
                    text = el.text.strip() if el.text and el.text.strip() else None
                    attrs = {k.split('}', 1)[-1]: v for k, v in el.attrib.items()} if el.attrib else {}
                    children = list(el)
                    if text:
                        print(f"{' '*indent}- {tag}: {text} (attrs: {attrs})")
                    elif attrs:
                        print(f"{' '*indent}- {tag}: (attrs: {attrs})")
                    else:
                        print(f"{' '*indent}- {tag}:")
                    for child in children:
                        print_element(child, indent + 4)
                print_element(first_entry)
            
            for entry in entries:
                timecard = parse_workday_timecard_xml(entry, {})
                if timecard:
                    timecards.append(timecard)

            # If we were given an ISO datetime window (not plain dates), filter locally to preserve partial-day runs
            if apply_time_filter and from_dt and to_dt and timecards:
                def _parse_workday_dt(dt_str: str):
                    if not dt_str:
                        return None
                    try:
                        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
                    except Exception:
                        return None

                before_count = len(timecards)
                filtered = []
                for tc in timecards:
                    tc_dt = _parse_workday_dt(tc.get('date_time'))
                    if not tc_dt:
                        continue
                    if from_dt <= tc_dt <= to_dt:
                        filtered.append(tc)
                timecards = filtered
                print(f"[REAL] Workday local time-window filter: {before_count} -> {len(timecards)} events within {from_date} .. {to_date}")
            else:
                print(f"[REAL] Workday returned {len(timecards)} events (no local time filter applied)")
            
            # Debug: Show location extraction stats
            with_location_id = sum(1 for tc in timecards if tc.get('location_id'))
            without_location = len(timecards) - with_location_id
            print(f"[REAL] Location extraction: {with_location_id} with location_id, {without_location} without")
            
            # Show unique location IDs found (these will be used as venue)
            location_ids_found = set(tc.get('location_id') for tc in timecards if tc.get('location_id'))
            if location_ids_found:
                print(f"[REAL] Unique location IDs (venues): {sorted(location_ids_found)}")
            
            print(f"[REAL] Workday Timecards API success: {len(timecards)} time clock events found")
            return timecards
        else:
            content_type = response.headers.get('Content-Type', '')
            snippet = response.text[:500] if response.text else ''
            print(f"[REAL] Workday Timecards API error: {response.status_code} (Content-Type: {content_type})")
            print(f"[REAL] Workday error response snippet (first 500 chars): {snippet}")
            return []
            
    except Exception as e:
        print(f"[REAL] Workday Timecards API exception: {e}")
        return []

def get_workday_timecards_by_date_range(from_date: str, to_date: str, secrets: dict, environment: str = 'prod') -> List[Dict[str, Any]]:
    """
    Get all time clock events for a date range across all locations.
    This is the most common use case for daily reconciliation.
    """
    return call_workday_timecards_api(
        from_date=from_date,
        to_date=to_date,
        secrets=secrets,
        environment=environment
    )

def get_workday_timecards_by_location(from_date: str, to_date: str, location_id: str, secrets: dict, environment: str = 'prod') -> List[Dict[str, Any]]:
    """
    Get time clock events for a specific location and date range.
    Useful for venue-specific reconciliation or troubleshooting.
    """
    return call_workday_timecards_api(
        from_date=from_date,
        to_date=to_date,
        location_id=location_id,
        secrets=secrets,
        environment=environment
    )

def get_workday_timecard_by_event_id(clock_event_id: str, secrets: dict, environment: str = 'prod') -> List[Dict[str, Any]]:
    """
    Get a single time clock event by its ID.
    Useful for debugging specific timecard issues.
    """
    return call_workday_timecards_api(
        clock_event_id=clock_event_id,
        secrets=secrets,
        environment=environment
    )

def parse_workday_timecard_xml(entry_element, namespace: dict) -> Dict[str, Any]:
    """
    Parse a single Workday timecard entry from XML.
    Handles the Toast-to-Workday punch mapping logic.
    """
    try:
        # Namespace-agnostic helpers (Workday report namespaces vary)
        def _local(tag: str) -> str:
            return tag.split('}', 1)[-1] if '}' in tag else tag

        def _find_first_by_local(el, local_name: str):
            for node in el.iter():
                if _local(node.tag) == local_name:
                    return node
            return None

        def _find_child_by_local(el, local_name: str):
            for node in list(el):
                if _local(node.tag) == local_name:
                    return node
            return None

        def _get_attr(el, attr_local: str):
            if el is None or not el.attrib:
                return None
            for k, v in el.attrib.items():
                if _local(k) == attr_local:
                    return v
            return None

        def _find_id_text(container, type_value: str):
            if container is None:
                return None
            for node in container.iter():
                if _local(node.tag) != 'ID':
                    continue
                t = _get_attr(node, 'type')
                if t == type_value and node.text:
                    return node.text
            return None

        # Extract basic information
        reference_id = _find_first_by_local(entry_element, 'referenceID')
        reference_id_text = reference_id.text if reference_id is not None and reference_id.text else 'Unknown'
        
        # Extract worker information
        worker_element = _find_first_by_local(entry_element, 'Worker')
        worker_name = _get_attr(worker_element, 'Descriptor') or 'Unknown'

        employee_id = _find_id_text(worker_element, 'Employee_ID') or 'Unknown'
        
        # Extract event information
        event_type_element = _find_first_by_local(entry_element, 'EventType')
        event_type = event_type_element.text if event_type_element is not None and event_type_element.text else 'Unknown'
        
        # Extract datetime
        date_time_element = _find_first_by_local(entry_element, 'DateTime')
        date_time = date_time_element.text if date_time_element is not None and date_time_element.text else None
        
        # Debug: Show raw DateTime from first few entries to verify format
        if employee_id == '1035434':
            print(f"[WORKDAY DEBUG] Employee 1035434 raw DateTime from XML: {date_time}")
        
        # Extract position information
        position_element = _find_first_by_local(entry_element, 'Position')
        position_name = _get_attr(position_element, 'Descriptor') or 'Unknown'
        position_id = _find_id_text(position_element, 'Position_ID') or 'Unknown'
        
        # Extract location information - field is "Location" with Descriptor attribute
        location_element = _find_first_by_local(entry_element, 'Location')
        location = None
        location_id = None
        
        if location_element is not None:
            location = _get_attr(location_element, 'Descriptor')
            location_id = _find_id_text(location_element, 'Location_ID')
        
        # Map Toast event types to Workday punch types
        # Toast sends: timeIn, timeOut (regular) or timeIn, timeOut (breaks)
        # We map breaks to: meal-out, meal-in
        mapped_event_type = event_type
        
        # Check if this is a break event based on reference ID or position
        is_break = False
        if reference_id_text and ('break' in reference_id_text.lower() or 'meal' in reference_id_text.lower()):
            is_break = True
        elif position_name and ('break' in position_name.lower() or 'meal' in position_name.lower()):
            is_break = True
        
        # Map event types for Workday compatibility
        if is_break:
            if event_type == 'Check-in':
                mapped_event_type = 'meal-in'
            elif event_type == 'Check-out':
                mapped_event_type = 'meal-out'
        else:
            # Regular work punches
            if event_type == 'Check-in':
                mapped_event_type = 'Check-in'
            elif event_type == 'Check-out':
                mapped_event_type = 'Check-out'
        
        # Extract business date
        business_date = extract_business_date(date_time) if date_time else None
        
        # Use location_id if available (e.g., "The_Colony"), otherwise fall back
        if location_id:
            venue = location_id
        elif location:
            venue = location
        else:
            venue = map_position_to_venue(position_id, position_name)
        
        return {
            'guid': reference_id_text,
            'employee_id': employee_id,
            'employee_name': worker_name,
            'venue': venue,
            'location': location,
            'location_id': location_id,
            'business_date': business_date,
            'date_time': date_time,
            'event_type': mapped_event_type,
            'original_event_type': event_type,
            'position_id': position_id,
            'position_name': position_name,
            'source': 'workday_timecards',
            'is_break': is_break
        }
        
    except Exception as e:
        print(f"Error parsing Workday timecard entry: {e}")
        return None

def extract_business_date(date_time_str: str) -> str:
    """
    Extract business date from Workday datetime string.
    Format: 2025-07-28T18:15:43.278-07:00
    """
    try:
        if date_time_str:
            # Parse the datetime string
            dt = datetime.fromisoformat(date_time_str.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d')
    except Exception as e:
        print(f"Error extracting business date from {date_time_str}: {e}")
    
    return None

def map_position_to_venue(position_id: str, position_name: str) -> str:
    """
    Map Workday position to venue based on position ID or name.
    
    NOTE: Position IDs are randomly generated (e.g., P_1321888_JP0040, P1136176)
    and do NOT contain venue information. This function will always return
    'Venue_Unknown' unless we have a specific mapping.
    
    The real venue mapping happens through:
    1. Employee ID lookup (temporary solution)
    2. sys-hris integration including location data (ideal solution)
    """
    # Position IDs are randomly generated and don't contain venue info
    # Examples: P_1321888_JP0040, P1136176, P1150916
    # These cannot be used for venue mapping
    
    # TODO: Remove this function once proper venue mapping is implemented
    # in the sys-hris integration or through employee ID lookup
    
    return 'Venue_Unknown'

def calculate_hours_from_event(event_type: str, date_time_str: str) -> float:
    """
    Calculate hours from event type and datetime.
    For now, return 0 as we need to pair check-in/check-out events.
    """
    # This is a placeholder - in a real implementation, you would need to:
    # 1. Pair check-in and check-out events for the same employee
    # 2. Calculate the time difference
    # 3. Convert to hours
    
    if event_type in ['Check-in', 'Check-out']:
        return 0.0  # Will be calculated when pairing events
    
    return 0.0

def pair_checkin_checkout_events(timecards: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Pair check-in and check-out events to calculate actual hours worked.
    Handles Toast-to-Workday punch mapping:
    - Regular shifts: check-in, check-out (2 punches)
    - Shifts with breaks: check-in, meal-out, meal-in, check-out (4 punches)
    
    Now groups by EMPLOYEE ONLY (not business_date) to handle cross-midnight shifts
    where check-in is on one day and check-out is on the next day.
    """
    # Group events by employee ONLY (not business_date) to handle cross-midnight shifts
    employee_events = defaultdict(list)
    
    for tc in timecards:
        if tc.get('event_type') in ['Check-in', 'Check-out', 'meal-out', 'meal-in']:
            key = tc['employee_id']
            employee_events[key].append(tc)
    
    # Sort events by datetime for each employee
    for key in employee_events:
        employee_events[key].sort(key=lambda x: x['date_time'])
    
    # Pair events and calculate hours
    paired_timecards = []
    
    for employee_id, events in employee_events.items():
        print(f"Processing events for employee {employee_id}: {len(events)} events")
        
        # Track punch sequence for this employee/date
        punch_sequence = []
        current_checkin = None
        current_checkin_event = None  # Track the full Check-in event for venue info
        total_hours = 0.0
        
        for event in events:
            event_type = event['event_type']
            event_time = event['date_time']
            
            print(f"  Event: {event_type} at {event_time}")
            
            if event_type == 'Check-in':
                if current_checkin is None:
                    # Start of shift
                    current_checkin = event_time
                    current_checkin_event = event  # Store the full event
                    punch_sequence.append(f"check-in: {event_time}")
                else:
                    # This is a meal-in (returning from break)
                    # Calculate break hours and continue
                    try:
                        checkin_dt = datetime.fromisoformat(current_checkin.replace('Z', '+00:00'))
                        meal_in_dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                        break_hours = (meal_in_dt - checkin_dt).total_seconds() / 3600
                        print(f"    Meal-in detected, break duration: {break_hours:.2f} hours")
                        current_checkin = event_time  # Reset for next work period
                        current_checkin_event = event  # Update to meal-in event
                        punch_sequence.append(f"meal-in: {event_time}")
                    except Exception as e:
                        print(f"    Error calculating break hours: {e}")
                        current_checkin = event_time
                        current_checkin_event = event
                        punch_sequence.append(f"meal-in: {event_time}")
                        
            elif event_type == 'Check-out':
                if current_checkin:
                    # End of work period
                    try:
                        checkin_dt = datetime.fromisoformat(current_checkin.replace('Z', '+00:00'))
                        checkout_dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                        work_hours = (checkout_dt - checkin_dt).total_seconds() / 3600
                        total_hours += work_hours
                        
                        print(f"    Work period: {current_checkin} to {event_time} = {work_hours:.2f} hours")
                        punch_sequence.append(f"check-out: {event_time}")
                        
                        # Get venue - prefer Check-out, fall back to Check-in if Check-out doesn't have valid venue
                        checkout_venue = event.get('venue')
                        checkin_venue = current_checkin_event.get('venue') if current_checkin_event else None
                        
                        # Use venue from whichever event has a valid location_id
                        if checkout_venue and checkout_venue not in ('Venue_Unknown', 'Unknown', None):
                            paired_venue = checkout_venue
                        elif checkin_venue and checkin_venue not in ('Venue_Unknown', 'Unknown', None):
                            paired_venue = checkin_venue
                        else:
                            paired_venue = checkout_venue or checkin_venue or 'Venue_Unknown'
                        
                        # Derive business_date from check-in event (use the check-in day as the shift date)
                        checkin_business_date = current_checkin_event.get('business_date') if current_checkin_event else None
                        if not checkin_business_date:
                            checkin_business_date = extract_business_date(current_checkin)
                        
                        # Create a timecard entry for this work period
                        paired_tc = {
                            'guid': f"{employee_id}_{checkin_business_date}_{current_checkin}",
                            'employee_id': employee_id,
                            'employee_name': event.get('employee_name', 'Unknown'),
                            'venue': paired_venue,
                            'business_date': checkin_business_date,
                            'time_in': current_checkin,
                            'time_out': event_time,
                            'hours': round(work_hours, 2),
                            'source': 'workday_timecards',
                            'status': 'active',
                            'position_id': event.get('position_id'),
                            'position_name': event.get('position_name'),
                            'punch_sequence': ' -> '.join(punch_sequence),
                            'total_shift_hours': round(total_hours, 2)
                        }
                        paired_timecards.append(paired_tc)
                        
                        # Reset for next pairing
                        current_checkin = None
                        current_checkin_event = None
                        punch_sequence = []
                        
                    except Exception as e:
                        print(f"    Error calculating work hours: {e}")
                        current_checkin = None
                        current_checkin_event = None
                else:
                    print(f"    Warning: Check-out without matching check-in for {employee_id}")
                    
            elif event_type == 'meal-out':
                if current_checkin:
                    # Start of meal break
                    punch_sequence.append(f"meal-out: {event_time}")
                    print(f"    Meal-out detected at {event_time}")
                else:
                    print(f"    Warning: Meal-out without matching check-in for {employee_id}")
                    
            elif event_type == 'meal-in':
                # This should be handled in the Check-in logic above
                pass
        
        # Check for unmatched check-in
        if current_checkin:
            print(f"    Warning: Unmatched check-in for {employee_id} at {current_checkin}")
    
    return paired_timecards

# --- Aggregation and Reconciliation ---
def aggregate_by_venue(timecards: List[Dict[str, Any]], track_punches: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate both count and hours by venue.
    
    Args:
        timecards: List of timecard records
        track_punches: If True, track raw punch count separately (for Toast data)
    """
    venue_stats = {}
    for tc in timecards:
        # Use 'venue' field which should be set to hris_location_id/location_id for both Toast and Workday
        venue_key = tc.get('venue', 'Unknown')
        hours = tc.get('hours', 0.0)
        
        if venue_key not in venue_stats:
            venue_stats[venue_key] = {'count': 0, 'hours': 0.0, 'punches': 0}
        
        venue_stats[venue_key]['count'] += 1
        venue_stats[venue_key]['hours'] += hours
        
        # For Toast, count actual punches based on what's present in the timecard
        # A punch exists for each: check-in (inDate), check-out (outDate), and any breaks
        if track_punches:
            punch_count = 0
            # Check-in punch
            if tc.get('inDate') or tc.get('time_in'):
                punch_count += 1
            # Check-out punch
            if tc.get('outDate') or tc.get('time_out'):
                punch_count += 1
            # Break punches (each break has start + end = 2 punches)
            breaks = tc.get('breaks', [])
            if breaks:
                for brk in breaks:
                    if brk.get('startDate') or brk.get('start'):
                        punch_count += 1
                    if brk.get('endDate') or brk.get('end'):
                        punch_count += 1
            venue_stats[venue_key]['punches'] += punch_count
    
    return venue_stats

def aggregate_by_employee(timecards: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Aggregate both count and hours by employee"""
    employee_stats = {}
    for tc in timecards:
        employee_id = tc.get('employee_id', 'Unknown')
        hours = tc.get('hours', 0.0)
        
        if employee_id not in employee_stats:
            employee_stats[employee_id] = {'count': 0, 'hours': 0.0}
        
        employee_stats[employee_id]['count'] += 1
        employee_stats[employee_id]['hours'] += hours
    
    return employee_stats

def aggregate_hours_by_date(timecards):
    date_hours = defaultdict(float)
    for tc in timecards:
        if not tc.get('deleted', False):
            date = tc['business_date']
            total_hours = tc.get('regularHours', 0.0) + tc.get('overtimeHours', 0.0)
            date_hours[date] += total_hours
    return date_hours

def match_timecards(toast: List[Dict[str, Any]], wd: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Match timecards between Toast and Workday systems.
    Since Workday RaaS doesn't include location, we match by:
    - Employee ID
    - Date/Time (within a reasonable window)
    - Event Type (Check-in/Check-out/meal-out/meal-in)
    - Position (mapped to venue)
    
    Returns detailed information about matches and missing punches.
    """
    print(f"\n[MATCH] Starting timecard matching...")
    print(f"[MATCH] Toast timecards to match: {len(toast)}")
    print(f"[MATCH] Workday timecards to match: {len(wd)}")
    
    # Helper function to normalize timestamp to UTC and truncate to minute
    # This handles both Toast (UTC with milliseconds) and Workday (local time with offset)
    def normalize_timestamp_to_key(ts_str):
        """
        Convert any timestamp to a normalized UTC key for matching.
        Uses second-level precision to differentiate same-minute punches.
        Returns: 'YYYY-MM-DDTHH:MM:SS' in UTC
        """
        if not ts_str:
            return None
        try:
            # Parse the timestamp with timezone info
            ts = ts_str.replace('Z', '+00:00')
            
            # Handle different formats
            if '.' in ts:
                # Has milliseconds - strip them before parsing
                # Format: 2026-01-05T11:58:54.415+0000
                base_part = ts.split('.')[0]
                tz_part = ts.split('.')[-1]
                # Extract timezone from the end (could be +0000 or +00:00)
                if '+' in tz_part:
                    tz = '+' + tz_part.split('+')[-1]
                elif tz_part.count('-') > 0:
                    tz = '-' + tz_part.split('-')[-1]
                else:
                    tz = '+00:00'
                # Normalize timezone format (0000 -> 00:00)
                if len(tz) == 5 and ':' not in tz:
                    tz = tz[:3] + ':' + tz[3:]
                ts = base_part + tz
            
            # Parse with fromisoformat
            dt = datetime.fromisoformat(ts)
            
            # Convert to UTC
            if dt.tzinfo:
                utc_dt = dt.astimezone(timezone.utc)
            else:
                utc_dt = dt.replace(tzinfo=timezone.utc)
            
            # Return key with minute precision (Workday RaaS API rounds seconds to :00)
            # Event type in key differentiates same-minute punches
            return utc_dt.strftime('%Y-%m-%dT%H:%M')
        except Exception as e:
            print(f"[MATCH] Warning: Could not parse timestamp '{ts_str}': {e}")
            # Fallback: just truncate to 16 chars (YYYY-MM-DDTHH:MM)
            return ts_str[:16] if len(ts_str) >= 16 else ts_str
    
    matched = []
    missing_in_workday = []
    missing_in_toast = []
    
    # Track detailed missing punch information
    missing_punch_details = {
        'toast_missing_in_workday': [],
        'workday_missing_in_toast': []
    }
    
    # Create mapping of Toast timecards by employee and normalized UTC time
    toast_by_employee_time = {}
    for tc in toast:
        employee_id = tc.get('employee_id', '')
        # Toast uses inDate/outDate, normalized uses time_in/time_out
        time_in = tc.get('inDate') or tc.get('time_in', '')
        time_out = tc.get('outDate') or tc.get('time_out', '')
        venue_guid = tc.get('venue_guid', '')
        venue_name = tc.get('venue_name', '')
        venue_site_id = tc.get('venue_site_id', '')
        hris_location_id = tc.get('hris_location_id', '')

        if employee_id and (time_in or time_out):
            # Create keys for both time_in and time_out events
            # Use normalized UTC timestamp truncated to minute for matching
            if time_in:
                normalized_time_in = normalize_timestamp_to_key(time_in)
                if normalized_time_in:
                    # Include event_type in key to handle same-minute punches (e.g., meal end + meal return)
                    key_in = f"{employee_id}_{normalized_time_in}_Check-in"
                    toast_by_employee_time[key_in] = {
                        'timecard': tc,
                        'event_type': 'Check-in',
                        'venue_guid': venue_guid,
                        'venue_name': venue_name,
                        'venue_site_id': venue_site_id,
                        'hris_location_id': hris_location_id,
                        'punch_time': time_in,
                        'employee_name': tc.get('employee_name', '')
                    }
            if time_out:
                normalized_time_out = normalize_timestamp_to_key(time_out)
                if normalized_time_out:
                    # Include event_type in key to handle same-minute punches
                    key_out = f"{employee_id}_{normalized_time_out}_Check-out"
                    toast_by_employee_time[key_out] = {
                        'timecard': tc,
                        'event_type': 'Check-out',
                        'venue_guid': venue_guid,
                        'venue_name': venue_name,
                        'venue_site_id': venue_site_id,
                        'hris_location_id': hris_location_id,
                        'punch_time': time_out,
                        'employee_name': tc.get('employee_name', '')
                    }

    # Create mapping of Workday timecards by employee and time
    # Workday paired timecards have time_in/time_out, raw events have date_time
    # Use normalized UTC timestamp to match with Toast
    wd_by_employee_time = {}
    for tc in wd:
        employee_id = tc.get('employee_id', '')
        # For paired timecards, use time_in and time_out
        time_in = tc.get('time_in', '')
        time_out = tc.get('time_out', '')
        # For raw events, use date_time
        date_time = tc.get('date_time', '')
        event_type = tc.get('event_type', '')
        venue = tc.get('venue', '')

        if employee_id:
            # Create keys for both time_in and time_out (for paired timecards)
            # Use normalized UTC timestamp truncated to minute for matching
            # Include event_type in key to handle same-minute punches (e.g., meal end + meal return)
            if time_in:
                normalized_time_in = normalize_timestamp_to_key(time_in)
                if normalized_time_in:
                    key_in = f"{employee_id}_{normalized_time_in}_Check-in"
                    wd_by_employee_time[key_in] = {
                        'timecard': tc,
                        'event_type': 'Check-in',
                        'venue': venue,
                        'punch_time': time_in,
                        'employee_name': tc.get('employee_name', '')
                    }
            if time_out:
                normalized_time_out = normalize_timestamp_to_key(time_out)
                if normalized_time_out:
                    key_out = f"{employee_id}_{normalized_time_out}_Check-out"
                    wd_by_employee_time[key_out] = {
                        'timecard': tc,
                        'event_type': 'Check-out',
                        'venue': venue,
                        'punch_time': time_out,
                        'employee_name': tc.get('employee_name', '')
                    }
            # Also handle raw events with date_time
            if date_time and not time_in and not time_out:
                normalized_date_time = normalize_timestamp_to_key(date_time)
                if normalized_date_time:
                    # Map event_type to standard Check-in/Check-out for key consistency
                    key_event_type = 'Check-in' if event_type in ['Check-in', 'meal-in'] else 'Check-out'
                    key = f"{employee_id}_{normalized_date_time}_{key_event_type}"
                    wd_by_employee_time[key] = {
                        'timecard': tc,
                        'event_type': event_type,
                        'venue': venue,
                        'punch_time': date_time,
                        'employee_name': tc.get('employee_name', '')
                    }

    # Debug: show sample keys from both systems
    print(f"[MATCH] Toast punch keys created: {len(toast_by_employee_time)}")
    print(f"[MATCH] Workday punch keys created: {len(wd_by_employee_time)}")
    
    # Show sample keys for debugging
    toast_keys_sample = list(toast_by_employee_time.keys())[:3]
    wd_keys_sample = list(wd_by_employee_time.keys())[:3]
    print(f"[MATCH] Sample Toast keys: {toast_keys_sample}")
    print(f"[MATCH] Sample Workday keys: {wd_keys_sample}")
    
    # Debug specific employee 1035434 (Maddi Pearl Price) to diagnose false positive
    debug_employee = '1035434'
    debug_toast_keys = [k for k in toast_by_employee_time.keys() if k.startswith(debug_employee)]
    debug_wd_keys = [k for k in wd_by_employee_time.keys() if k.startswith(debug_employee)]
    if debug_toast_keys or debug_wd_keys:
        print(f"[MATCH DEBUG] Employee {debug_employee} Toast keys: {sorted(debug_toast_keys)}")
        print(f"[MATCH DEBUG] Employee {debug_employee} Workday keys: {sorted(debug_wd_keys)}")
        # Show raw timestamps for this employee
        for k in sorted(debug_toast_keys):
            print(f"[MATCH DEBUG]   Toast {k}: raw={toast_by_employee_time[k]['punch_time']} type={toast_by_employee_time[k]['event_type']}")
        for k in sorted(debug_wd_keys):
            print(f"[MATCH DEBUG]   Workday {k}: raw={wd_by_employee_time[k]['punch_time']} type={wd_by_employee_time[k]['event_type']}")
        # Show which keys match (use different var names to avoid overwriting main variables)
        debug_matching_keys = set(debug_toast_keys) & set(debug_wd_keys)
        debug_missing_in_wd = set(debug_toast_keys) - set(debug_wd_keys)
        debug_missing_in_toast = set(debug_wd_keys) - set(debug_toast_keys)
        print(f"[MATCH DEBUG]   Matching: {len(debug_matching_keys)}, Missing in WD: {len(debug_missing_in_wd)}, Missing in Toast: {len(debug_missing_in_toast)}")
        if debug_missing_in_wd:
            print(f"[MATCH DEBUG]   Missing in Workday: {sorted(debug_missing_in_wd)}")
    
    # Check Toast timecards against Workday
    for key, toast_data in toast_by_employee_time.items():
        if key in wd_by_employee_time:
            wd_data = wd_by_employee_time[key]

            # Check if event types match (allowing for meal mapping)
            toast_event = toast_data['event_type']
            wd_event = wd_data['event_type']

            # Map meal events for comparison
            if toast_event == 'Check-in' and wd_event == 'meal-in':
                event_match = True
            elif toast_event == 'Check-out' and wd_event == 'meal-out':
                event_match = True
            elif toast_event == wd_event:
                event_match = True
            else:
                event_match = False

            if event_match:
                matched.append({
                    'toast': toast_data['timecard'],
                    'workday': wd_data['timecard'],
                    'match_key': key,
                    'event_type': wd_event
                })
            else:
                missing_in_workday.append(toast_data['timecard'])
                # Add detailed missing punch information
                missing_punch_details['toast_missing_in_workday'].append({
                    'employee_id': toast_data['timecard'].get('employee_id', ''),
                    'employee_name': toast_data['employee_name'],
                    'venue_site_id': toast_data['venue_site_id'],
                    'hris_location_id': toast_data.get('hris_location_id', ''),
                    'venue_name': toast_data['venue_name'],
                    'venue_guid': toast_data['venue_guid'],
                    'punch_time': toast_data['punch_time'],
                    'event_type': toast_event,
                    'expected_workday_event': toast_event,  # Same event type expected in Workday
                    'position': toast_data['timecard'].get('position', ''),
                    'hours': toast_data['timecard'].get('hours', 0.0)
                })
        else:
            missing_in_workday.append(toast_data['timecard'])
            # Add detailed missing punch information
            missing_punch_details['toast_missing_in_workday'].append({
                'employee_id': toast_data['timecard'].get('employee_id', ''),
                'employee_name': toast_data['employee_name'],
                'venue_site_id': toast_data['venue_site_id'],
                'hris_location_id': toast_data.get('hris_location_id', ''),
                'venue_name': toast_data['venue_name'],
                'venue_guid': toast_data['venue_guid'],
                'punch_time': toast_data['punch_time'],
                'event_type': toast_data['event_type'],
                'expected_workday_event': toast_data['event_type'],  # Same event type expected in Workday
                'position': toast_data['timecard'].get('position', ''),
                'hours': toast_data['timecard'].get('hours', 0.0)
            })

    # Check Workday timecards against Toast (find extra Workday entries)
    for key, wd_data in wd_by_employee_time.items():
        if key not in toast_by_employee_time:
            missing_in_toast.append(wd_data['timecard'])
            # Add detailed missing punch information
            missing_punch_details['workday_missing_in_toast'].append({
                'employee_id': wd_data['timecard'].get('employee_id', ''),
                'employee_name': wd_data['employee_name'],
                'venue': wd_data['venue'],
                'punch_time': wd_data['punch_time'],
                'event_type': wd_data['event_type'],
                'position': wd_data['timecard'].get('position', ''),
                'hours': wd_data['timecard'].get('hours', 0.0)
            })

    # Summary
    print(f"[MATCH] Results:")
    print(f"[MATCH]   Matched: {len(matched)}")
    print(f"[MATCH]   Toast missing in Workday: {len(missing_punch_details['toast_missing_in_workday'])}")
    print(f"[MATCH]   Workday missing in Toast: {len(missing_punch_details['workday_missing_in_toast'])}")
    
    return {
        'matched': matched,
        'missing_in_workday': missing_in_workday,
        'missing_in_toast': missing_in_toast,
        'missing_punch_details': missing_punch_details
    }

def detect_odd_punch_counts(timecards: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Detect employees with odd numbers of punches per day, which indicates mismatched punches.
    Returns a dictionary of venue -> list of employee IDs with odd punch counts.
    """
    # Group by venue, employee, and business date
    employee_punches = defaultdict(list)
    
    for tc in timecards:
        if tc.get('event_type') in ['Check-in', 'Check-out', 'meal-out', 'meal-in']:
            key = (tc.get('venue', 'Unknown'), tc['employee_id'], tc.get('business_date', 'Unknown'))
            employee_punches[key].append(tc)
    
    # Check for odd punch counts
    odd_punch_venues = defaultdict(list)
    
    for (venue, employee_id, business_date), punches in employee_punches.items():
        punch_count = len(punches)
        
        if punch_count % 2 != 0:  # Odd number of punches
            print(f"⚠️  ODD PUNCH COUNT: {employee_id} at {venue} on {business_date} has {punch_count} punches")
            print(f"   Punch sequence: {[p.get('event_type') for p in punches]}")
            odd_punch_venues[venue].append(f"{employee_id} ({business_date}): {punch_count} punches")
    
    return dict(odd_punch_venues)

# --- Main Handler ---
def timecard_reconciliation_handler(event, context):
    """
    Lambda handler for timecard reconciliation.
    
    Supports both scheduled runs (default) and ad-hoc runs with parameters.
    
    Event payload for ad-hoc runs:
    {
        "action": "adhoc_reconciliation",
        "parameters": {
            "from_date": "2025-07-28",
            "to_date": "2025-07-28", 
            "venue_id": "L255",  # Optional
            "clock_event_id": "12345",  # Optional
            "run_type": "date_range|venue_specific|single_event|weekly_report"
        }
    }
    """
    try:
        # Check if this is an ad-hoc run with parameters
        if event and isinstance(event, dict) and event.get('action') == 'adhoc_reconciliation':
            return handle_adhoc_reconciliation(event.get('parameters', {}))
        else:
            # Default scheduled run (yesterday's data)
            return handle_scheduled_reconciliation()
            
    except Exception as e:
        error_msg = f"Lambda execution failed: {str(e)}"
        print(f"❌ {error_msg}")
        
        # Send error notification to Slack
        try:
            webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
            send_slack_message(f"🚨 Timecard Reconciliation Error: {error_msg}", webhook_url)
        except:
            pass
            
        return {
            'statusCode': 500,
            'body': error_msg
        }

def handle_adhoc_reconciliation(parameters: dict):
    """
    Handle ad-hoc reconciliation runs with specific parameters.
    """
    print(f"🎯 Ad-hoc reconciliation with parameters: {parameters}")
    
    # Extract parameters
    from_date = parameters.get('from_date')
    to_date = parameters.get('to_date')
    venue_id = parameters.get('venue_id')
    clock_event_id = parameters.get('clock_event_id')
    run_type = parameters.get('run_type', 'date_range')
    environment = parameters.get('environment', 'prod')  # prod, preprod, or sandbox
    
    # Validate parameters
    if not from_date and not to_date and not clock_event_id:
        return {
            'statusCode': 400,
            'body': 'Error: Must provide either date range or clock_event_id'
        }
    
    # Get secrets based on environment
    secrets = get_secrets_from_vault(environment)
    
    # Send start notification
    start_msg = f"🚀 Starting ad-hoc reconciliation: {run_type}"
    if from_date and to_date:
        start_msg += f" ({from_date} to {to_date})"
    if venue_id:
        start_msg += f" for venue {venue_id}"
    if clock_event_id:
        start_msg += f" for event {clock_event_id}"
    
    webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    send_slack_message(start_msg, webhook_url)
    
    # Get Toast timecards
    print(f"[REAL] Getting Toast timecards for ad-hoc run...")
    toast_raw_events = get_all_venue_timecards(from_date, to_date, secrets)
    
    # Get Workday timecards based on run type
    print(f"[REAL] Getting Workday timecards for ad-hoc run...")
    if clock_event_id:
        # Single event lookup
        wd_raw_events = get_workday_timecard_by_event_id(clock_event_id, secrets, environment)
    elif venue_id:
        # Venue-specific lookup
        wd_raw_events = get_workday_timecards_by_location(from_date, to_date, venue_id, secrets, environment)
    else:
        # Date range lookup (all venues)
        wd_raw_events = get_workday_timecards_by_date_range(from_date, to_date, secrets, environment)
    
    # Print Workday summary
    print(f"\n[REAL] WORKDAY SUMMARY:")
    print(f"[REAL] {'='*60}")
    total_workday_events = len(wd_raw_events)
    total_workday_employees = len(set(event.get('employee_id', '') for event in wd_raw_events if event.get('employee_id')))
    
    # Group by venue if available
    workday_by_venue = {}
    for event in wd_raw_events:
        venue = event.get('venue', 'Unknown')
        if venue not in workday_by_venue:
            workday_by_venue[venue] = {'events': 0, 'employees': set()}
        workday_by_venue[venue]['events'] += 1
        if event.get('employee_id'):
            workday_by_venue[venue]['employees'].add(event.get('employee_id'))
    
    for venue, data in workday_by_venue.items():
        print(f"[REAL] 📊 {venue}: {data['events']} events, {len(data['employees'])} employees")
    
    print(f"[REAL] {'='*60}")
    print(f"[REAL] WORKDAY TOTALS: {total_workday_events} events, {total_workday_employees} employees")
    print(f"[REAL] {'='*60}")
    
    # Process the data
    return process_reconciliation_data(toast_raw_events, wd_raw_events, from_date, run_type, environment)

def handle_scheduled_reconciliation(environment: str = 'prod'):
    """
    Handle scheduled daily reconciliation (default behavior).
    Runs for production environment by default.
    """
    print(f"📅 Running scheduled daily reconciliation (environment: {environment})...")
    
    # Calculate yesterday's date
    yesterday = datetime.now() - timedelta(days=1)
    date_str = yesterday.strftime('%Y-%m-%d')
    
    # Get secrets for the specified environment
    secrets = get_secrets_from_vault(environment)
    
    # Send start notification
    webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    send_slack_message(f"🚀 Starting daily reconciliation for {date_str}", webhook_url)
    
    # Get Toast timecards
    print(f"[REAL] Getting Toast timecards...")
    toast_raw_events = get_all_venue_timecards(date_str, date_str, secrets)
    
    # Get Workday timecards
    print(f"[REAL] Getting Workday timecards...")
    wd_raw_events = get_workday_timecards_by_date_range(date_str, date_str, secrets)
    
    # Process the data
    return process_reconciliation_data(toast_raw_events, wd_raw_events, date_str, "daily_scheduled", environment)

def process_reconciliation_data(toast_raw_events, wd_raw_events, business_date, run_type, environment: str = 'local'):
    """
    Process reconciliation data and generate report.
    
    Args:
        toast_raw_events: List of Toast timecard events
        wd_raw_events: List of Workday timecard events
        business_date: The business date being reconciled
        run_type: Type of run (e.g., 'date_range', 'daily_scheduled')
        environment: Environment for config ('prod', 'preprod', 'sandbox', 'local')
    """
    # 5.5 Get the set of employee IDs from Toast (source of truth)
    # We'll use this to filter Workday events to only relevant employees
    toast_employee_ids = set(tc.get('employee_id') for tc in toast_raw_events if tc.get('employee_id'))
    print(f"\n[REAL] Toast has {len(toast_employee_ids)} unique employees")
    
    # Filter Workday events to only include employees that exist in Toast
    # This ensures we're comparing apples to apples
    original_wd_count = len(wd_raw_events)
    wd_raw_events_filtered = [e for e in wd_raw_events if e.get('employee_id') in toast_employee_ids]
    filtered_out_count = original_wd_count - len(wd_raw_events_filtered)
    
    if filtered_out_count > 0:
        # Get the extra employees that aren't in Toast
        extra_wd_employees = set(e.get('employee_id') for e in wd_raw_events if e.get('employee_id') not in toast_employee_ids)
        print(f"[REAL] Filtered out {filtered_out_count} Workday events for {len(extra_wd_employees)} employees not in Toast data")
        print(f"[REAL] (These may be manual Workday entries or employees outside the Toast query scope)")
    
    # Use filtered Workday events from here on
    wd_raw_events = wd_raw_events_filtered
    print(f"[REAL] Using {len(wd_raw_events)} Workday events (filtered to Toast employees only)")
    
    # 6. Pair Workday events to calculate hours
    print(f"\n[REAL] Pairing {len(wd_raw_events)} Workday events...")
    paired_workday_timecards = pair_checkin_checkout_events(wd_raw_events)
    print(f"[REAL] Created {len(paired_workday_timecards)} paired Workday timecards")
    
    # Debug: Show venue distribution in paired timecards
    paired_with_venue = sum(1 for tc in paired_workday_timecards if tc.get('venue') and tc.get('venue') not in ('Venue_Unknown', 'Unknown'))
    paired_venues = set(tc.get('venue') for tc in paired_workday_timecards)
    print(f"[REAL] Paired timecards venue stats: {paired_with_venue} with valid venue, {len(paired_workday_timecards) - paired_with_venue} without")
    print(f"[REAL] Paired timecard venues: {sorted(paired_venues)}")
    
    # 6.5 Show Workday location stats (venue should already be set from location_id in XML)
    wd_with_location = sum(1 for e in wd_raw_events if e.get('venue') and e.get('venue') != 'Venue_Unknown')
    wd_without_location = len(wd_raw_events) - wd_with_location
    print(f"\n[REAL] Raw Workday venue stats: {wd_with_location} with location, {wd_without_location} without")
    
    # Show unique Workday venues
    wd_venues = set(e.get('venue') for e in wd_raw_events if e.get('venue'))
    if wd_venues:
        print(f"[REAL] Workday venues found: {sorted(wd_venues)}")
    
    # Only apply employee→venue mapping to Workday events WITHOUT a location
    # (Don't overwrite venue if location_id was extracted from XML)
    print(f"\n[REAL] Building employee→venue mapping from Toast data (for fallback only)...")
    employee_venue_map = {}
    for tc in toast_raw_events:
        emp_id = tc.get('employee_id')
        venue = tc.get('venue')  # This is hris_location_id or site_id
        venue_name = tc.get('venue_name')
        if emp_id and venue:
            employee_venue_map[emp_id] = {
                'venue': venue,
                'venue_name': venue_name
            }
    print(f"[REAL] Built mapping for {len(employee_venue_map)} employees from Toast data")
    
    # Apply mapping ONLY to Workday events that don't have a venue yet
    mapped_count = 0
    for wd_event in wd_raw_events:
        # Skip if already has a valid venue from location_id
        if wd_event.get('venue') and wd_event.get('venue') != 'Venue_Unknown':
            continue
            
        emp_id = wd_event.get('employee_id')
        if emp_id and emp_id in employee_venue_map:
            venue_info = employee_venue_map[emp_id]
            wd_event['venue'] = venue_info['venue']
            wd_event['venue_name'] = venue_info['venue_name']
            mapped_count += 1
    
    if mapped_count > 0:
        print(f"[REAL] Fallback mapping: {mapped_count} Workday events mapped using employee IDs")
    
    # Count remaining unmapped
    still_unmapped = sum(1 for e in wd_raw_events if not e.get('venue') or e.get('venue') == 'Venue_Unknown')
    if still_unmapped > 0:
        print(f"[REAL] {still_unmapped} Workday events still unmapped (no location in XML and employee not in Toast data)")
    
    # 7. Detect odd punch counts (mismatched punches)
    # Only meaningful for HISTORICAL reports - current day would flag everyone still working
    # business_date format: "2026-01-05-05:00" or "2026-01-05"
    report_date_str = business_date.split('-')[0:3]  # Get YYYY-MM-DD part
    report_date_str = '-'.join(report_date_str)
    today_str = datetime.now().strftime('%Y-%m-%d')
    
    if report_date_str < today_str:
        # Historical report - odd punches indicate actual issues
        print(f"\n[REAL] Detecting odd punch counts (historical report - {report_date_str} < {today_str})...")
        odd_punch_venues = detect_odd_punch_counts(wd_raw_events)
        total_odd = sum(len(employees) for employees in odd_punch_venues.values())
        print(f"[REAL] Found {total_odd} employees with odd punch counts across {len(odd_punch_venues)} venues")
    else:
        # Current-day report - skip odd punch detection (would flag everyone still working)
        print(f"\n[REAL] Odd punch detection SKIPPED (current-day report - employees may still be on shift)")
        odd_punch_venues = {}
    
    # 8. Aggregate by venue
    print(f"\n[REAL] Aggregating data by venue...")
    
    # Build siteId ↔ hris_location mapping from Toast data
    # Toast timecards have: venue_site_id, hris_location_id (if enriched), venue_name
    site_to_hris = {}
    hris_to_site = {}
    site_to_name = {}
    for tc in toast_raw_events:
        site_id = tc.get('venue_site_id')
        hris_loc = tc.get('hris_location_id')
        venue_name = tc.get('venue_name', '')
        if site_id:
            site_to_name[site_id] = venue_name
            if hris_loc and hris_loc != site_id:
                site_to_hris[site_id] = hris_loc
                hris_to_site[hris_loc] = site_id
    
    print(f"[REAL] Built venue mapping: {len(site_to_hris)} siteId→hris mappings")
    if site_to_hris:
        for sid, hloc in list(site_to_hris.items())[:5]:
            print(f"[REAL]   {sid} → {hloc}")
        if len(site_to_hris) > 5:
            print(f"[REAL]   ... and {len(site_to_hris) - 5} more")
    
    # Aggregate Toast by venue (will use siteId if no hris_location_id)
    # track_punches=True to also count raw punch events for debugging
    toast_stats_raw = aggregate_by_venue(toast_raw_events, track_punches=True)
    
    # Aggregate Workday by venue (uses hris_location from XML)
    # Use raw events for punch counts (to capture all punches including cross-midnight)
    # Use paired timecards for hours (where pairing was successful)
    wd_stats_raw = aggregate_by_venue(wd_raw_events)
    
    # Also aggregate from paired timecards to get hours for successfully paired events
    wd_stats_paired = aggregate_by_venue(paired_workday_timecards)
    
    # Merge hours from paired timecards into raw stats
    for venue_key, paired_stats in wd_stats_paired.items():
        if venue_key in wd_stats_raw:
            # Add hours from paired timecards (punch counts stay from raw events)
            wd_stats_raw[venue_key]['hours'] = paired_stats.get('hours', 0.0)
        else:
            # Venue only in paired (shouldn't happen, but handle it)
            wd_stats_raw[venue_key] = paired_stats
    
    # Calculate total hours from paired timecards for debugging
    total_paired_hours = sum(stats.get('hours', 0.0) for stats in wd_stats_paired.values())
    print(f"[REAL] Workday hours: {len(paired_workday_timecards)} paired timecards = {total_paired_hours:.2f} hours merged into {len(wd_stats_raw)} venue stats")
    
    print(f"[REAL] Toast venues: {sorted(toast_stats_raw.keys())[:10]}...")
    print(f"[REAL] Workday venues: {sorted(wd_stats_raw.keys())[:10]}...")
    
    # Merge the stats: normalize to use siteId as the primary key
    # For Toast: already keyed by siteId (or hris_loc if enriched)
    # For Workday: keyed by hris_location, need to map back to siteId
    toast_stats = {}
    wd_stats = {}
    venue_names = {}  # Map venue key to display name
    
    # Process Toast stats - normalize key to siteId
    for venue_key, stats in toast_stats_raw.items():
        # If this is an hris_location that maps to a siteId, use siteId
        if venue_key in hris_to_site:
            site_id = hris_to_site[venue_key]
            toast_stats[site_id] = stats
            venue_names[site_id] = venue_key  # The hris_location is the name
        else:
            # This is already a siteId
            toast_stats[venue_key] = stats
            venue_names[venue_key] = site_to_name.get(venue_key, venue_key)
    
    # Process Workday stats - map hris_location back to siteId
    for venue_key, stats in wd_stats_raw.items():
        if venue_key in hris_to_site:
            # This hris_location maps to a siteId
            site_id = hris_to_site[venue_key]
            wd_stats[site_id] = stats
            venue_names[site_id] = venue_key  # Store the hris_location as name
        else:
            # No mapping found - keep as is but flag it
            wd_stats[venue_key] = stats
            venue_names[venue_key] = venue_key
    
    print(f"[REAL] After normalization - Toast venues: {len(toast_stats)}, Workday venues: {len(wd_stats)}")

    # 10. Match timecards and find missing IDs
    # Use raw events for matching (not paired timecards) to capture all punches
    # including cross-midnight shifts where check-in was on previous day
    match_results = match_timecards(toast_raw_events, wd_raw_events)
    
    # Extract detailed missing punch information
    missing_punch_details = match_results.get('missing_punch_details', {})
    toast_missing_in_workday = missing_punch_details.get('toast_missing_in_workday', [])
    workday_missing_in_toast = missing_punch_details.get('workday_missing_in_toast', [])
    
    # 11. Note: Cache lookup for venue mapping will be added later
    # For now, we'll work with the basic reconciliation data
    print(f"\n[REAL] Basic reconciliation complete - {len(toast_missing_in_workday)} Toast missing, {len(workday_missing_in_toast)} Workday missing")
    
    # Group missing punches by venue for reporting
    missing_punches_by_venue = {}
    for punch in toast_missing_in_workday:
        venue_key = punch.get('hris_location_id') or punch.get('venue_site_id', 'Unknown')
        if venue_key not in missing_punches_by_venue:
            missing_punches_by_venue[venue_key] = {
                'venue_name': punch.get('venue_name', 'Unknown'),
                'missing_punches': []
            }
        missing_punches_by_venue[venue_key]['missing_punches'].append(punch)
    
    # 11. Prepare summary by venue
    # Calculate totals - use punch counts for accurate comparison
    total_toast_punches = sum(stats.get('punches', 0) for stats in toast_stats.values())
    total_toast_hours = sum(stats['hours'] for stats in toast_stats.values())
    total_wd_punches = sum(stats.get('count', 0) for stats in wd_stats.values())
    total_wd_hours = sum(stats.get('hours', 0.0) for stats in wd_stats.values())
    
    # Count odd punch issues
    total_odd_punch_employees = sum(len(employees) for employees in odd_punch_venues.values())
    total_venues_with_odd_punches = len(odd_punch_venues)
    
    summary_lines = [
        f"Reconciliation for {business_date}",
        f"TOTALS:",
        f"  Toast: {total_toast_punches} punches, {total_toast_hours:.2f} hours",
        f"  Workday: {total_wd_punches} punches, {total_wd_hours:.2f} hours",
        f"  Punch diff: {total_toast_punches - total_wd_punches}",
        f"  Hours off by: {total_toast_hours - total_wd_hours:.2f}",
        "",
        f"PUNCH VALIDATION:",
        f"  Employees with odd punch counts: {total_odd_punch_employees}",
        f"  Venues with punch issues: {total_venues_with_odd_punches}",
        "",
        f"MISSING PUNCHES FOR REPROCESSING:",
        f"  Toast punches missing in Workday: {len(toast_missing_in_workday)}",
        f"  Workday punches missing in Toast: {len(workday_missing_in_toast)}",
        ""
    ]
    
    # Add venue-by-venue summary
    summary_lines.append("BY VENUE:")
    all_venues = set(toast_stats.keys()) | set(wd_stats.keys())
    for venue in sorted(all_venues):
        toast_count = toast_stats.get(venue, {}).get('count', 0)
        toast_hours = toast_stats.get(venue, {}).get('hours', 0.0)
        wd_count = wd_stats.get(venue, {}).get('count', 0)
        wd_hours = wd_stats.get(venue, {}).get('hours', 0.0)
        
        # Count odd punch employees for this venue
        venue_odd_punch_count = len(odd_punch_venues.get(venue, []))
        
        summary_lines.append(f"  {venue}:")
        summary_lines.append(f"    Toast: {toast_count} timecards, {toast_hours:.2f} hours")
        summary_lines.append(f"    Workday: {wd_count} timecards, {wd_hours:.2f} hours")
        summary_lines.append(f"    Count diff: {toast_count - wd_count}")
        summary_lines.append(f"    Hours diff: {toast_hours - wd_hours:.2f}")
        summary_lines.append(f"    Odd punch employees: {venue_odd_punch_count}")
        
        # Add missing punch details for this venue
        if venue in missing_punches_by_venue:
            missing_punches = missing_punches_by_venue[venue]['missing_punches']
            if missing_punches:
                summary_lines.append(f"    Missing punches for reprocessing:")
                for punch in missing_punches[:5]:  # Show first 5 missing punches
                    summary_lines.append(f"      - {punch['employee_name']} ({punch['employee_id']}) {punch['event_type']} at {punch['punch_time']}")
                if len(missing_punches) > 5:
                    summary_lines.append(f"      ... and {len(missing_punches) - 5} more")
        summary_lines.append("")
    
    # Add detailed missing punch information for reprocessing
    if toast_missing_in_workday or workday_missing_in_toast:
        summary_lines.append("DETAILED MISSING PUNCHES FOR REPROCESSING:")
        summary_lines.append("")
        
        if toast_missing_in_workday:
            summary_lines.append("Toast punches missing in Workday (reprocess these):")
            for punch in toast_missing_in_workday:
                venue_label = punch.get('hris_location_id') or punch.get('venue_site_id', 'Unknown')
                summary_lines.append(f"  - Venue {venue_label} ({punch['venue_name']}): {punch['employee_name']} ({punch['employee_id']}) {punch['event_type']} at {punch['punch_time']} - Expected Workday event: {punch['expected_workday_event']}")
            summary_lines.append("")
        
        if workday_missing_in_toast:
            summary_lines.append("Workday punches missing in Toast (investigate these):")
            for punch in workday_missing_in_toast:
                summary_lines.append(f"  - {punch['venue']}: {punch['employee_name']} ({punch['employee_id']}) {punch['event_type']} at {punch['punch_time']}")
            summary_lines.append("")
    
    # Add odd punch details
    if odd_punch_venues:
        summary_lines.append("VENUES WITH ODD PUNCH COUNTS:")
        for venue in sorted(odd_punch_venues.keys()):
            employees_with_odd_punch = odd_punch_venues[venue]
            summary_lines.append(f"  - {venue}: {len(employees_with_odd_punch)} employees with odd punches")
            for employee_info in employees_with_odd_punch[:3]:  # Show first 3 employees
                summary_lines.append(f"    * {employee_info}")
            if len(employees_with_odd_punch) > 3:
                summary_lines.append(f"    * ... and {len(employees_with_odd_punch) - 3} more")
        summary_lines.append("")
    
    summary_text = "\n".join(summary_lines)

    # Notify finish
    webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    send_slack_message(f":white_check_mark: Timecard reconciliation finished for {business_date}\n\n{summary_text}", webhook_url)

    # Send email summary
    EMAIL_TO = os.environ.get('EMAIL_TO', '').split(',') if os.environ.get('EMAIL_TO') else []
    EMAIL_FROM = os.environ.get('EMAIL_FROM')
    if EMAIL_TO and EMAIL_FROM:
        send_email(
            subject=f"Timecard Reconciliation Results for {business_date}",
            body=summary_text,
            to_addresses=EMAIL_TO,
            from_address=EMAIL_FROM
        )

    # Print to stdout for local testing
    print(summary_text)

    # Generate and save HTML report
    print("\n[REAL] Generating HTML report...")
    html_report = generate_html_report(
        business_date=business_date,
        run_type=run_type,
        toast_stats=toast_stats,
        wd_stats=wd_stats,
        toast_missing_in_workday=toast_missing_in_workday,
        workday_missing_in_toast=workday_missing_in_toast,
        odd_punch_venues=odd_punch_venues,
        missing_punches_by_venue=missing_punches_by_venue,
        venue_names=venue_names
    )
    
    # Save the HTML report
    # Output path determined by: explicit path > REPORT_OUTPUT_PATH env var > environment config
    # - Local/sandbox: ./reports
    # - Prod/preprod: \\TIO365TEST\Integrations\Reconciliation\Reports
    report_path = save_html_report(html_report, business_date, environment=environment)
    
    # Notify about the report location in Slack
    if report_path:
        send_slack_message(f"📊 HTML Report saved to: {report_path}", webhook_url)

    # 8. (Optional) Prepare for re-running missing timecards
    # for venue, res in match_results.items():
    #     for missing_guid in res['missing_in_workday']:
    #         print(f"Would re-sync timecard {missing_guid} for venue {venue}")
    
    return {
        'statusCode': 200,
        'body': {
            'summary': summary_text,
            'report_path': report_path,
            'stats': {
                'total_toast_punches': total_toast_punches,
                'total_toast_hours': total_toast_hours,
                'total_wd_punches': total_wd_punches,
                'total_wd_hours': total_wd_hours,
                'missing_in_workday': len(toast_missing_in_workday),
                'missing_in_toast': len(workday_missing_in_toast),
                'odd_punch_employees': total_odd_punch_employees
            }
        }
    }

def normalize_toast_timecard(tc: dict) -> dict:
    """Convert Toast/SYS-POS timecard to canonical format"""
    # Extract employee ID from externalId (e.g., "CUSTOM-TOPGOLF:1042447" -> "1042447")
    employee_external_id = tc.get('employeeReference', {}).get('externalId', '')
    employee_id = 'Unknown'
    if employee_external_id and ':' in employee_external_id:
        employee_id = employee_external_id.split(':')[-1]
    elif employee_external_id:
        employee_id = employee_external_id
    
    return {
        'guid': tc['guid'],
        'employee_id': employee_id,
        'venue': tc.get('venue', 'Unknown'),
        'business_date': tc.get('businessDate'),
        'hours': tc.get('regularHours', 0.0) + tc.get('overtimeHours', 0.0),
        'time_in': tc.get('inDate'),
        'time_out': tc.get('outDate'),
        'status': 'deleted' if tc.get('deleted', False) else 'active',
        'source': 'toast',
        # Optional fields
        'job_profile': tc.get('jobReference', {}).get('externalId'),
        'modified_date': tc.get('modifiedDate'),
        'auto_clocked_out': tc.get('autoClockedOut', False)
    }

def normalize_workday_timecard(tc: dict) -> dict:
    """Convert Workday timecard to canonical format"""
    return {
        'guid': tc.get('guid') or tc.get('uniqueId'),  # Workday might use different field
        'employee_id': tc.get('employee_id') or tc.get('workerId') or tc.get('employeeId'),
        'venue': tc.get('venue') or tc.get('location') or 'Unknown',  # If you map venue to Workday location
        'business_date': tc.get('business_date') or tc.get('calendarDate') or tc.get('businessDate'),
        'hours': tc.get('hours', 0.0),
        'time_in': tc.get('time_in') or tc.get('inTime'),
        'time_out': tc.get('time_out') or tc.get('outTime'),
        'status': 'active',  # Workday typically doesn't have deleted status
        'source': 'workday_timecards',
        # Optional fields
        'job_profile': tc.get('position_id') or tc.get('jobId'),
        'modified_date': tc.get('modified_date') or tc.get('lastModifiedDate'),
        'employee_name': tc.get('employee_name'),
        'position_name': tc.get('position_name')
    }

if __name__ == "__main__":
    # For local testing
    timecard_reconciliation_handler({}, {}) 