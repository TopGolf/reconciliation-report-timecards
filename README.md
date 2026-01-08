# Timecard Reconciliation Report

Automated reconciliation system for comparing timecard data between **Toast POS** and **Workday HRIS**. Generates detailed HTML reports identifying discrepancies to ensure payroll accuracy.

## Overview

This Lambda function compares time punch data from Toast (source of truth) against Workday to identify:
- Missing punches in Workday that exist in Toast
- Hour discrepancies between systems
- Incomplete timecards (odd punch counts)

Reports are generated as interactive HTML files with venue-level drill-down capabilities.

## Features

- **Multi-venue support**: Processes all 48+ Topgolf venues in parallel
- **Interactive HTML reports**: Collapsible sections per venue showing missing punch details
- **Environment flexibility**: Supports prod, preprod, sandbox, and local configurations
- **Vault integration**: Secure credential management via HashiCorp Vault (token or IAM auth)
- **Slack notifications**: Real-time alerts to `#timecard-reconciliation-project`
- **Windows share output**: Reports saved to `\\TIO365TEST\Integrations\Reconciliation\Reports`

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Toast POS  │     │   Workday   │     │    Cache    │
│    API      │     │  RaaS API   │     │   SYS-API   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────┬───────┴───────────────────┘
                   │
           ┌───────▼───────┐
           │    Lambda     │
           │ Reconciliation│
           └───────┬───────┘
                   │
       ┌───────────┼───────────┐
       │           │           │
       ▼           ▼           ▼
   ┌───────┐  ┌────────┐  ┌─────────┐
   │ Slack │  │  HTML  │  │  Vault  │
   │ Notify│  │ Report │  │ Secrets │
   └───────┘  └────────┘  └─────────┘
```

## Environment Configuration

| Environment | Workday Host | Cache Host | Report Output |
|-------------|--------------|------------|---------------|
| `prod` | services1.wd501.myworkday.com | tg-cache-sys-api.rtf.topgolf.io | `\\TIO365TEST\...\Reports` |
| `preprod` | impl-services1.wd501.myworkday.com | tg-cache-sys-api.preprod.rtf.topgolf.io | `\\TIO365TEST\...\Reports` |
| `sandbox` | impl-services1.wd501.myworkday.com | tg-cache-sys-api.preprod.rtf.topgolf.io | `./reports` |
| `local` | services1.wd501.myworkday.com | tg-cache-sys-api.preprod.rtf.topgolf.io | `./reports` |

## Installation

### Prerequisites

- Python 3.9+
- Access to Toast POS API
- Access to Workday RaaS API
- HashiCorp Vault access (for secrets)

### Dependencies

```bash
pip install requests hvac boto3
```

### Environment Variables

```bash
# Required
export VAULT_TOKEN="your-vault-token"          # For local testing
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."

# Optional (defaults in code)
export REPORT_OUTPUT_PATH="./reports"          # Override report location
export TOAST_CLIENT_ID="..."                   # Toast OAuth credentials
export TOAST_CLIENT_SECRET="..."
export WORKDAY_USERNAME="..."
export WORKDAY_PASSWORD="..."
```

## Usage

### Ad-hoc Reconciliation (Local)

```bash
cd /path/to/reconciliation-report-timecards

python3 -c "
from timecard_reconciliation_lambda import timecard_reconciliation_handler

event = {
    'action': 'adhoc_reconciliation',
    'parameters': {
        'from_date': '2026-01-05-05:00',
        'to_date': '2026-01-06-05:00',
        'environment': 'prod'  # or 'preprod', 'sandbox', 'local'
    }
}
result = timecard_reconciliation_handler(event, {})
print('Result:', result)
"
```

### Scheduled Daily Run (Lambda)

The function automatically runs for yesterday's date when triggered by:
- **CloudWatch Events**: Daily at 9am CST
- **SQS Message**: End-of-batch completion from `pos-timecard-batch-completion-queue`

### Lambda Event Format

```json
{
  "action": "adhoc_reconciliation",
  "parameters": {
    "from_date": "2026-01-05-05:00",
    "to_date": "2026-01-06-05:00",
    "environment": "prod"
  }
}
```

## Report Output

### Summary Cards
- **Toast Timecards**: Total punches from Toast POS
- **Workday Timecards**: Total punches from Workday
- **Punch Diff**: Difference (negative = missing in Workday)
- **Hours Diff**: Hour discrepancy between systems

### Venue Comparison Table
| Column | Description |
|--------|-------------|
| Site ID | Venue site identifier |
| Venue | Location name |
| Toast Punches | Raw punch count from Toast |
| Toast Hours | Calculated hours from Toast |
| Workday Punches | Raw punch count from Workday |
| Workday Hours | Calculated hours from Workday |
| Punch Diff | Workday - Toast (negative = missing) |
| Hours Diff | Hour variance |
| Incomplete | Odd punch counts (historical only) |
| Missing in Workday | Button to view missing punch details |

### Missing Punch Details
Expandable accordion sections per venue showing:
- Employee ID
- Event type (Check-in, Check-out)
- Timestamp (UTC)
- Expected Workday event

## Business Logic

### POS Business Day
- Runs from **5:00 AM to 5:00 AM** (next day)
- Date ranges should use format: `YYYY-MM-DD-05:00`

### Matching Algorithm
1. Normalize all timestamps to UTC (minute precision)
2. Create unique key: `{employee_id}_{timestamp}_{event_type}`
3. Compare Toast keys against Workday keys
4. Report any Toast keys not found in Workday

### Hour Calculation
- Pairs Check-in and Check-out events by employee
- Calculates duration in hours
- Cross-midnight shifts handled correctly

## Vault Configuration

### Preprod
- **URL**: `https://vault.preprod.topgolf.io`
- **Mount**: `mulesoft-integrations`
- **Path**: `sys-hris-api`
- **Key**: `workday_password_prop`

### Production
- **URL**: `https://vault.topgolf.io`
- **Mount**: `mulesoft-integrations`
- **Path**: `sys-hris-api`
- **Key**: `workday_password_prop`

## AWS Resources

| Resource | ARN/Details |
|----------|-------------|
| SQS Queue | `arn:aws:sqs:us-east-1:484346401365:pos-timecard-batch-completion-queue` |
| Schedule | Daily at 9:00 AM CST |
| IAM Auth | Lambda uses IAM role for Vault access |

## Troubleshooting

### Common Issues

**"Venue_Unknown" entries**
- Check that location data is attached to Workday punches
- Verify cache has correct HRIS location mappings

**Missing punches showing as false positives**
- Same-minute punches may overwrite each other
- Event type is now included in matching key to prevent this

**Hours showing 0.00**
- Check that Check-in/Check-out pairs are complete
- Cross-midnight shifts require correct business date handling

**Report not saving to Windows share**
- Verify network connectivity to `\\TIO365TEST`
- Check Lambda has write permissions to the share

### Debug Mode

Add employee ID filtering to trace specific issues:
```python
# In match_timecards function
if employee_id == '1035434':
    print(f"[MATCH DEBUG] Employee {employee_id} keys: {list(toast_by_key.keys())}")
```

## Development

### Project Structure
```
reconciliation-report-timecards/
├── README.md
├── timecard_reconciliation_lambda.py   # Main Lambda function
├── requirements.txt                     # Python dependencies
└── reports/                            # Local report output (gitignored)
```

### Running Tests
```bash
# Test with sandbox environment (no production impact)
python3 -c "
from timecard_reconciliation_lambda import timecard_reconciliation_handler
event = {'action': 'adhoc_reconciliation', 'parameters': {'from_date': '2026-01-05-05:00', 'to_date': '2026-01-06-05:00', 'environment': 'sandbox'}}
timecard_reconciliation_handler(event, {})
"
```

## Roadmap

- [ ] Add venue filter parameter (`-v/--venue`) for single-venue runs
- [ ] CLI wrapper script with argparse for easier local testing
- [ ] Fix global hours calculation discrepancy
- [ ] Implement full 5am-5am POS business day logic
- [ ] Add `--dry-run` flag to skip Slack notifications
- [ ] CloudWatch dashboard for monitoring

## Contributing

1. Create feature branch from `main`
2. Test changes locally with `sandbox` environment
3. Verify in `preprod` before production deploy
4. Submit PR with description of changes

## Support

- **Slack**: `#timecard-reconciliation-project`
- **Team**: Integration Engineering

---

*Last updated: January 2026*
