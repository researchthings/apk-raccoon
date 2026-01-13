#!/usr/bin/env python3
"""
HTML Report Generator for APK Raccoon

Generates an interactive HTML5 dashboard from consolidated CSV findings with:
- Severity distribution charts (Chart.js)
- Searchable/sortable findings table (DataTables)
- OWASP MASTG and MITRE ATT&CK enrichment
- Dark/light mode toggle
- Export capabilities

Usage:
    python generate_html_report.py <findings.csv> <output.html> [--title "Report Title"]
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

# OWASP MASTG mapping for rule IDs
OWASP_MAPPING = {
    # Manifest issues
    "MAN_": "MASVS-PLATFORM-1",
    "COMP_EXPORTED": "MASVS-PLATFORM-1",
    # Secrets
    "SEC_": "MASVS-STORAGE-1",
    "API_KEY": "MASVS-STORAGE-1",
    # Crypto
    "CRYPTO_": "MASVS-CRYPTO-1",
    "WEAK_": "MASVS-CRYPTO-1",
    # WebView
    "WEB_": "MASVS-PLATFORM-2",
    "WEBVIEW_": "MASVS-PLATFORM-2",
    # Storage/Logging
    "LOG_": "MASVS-STORAGE-2",
    "STORAGE_": "MASVS-STORAGE-1",
    # Network
    "NET_": "MASVS-NETWORK-1",
    "SSL_": "MASVS-NETWORK-2",
    "TLS_": "MASVS-NETWORK-2",
    "CERT_": "MASVS-NETWORK-2",
    # Auth
    "AUTH_": "MASVS-AUTH-1",
    "BIOMETRIC_": "MASVS-AUTH-2",
    # Injection
    "SQL_": "MASVS-CODE-4",
    "CMD_": "MASVS-CODE-4",
    "INJ_": "MASVS-CODE-4",
    # Binary
    "BIN_": "MASVS-RESILIENCE-1",
    "ROOT_": "MASVS-RESILIENCE-2",
    # Privacy
    "PRIV_": "MASVS-PRIVACY-1",
    "PII_": "MASVS-PRIVACY-1",
    # Content Providers
    "PROV_": "MASVS-PLATFORM-1",
    # PendingIntent
    "PEND_": "MASVS-PLATFORM-1",
    # Firebase
    "FIRE_": "MASVS-STORAGE-1",
    # Task Hijacking
    "TASK_": "MASVS-PLATFORM-1",
    # Deep Links
    "DEEP_": "MASVS-PLATFORM-1",
    "LINK_": "MASVS-PLATFORM-1",
    # Tapjacking
    "TAP_": "MASVS-PLATFORM-3",
    # Broadcasts
    "BCAST_": "MASVS-PLATFORM-1",
    # Native libs
    "NATIVE_": "MASVS-CODE-3",
    "ELF_": "MASVS-CODE-3",
    # Dynamic loading
    "DYN_": "MASVS-CODE-4",
    "LOAD_": "MASVS-CODE-4",
    # New scanners
    "ZIP_": "MASVS-CODE-4",
    "SER_": "MASVS-CODE-4",
    "FRAG_": "MASVS-PLATFORM-1",
    "XXE_": "MASVS-CODE-4",
    "IMPL_": "MASVS-PLATFORM-1",
    "CLIP_": "MASVS-STORAGE-2",
    "KEY_": "MASVS-STORAGE-2",
    "RAND_": "MASVS-CRYPTO-1",
    "SIG_": "MASVS-RESILIENCE-3",
    "DEP_": "MASVS-CODE-4",
}

# CWE mapping for common rule prefixes
CWE_MAPPING = {
    "ZIP_": "CWE-22",
    "SER_": "CWE-502",
    "FRAG_": "CWE-470",
    "XXE_": "CWE-611",
    "IMPL_": "CWE-927",
    "CLIP_": "CWE-200",
    "KEY_": "CWE-524",
    "RAND_": "CWE-338",
    "SIG_": "CWE-347",
    "DEP_": "CWE-477",
    "SQL_": "CWE-89",
    "CMD_": "CWE-78",
    "CRYPTO_": "CWE-327",
    "NET_": "CWE-319",
    "SSL_": "CWE-295",
    "LOG_": "CWE-532",
    "SEC_": "CWE-798",
    "API_KEY": "CWE-798",
    "MAN_DEBUG": "CWE-489",
    "MAN_BACKUP": "CWE-919",
    "WEB_JS": "CWE-749",
    "PROV_": "CWE-926",
    "PEND_": "CWE-927",
    "TASK_": "CWE-1021",
    "TAP_": "CWE-1021",
}

# MITRE ATT&CK Mobile mapping
MITRE_MAPPING = {
    "SEC_": "T1634 - Credentials from Password Store",
    "API_KEY": "T1634 - Credentials from Password Store",
    "LOG_": "T1533 - Data from Local System",
    "STORAGE_": "T1533 - Data from Local System",
    "NET_": "T1639 - Exfiltration Over C2",
    "SSL_": "T1557 - Adversary-in-the-Middle",
    "CRYPTO_": "T1600 - Weaken Encryption",
    "ROOT_": "T1404 - Exploit Public-Facing App",
    "BIN_OBFUSC": "T1406 - Obfuscated Files",
    "DYN_": "T1575 - Native Code",
    "BCAST_": "T1398 - Boot or Logon Initialization",
    "CLIP_": "T1414 - Clipboard Data",
    "KEY_": "T1417 - Input Capture",
    "PRIV_LOCATION": "T1430 - Location Tracking",
    "PRIV_IMEI": "T1426 - System Information Discovery",
}


def get_owasp_category(rule_id: str) -> str:
    """Get OWASP MASVS category for a rule ID."""
    for prefix, category in OWASP_MAPPING.items():
        if rule_id.startswith(prefix):
            return category
    return "MASVS-CODE-4"


def get_cwe(rule_id: str) -> str:
    """Get CWE ID for a rule ID."""
    for prefix, cwe in CWE_MAPPING.items():
        if rule_id.startswith(prefix):
            return cwe
    return ""


def get_mitre(rule_id: str) -> str:
    """Get MITRE ATT&CK technique for a rule ID."""
    for prefix, technique in MITRE_MAPPING.items():
        if rule_id.startswith(prefix):
            return technique
    return ""


def read_findings(csv_path: str) -> list[dict]:
    """Read findings from CSV file."""
    findings = []
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Skip summary rows
                if row.get("RuleID", "").endswith("_SUMMARY"):
                    continue
                # Skip Info severity (good practices)
                if row.get("Severity") == "Info":
                    continue
                findings.append(row)
    except Exception as e:
        print(f"Error reading CSV: {e}", file=sys.stderr)
        sys.exit(1)
    return findings


def generate_html_report(findings: list[dict], title: str, output_path: str):
    """Generate HTML report from findings."""

    # Count severities
    severity_counts = Counter(f.get("Severity", "Unknown") for f in findings)

    # Count by source/scanner
    source_counts = Counter(f.get("Source", "Unknown") for f in findings)

    # Count by OWASP category
    owasp_counts = Counter(get_owasp_category(f.get("RuleID", "")) for f in findings)

    # Prepare findings data for JavaScript
    findings_json = []
    for i, f in enumerate(findings):
        rule_id = f.get("RuleID", "")
        findings_json.append({
            "id": i + 1,
            "severity": f.get("Severity", "Unknown"),
            "title": f.get("Title", ""),
            "ruleId": rule_id,
            "source": f.get("Source", ""),
            "location": f.get("Location", ""),
            "evidence": f.get("Evidence", ""),
            "howFound": f.get("HowFound", ""),
            "owasp": get_owasp_category(rule_id),
            "cwe": get_cwe(rule_id),
            "mitre": get_mitre(rule_id),
        })

    # Generate timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Severity colors
    severity_colors = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#ca8a04",
        "Low": "#16a34a",
        "Info": "#6b7280",
    }

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
            --card-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }}

        [data-theme="dark"] {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --text-primary: #e4e4e7;
            --text-secondary: #a1a1aa;
            --border-color: #3f3f46;
            --card-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.3);
        }}

        body {{
            background-color: var(--bg-secondary);
            color: var(--text-primary);
            transition: all 0.3s ease;
        }}

        .card {{
            background-color: var(--bg-primary);
            border-color: var(--border-color);
            box-shadow: var(--card-shadow);
        }}

        .card-header {{
            background-color: var(--bg-secondary);
            border-color: var(--border-color);
        }}

        .table {{
            color: var(--text-primary);
        }}

        .table-striped > tbody > tr:nth-of-type(odd) {{
            background-color: rgba(0, 0, 0, 0.02);
        }}

        [data-theme="dark"] .table-striped > tbody > tr:nth-of-type(odd) {{
            background-color: rgba(255, 255, 255, 0.02);
        }}

        .severity-badge {{
            font-weight: 600;
            padding: 0.35em 0.65em;
            border-radius: 0.375rem;
        }}

        .severity-critical {{ background-color: #dc2626; color: white; }}
        .severity-high {{ background-color: #ea580c; color: white; }}
        .severity-medium {{ background-color: #ca8a04; color: white; }}
        .severity-low {{ background-color: #16a34a; color: white; }}
        .severity-info {{ background-color: #6b7280; color: white; }}

        .stat-card {{
            text-align: center;
            padding: 1.5rem;
        }}

        .stat-number {{
            font-size: 2.5rem;
            font-weight: 700;
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .theme-toggle {{
            cursor: pointer;
            font-size: 1.25rem;
            padding: 0.5rem;
            border-radius: 0.375rem;
            transition: background-color 0.2s;
        }}

        .theme-toggle:hover {{
            background-color: var(--bg-secondary);
        }}

        .evidence-cell {{
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .evidence-cell:hover {{
            white-space: normal;
            word-break: break-all;
        }}

        .enrichment-badge {{
            font-size: 0.75rem;
            margin-right: 0.25rem;
            margin-bottom: 0.25rem;
            display: inline-block;
        }}

        .navbar-brand {{
            font-weight: 700;
            font-size: 1.5rem;
        }}

        .navbar-brand span {{
            color: #10b981;
        }}

        @media print {{
            .no-print {{ display: none !important; }}
            .card {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4 no-print">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">🦝 APK <span>Raccoon</span></a>
            <div class="d-flex align-items-center">
                <span class="text-light me-3">{html.escape(title)}</span>
                <span class="theme-toggle text-light" onclick="toggleTheme()" title="Toggle dark/light mode">🌓</span>
            </div>
        </div>
    </nav>

    <div class="container-fluid">
        <!-- Summary Stats -->
        <div class="row mb-4">
            <div class="col-md-2">
                <div class="card stat-card">
                    <div class="stat-number text-danger">{severity_counts.get("Critical", 0)}</div>
                    <div class="stat-label">Critical</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card stat-card">
                    <div class="stat-number" style="color: #ea580c;">{severity_counts.get("High", 0)}</div>
                    <div class="stat-label">High</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card stat-card">
                    <div class="stat-number" style="color: #ca8a04;">{severity_counts.get("Medium", 0)}</div>
                    <div class="stat-label">Medium</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card stat-card">
                    <div class="stat-number text-success">{severity_counts.get("Low", 0)}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card stat-card">
                    <div class="stat-number text-primary">{len(findings)}</div>
                    <div class="stat-label">Total</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card stat-card">
                    <div class="stat-number text-info">{len(source_counts)}</div>
                    <div class="stat-label">Scanners</div>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0">Severity Distribution</h6>
                    </div>
                    <div class="card-body">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0">Findings by Scanner</h6>
                    </div>
                    <div class="card-body">
                        <canvas id="sourceChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0">OWASP MASVS Categories</h6>
                    </div>
                    <div class="card-body">
                        <canvas id="owaspChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Findings Table -->
        <div class="card mb-4">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h6 class="mb-0">Security Findings</h6>
                <div class="no-print">
                    <button class="btn btn-sm btn-outline-secondary me-2" onclick="window.print()">
                        📄 Print/PDF
                    </button>
                    <button class="btn btn-sm btn-outline-primary" onclick="exportCSV()">
                        📥 Export CSV
                    </button>
                </div>
            </div>
            <div class="card-body">
                <table id="findingsTable" class="table table-striped table-hover" style="width:100%">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>Rule ID</th>
                            <th>Scanner</th>
                            <th>Location</th>
                            <th>Evidence</th>
                            <th>Enrichment</th>
                        </tr>
                    </thead>
                    <tbody>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer -->
        <div class="text-center text-muted mb-4">
            <small>
                Generated by APK Raccoon on {timestamp} |
                <a href="https://github.com/anthropics/claude-code" target="_blank">Powered by Claude Code</a>
            </small>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>

    <script>
    document.addEventListener('DOMContentLoaded', function() {{
        // Findings data
        const findings = {json.dumps(findings_json)};

        // Severity counts for charts
        const severityCounts = {json.dumps(dict(severity_counts))};
        const sourceCounts = {json.dumps(dict(source_counts))};
        const owaspCounts = {json.dumps(dict(owasp_counts))};

        // Theme handling
        function toggleTheme() {{
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateChartColors();
        }}

        // Initialize theme
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);

        // Severity chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        const severityChart = new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [
                        severityCounts['Critical'] || 0,
                        severityCounts['High'] || 0,
                        severityCounts['Medium'] || 0,
                        severityCounts['Low'] || 0
                    ],
                    backgroundColor: ['#dc2626', '#ea580c', '#ca8a04', '#16a34a'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});

        // Source chart
        const sourceCtx = document.getElementById('sourceChart').getContext('2d');
        const sourceLabels = Object.keys(sourceCounts).slice(0, 10);
        const sourceData = sourceLabels.map(k => sourceCounts[k]);
        const sourceChart = new Chart(sourceCtx, {{
            type: 'bar',
            data: {{
                labels: sourceLabels,
                datasets: [{{
                    label: 'Findings',
                    data: sourceData,
                    backgroundColor: '#3b82f6',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            stepSize: 1
                        }}
                    }}
                }}
            }}
        }});

        // OWASP chart
        const owaspCtx = document.getElementById('owaspChart').getContext('2d');
        const owaspLabels = Object.keys(owaspCounts);
        const owaspData = owaspLabels.map(k => owaspCounts[k]);
        const owaspChart = new Chart(owaspCtx, {{
            type: 'polarArea',
            data: {{
                labels: owaspLabels,
                datasets: [{{
                    data: owaspData,
                    backgroundColor: [
                        'rgba(59, 130, 246, 0.7)',
                        'rgba(16, 185, 129, 0.7)',
                        'rgba(245, 158, 11, 0.7)',
                        'rgba(239, 68, 68, 0.7)',
                        'rgba(139, 92, 246, 0.7)',
                        'rgba(236, 72, 153, 0.7)',
                        'rgba(6, 182, 212, 0.7)',
                        'rgba(132, 204, 22, 0.7)'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            font: {{
                                size: 10
                            }}
                        }}
                    }}
                }}
            }}
        }});

        function updateChartColors() {{
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            const textColor = isDark ? '#e4e4e7' : '#212529';

            [severityChart, sourceChart, owaspChart].forEach(chart => {{
                if (chart.options.plugins.legend) {{
                    chart.options.plugins.legend.labels = chart.options.plugins.legend.labels || {{}};
                    chart.options.plugins.legend.labels.color = textColor;
                }}
                if (chart.options.scales) {{
                    Object.values(chart.options.scales).forEach(scale => {{
                        scale.ticks = scale.ticks || {{}};
                        scale.ticks.color = textColor;
                    }});
                }}
                chart.update();
            }});
        }}

        // Initialize DataTable
        const table = $('#findingsTable').DataTable({{
            data: findings,
            columns: [
                {{ data: 'id' }},
                {{
                    data: 'severity',
                    render: function(data) {{
                        const cls = 'severity-' + data.toLowerCase();
                        return '<span class="severity-badge ' + cls + '">' + data + '</span>';
                    }}
                }},
                {{ data: 'title' }},
                {{ data: 'ruleId' }},
                {{ data: 'source' }},
                {{
                    data: 'location',
                    render: function(data) {{
                        const short = data.split('/').pop();
                        return '<span title="' + data + '">' + short + '</span>';
                    }}
                }},
                {{
                    data: 'evidence',
                    className: 'evidence-cell',
                    render: function(data) {{
                        return '<code>' + escapeHtml(data) + '</code>';
                    }}
                }},
                {{
                    data: null,
                    render: function(row) {{
                        let badges = '';
                        if (row.owasp) {{
                            badges += '<span class="badge bg-primary enrichment-badge">' + row.owasp + '</span>';
                        }}
                        if (row.cwe) {{
                            badges += '<span class="badge bg-secondary enrichment-badge">' + row.cwe + '</span>';
                        }}
                        if (row.mitre) {{
                            badges += '<span class="badge bg-info enrichment-badge" title="' + row.mitre + '">MITRE</span>';
                        }}
                        return badges || '-';
                    }}
                }}
            ],
            order: [[1, 'asc'], [0, 'asc']],
            pageLength: 25,
            language: {{
                search: "Filter:",
                lengthMenu: "Show _MENU_ findings"
            }}
        }});

        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}

        function exportCSV() {{
            let csv = 'ID,Severity,Title,RuleID,Scanner,Location,Evidence,OWASP,CWE,MITRE\\n';
            findings.forEach(f => {{
                csv += [
                    f.id,
                    f.severity,
                    '"' + f.title.replace(/"/g, '""') + '"',
                    f.ruleId,
                    f.source,
                    '"' + f.location.replace(/"/g, '""') + '"',
                    '"' + f.evidence.replace(/"/g, '""') + '"',
                    f.owasp,
                    f.cwe,
                    '"' + (f.mitre || '').replace(/"/g, '""') + '"'
                ].join(',') + '\\n';
            }});

            const blob = new Blob([csv], {{ type: 'text/csv' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'apk_raccoon_findings.csv';
            a.click();
        }}

        // Apply saved theme to charts
        updateChartColors();
    }}); // End DOMContentLoaded
    </script>
</body>
</html>
'''

    # Write HTML file
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"Generated HTML report: {output_path}")
    print(f"  Total findings: {len(findings)}")
    print(f"  Critical: {severity_counts.get('Critical', 0)}")
    print(f"  High: {severity_counts.get('High', 0)}")
    print(f"  Medium: {severity_counts.get('Medium', 0)}")
    print(f"  Low: {severity_counts.get('Low', 0)}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate HTML report from APK Raccoon findings"
    )
    parser.add_argument("csv_file", help="Input CSV file with findings")
    parser.add_argument("output_file", help="Output HTML file path")
    parser.add_argument(
        "--title",
        default="APK Security Analysis Report",
        help="Report title"
    )

    args = parser.parse_args()

    if not os.path.exists(args.csv_file):
        print(f"Error: CSV file not found: {args.csv_file}", file=sys.stderr)
        sys.exit(1)

    findings = read_findings(args.csv_file)
    generate_html_report(findings, args.title, args.output_file)


if __name__ == "__main__":
    main()
