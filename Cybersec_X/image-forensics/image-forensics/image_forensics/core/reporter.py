"""Report generation module for forensic analysis."""

import json
import csv
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path


class ReportGenerator:
    """Generates forensic reports in various formats."""

    def __init__(self):
        """Initialize the report generator."""
        pass

    def save_json(self, data: Any, output_path: str) -> None:
        """Save data as JSON.

        Args:
            data: Data to save
            output_path: Output file path
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

    def save_csv(self, metadata_list: List[Dict], output_path: str) -> None:
        """Save metadata as CSV.

        Args:
            metadata_list: List of metadata dictionaries
            output_path: Output file path
        """
        if not metadata_list:
            return

        # Flatten metadata to CSV columns
        rows = []
        all_fields = set()

        for metadata in metadata_list:
            row = {'filename': metadata.get('filename', '')}

            # Basic info
            basic = metadata.get('basic_info', {})
            for key, value in basic.items():
                col_name = f"basic_{key}"
                row[col_name] = str(value)
                all_fields.add(col_name)

            # EXIF
            exif = metadata.get('exif', {})
            for key, value in exif.items():
                row[f"exif_{key}"] = str(value)
                all_fields.add(f"exif_{key}")

            # GPS
            gps = metadata.get('gps', {})
            for key, value in gps.items():
                row[f"gps_{key}"] = str(value)
                all_fields.add(f"gps_{key}")

            # File info
            file_info = metadata.get('file_info', {})
            for key, value in file_info.items():
                if key != 'size_bytes':
                    row[f"file_{key}"] = str(value)
                    all_fields.add(f"file_{key}")

            rows.append(row)

        # Write CSV
        fieldnames = ['filename'] + sorted([f for f in all_fields if f != 'filename'])

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    def generate_html_report(self, report_data: Dict, output_path: str) -> None:
        """Generate HTML forensic report.

        Args:
            report_data: Report data dictionary
            output_path: Output file path
        """
        metadata = report_data.get('metadata', {})
        analysis = report_data.get('analysis', {})
        hashes = report_data.get('hashes', {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Image Forensics Report - {metadata.get('filename', 'Unknown')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; margin-bottom: 20px; }}
        h2 {{ color: #ff6b6b; margin: 20px 0 10px; font-size: 1.3em; }}
        h3 {{ color: #ffd93d; margin: 15px 0 8px; font-size: 1.1em; }}
        .card {{ background: #16213e; border-radius: 8px; padding: 15px; margin-bottom: 15px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #0f3460; }}
        th {{ background: #0f3460; color: #00d4ff; }}
        .risk-critical {{ color: #ff4444; font-weight: bold; }}
        .risk-high {{ color: #ff6b6b; font-weight: bold; }}
        .risk-medium {{ color: #ffd93d; font-weight: bold; }}
        .risk-low {{ color: #6bff6b; font-weight: bold; }}
        .risk-minimal {{ color: #888; }}
        .anomaly {{ background: #2d1f1f; border-left: 4px solid #ff4444; padding: 10px; margin: 5px 0; }}
        .finding {{ background: #1f2d2d; border-left: 4px solid #00d4ff; padding: 10px; margin: 5px 0; }}
        .hash {{ font-family: monospace; font-size: 0.9em; background: #0f3460; padding: 5px 10px; border-radius: 4px; word-break: break-all; }}
        .metadata-key {{ color: #ff44ff; }}
        .metadata-value {{ color: #fff; }}
        .timestamp {{ color: #888; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📸 Image Forensics Analysis Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="card">
            <h2>File Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Filename</td><td>{metadata.get('filename', 'N/A')}</td></tr>
                <tr><td>File Path</td><td>{metadata.get('file_path', 'N/A')}</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Cryptographic Hashes (Chain of Custody)</h2>
            <table>
                <tr><th>Algorithm</th><th>Hash Value</th></tr>
                <tr><td>MD5</td><td><span class="hash">{hashes.get('md5', 'N/A')}</span></td></tr>
                <tr><td>SHA1</td><td><span class="hash">{hashes.get('sha1', 'N/A')}</span></td></tr>
                <tr><td>SHA256</td><td><span class="hash">{hashes.get('sha256', 'N/A')}</span></td></tr>
                <tr><td>SHA512</td><td><span class="hash">{hashes.get('sha512', 'N/A')}</span></td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Risk Assessment</h2>
            <p>Risk Level: <span class="risk-{analysis.get('risk_level', 'unknown')}">{analysis.get('risk_level', 'Unknown').upper()}</span></p>
            <p>Risk Score: {analysis.get('risk_score', 0)}</p>
        </div>
"""

        # Add anomalies section
        anomalies = analysis.get('anomalies', [])
        if anomalies:
            html += '<div class="card"><h2>⚠️ Anomalies Detected</h2>'
            for anomaly in anomalies:
                html += f"""
                <div class="anomaly">
                    <strong>[{anomaly.get('severity', 'info').upper()}]</strong> {anomaly.get('type', 'Unknown')}: {anomaly.get('description', '')}
                </div>"""
            html += '</div>'

        # Add findings section
        findings = analysis.get('findings', [])
        if findings:
            html += '<div class="card"><h2>📋 Findings</h2>'
            for finding in findings:
                html += f'<div class="finding">{finding}</div>'
            html += '</div>'

        # Add basic info section
        basic_info = metadata.get('basic_info', {})
        if basic_info:
            html += '<div class="card"><h2>Image Properties</h2><table>'
            for key, value in basic_info.items():
                html += f'<tr><td class="metadata-key">{key}</td><td class="metadata-value">{value}</td></tr>'
            html += '</table></div>'

        # Add EXIF section
        exif = metadata.get('exif', {})
        if exif:
            html += '<div class="card"><h2>EXIF Metadata</h2><table>'
            html += '<tr><th>Tag</th><th>Value</th></tr>'
            for key, value in list(exif.items())[:50]:  # Limit for readability
                html += f'<tr><td class="metadata-key">{key}</td><td class="metadata-value">{value}</td></tr>'
            html += '</table></div>'

        # Add GPS section
        gps = metadata.get('gps', {})
        if gps:
            html += '<div class="card"><h2>GPS Coordinates</h2><table>'
            for key, value in gps.items():
                html += f'<tr><td class="metadata-key">{key}</td><td class="metadata-value">{value}</td></tr>'
            html += '</table></div>'

        # Add software section
        software = metadata.get('software', {})
        if software:
            html += '<div class="card"><h2>Software/Processing History</h2><table>'
            for key, value in software.items():
                html += f'<tr><td class="metadata-key">{key}</td><td class="metadata-value">{value}</td></tr>'
            html += '</table></div>'

        # Close HTML
        html += f"""
        <div class="card">
            <p class="timestamp">Analysis completed: {analysis.get('timestamp_analyzed', 'N/A')}</p>
        </div>
    </div>
</body>
</html>"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def generate_summary(self, metadata: Dict) -> str:
        """Generate text summary of metadata.

        Args:
            metadata: Metadata dictionary

        Returns:
            Formatted text summary
        """
        lines = []
        lines.append(f"File: {metadata.get('filename', 'Unknown')}")
        lines.append("-" * 40)

        basic = metadata.get('basic_info', {})
        if basic:
            lines.append(f"Dimensions: {basic.get('dimensions', 'Unknown')}")
            lines.append(f"Format: {basic.get('format', 'Unknown')}")

        exif = metadata.get('exif', {})
        if exif:
            lines.append(f"Camera: {exif.get('Make', '')} {exif.get('Model', '')}")
            lines.append(f"Date: {exif.get('DateTimeOriginal', exif.get('DateTime', 'Unknown'))}")

        gps = metadata.get('gps', {})
        if gps and 'latitude_decimal' in gps:
            lines.append(f"GPS: {gps['latitude_decimal']}, {gps['longitude_decimal']}")

        return "\n".join(lines)