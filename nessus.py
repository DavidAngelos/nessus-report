#!/usr/bin/env python3
"""
Nessus CSV Report Generator
Converts Nessus CSV exports into professional customer-ready reports
"""

import pandas as pd
import argparse
import sys
from datetime import datetime
from pathlib import Path
import re
from openpyxl import load_workbook
from openpyxl.chart import PieChart, BarChart, Reference
from openpyxl.chart.label import DataLabelList

class NessusReportGenerator:
    def __init__(self, csv_file):
        self.csv_file = csv_file
        self.df = None
        self.summary_stats = {}
        
    def load_data(self):
        """Load and validate the Nessus CSV file"""
        try:
            # Try different encodings in case of special characters
            encodings = ['utf-8', 'latin-1', 'cp1252']
            for encoding in encodings:
                try:
                    self.df = pd.read_csv(self.csv_file, encoding=encoding)
                    print(f"Successfully loaded {len(self.df)} records using {encoding} encoding")
                    break
                except UnicodeDecodeError:
                    continue
            
            if self.df is None:
                raise ValueError("Could not read CSV file with any supported encoding")
                
            # Display available columns for debugging
            print(f"Available columns: {list(self.df.columns)}")
            
            # Clean column names (remove extra spaces, standardize)
            self.df.columns = self.df.columns.str.strip()
            
            # Remove informational findings that are not security issues
            informational_filters = [
                'Nessus Scan Information',
                'Traceroute Information',
                'Service Detection',
                'Nessus SYN scanner',
                'OS Identification',
                'Device Type',
                'Common Platform Enumeration',
                'Target Credential Status',
                'OS Security Patch Assessment Not Available'
            ]
            
            print(f"Total findings before filtering: {len(self.df)}")
            
            # Filter out purely informational findings
            self.df = self.df[~self.df['Name'].isin(informational_filters)]
            
            print(f"Security-relevant findings after filtering: {len(self.df)}")
            
            return True
            
        except Exception as e:
            print(f"Error loading CSV file: {e}")
            return False
    
    def clean_data(self):
        """Clean and standardize the data"""
        # Remove empty rows
        self.df = self.df.dropna(how='all')
        
        # Clean up text fields - remove extra quotes and whitespace
        text_columns = ['Name', 'Synopsis', 'Description', 'Solution', 'CVE']
        for col in text_columns:
            if col in self.df.columns:
                self.df[col] = self.df[col].astype(str).str.strip().str.replace('"', '')
        
        # Clean up Risk field
        if 'Risk' in self.df.columns:
            self.df['Risk'] = self.df['Risk'].astype(str).str.strip()
        
        # Clean up CVSS scores
        for col in ['CVSS v2.0 Base Score', 'CVSS v3.0 Base Score']:
            if col in self.df.columns:
                self.df[col] = self.df[col].astype(str).str.strip()
                # Convert empty strings to None
                self.df[col] = self.df[col].replace('', None)
        
        # Clean up Host/IP information
        if 'Host' in self.df.columns:
            self.df['Host'] = self.df['Host'].astype(str).str.strip()
            
        # Create a combined CVSS score column for sorting
        self.df['CVSS_Score'] = None
        if 'CVSS v3.0 Base Score' in self.df.columns:
            self.df['CVSS_Score'] = pd.to_numeric(self.df['CVSS v3.0 Base Score'], errors='coerce')
        
        # Fall back to CVSS v2.0 if v3.0 is not available
        if 'CVSS v2.0 Base Score' in self.df.columns:
            mask = self.df['CVSS_Score'].isna()
            self.df.loc[mask, 'CVSS_Score'] = pd.to_numeric(self.df.loc[mask, 'CVSS v2.0 Base Score'], errors='coerce')
    
    def generate_summary(self):
        """Generate summary statistics"""
        # Risk level summary
        if 'Risk' in self.df.columns:
            risk_counts = self.df['Risk'].value_counts()
            self.summary_stats['by_severity'] = risk_counts.to_dict()
            
            # Calculate risk score based on severity
            risk_weights = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'None': 0}
            total_risk_score = sum(risk_weights.get(risk, 0) * count for risk, count in risk_counts.items())
            self.summary_stats['risk_score'] = total_risk_score
        
        # Host statistics
        if 'Host' in self.df.columns:
            hosts_with_issues = self.df[self.df['Risk'] != 'None']['Host'].nunique()
            total_hosts = self.df['Host'].nunique()
            self.summary_stats['total_hosts'] = total_hosts
            self.summary_stats['hosts_with_issues'] = hosts_with_issues
            
            # Most affected hosts
            host_counts = self.df[self.df['Risk'] != 'None']['Host'].value_counts()
            self.summary_stats['most_affected_hosts'] = host_counts.head(10).to_dict()
        
        # Total findings
        security_findings = len(self.df[self.df['Risk'] != 'None'])
        self.summary_stats['total_findings'] = len(self.df)
        self.summary_stats['security_findings'] = security_findings
        
        # Top vulnerabilities by occurrence
        vuln_counts = self.df[self.df['Risk'] != 'None']['Name'].value_counts()
        self.summary_stats['top_vulnerabilities'] = vuln_counts.head(10).to_dict()
        
        # CVSS statistics
        if 'CVSS_Score' in self.df.columns:
            cvss_data = self.df[self.df['CVSS_Score'].notna()]['CVSS_Score']
            if len(cvss_data) > 0:
                self.summary_stats['avg_cvss'] = round(cvss_data.mean(), 2)
                self.summary_stats['max_cvss'] = round(cvss_data.max(), 2)
                self.summary_stats['high_cvss_count'] = len(cvss_data[cvss_data >= 7.0])
        
        # Port/Service statistics
        if 'Port' in self.df.columns:
            common_ports = self.df[self.df['Risk'] != 'None']['Port'].value_counts()
            self.summary_stats['common_vulnerable_ports'] = common_ports.head(10).to_dict()
    
    def create_executive_summary(self):
        """Create executive summary dataframe"""
        summary_data = []
        
        # Overview
        summary_data.append(['Assessment Overview', ''])
        summary_data.append(['Total Hosts Scanned', self.summary_stats.get('total_hosts', 'N/A')])
        summary_data.append(['Hosts with Security Issues', self.summary_stats.get('hosts_with_issues', 'N/A')])
        summary_data.append(['Total Findings', self.summary_stats.get('total_findings', 'N/A')])
        summary_data.append(['Security-Relevant Findings', self.summary_stats.get('security_findings', 'N/A')])
        
        # CVSS Statistics
        if 'avg_cvss' in self.summary_stats:
            summary_data.append(['', ''])
            summary_data.append(['CVSS Metrics', ''])
            summary_data.append(['Average CVSS Score', self.summary_stats.get('avg_cvss', 'N/A')])
            summary_data.append(['Highest CVSS Score', self.summary_stats.get('max_cvss', 'N/A')])
            summary_data.append(['High Risk Findings (CVSS â‰¥ 7.0)', self.summary_stats.get('high_cvss_count', 'N/A')])
        
        # Risk Distribution
        if 'by_severity' in self.summary_stats:
            summary_data.append(['', ''])
            summary_data.append(['Risk Level Distribution', ''])
            risk_order = ['Critical', 'High', 'Medium', 'Low', 'None']
            for risk in risk_order:
                count = self.summary_stats['by_severity'].get(risk, 0)
                if count > 0:
                    summary_data.append([f'{risk} Risk', count])
        
        # Top Issues
        if 'top_vulnerabilities' in self.summary_stats:
            summary_data.append(['', ''])
            summary_data.append(['Most Common Vulnerabilities', ''])
            for vuln, count in list(self.summary_stats['top_vulnerabilities'].items())[:5]:
                # Truncate long vulnerability names
                vuln_name = vuln[:60] + "..." if len(vuln) > 60 else vuln
                summary_data.append([vuln_name, count])
        
        return pd.DataFrame(summary_data, columns=['Metric', 'Value'])
    
    def generate_colored_findings_table(self):
        detailed_df = self.create_detailed_report()

        def color_row(row):
            color_map = {
                "Critical": "#8e44ad",  # Purple
                "High": "#e74c3c",      # Red
                "Medium": "#f39c12",    # Orange
                "Low": "#27ae60"        # Green
            }
            bg = color_map.get(row['Risk'], "")
            return f'background-color: {bg}; color: white;' if bg else ''

        styled_df = detailed_df.style.apply(
            lambda row: [color_row(row)] * len(row), axis=1
        )
        return styled_df.to_html()


    def create_detailed_report(self):
        """Create detailed findings report"""
        # Select columns that are relevant for customer reports
        customer_columns = [
            'Host',
            'Port',
            'Protocol', 
            'Name',
            'Risk',
            'CVSS v3.0 Base Score',
            'CVSS v2.0 Base Score',
            'CVE',
            'Synopsis',
            'Description',
            'Solution'
        ]
        
        # Only include columns that exist in the dataframe
        available_columns = [col for col in customer_columns if col in self.df.columns]
        
        # Filter out informational findings for the customer report
        security_df = self.df[self.df['Risk'] != 'None'].copy()
        
        if len(security_df) == 0:
            # If no security findings, show a subset of all findings
            security_df = self.df.copy()
        
        detailed_df = security_df[available_columns].copy()
        
        if 'CVSS_Score' in security_df.columns:
            detailed_df['CVSS_Score'] = security_df['CVSS_Score']

        # Include CVSS_Score temporarily for sorting
        if 'CVSS_Score' in self.df.columns:
            security_df['CVSS_Score'] = self.df.loc[security_df.index, 'CVSS_Score']

        # Sort by risk level and CVSS score
        risk_order = ['Critical', 'High', 'Medium', 'Low', 'None']
        if 'Risk' in detailed_df.columns:
            detailed_df['Risk'] = pd.Categorical(detailed_df['Risk'], categories=risk_order, ordered=True)
            detailed_df = detailed_df.sort_values(['Risk', 'CVSS_Score'], ascending=[True, False], na_position='last')
        
        # Clean up the description and solution fields for better presentation
        if 'Description' in detailed_df.columns:
            detailed_df['Description'] = detailed_df['Description'].str.replace('\n\n', ' ').str.replace('\n', ' ')
            # Limit description length for readability
            detailed_df['Description'] = detailed_df['Description'].apply(
                lambda x: x[:500] + "..." if len(str(x)) > 500 else x
            )
        
        if 'Solution' in detailed_df.columns:
            detailed_df['Solution'] = detailed_df['Solution'].str.replace('\n\n', ' ').str.replace('\n', ' ')
        
        # Create a combined CVSS column for the report
        if 'CVSS v3.0 Base Score' in detailed_df.columns and 'CVSS v2.0 Base Score' in detailed_df.columns:
            detailed_df['CVSS Score'] = detailed_df['CVSS v3.0 Base Score'].fillna(detailed_df['CVSS v2.0 Base Score'])
            # Remove the individual CVSS columns to avoid confusion
            detailed_df = detailed_df.drop(['CVSS v3.0 Base Score', 'CVSS v2.0 Base Score'], axis=1)
        
        # Remove the temporary CVSS_Score column if it exists
        if 'CVSS_Score' in detailed_df.columns:
            detailed_df = detailed_df.drop('CVSS_Score', axis=1)

        return detailed_df
        
    def create_host_summary(self):
        """Create a summary by host"""
        if 'Host' not in self.df.columns:
            return pd.DataFrame()
        
        host_summary = []
        security_df = self.df[self.df['Risk'] != 'None']
        
        for host in sorted(security_df['Host'].unique()):
            host_data = security_df[security_df['Host'] == host]
            
            # Count findings by risk level
            risk_counts = host_data['Risk'].value_counts()
            
            # Calculate highest CVSS score
            cvss_scores = host_data['CVSS_Score'].dropna()
            max_cvss = cvss_scores.max() if len(cvss_scores) > 0 else 'N/A'
            
            # Get most common ports
            common_ports = host_data['Port'].value_counts().head(3)
            ports_str = ', '.join([f"{port}({count})" for port, count in common_ports.items()])
            
            host_summary.append({
                'Host': host,
                'Total Issues': len(host_data),
                'Critical': risk_counts.get('Critical', 0),
                'High': risk_counts.get('High', 0),
                'Medium': risk_counts.get('Medium', 0),
                'Low': risk_counts.get('Low', 0),
                'Highest CVSS': max_cvss,
                'Common Ports': ports_str
            })
        
        return pd.DataFrame(host_summary)
    
    def export_to_csv(self, output_prefix):
        """Export reports to CSV files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Executive Summary
        summary_df = self.create_executive_summary()
        summary_file = f"{output_prefix}_executive_summary_{timestamp}.csv"
        summary_df.to_csv(summary_file, index=False)
        print(f"Executive summary exported to: {summary_file}")
        
        # Detailed Report
        detailed_df = self.create_detailed_report()
        detailed_file = f"{output_prefix}_detailed_findings_{timestamp}.csv"
        detailed_df.to_csv(detailed_file, index=False)
        print(f"Detailed findings exported to: {detailed_file}")
        
        return summary_file, detailed_file
    
    def export_to_excel(self, output_prefix):
        """Export reports to Excel with multiple sheets and charts"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        excel_file = f"{output_prefix}_security_assessment_{timestamp}.xlsx"

        # Step 1: Create Excel file with pandas
        with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
            summary_df = self.create_executive_summary()
            summary_df.to_excel(writer, sheet_name='Executive Summary', index=False)

            host_summary_df = self.create_host_summary()
            if not host_summary_df.empty:
                host_summary_df.to_excel(writer, sheet_name='Host Summary', index=False)

            detailed_df = self.create_detailed_report()
            detailed_df.to_excel(writer, sheet_name='Security Findings', index=False)

            info_findings = self.df[self.df['Risk'] == 'None']
            if not info_findings.empty:
                info_columns = ['Host', 'Port', 'Protocol', 'Name', 'Synopsis']
                available_info_cols = [col for col in info_columns if col in info_findings.columns]
                info_findings[available_info_cols].to_excel(writer, sheet_name='Informational', index=False)

        # Step 2: Reopen with openpyxl and add charts
        from openpyxl import load_workbook
        from openpyxl.chart import PieChart, BarChart, Reference
        from openpyxl.chart.label import DataLabelList

        wb = load_workbook(excel_file)
        chart_ws = wb.create_sheet("Charts")

        # Pie chart: Risk level distribution
        chart_ws.append(["Risk", "Count"])
        for risk, count in self.summary_stats.get("by_severity", {}).items():
            chart_ws.append([risk, count])

        pie = PieChart()
        pie.title = "Findings by Risk"
        data = Reference(chart_ws, min_col=2, min_row=1, max_row=5)
        labels = Reference(chart_ws, min_col=1, min_row=2, max_row=5)
        pie.add_data(data, titles_from_data=True)
        pie.set_categories(labels)
        pie.dataLabels = DataLabelList()
        pie.dataLabels.showVal = True
        chart_ws.add_chart(pie, "E2")

        # Bar chart: Top hosts
        start_row = len(chart_ws["A"]) + 3
        chart_ws.append([])
        chart_ws.append(["Host", "Findings"])
        for host, count in self.summary_stats.get("most_affected_hosts", {}).items():
            chart_ws.append([host, count])

        bar1 = BarChart()
        bar1.title = "Top 5 Most Affected Hosts"
        data = Reference(chart_ws, min_col=2, min_row=start_row+1, max_row=start_row+5)
        labels = Reference(chart_ws, min_col=1, min_row=start_row+2, max_row=start_row+6)
        bar1.add_data(data, titles_from_data=True)
        bar1.set_categories(labels)
        chart_ws.add_chart(bar1, f"E{start_row + 1}")

        # Bar chart: Top vulnerabilities
        start_row2 = len(chart_ws["A"]) + 3
        chart_ws.append([])
        chart_ws.append(["Vulnerability", "Count"])
        for vuln, count in self.summary_stats.get("top_vulnerabilities", {}).items():
            label = vuln[:30] + '...' if len(vuln) > 30 else vuln
            chart_ws.append([label, count])

        bar2 = BarChart()
        bar2.title = "Top 5 Vulnerabilities"
        data = Reference(chart_ws, min_col=2, min_row=start_row2+1, max_row=start_row2+5)
        labels = Reference(chart_ws, min_col=1, min_row=start_row2+2, max_row=start_row2+6)
        bar2.add_data(data, titles_from_data=True)
        bar2.set_categories(labels)
        chart_ws.add_chart(bar2, f"E{start_row2 + 1}")

        wb.save(excel_file)
        print(f"Excel report exported to: {excel_file}")
        return excel_file
    
    def export_to_html(self, output_prefix):
        """Export to HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_file = f"{output_prefix}_security_report_{timestamp}.html"
        
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
                .header {{ background: linear-gradient(135deg, #2c3e50, #3498db); color: white; padding: 30px; text-align: center; border-radius: 10px; }}
                .summary {{ background-color: #ecf0f1; padding: 20px; margin: 20px 0; border-radius: 8px; }}
                .risk-high {{ background-color: #e74c3c; color: white; padding: 5px; border-radius: 3px; }}
                .risk-medium {{ background-color: #f39c12; color: white; padding: 5px; border-radius: 3px; }}
                .risk-low {{ background-color: #27ae60; color: white; padding: 5px; border-radius: 3px; }}
                .risk-critical {{ background-color: #8e44ad; color: white; padding: 5px; border-radius: 3px; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #3498db; color: white; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .section {{ margin: 30px 0; }}
                h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                .metric-value {{ font-weight: bold; color: #2980b9; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Assessment Report</h1>
                <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="summary">
                    {self.create_executive_summary().to_html(index=False, escape=False, classes='summary-table')}
                </div>
            </div>
            
            <div class="section">
                <h2>Host Summary</h2>
                {self.create_host_summary().to_html(index=False, escape=False) if not self.create_host_summary().empty else '<p>No host-specific data available</p>'}
            </div>
            
            <div class="section">
                <h2>Security Findings</h2>
                {self.generate_colored_findings_table()}
            </div>
            
            <div class="section">
                <h2>Report Notes</h2>
                <p><strong>Risk Levels:</strong></p>
                <ul>
                    <li><span class="risk-critical">Critical</span>: Immediate action required</li>
                    <li><span class="risk-high">High</span>: Address as soon as possible</li>
                    <li><span class="risk-medium">Medium</span>: Address in next maintenance window</li>
                    <li><span class="risk-low">Low</span>: Address when convenient</li>
                </ul>
                <p><strong>CVSS Scoring:</strong> Common Vulnerability Scoring System scores range from 0.0 to 10.0, with higher scores indicating more severe vulnerabilities.</p>
            </div>
        </body>
        </html>
        """
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"HTML report exported to: {html_file}")
        return html_file

def main():
    parser = argparse.ArgumentParser(description='Convert Nessus CSV exports to customer-ready reports')
    parser.add_argument('csv_file', help='Path to the Nessus CSV file')
    parser.add_argument('-o', '--output', default='security_report', help='Output file prefix (default: security_report)')
    parser.add_argument('-f', '--format', choices=['csv', 'excel', 'html', 'all'], default='all', 
                        help='Output format (default: all)')
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not Path(args.csv_file).exists():
        print(f"Error: Input file '{args.csv_file}' not found")
        sys.exit(1)
    
    # Create report generator
    generator = NessusReportGenerator(args.csv_file)
    
    # Load and process data
    if not generator.load_data():
        sys.exit(1)
    
    generator.clean_data()
    generator.generate_summary()
    
    # Export based on format choice
    if args.format in ['csv', 'all']:
        generator.export_to_csv(args.output)
    
    if args.format in ['excel', 'all']:
        generator.export_to_excel(args.output)
    
    if args.format in ['html', 'all']:
        generator.export_to_html(args.output)
    
    print("\nReport generation completed successfully!")

if __name__ == "__main__":
    main()