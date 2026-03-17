#!/usr/bin/env python3
"""
Secret Scanner - Detect hardcoded credentials in code repositories
Scans files for common secret patterns (API keys, passwords, tokens)
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import List, Dict

class SecretScanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.findings = []
        
        # Secret patterns (regex)
        self.patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'(?i)aws(.{0,20})?["\'][0-9a-zA-Z\/+]{40}["\']',
            'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
            'Generic API Key': r'(?i)(api[_-]?key|apikey)[\s]*[=:][\s]*["\']([0-9a-zA-Z\-_]{20,})["\']',
            'Generic Secret': r'(?i)(secret|password|passwd|pwd)[\s]*[=:][\s]*["\']([^\s]{8,})["\']',
            'Private SSH Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Azure Storage Key': r'(?i)DefaultEndpointsProtocol=https;AccountName=.*;AccountKey=[0-9a-zA-Z+/=]{88}',
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'Database Connection String': r'(?i)(jdbc|mongodb|mysql|postgresql):\/\/[^\s]+'
        }
        
        # Files to ignore
        self.ignore_extensions = {'.jpg', '.png', '.gif', '.pdf', '.zip', '.tar', '.exe', '.bin'}
        self.ignore_dirs = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build'}
    
    def scan(self) -> List[Dict]:
        """Scan repository for secrets"""
        print(f"🔍 Scanning repository: {self.repo_path}")
        
        for file_path in self._get_files():
            self._scan_file(file_path)
        
        return self.findings
    
    def _get_files(self) -> List[Path]:
        """Get all files to scan"""
        files = []
        for root, dirs, filenames in os.walk(self.repo_path):
            # Remove ignored directories
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            
            for filename in filenames:
                file_path = Path(root) / filename
                if file_path.suffix not in self.ignore_extensions:
                    files.append(file_path)
        
        return files
    
    def _scan_file(self, file_path: Path):
        """Scan a single file for secrets"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            for line_num, line in enumerate(content.split('\n'), 1):
                for secret_type, pattern in self.patterns.items():
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        # Determine severity
                        severity = self._get_severity(secret_type)
                        
                        self.findings.append({
                            'file': str(file_path.relative_to(self.repo_path)),
                            'line': line_num,
                            'type': secret_type,
                            'severity': severity,
                            'match': match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0)
                        })
        except Exception as e:
            # Skip files that can't be read
            pass
    
    def _get_severity(self, secret_type: str) -> str:
        """Determine severity based on secret type"""
        critical = ['AWS Access Key', 'AWS Secret Key', 'Private SSH Key', 'Stripe API Key', 'Azure Storage Key']
        high = ['GitHub Token', 'Generic API Key', 'Slack Token', 'Google API Key']
        
        if secret_type in critical:
            return 'CRITICAL'
        elif secret_type in high:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def generate_report(self, output_format: str = 'text', output_file: str = None):
        """Generate report in specified format"""
        if output_format == 'json':
            report = json.dumps(self.findings, indent=2)
        else:
            report = self._generate_text_report()
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"\nReport saved to: {output_file}")
        else:
            print(report)
    
    def _generate_text_report(self) -> str:
        """Generate human-readable text report"""
        lines = []
        lines.append("\n" + "=" * 70)
        lines.append("SECRET SCANNER RESULTS")
        lines.append("=" * 70 + "\n")
        
        if not self.findings:
            lines.append("No secrets found!")
            lines.append("=" * 70 + "\n")
            return "\n".join(lines)
        
        # Group by severity
        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
        
        if critical:
            lines.append("CRITICAL FINDINGS:")
            for finding in critical:
                lines.append(f"   {finding['type']} found in {finding['file']}:{finding['line']}")
                lines.append(f"   Match: {finding['match']}")
                lines.append("")
        
        if high:
            lines.append("HIGH FINDINGS:")
            for finding in high:
                lines.append(f"   {finding['type']} found in {finding['file']}:{finding['line']}")
                lines.append(f"   Match: {finding['match']}")
                lines.append("")
        
        if medium:
            lines.append("🔸 MEDIUM FINDINGS:")
            for finding in medium:
                lines.append(f"   {finding['type']} found in {finding['file']}:{finding['line']}")
                lines.append("")
        
        lines.append("=" * 70)
        lines.append(f" Total secrets found: {len(self.findings)}")
        lines.append(f"   Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)}")
        lines.append("=" * 70 + "\n")
        
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description='Secret Scanner - Detect hardcoded credentials')
    parser.add_argument('--repo', '-r', required=True, help='Path to repository to scan')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', '-f', choices=['text', 'json'], default='text', help='Output format')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.repo):
        print(f" Error: Repository path not found: {args.repo}")
        return 1
    
    scanner = SecretScanner(args.repo)
    scanner.scan()
    scanner.generate_report(output_format=args.format, output_file=args.output)
    
    return 0 if len(scanner.findings) == 0 else 1


if __name__ == "__main__":
    exit(main())